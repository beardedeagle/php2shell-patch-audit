#!/usr/bin/env python3
"""PHP2Shell audit: Linux/Windows discovery, portable file checks and remote inspection."""

import argparse
import base64
import gzip
import hashlib
import html
import http.client
import json
import ntpath
import os
import re
import secrets
import shlex
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zlib
from contextlib import ExitStack
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path, PureWindowsPath

CVES = ("CVE-2026-109618", "CVE-2026-109619")
BASELINES = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
KINDS = {"fpm", "mod_php", "cgi", "lsphp", "frankenphp", "php", "embedded"}
MAX_CONFIG = 1024 * 1024
# Both Ubuntu CVE pages confirmed these package revisions on 2026-10-22.
UBUNTU_FIXES = {
    ("14.04", "php5"): "5.5.9+dfsg-1ubuntu4.29+esm18",
    ("16.04", "php7.0"): "7.0.33-0ubuntu0.16.04.16+esm22",
    ("18.04", "php7.2"): "7.2.24-0ubuntu0.18.04.17+esm14",
    ("20.04", "php7.4"): "7.4.3-4ubuntu2.29+esm5",
    ("22.04", "php8.1"): "8.1.2-1ubuntu2.28",
    ("24.04", "php8.3"): "8.3.6-0ubuntu0.24.04.13",
    ("26.04", "php8.5"): "8.5.4-0ubuntu1.5",
    ("26.10", "php8.5"): "8.5.9-0ubuntu2.1",
}
UBUNTU_SOURCES = ["https://ubuntu.com/security/" + cve for cve in CVES]
# Debian's trackers for both CVEs, checked 2026-10-22. Derivatives need their own rules.
DEBIAN_FIXES = {("12", "php8.2"): "8.2.35-1~deb12u1",
                ("13", "php8.4"): "8.4.27-1~deb13u1"}
DEBIAN_SOURCES = ["https://security-tracker.debian.org/tracker/" + cve for cve in CVES]
MANAGERS = {"dpkg", "rpm", "apk", "pacman"}


class AuditError(Exception):
    pass


def command(argv, timeout=15, data=None):
    """Fixed system utilities, or a binary explicitly selected with --probe-php."""
    environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
    if sys.platform == "win32":
        directory = windows_system_directory()
        environment = {"SystemRoot": str(directory.parent), "PATH": str(directory),
                       "TEMP": os.environ.get("TEMP", str(directory.parent / "Temp"))}
        if Path(argv[0]).name.lower() == "ssh.exe":
            for key in ("USERPROFILE", "HOMEDRIVE", "HOMEPATH"):
                if key in os.environ:
                    environment[key] = os.environ[key]
    if Path(argv[0]).name == "ssh" and "SSH_AUTH_SOCK" in os.environ:
        environment["SSH_AUTH_SOCK"] = os.environ["SSH_AUTH_SOCK"]
    if Path(argv[0]).name in ("docker", "podman"):
        environment["HOME"] = str(Path.home())
        for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY",
                    "DOCKER_CERT_PATH", "CONTAINER_HOST", "CONTAINER_CONNECTION", "XDG_RUNTIME_DIR"):
            if key in os.environ:
                environment[key] = os.environ[key]
    try:
        return subprocess.run(argv, input=data, text=True, capture_output=True,
                              timeout=timeout, check=False,
                              env=environment, encoding="utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AuditError("Command failed or timed out: " + argv[0]) from exc


def windows_system_directory():
    import ctypes
    buffer = ctypes.create_unicode_buffer(32768)
    size = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))
    require(0 < size < len(buffer), "Cannot locate Windows system directory")
    return Path(buffer.value)


def system_tool(name):
    if sys.platform == "win32":
        relative = {"powershell": "WindowsPowerShell/v1.0/powershell.exe",
                    "ssh": "OpenSSH/ssh.exe"}.get(name)
        require(relative is not None, "Unsupported Windows utility: " + name)
        path = windows_system_directory() / relative
        require(path.is_file(), "Missing Windows system utility: " + name)
        return str(path)
    directories = ("/usr/bin", "/bin", "/usr/sbin", "/sbin")
    if name in ("docker", "podman"):
        directories += ("/usr/local/bin", "/opt/homebrew/bin")
    owners = {0}
    if name in ("docker", "podman") and os.getuid() == os.geteuid():
        owners.add(os.getuid())
    for directory in directories:
        path = Path(directory) / name
        try:
            info = path.stat()
            if (stat.S_ISREG(info.st_mode) and info.st_uid in owners
                    and not info.st_mode & 0o022 and os.access(path, os.X_OK)):
                return str(path)
        except OSError:
            continue
    raise AuditError("Missing trusted system utility: " + name)


def load_json(path):
    with open(path, "rb") as stream:
        data = stream.read(MAX_CONFIG + 1)
    if len(data) > MAX_CONFIG:
        raise AuditError("Configuration exceeds 1 MiB")
    return json.loads(data)


def require(condition, message):
    if not condition:
        raise AuditError(message)


def absolute_path(value):
    return bool(isinstance(value, str) and not any(ord(c) < 32 for c in value)
            and not value.startswith(("//", "\\\\"))
            and (value.startswith("/") or
                 (PureWindowsPath(value).is_absolute() and re.match(r"^[A-Za-z]:", value)
                  and ":" not in value[2:])))


def path_key(value):
    return ntpath.normcase(ntpath.normpath(value)) if re.match(r"^[A-Za-z]:", value) else value


def validate_config(inventory, evidence):
    if inventory is not None:
        require(isinstance(inventory, dict) and inventory.get("schema") == 1,
                "Inventory must have schema=1")
        require(inventory.get("coverage_confirmed") is True and
                isinstance(inventory.get("scope"), str) and inventory["scope"].strip(),
                "Inventory needs scope and an explicit coverage_confirmed=true assertion")
        require(isinstance(inventory.get("runtimes"), list) and inventory["runtimes"],
                "Inventory must contain expected runtimes")
        keys = set()
        for item in inventory["runtimes"]:
            require(isinstance(item, dict), "Invalid inventory entry")
            require(isinstance(item.get("label"), str) and item["label"].strip(),
                    "Inventory entry needs a label")
            require(isinstance(item.get("kind"), str) and item["kind"] in KINDS
                    and absolute_path(item.get("path")),
                    "Inventory entry needs a supported kind and absolute runtime path")
            key = (item["kind"], path_key(item["path"]))
            require(key not in keys, "Duplicate inventory runtime")
            keys.add(key)
    require(isinstance(evidence, dict) and evidence.get("schema") == 1,
            "Evidence must have schema=1")
    for field in ("vendor_fixes", "builds", "rpm_advisories"):
        require(isinstance(evidence.get(field, []), list), "Invalid evidence list: " + field)
    seen = set()
    for row in evidence.get("vendor_fixes", []):
        require(isinstance(row, dict), "Invalid vendor rule")
        for key in ("os_id", "os_version", "package", "fixed_version"):
            require(isinstance(row.get(key), str) and
                    re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+:~^_-]*", row[key]),
                    "Invalid vendor rule field: " + key)
        require(isinstance(row.get("manager"), str) and row["manager"] in MANAGERS and
                sorted(row.get("cves", [])) == sorted(CVES),
                "Each vendor rule must cover both CVEs and name dpkg, rpm, apk or pacman")
        require(isinstance(row.get("sources"), list) and row["sources"] and
                all(isinstance(url, str) and url.startswith("https://")
                    for url in row["sources"]), "Vendor rule needs advisory sources")
        key = tuple(row[k] for k in ("os_id", "os_version", "manager", "package"))
        require(key not in seen, "Duplicate vendor rule")
        seen.add(key)
    seen = set()
    for row in evidence.get("builds", []):
        require(isinstance(row, dict) and isinstance(row.get("sha256"), str) and
                re.fullmatch(r"[0-9a-f]{64}", row["sha256"]), "Invalid build SHA-256")
        require(isinstance(row.get("php_version"), str) and
                isinstance(row.get("source"), str) and row["source"].strip(),
                "Build evidence needs php_version and trusted build provenance")
        require(row["sha256"] not in seen, "Duplicate build SHA-256")
        if "fixed_cves" in row:
            require(isinstance(row["fixed_cves"], list) and sorted(row["fixed_cves"]) == sorted(CVES),
                    "Build fixed_cves must establish fixes for both CVEs")
        seen.add(row["sha256"])
    for row in evidence.get("rpm_advisories", []):
        require(isinstance(row, dict), "Invalid imported RPM advisory")
        for key in ("os_id", "os_version", "package", "version", "arch"):
            require(isinstance(row.get(key), str) and
                    re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+:~^_-]*", row[key]),
                    "Invalid RPM advisory field: " + key)
        require(isinstance(row.get("module"), str) and
                re.fullmatch(r"[A-Za-z0-9.+:_-]*", row["module"]) and
                isinstance(row.get("cves"), list) and row["cves"] and
                all(cve in CVES for cve in row["cves"]) and
                isinstance(row.get("source"), str) and row["source"], "Invalid RPM advisory scope")


def load_updateinfo(path, distro):
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rb") as stream:
        data = stream.read(32 * MAX_CONFIG + 1)
    require(len(data) <= 32 * MAX_CONFIG, "Updateinfo exceeds 32 MiB decompressed")
    text = data.decode("utf-8-sig")
    require("<!DOCTYPE" not in text and "<!ENTITY" not in text, "XML declarations are not allowed")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise AuditError("Invalid updateinfo XML") from exc
    for element in root.iter():
        element.tag = element.tag.rsplit("}", 1)[-1]
    require(root.tag == "updates", "Expected updateinfo updates document")
    records = []
    for update in root.findall("update"):
        cves = sorted({ref.get("id") for ref in update.findall("references/reference")
                       if ref.get("type", "").lower() == "cve" and ref.get("id") in CVES})
        if not cves:
            continue
        for collection in update.findall("pkglist/collection"):
            module = collection.find("module")
            stream = ":".join(module.get(key, "") for key in ("name", "stream", "context")) if module is not None else ""
            for package in collection.findall("package"):
                records.append({"os_id": distro[0], "os_version": distro[1],
                                "package": package.get("name"), "arch": package.get("arch"),
                                "version": package.get("epoch", "0") + ":" + package.get("version", "") + "-" + package.get("release", ""),
                                "module": stream, "cves": cves,
                                "source": str(path) + "#" + (update.findtext("id") or "unnamed")})
    validate_config(None, {"schema": 1, "rpm_advisories": records})
    require(records, "Updateinfo has no package records for these CVEs")
    return records


def updateinfo_rule(package, distro, evidence):
    if package["manager"] != "rpm" or not evidence.get("rpm_advisories"):
        return None
    if package.get("module") is None:
        return None
    module = package["module"].split(":")
    stream = ":".join((module[0], module[1], module[3])) if len(module) >= 4 else ""
    branch = re.match(r"[0-9]+:([0-9]+\.[0-9]+)\.", package["version"])
    if not branch or (package.get("module") and not stream):
        return None
    matches = [r for r in evidence.get("rpm_advisories", [])
               if (r["os_id"], r["os_version"]) == distro and
               r["package"] == package["package"] and r["arch"] == package.get("arch")
               and r["module"] == stream and
               re.match(r"[0-9]+:" + re.escape(branch[1]) + r"\.", r["version"])]
    minima, sources = [], set()
    for cve in CVES:
        candidates = [row for row in matches if cve in row["cves"]]
        if not candidates:
            return None
        minimum = candidates[0]["version"]
        for row in candidates:
            if package_status({"manager": "rpm", "version": row["version"]}, minimum) == "AFFECTED":
                minimum = row["version"]
            sources.add(row["source"])
        minima.append(minimum)
    fixed = minima[0]
    for version in minima[1:]:
        if package_status({"manager": "rpm", "version": version}, fixed) == "PATCHED":
            fixed = version
    return {"fixed_version": fixed, "sources": sorted(sources)}


def upstream_status(version):
    match = re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version)
    if not match:
        return "UNKNOWN"
    major, minor, patch = map(int, match.groups())
    minimum = BASELINES.get((major, minor))
    if minimum is None:
        return "UNKNOWN"
    return "PATCHED" if patch >= minimum else "AFFECTED"


def os_release():
    # Parse the two simple fields without sourcing a shell file.
    values = {}
    path = Path("/etc/os-release")
    if not path.is_file():
        path = Path("/usr/lib/os-release")
    for line in path.read_text().splitlines():
        match = re.fullmatch(r'(ID|VERSION_ID|VERSION_CODENAME)=["\']?([A-Za-z0-9._-]+)["\']?', line)
        if match:
            values[match[1]] = match[2]
    require("ID" in values, "Cannot determine OS release")
    return values["ID"], values.get("VERSION_ID", values.get("VERSION_CODENAME", "rolling"))


def start_time(pid):
    return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]


def same_namespace(pid):
    remote = os.stat(f"/proc/{pid}/ns/mnt")
    local = os.stat("/proc/self/ns/mnt")
    return ((remote.st_dev, remote.st_ino) == (local.st_dev, local.st_ino) and
            os.stat(f"/proc/{pid}/root").st_ino == os.stat("/").st_ino and
            os.stat(f"/proc/{pid}/root").st_dev == os.stat("/").st_dev)


def executable_kind(path):
    name = Path(path).name.lower()
    patterns = ((r"php-fpm[0-9.-]*", "fpm"), (r"php-cgi[0-9.-]*", "cgi"),
                (r"lsphp[0-9.-]*", "lsphp"), (r"frankenphp", "frankenphp"),
                (r"php[0-9.-]*", "php"), (r"caddy", "embedded"))
    return next((kind for pattern, kind in patterns if re.fullmatch(pattern, name)), None)


def proc_path(raw):
    deleted = raw.endswith(" (deleted)")
    if deleted:
        raw = raw[:-10]
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), raw), deleted


@dataclass
class Runtime:
    pid: int
    kind: str
    path: str
    live_path: str
    start: str
    deleted: bool = False
    device: int = 0
    inode: int = 0


def discover(inventory):
    if sys.platform == "win32":
        return discover_windows(inventory)
    require(sys.platform.startswith("linux"),
            "Process inspection supports Linux and Windows; use --files for other systems")
    expected = {row["path"]: row["kind"] for row in (inventory or {}).get("runtimes", [])
                if row["kind"] != "mod_php"}
    runtimes, issues = [], []
    try:
        pids = sorted(int(p.name) for p in Path("/proc").iterdir() if p.name.isdigit())
    except OSError as exc:
        raise AuditError("Cannot enumerate /proc") from exc
    require(pids, "No processes visible in /proc")
    for pid in pids:
        try:
            started = start_time(pid)
            try:
                raw_exe = os.readlink(f"/proc/{pid}/exe")
            except FileNotFoundError:
                if not Path(f"/proc/{pid}/cmdline").read_bytes():
                    continue  # Kernel thread or zombie; no executing userspace image.
                raise
            exe, deleted = proc_path(raw_exe)
            kind = expected.get(exe) or executable_kind(exe)
            found = []
            if kind:
                found.append(Runtime(pid, kind, exe, f"/proc/{pid}/exe", started, deleted))
            # Inspect modules even for renamed Apache/embedded-server executables.
            for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
                fields = line.split(None, 5)
                if len(fields) != 6:
                    continue
                path, removed = proc_path(fields[5])
                is_module = re.search(r"(?:^|/)libphp[^/]*\.so(?:\.[0-9]+)*$", path)
                is_expected = any(row["kind"] == "mod_php" and row["path"] == path
                                  for row in (inventory or {}).get("runtimes", []))
                if not is_module and not is_expected:
                    continue
                device = os.makedev(*(int(part, 16) for part in fields[3].split(":")))
                if not any(r.path == path and r.kind == "mod_php" for r in found):
                    found.append(Runtime(pid, "mod_php", path,
                                         f"/proc/{pid}/map_files/{fields[0]}", started,
                                         removed, device, int(fields[4])))
            if found and not same_namespace(pid):
                issues.append(f"PID {pid}: different mount/root namespace; audit inside it")
                continue
            if found and start_time(pid) != started:
                issues.append(f"PID {pid}: process identity changed during discovery")
                continue
            runtimes.extend(found)
        except FileNotFoundError:
            if Path(f"/proc/{pid}").exists():
                issues.append(f"PID {pid}: runtime inspection was incomplete")
        except (OSError, ValueError, IndexError):
            issues.append(f"PID {pid}: cannot inspect executable/modules; coverage incomplete")
    return runtimes, issues


WINDOWS_DISCOVERY = r'''
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
# Windows PowerShell 5.1 already returns the JSON array as one object.
$expected = [Console]::In.ReadToEnd() | ConvertFrom-Json
$processes = @()
$issues = @()
foreach ($process in @(Get-Process)) {
    if ($process.Id -in @(0, 4, $PID)) { continue }
    try {
        $started = $process.StartTime.ToUniversalTime().Ticks.ToString()
        $path = $process.MainModule.FileName
        if (-not $path) { throw 'Executable path unavailable' }
        $modules = @()
        foreach ($module in @($process.Modules)) {
            if ($module.ModuleName -match '^(php[0-9].*|libphp.*)\.(dll|so)$' -or
                $module.FileName -in $expected) {
                $modules += @{path=$module.FileName; version=$module.FileVersionInfo.ProductVersion}
            }
        }
        $current = Get-Process -Id $process.Id
        if ($current.StartTime.ToUniversalTime().Ticks.ToString() -ne $started) {
            throw 'Process identity changed'
        }
        $processes += @{pid=$process.Id; start=$started; path=$path; modules=$modules}
    } catch {
        $issues += "PID $($process.Id): cannot inspect executable/modules: $($_.Exception.Message)"
    }
}
@{processes=$processes; issues=$issues} | ConvertTo-Json -Depth 6 -Compress
'''


def powershell_json(script, data):
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    result = command([system_tool("powershell"), "-NoLogo", "-NoProfile", "-NonInteractive",
                      "-EncodedCommand", encoded], timeout=120, data=json.dumps(data))
    require(result.returncode == 0, "Windows inspection failed: " + result.stderr[:1000])
    return json.loads(result.stdout.lstrip("\ufeff"))


def discover_windows(inventory):
    expected = {path_key(row["path"]): row["kind"]
                for row in (inventory or {}).get("runtimes", [])}
    snapshot = powershell_json(WINDOWS_DISCOVERY, list(expected))
    require(isinstance(snapshot, dict) and isinstance(snapshot.get("processes"), list)
            and isinstance(snapshot.get("issues"), list)
            and all(isinstance(issue, str) for issue in snapshot["issues"]),
            "Malformed Windows process snapshot")
    runtimes = []
    for process in snapshot["processes"]:
        require(isinstance(process, dict) and type(process.get("pid")) is int
                and process["pid"] > 0 and absolute_path(process.get("path"))
                and isinstance(process.get("start"), str)
                and isinstance(process.get("modules"), list), "Malformed Windows process")
        path = process["path"]
        name = ntpath.basename(path).lower()
        kind = expected.get(path_key(path)) or executable_kind("/" + name.removesuffix(".exe"))
        if kind:
            runtimes.append(Runtime(process["pid"], kind, path, path, process["start"]))
        for module in process["modules"]:
            require(isinstance(module, dict) and absolute_path(module.get("path")),
                    "Malformed Windows module")
            path = module["path"]
            if (path_key(path) in expected or
                    re.fullmatch(r"(?:php[0-9].*|libphp.*)\.(?:dll|so)", ntpath.basename(path), re.I)):
                kind = expected.get(path_key(path), "mod_php")
                if not any(r.pid == process["pid"] and path_key(r.path) == path_key(path) for r in runtimes):
                    runtimes.append(Runtime(process["pid"], kind, path, path, process["start"]))
    return runtimes, snapshot["issues"]


def hash_stream(stream):
    info = os.fstat(stream.fileno())
    require(stat.S_ISREG(info.st_mode), "Image is not a regular file")
    hashes = {name: hashlib.new(name, usedforsecurity=False)
              for name in ("md5", "sha1", "sha256", "sha384", "sha512")}
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        for digest in hashes.values():
            digest.update(block)
    after = os.fstat(stream.fileno())
    require((info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
            (after.st_size, after.st_mtime_ns, after.st_ctime_ns), "File changed while hashing")
    return {name: digest.hexdigest() for name, digest in hashes.items()}, info


def hash_file(path):
    require(absolute_path(path) and Path(path).is_absolute(), "File path must be absolute on this host")
    require(Path(path).is_file(), "File is missing or is not a regular file: " + path)
    with open(path, "rb") as stream:
        hashes, info = hash_stream(stream)
        # Windows stat/fstat can disagree on ctime semantics; compare open handles.
        with open(path, "rb") as current_stream:
            current = os.fstat(current_stream.fileno())
        require((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
                (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_ctime_ns),
                "File pathname changed while hashing")
    return hashes


def hash_runtime(runtime):
    require(start_time(runtime.pid) == runtime.start, "Process exited or PID was reused")
    with ExitStack() as stack:
        try:
            stream = stack.enter_context(open(runtime.live_path, "rb"))
        except OSError:
            # map_files may need extra capabilities. A pathname is acceptable only
            # when its device/inode proves it is the file in the inspected mapping.
            require(runtime.kind == "mod_php" and not runtime.deleted,
                    "Cannot read the running file")
            stream = stack.enter_context(open(runtime.path, "rb"))
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode), "Running image is not a regular file")
        if runtime.kind == "mod_php":
            require((info.st_dev, info.st_ino) == (runtime.device, runtime.inode),
                    "Module pathname no longer identifies the running mapping")
        hashes, info = hash_stream(stream)
    require(start_time(runtime.pid) == runtime.start, "Process exited or PID was reused")
    if runtime.kind == "mod_php":
        mapped = False
        for line in Path(f"/proc/{runtime.pid}/maps").read_text().splitlines():
            fields = line.split(None, 5)
            if len(fields) == 6:
                device = os.makedev(*(int(part, 16) for part in fields[3].split(":")))
                if (device, int(fields[4])) == (info.st_dev, info.st_ino):
                    mapped = True
        require(mapped, "PHP module mapping changed during inspection")
    else:
        current = os.stat(runtime.live_path)
        require((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino),
                "Process executable changed during inspection")
    restart = runtime.deleted
    try:
        disk = os.stat(runtime.path)
        restart |= (disk.st_dev, disk.st_ino) != (info.st_dev, info.st_ino)
    except FileNotFoundError:
        restart = True
    return hashes, restart


def dpkg_metadata(path):
    tool = system_tool("dpkg-query")
    result = command([tool, "-S", "--", path])
    owners = set()
    for line in result.stdout.splitlines():
        owner, sep, owned_path = line.partition(": ")
        if sep and owned_path == path:
            owners.add(owner)
    require(result.returncode == 0 and len(owners) == 1, "No unique dpkg owner for runtime")
    owner = owners.pop()
    require(re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?", owner), "Invalid package owner")
    result = command([tool, "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Status}\n", "--", owner])
    fields = result.stdout.strip().split("\t")
    require(result.returncode == 0 and len(fields) == 3 and fields[2] == "installed",
            "Package is not fully installed")
    package, version, _ = fields
    require(re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?", package), "Invalid package name")
    checksum = None
    for name in dict.fromkeys((package, owner, package.split(":")[0])):
        manifest = Path("/var/lib/dpkg/info") / (name + ".md5sums")
        if not manifest.is_file():
            continue
        for line in manifest.read_text().splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2 and "/" + parts[1].lstrip("./") == path:
                require(re.fullmatch(r"[0-9a-f]{32}", parts[0]), "Invalid package checksum")
                checksum = parts[0]
    require(checksum is not None, "Package has no checksum for the running file")
    return {"manager": "dpkg", "package": package.split(":")[0], "version": version,
            "algorithm": "md5", "digest": checksum}


def rpm_metadata(path):
    tool = system_tool("rpm")
    result = command([tool, "-qf", "--qf",
                      "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{FILEDIGESTALGO}\n", "--", path])
    fields = result.stdout.strip().split("\t")
    require(result.returncode == 0 and len(fields) == 5, "No unique RPM owner for runtime")
    package, epoch, version, release, algorithm = fields
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+._-]*", package), "Invalid RPM name")
    require(epoch.isdigit(), "Cannot determine RPM epoch")
    algorithm = {"1": "md5", "2": "sha1", "8": "sha256", "9": "sha384", "10": "sha512"}.get(algorithm)
    require(algorithm is not None, "Unsupported RPM file digest algorithm")
    result = command([tool, "-qf", "--qf", "[%{FILENAMES}\t%{FILEDIGESTS}\n]", "--", path])
    digests = [line.split("\t")[1] for line in result.stdout.splitlines()
               if line.startswith(path + "\t") and len(line.split("\t")) == 2]
    require(result.returncode == 0 and len(digests) == 1 and
            re.fullmatch(r"[0-9a-f]+", digests[0]), "No unique RPM file checksum")
    identity = command([tool, "-qf", "--qf", "%{ARCH}\t%{VENDOR}\n", "--", path])
    identity_fields = identity.stdout.strip().split("\t")
    require(identity.returncode == 0 and len(identity_fields) == 2, "Cannot determine RPM architecture/vendor")
    arch, vendor = identity_fields
    module_query = command([tool, "-qf", "--qf", "%{MODULARITYLABEL}", "--", path])
    module = module_query.stdout.strip() if module_query.returncode == 0 else None
    return {"manager": "rpm", "package": package, "version": f"{epoch}:{version}-{release}",
            "algorithm": algorithm, "digest": digests[0], "arch": arch,
            "module": "" if module == "(none)" else module, "vendor": vendor}


def apk_metadata(path):
    matches = []
    with Path("/lib/apk/db/installed").open() as stream:
        name = version = directory = filename = None
        for line in stream:
            line = line.rstrip("\r\n")
            if not line:
                name = version = directory = filename = None
                continue
            key, sep, value = line.partition(":")
            if not sep:
                continue
            if key == "P":
                name = value
            elif key == "V":
                version = value
            elif key == "F":
                directory, filename = value, None
            elif key == "R":
                filename = value
            elif key == "Z" and directory is not None and filename is not None:
                if "/" + "/".join(filter(None, (directory, filename))) != path:
                    continue
                require(value.startswith("Q1"), "Unsupported APK checksum encoding")
                digest = base64.b64decode(value[2:], validate=True)
                require(len(digest) == 20 and name and version, "Invalid APK file checksum")
                matches.append({"manager": "apk", "package": name, "version": version,
                                "algorithm": "sha1", "digest": digest.hex()})
    require(len(matches) == 1, "No unique APK file checksum; use build evidence")
    return matches[0]


def pacman_metadata(path):
    result = command([system_tool("pacman"), "-Qoq", "--", path])
    owners = result.stdout.splitlines()
    require(result.returncode == 0 and len(owners) == 1
            and re.fullmatch(r"[A-Za-z0-9@_+][A-Za-z0-9@_.+-]*", owners[0]),
            "No unique pacman owner for file")
    package = owners[0]
    result = command([system_tool("pacman"), "-Q", "--", package])
    parts = result.stdout.split()
    require(result.returncode == 0 and len(parts) == 2 and parts[0] == package
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+:~^_-]*", parts[1]),
            "Cannot determine pacman package version")
    version = parts[1]
    manifest = Path("/var/lib/pacman/local") / (package + "-" + version) / "mtree"
    matches = []
    with gzip.open(manifest, "rt") as stream:
        for line in stream:
            fields = line.split()
            if not fields or not fields[0].startswith("./"):
                continue
            name = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), fields[0][1:])
            if name == path:
                digests = [v[len("sha256digest="):] for v in fields[1:] if v.startswith("sha256digest=")]
                require(len(digests) == 1 and re.fullmatch(r"[0-9a-f]{64}", digests[0]),
                        "No SHA-256 for file in pacman mtree")
                matches.extend(digests)
    require(len(matches) == 1, "No unique pacman file checksum; use build evidence")
    return {"manager": "pacman", "package": package, "version": version,
            "algorithm": "sha256", "digest": matches[0]}


def package_metadata(path):
    require(sys.platform.startswith("linux"), "Use SHA-256 build evidence for this platform")
    if Path("/var/lib/dpkg/status").is_file():
        return dpkg_metadata(path)
    if Path("/lib/apk/db/installed").is_file():
        return apk_metadata(path)
    if Path("/var/lib/pacman/local").is_dir():
        return pacman_metadata(path)
    if any(Path(p).is_dir() for p in ("/var/lib/rpm", "/usr/lib/sysimage/rpm")):
        return rpm_metadata(path)
    raise AuditError("No supported package database; use SHA-256 build evidence for this build")


def fixed_rule(package, distro, evidence):
    for rule in evidence.get("vendor_fixes", []):
        if (rule["os_id"], rule["os_version"], rule["manager"], rule["package"]) == (
                *distro, package["manager"], package["package"]):
            return rule
    if distro[0] in ("ubuntu", "debian") and package["manager"] == "dpkg":
        fixes, sources = (UBUNTU_FIXES, UBUNTU_SOURCES) if distro[0] == "ubuntu" else (DEBIAN_FIXES, DEBIAN_SOURCES)
        for (release, source), version in fixes.items():
            # Only PHP runtime packages are covered, not arbitrary name prefixes.
            names = {source + suffix for suffix in ("-fpm", "-cgi", "-cli", "-common")}
            names.add("libapache2-mod-" + source)
            if distro[1] == release and package["package"] in names:
                return {"fixed_version": version, "sources": sources}
    if (distro[0] == "rhel" and package["manager"] == "rpm"
            and package.get("vendor") == "Red Hat, Inc."
            and package["package"] in {"php", "php-cli", "php-common", "php-fpm"}):
        if (distro[1] == "8.10" and (package.get("module") or "").startswith("php:7.4:")
                and package["version"].startswith("0:7.4.")):
            return {"fixed_version": "0:7.4.33-8.module+el8.10.0+25117+30337cca",
                    "sources": ["https://access.redhat.com/errata/RHSA-2026:87080"]}
        if distro[1] == "9.8" and package.get("module") == "" and package["version"].startswith("0:8.0."):
            return {"fixed_version": "0:8.0.30-8.el9_8.1",
                    "sources": ["https://access.redhat.com/errata/RHSA-2026:87151"]}
    imported = updateinfo_rule(package, distro, evidence)
    if imported:
        return imported
    raise AuditError("No vendor advisory rule for this OS/package; supply verified evidence")


def package_status(package, fixed):
    if package["manager"] == "dpkg":
        result = command([system_tool("dpkg"), "--compare-versions", package["version"], "ge", fixed])
        require(result.returncode in (0, 1), "Package version comparison failed")
        return "PATCHED" if result.returncode == 0 else "AFFECTED"
    # Constrained values cannot inject Lua, RPM macros, or shell syntax.
    for value in (package["version"], fixed):
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+:~^_-]*", value), "Invalid package version")
    if package["manager"] == "apk":
        result = command([system_tool("apk"), "version", "-t", package["version"], fixed])
        require(result.returncode == 0 and result.stdout.strip() in ("<", "=", ">"),
                "APK version comparison failed")
        return "AFFECTED" if result.stdout.strip() == "<" else "PATCHED"
    if package["manager"] == "pacman":
        result = command([system_tool("vercmp"), package["version"], fixed])
        require(result.returncode == 0 and re.fullmatch(r"-?[0-9]+", result.stdout.strip()),
                "pacman version comparison failed")
        return "AFFECTED" if int(result.stdout.strip()) < 0 else "PATCHED"
    require(package["manager"] == "rpm", "Unsupported version comparison")
    expression = '%{lua:print(rpm.vercmp("' + package["version"] + '","' + fixed + '"))}'
    result = command([system_tool("rpm"), "--eval", expression])
    require(result.returncode == 0 and result.stdout.strip() in ("-1", "0", "1"),
            "RPM version comparison unavailable")
    return "AFFECTED" if result.stdout.strip() == "-1" else "PATCHED"


def inspect_runtime(runtime, distro, evidence):
    record = {"pid": runtime.pid, "kind": runtime.kind, "path": runtime.path,
              "status": "UNKNOWN", "restart_needed": runtime.deleted}
    try:
        if sys.platform == "win32":
            record.update(inspect_file({"kind": runtime.kind, "path": runtime.path}, distro, evidence))
            record.update(pid=runtime.pid, assessment_scope="observed-file")
            record["file_status"] = record["status"]
            record["status"] = "UNKNOWN"
            record["detail"] += "; Windows module paths do not prove loaded-image identity; file status is separate"
            return record
        hashes, restart = hash_runtime(runtime)
        record.update(sha256=hashes["sha256"], restart_needed=restart)
        assess_file(record, hashes, distro, evidence)
    except (AuditError, OSError, ValueError, IndexError, EOFError, zlib.error) as exc:
        record["detail"] = str(exc)
    return record


def assess_file(record, hashes, distro, evidence):
    record["sha256"] = hashes["sha256"]
    build = next((row for row in evidence.get("builds", []) if row["sha256"] == hashes["sha256"]), None)
    if build:
        record.update(status="PATCHED" if build.get("fixed_cves") else upstream_status(build["php_version"]), php_version=build["php_version"],
                      source=build["source"], detail="File SHA-256 matches operator-supplied build provenance")
        return
    package = package_metadata(record["path"])
    record.update(package=package["package"], package_version=package["version"])
    require(hashes[package["algorithm"]] == package["digest"],
            "File differs from installed package checksum; patch status unresolved")
    record["manager"] = package["manager"]
    require(distro is not None, "Cannot determine OS release for vendor comparison")
    rule = fixed_rule(package, distro, evidence)
    record.update(status=package_status(package, rule["fixed_version"]),
                  fixed_version=rule["fixed_version"], sources=rule["sources"],
                  detail="File checksum matches installed package metadata")


def inspect_file(item, distro, evidence):
    record = {"pid": 0, "kind": item["kind"], "path": item["path"], "status": "UNKNOWN",
              "restart_needed": False, "assessment_scope": "installed-file"}
    try:
        assess_file(record, hash_file(item["path"]), distro, evidence)
    except (AuditError, OSError, ValueError, IndexError, EOFError, zlib.error) as exc:
        record["detail"] = str(exc)
    if sys.platform == "win32" and record["status"] == "UNKNOWN":
        try:
            record["version_hint"] = powershell_json(r'''
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$path = [Console]::In.ReadToEnd() | ConvertFrom-Json
$info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path)
@{product_version=$info.ProductVersion; file_version=$info.FileVersion} | ConvertTo-Json -Compress
''', item["path"])
        except (AuditError, OSError, ValueError) as exc:
            record["detail"] += "; Windows version resource unavailable: " + str(exc)
    return record


def finish(records, issues, mode="local", scope=None):
    if any(row["status"] == "AFFECTED" for row in records):
        status = 1
    elif (not records or issues or any(row["status"] != "PATCHED" or row["restart_needed"]
                                      for row in records)):
        status = 2
    else:
        status = 0
    return {"schema": 1, "completed": True, "mode": mode, "scope": scope,
            "cves": list(CVES), "verdict": {0: "PATCHED", 1: "AFFECTED", 2: "UNKNOWN"}[status],
            "exit_status": status, "runtimes": records, "issues": issues}


def audit_local(inventory, evidence, files=False):
    validate_config(inventory, evidence)
    if files:
        require(inventory is not None, "--files requires an explicit --inventory")
        try:
            distro = os_release()
        except (OSError, AuditError):
            distro = None
        result = finish([inspect_file(row, distro, evidence) for row in inventory["runtimes"]], [], scope=inventory["scope"])
        result["assessment_scope"] = "installed-files-only"
        result["limitations"] = ["Does not establish running-process patch status or deployment coverage beyond listed files"]
        return result
    try:
        runtimes, issues = discover(inventory)
    except (AuditError, OSError) as exc:
        return finish([], [str(exc)])
    if inventory is None:
        issues.append("No confirmed inventory: automatic discovery cannot prove deployment coverage")
    else:
        expected = {(row["kind"], path_key(row["path"])): row["label"] for row in inventory["runtimes"]}
        found = {(r.kind, path_key(r.path)) for r in runtimes}
        for key in expected.keys() - found:
            issues.append("Expected runtime not observed: " + expected[key] + " (" + key[1] + ")")
        for key in found - expected.keys():
            issues.append("Runtime missing from inventory: " + key[0] + " " + key[1])
    try:
        distro = os_release()
    except (OSError, AuditError):
        distro = None
    records = [inspect_runtime(runtime, distro, evidence) for runtime in runtimes]
    return finish(records, issues, scope=(inventory or {}).get("scope"))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_target(target):
    if "://" not in target:
        target = "https://" + target
    parsed = urllib.parse.urlsplit(target)
    require(parsed.scheme in ("http", "https") and parsed.hostname and not parsed.username
            and not parsed.password and not parsed.fragment and not any(ord(c) < 32 for c in target),
            "HTTP target must be an http(s) URL without credentials, fragments or control characters")
    return target


def http_observation(opener, target, method, read_body=False, data=None, headers=None):
    request_headers = {"User-Agent": "PHP2Shell-Patch-Audit/1", "Accept-Encoding": "identity"}
    request_headers.update(headers or {})
    request = urllib.request.Request(target, method=method, data=data, headers=request_headers)
    try:
        response = opener.open(request, timeout=10)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        observed = {"http_status": response.code, "method": method,
                    "headers": {key: response.headers.get_all(key, []) for key in
                                ("Server", "X-Powered-By", "X-PHP-Version", "Location", "Via")},
                    "php_session_cookie": any(re.match(r"\s*PHPSESSID=", c, re.I)
                                              for c in response.headers.get_all("Set-Cookie", []))}
        body = response.read(256 * 1024 + 1) if read_body else b""
        observed["body_truncated"] = len(body) > 256 * 1024
        return observed, body[:256 * 1024].decode("utf-8", errors="replace")


class PHPInfoParser(HTMLParser):
    fields = {"Server API", "PHP Version", "memory_limit", "post_max_size", "max_input_vars",
              "file_uploads", "session.upload_progress.enabled", "session.upload_progress.cleanup",
              "session.use_strict_mode", "session.cookie_httponly", "session.cookie_secure"}

    def __init__(self):
        super().__init__()
        self.values, self.cells, self.cell = {}, [], None

    def handle_starttag(self, tag, attrs):
        if tag == "tr":
            self.cells = []
        elif tag in ("td", "th"):
            self.cell = ""

    def handle_data(self, data):
        if self.cell is not None:
            self.cell = (self.cell + data)[:256]

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self.cell is not None:
            self.cells.append(self.cell.strip())
            self.cell = None
        elif tag == "tr" and len(self.cells) >= 2 and self.cells[0] in self.fields:
            self.values[self.cells[0]] = self.cells[1:3]


def http_details(body):
    parser = PHPInfoParser()
    parser.feed(body)
    plain = html.unescape(re.sub(r"<[^>]+>", " ", body))
    versions = re.findall(r"\bPHP Version\s+([0-9][^\s<;,]*)", plain, re.I)
    # Store only selected configuration fields, never the environment or raw phpinfo body.
    return {"phpinfo_versions": list(dict.fromkeys(versions)), "phpinfo_settings": parser.values,
            "body_versions": re.findall(r"\bPHP/([0-9][^\s<>;,]*)", plain, re.I),
            "php_source_observed": "<?php" in body,
            "php_link_observed": bool(re.search(r"(?:href|action)\s*=\s*['\"][^'\"]*\.php(?:[?'\"])", body, re.I)),
            "cms_hints": [name for name, marker in (("WordPress", "wp-content/"),
                          ("Drupal", "Drupal.settings"), ("Joomla", 'name="generator" content="Joomla'))
                          if marker.lower() in body.lower()]}


def audit_http(target, details=False, multipart=False):
    target = http_target(target)
    # Avoid ambient proxies and cross-origin redirects; neither is inventory evidence.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    result = finish([], ["HTTP banners are hints only; authenticated runtime evidence is required"], "http")
    result["target"] = target
    try:
        observation, body = http_observation(opener, target, "GET" if details or multipart else "HEAD", details or multipart)
        if observation["method"] == "HEAD" and observation["http_status"] in (405, 501):
            observation, body = http_observation(opener, target, "GET")
        result.update(observation)
        banners = " ".join(value for key in ("Server", "X-Powered-By") for value in result["headers"][key])
        result["reported_versions"] = re.findall(r"PHP/([^\s;,]+)", banners, re.IGNORECASE)
        result["reported_versions"].extend(value.strip() for value in result["headers"]["X-PHP-Version"])
        if details:
            result.update(http_details(body))
            result["reported_versions"].extend(result["phpinfo_versions"])
            result["reported_versions"].extend(result["body_versions"])
        result["version_hints"] = [{"version": v, "upstream_comparison": upstream_status(v)}
                                   for v in dict.fromkeys(result["reported_versions"])]
        if multipart:
            # This opt-in test sends one ordinary field, no file or upload-progress payload.
            boundary = "php2shell-" + secrets.token_hex(12)
            payload = ("--" + boundary + '\r\nContent-Disposition: form-data; name="test_field"\r\n\r\n'
                       + "multipart_test\r\n--" + boundary + "--\r\n").encode("ascii")
            post, post_body = http_observation(opener, target, "POST", True, payload,
                                               {"Content-Type": "multipart/form-data; boundary=" + boundary})
            markers = ("MULTIPART_REACHED_PHP", "PHP_EXECUTED")
            control_ok = observation["http_status"] == 200 and any(m in body for m in markers)
            reached = post["http_status"] == 200 and any(m in post_body for m in markers)
            result["multipart"] = {"http_status": post["http_status"], "control_marker": control_ok,
                                   "php_marker": reached,
                                   "observation": "reached_php" if reached else (
                                       "blocked_for_this_request" if control_ok and post["http_status"] == 403 else "unknown")}
            result["issues"].append("Multipart filtering is partial mitigation; this request cannot prove a fix or universal blocking")
    except (OSError, urllib.error.URLError, ValueError, http.client.HTTPException) as exc:
        result["issues"].append("HTTP probe failed: " + str(exc))
    return result


def remote_main(payload):
    try:
        require(sys.version_info >= (3, 9), "Python 3.9+ is required")
        result = audit_local(payload["inventory"], payload["evidence"], payload.get("files", False))
    except (AuditError, OSError, ValueError, TypeError, EOFError, zlib.error) as exc:
        result = finish([], ["Remote audit failed: " + str(exc)])
    result["token"] = payload["token"]
    print(json.dumps(result))
    return result["exit_status"]


def valid_remote_result(result, token, rc):
    if not isinstance(result, dict) or result.get("token") != token:
        return False
    if result.get("schema") != 1 or result.get("completed") is not True:
        return False
    if result.get("cves") != list(CVES) or result.get("mode") != "local":
        return False
    records, issues = result.get("runtimes"), result.get("issues")
    if not isinstance(records, list) or not isinstance(issues, list) or not all(isinstance(x, str) for x in issues):
        return False
    for row in records:
        if (not isinstance(row, dict) or row.get("status") not in ("PATCHED", "AFFECTED", "UNKNOWN")
                or type(row.get("restart_needed")) is not bool or type(row.get("pid")) is not int
                or not isinstance(row.get("kind"), str) or row["kind"] not in KINDS
                or not isinstance(row.get("path"), str)):
            return False
    expected = finish(records, issues)
    return rc == result.get("exit_status") == expected["exit_status"] and result.get("verdict") == expected["verdict"]


def remote_program(inventory, evidence, files=False):
    token = secrets.token_hex(24)
    payload = {"token": token, "inventory": inventory, "evidence": evidence, "files": files}
    source = Path(__file__).read_text()
    # repr embeds data as Python string literals; no target/config enters shell code.
    program = "import json\nns={'__name__':'php2shell_remote'}\n"
    program += "exec(compile(" + ascii(source) + ",'<audit>','exec'),ns)\n"
    program += "raise SystemExit(ns['remote_main'](json.loads(" + repr(json.dumps(payload)) + ")))\n"
    return token, program


def run_remote(argv, mode, target, inventory, evidence, files=False):
    token, program = remote_program(inventory, evidence, files)
    run = None
    try:
        run = command(argv, timeout=120, data=program)
        result = json.loads(run.stdout)
        require(valid_remote_result(result, token, run.returncode), "Remote result missing, incomplete, or inconsistent")
        result.pop("token")
        require(result.get("assessment_scope") == ("installed-files-only" if files else None),
                "Remote result has the wrong assessment scope")
        result["mode"] = mode
        result["target"] = target
        return result
    except (AuditError, ValueError, TypeError) as exc:
        result = finish([], [mode + "/setup/audit failure: " + str(exc)], mode)
        if run is not None:
            result["issues"].append(f"Transport exit {run.returncode}; stderr: {run.stderr.strip()[:2000]}")
        result["target"] = target
        return result


def audit_ssh(host, sudo, inventory, evidence, files=False, remote_os="linux", python=None):
    require(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@:\[\]-]*", host), "Invalid SSH destination")
    if remote_os == "windows":
        require(not sudo, "--sudo is not supported for Windows SSH")
        require(absolute_path(python) and re.match(r"^[A-Za-z]:", python)
                and python.lower().endswith(".exe"), "Windows SSH requires --remote-python with an absolute .exe path")
        script = "$source=[Console]::In.ReadToEnd(); $source | & '" + python.replace("'", "''") + "' -; exit $LASTEXITCODE"
        remote = "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand " + base64.b64encode(script.encode("utf-16le")).decode("ascii")
    else:
        python = python or "/usr/bin/python3"
        require(absolute_path(python) and python.startswith("/"), "Remote Python must be an absolute POSIX path")
        remote = shlex.quote(python) + " -"
        if sudo:
            remote = "/usr/bin/sudo -n -- " + remote
    return run_remote([system_tool("ssh"), "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                       "-o", "StrictHostKeyChecking=yes", "--", host, remote], "ssh", host, inventory, evidence, files)


def audit_container(container, engine, inventory, evidence, files=False, python=None):
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", container), "Invalid container name or ID")
    require(engine in ("docker", "podman"), "Unsupported container engine")
    python = python or "/usr/bin/python3"
    require(absolute_path(python) and python.startswith("/"), "Container Python must be an absolute POSIX path")
    return run_remote([system_tool(engine), "exec", "-i", container, python, "-"],
                      "container", container, inventory, evidence, files)


def audit_probe(path):
    result = finish([], ["An executed binary's version is a hint, not verified package or running-worker evidence"], "probe")
    result["target"] = path
    try:
        require(absolute_path(path) and Path(path).is_absolute(), "Probe requires an absolute local binary path")
        require(sys.platform != "win32" or path.lower().endswith(".exe"), "Windows probes require an .exe, not a shell script")
        before = hash_file(path)["sha256"]
        args = [path, "php-cli", "-n", "-v"] if ntpath.basename(path).lower() in ("frankenphp", "frankenphp.exe") else [path, "-n", "-v"]
        run = command(args)
        require(run.returncode == 0, "PHP version probe failed")
        require(hash_file(path)["sha256"] == before, "PHP binary changed during probe")
        versions = re.findall(r"\bPHP\s+([^\s]+)", run.stdout)
        result.update(sha256=before, version_hints=[{"version": v, "upstream_comparison": upstream_status(v)} for v in versions])
    except (AuditError, OSError, ValueError) as exc:
        result["issues"].append(str(exc))
    return result


def audit_logs(path, events=False):
    result = finish([], ["Log observations cannot establish patch status or exclude compromise"], "process-events" if events else "log")
    result.update(target=str(path), observations=[], counts={}, observation_limit=100)
    seen, sequences, total = set(), {}, 0
    patterns = {"memory_exhaustion": re.compile(r"Allowed memory size of .* exhausted", re.I),
                "heap_corruption": re.compile(r"zend_mm_heap corrupted", re.I),
                "worker_crash": re.compile(r"(?:child|worker|php|apache|httpd).*?(?:segmentation fault|SIGSEGV|signal 11|segfault)", re.I)}
    try:
        with open(path, "rb") as stream:
            for number in range(1, 1000001):
                raw = stream.readline(MAX_CONFIG + 1)
                if not raw:
                    break
                total += len(raw)
                require(len(raw) <= MAX_CONFIG and total <= 64 * MAX_CONFIG, "Log exceeds the 64 MiB / 1 MiB line limit")
                line = raw.decode("utf-8")
                if not events:
                    for label, pattern in patterns.items():
                        if pattern.search(line):
                            result["counts"][label] = result["counts"].get(label, 0) + 1
                            if len(result["observations"]) < 100:
                                result["observations"].append({"line": number, "signal": label})
                    continue
                event = json.loads(line)
                require(isinstance(event, dict) and event.get("schema_version") == 1
                        and isinstance(event.get("event_id"), str) and isinstance(event.get("agent_instance_id"), str)
                        and type(event.get("sequence")) is int and isinstance(event.get("event_type"), str),
                        "Invalid process-watcher event at line " + str(number))
                identity = (event["agent_instance_id"], event["event_id"])
                if identity in seen:
                    continue
                seen.add(identity)
                instance, sequence = event["agent_instance_id"], event["sequence"]
                gap = instance in sequences and sequence != sequences[instance] + 1
                sequences[instance] = sequence
                quality = event.get("data_quality") or {}
                lineage = event.get("lineage") or {}
                process, root = event.get("process") or {}, event.get("root") or {}
                require(all(isinstance(value, dict) for value in (quality, lineage, process, root)), "Malformed event data")
                if gap or event["event_type"] == "agent.gap" or quality.get("collection_gap"):
                    result["counts"]["observation_gap"] = result["counts"].get("observation_gap", 0) + 1
                if (event["event_type"] == "process.exec" and lineage.get("role") == "descendant"
                        and isinstance(root.get("image"), str) and
                        (executable_kind("/" + root["image"]) or root["image"] in ("apache2", "httpd", "w3wp.exe"))):
                    image = process.get("image")
                    require(isinstance(image, str), "Missing process image")
                    result["counts"]["php_descendant_exec"] = result["counts"].get("php_descendant_exec", 0) + 1
                    if len(result["observations"]) < 100:
                        result["observations"].append({"line": number, "event_id": event["event_id"],
                            "root": root["image"], "image": image, "lineage_complete": lineage.get("complete") is True,
                            "review_required": bool(re.fullmatch(r"(?:sh|dash|bash|zsh|ksh|ash|busybox|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|nc|ncat|socat[0-9]*|curl|wget|cmd\.exe|powershell\.exe|pwsh\.exe)", image, re.I))})
            else:
                raise AuditError("Log exceeds one million lines")
    except (OSError, AuditError, ValueError) as exc:
        result["issues"].append(str(exc))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-s", "--ssh", action="append", default=[], metavar="USER@HOST")
    parser.add_argument("--sudo", action="store_true", help="Noninteractive remote sudo")
    parser.add_argument("-u", "--http", "--url", action="append", default=[], metavar="URL")
    parser.add_argument("--targets-file", help="HTTP targets, one URL/hostname per line; # comments allowed")
    parser.add_argument("--http-details", "--phpinfo", action="append", default=[], metavar="URL",
                        help="GET this exact URL; collect PHP/CMS hints and selected phpinfo settings")
    parser.add_argument("--multipart-check", action="append", default=[], metavar="URL",
                        help="Opt-in: GET and one small multipart POST to a dedicated test endpoint")
    parser.add_argument("--files", action="store_true", help="Audit only installed files from inventory, including inactive deployments")
    parser.add_argument("--container", action="append", default=[], metavar="NAME_OR_ID")
    parser.add_argument("--engine", choices=("docker", "podman"), default="docker")
    parser.add_argument("--remote-os", choices=("linux", "windows"), default="linux")
    parser.add_argument("--remote-python", help="Absolute target Python path; required for Windows SSH")
    parser.add_argument("--probe-php", action="append", default=[], metavar="TRUSTED_BINARY",
                        help="Opt-in: execute this local trusted PHP binary with -n -v; hints only")
    parser.add_argument("--log", action="append", default=[], metavar="FILE", help="Review PHP/web-server error logs")
    parser.add_argument("--process-events", action="append", default=[], metavar="JSONL", help="Review exported process-watcher events")
    parser.add_argument("--updateinfo", action="append", default=[], metavar="XML_OR_GZ", help="Trusted RPM repository updateinfo metadata")
    parser.add_argument("--updateinfo-os", metavar="ID:VERSION", help="Exact target OS/release covered by supplied updateinfo")
    parser.add_argument("--inventory", help="Explicit expected runtime inventory JSON")
    parser.add_argument("--evidence", help="Trusted vendor fixes/custom-build provenance JSON")
    parser.add_argument("--json", action="store_true", help="Emit full machine-readable evidence")
    args = parser.parse_args(argv)
    try:
        require(sys.version_info >= (3, 9), "Python 3.9+ is required")
        require(not args.sudo or args.ssh, "--sudo requires --ssh")
        require(not args.inventory or len(args.ssh) + len(args.container) <= 1,
                "Use one remote host/container per invocation with its own inventory")
        require(not args.probe_php or not (args.ssh or args.container), "--probe-php executes locally; use a separate invocation")
        require(not args.files or args.inventory, "--files requires --inventory")
        require(not args.remote_python or args.ssh or args.container, "--remote-python requires --ssh or --container")
        require(args.remote_os != "windows" or (args.ssh and not args.container), "--remote-os windows requires SSH, not container transport")
        require(bool(args.updateinfo) == bool(args.updateinfo_os), "Use --updateinfo together with --updateinfo-os ID:VERSION")
        inventory = load_json(args.inventory) if args.inventory else None
        evidence = load_json(args.evidence) if args.evidence else {"schema": 1}
        validate_config(inventory, evidence)
        if args.targets_file:
            with open(args.targets_file, "rb") as stream:
                data = stream.read(MAX_CONFIG + 1)
            require(len(data) <= MAX_CONFIG, "Target list exceeds 1 MiB")
            targets = [line.strip() for line in data.decode("utf-8-sig").splitlines()
                       if line.strip() and not line.lstrip().startswith("#")]
            require(targets, "Target list is empty")
            args.http.extend(targets)
        if args.updateinfo:
            distro = args.updateinfo_os.split(":")
            require(len(distro) == 2 and all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", part) for part in distro),
                    "--updateinfo-os must be ID:VERSION")
            evidence.setdefault("rpm_advisories", []).extend(
                row for path in args.updateinfo for row in load_updateinfo(path, distro))
        reports = []
        targets = ([("ssh", host) for host in args.ssh] + [("container", name) for name in args.container]
                   + [("http", url) for url in args.http] + [("http-details", url) for url in args.http_details]
                   + [("multipart", url) for url in args.multipart_check] + [("probe", path) for path in args.probe_php]
                   + [("log", path) for path in args.log] + [("process-events", path) for path in args.process_events])
        for mode, target in targets:
            try:
                if mode == "ssh":
                    reports.append(audit_ssh(target, args.sudo, inventory, evidence,
                                             args.files, args.remote_os, args.remote_python))
                elif mode == "container":
                    reports.append(audit_container(target, args.engine, inventory, evidence, args.files, args.remote_python))
                elif mode in ("http", "http-details", "multipart"):
                    reports.append(audit_http(target, mode == "http-details", mode == "multipart"))
                elif mode == "probe":
                    reports.append(audit_probe(target))
                else:
                    reports.append(audit_logs(target, events=mode == "process-events"))
            except (AuditError, OSError, ValueError, TypeError) as exc:
                failure = finish([], [str(exc)], mode)
                failure["target"] = target
                reports.append(failure)
        if not reports or (args.files and not (args.ssh or args.container)):
            reports.append(audit_local(inventory, evidence, args.files))
    except (AuditError, OSError, ValueError, TypeError, EOFError, zlib.error) as exc:
        reports = [finish([], [str(exc)])]
    status = 1 if any(r["exit_status"] == 1 for r in reports) else (
        2 if any(r["exit_status"] == 2 for r in reports) else 0)
    if args.json:
        print(json.dumps({"schema": 1, "exit_status": status, "reports": reports}, indent=2))
    else:
        for report in reports:
            label = json.dumps(report.get("target", report.get("scope") or "local namespace"))
            print(f'[{report["verdict"]}] {label}')
            if report.get("assessment_scope"):
                print("  Scope: " + report["assessment_scope"])
            for row in report["runtimes"]:
                print(f'  {row["status"]}: PID {row["pid"]} {row["kind"]} {json.dumps(row["path"])}')
                print("    " + json.dumps(row.get("detail", "")))
                if "file_status" in row:
                    print("    Installed file: " + row["file_status"] + "; loaded image unverified")
                if row.get("version_hint"):
                    print("    Version resource (hint): " + json.dumps(row["version_hint"]))
                if row["restart_needed"]:
                    print("    RESTART REQUIRED: running file was removed/replaced; re-audit afterward")
            for issue in report["issues"]:
                print("  " + json.dumps(issue))
            if report["mode"] == "http":
                print("  HTTP evidence: " + json.dumps(report.get("headers", {})))
            for field in ("version_hints", "phpinfo_settings", "cms_hints", "multipart", "counts", "observations", "limitations"):
                if report.get(field):
                    print("  " + field + ": " + json.dumps(report[field]))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
