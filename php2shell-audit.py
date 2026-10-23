#!/usr/bin/env python3
"""PHP2Shell audit: Linux/macOS/Windows discovery, file checks and remote inspection."""

import argparse
import base64
import bz2
import ctypes
import errno
import gzip
import hashlib
import html
import http.client
import json
import lzma
import ntpath
import os
import platform
import re
import secrets
import shlex
import sqlite3
import stat
import subprocess
import sys
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zlib
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath, PureWindowsPath

CVES = ("CVE-2026-109618", "CVE-2026-109619")
BASELINES = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
KINDS = {"fpm", "mod_php", "cgi", "lsphp", "frankenphp", "php", "embedded"}
MAX_CONFIG = 1024 * 1024
MAX_ARCHIVE = 512 * 1024 * 1024
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
# Both CVEs in Alpine's release-scoped community secdb, verified 2026-10-23.
ALPINE_FIXES = {"php83": "8.3.36-r0", "php84": "8.4.27-r0", "php85": "8.5.12-r0"}
# Exact Arch binary-package advisories, verified 2026-10-23.
ARCH_FIXES = {"php": ("8.5.12-1", "AVG-2909"), "php-legacy": ("8.3.36-1", "AVG-2910")}
TOOL_VERSION = "1.1.0"
GUIDANCE = {
    "ubuntu": "https://ubuntu.com/server/docs/how-to/software/package-management/",
    "debian": "https://www.debian.org/doc/manuals/debian-handbook/sect.regular-upgrades.en.html",
    "rhel": "https://access.redhat.com/solutions/10021",
    "rocky": "https://docs.rockylinux.org/guides/package_management/dnf_package_manager/",
    "almalinux": "https://wiki.almalinux.org/documentation/errata.html",
    "alpine": "https://docs.alpinelinux.org/user-handbook/0.1a/Working/apk.html#_upgrading_packages",
    "arch": "https://wiki.archlinux.org/title/System_maintenance",
    "homebrew": "https://docs.brew.sh/FAQ#how-do-i-update-my-local-packages",
    "macports": "https://guide.macports.org/#using.port.upgrade",
    "win32": "https://www.php.net/manual/en/install.windows.manual.php",
}
NEXT_STEPS = {
    "ACCESS_DENIED": "Obtain read access to the reported process/file and rerun the audit.",
    "FILE_MISSING": "Check the inventory path and deployment; inspect inactive artifacts separately.",
    "FILE_CHANGED": "Recheck the deployed artifact and restart affected workers as appropriate, then re-audit.",
    "PROCESS_CHANGED": "Rerun after the worker stops exiting or changing during inspection.",
    "EVIDENCE_MISSING": "Supply trusted SHA-256 build evidence or a matching verified package archive.",
    "EVIDENCE_MISMATCH": "Investigate the file/evidence mismatch; obtain evidence for the actual artifact.",
    "VENDOR_RULE_MISSING": "Supply a vendor rule for this exact release/package covering both CVEs.",
    "VERSION_UNSUPPORTED": "Supply verified backport evidence for both CVEs or use a supported fixed build.",
    "LOADED_IMAGE_UNVERIFIED": "Assess installed files with --files; that result cannot clear Windows running images.",
    "RESTART_REQUIRED": "Restart or replace the affected deployment using its normal procedure, then re-audit.",
    "AFFECTED": "Apply a vendor/build update fixing both CVEs, restart affected workers, and re-audit.",
    "INVENTORY_UNCONFIRMED": "Review discovered and inactive deployments, then supply a confirmed inventory.",
    "EXPECTED_RUNTIME_MISSING": "Check the expected service/namespace; assess inactive files separately.",
    "UNEXPECTED_RUNTIME": "Identify the runtime and include it in the reviewed deployment inventory.",
    "DISCOVERY_INCOMPLETE": "Resolve process access or namespace restrictions and rerun within the deployment.",
    "NO_RUNTIME_FOUND": "Confirm the target namespace and inventory; use --files for inactive deployments.",
    "TRANSPORT_FAILED": "Check SSH/container access, the target Python path, and the reported transport error.",
    "OBSERVATION_ONLY": "Run a local or remote artifact audit with confirmed inventory and trusted evidence.",
    "INSPECTION_FAILED": "Resolve the reported inspection error and rerun; do not clear this deployment.",
}


class AuditError(Exception):
    """Audit failure with a stable diagnostic code."""

    def __init__(self, message, code="INSPECTION_FAILED"):
        """Initialize an audit failure.

        Args:
            message (str): Human-readable failure detail.
            code (str): Key in NEXT_STEPS identifying the unresolved condition.
        """
        super().__init__(message)
        self.code = code


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


def require(condition, message, code="INSPECTION_FAILED"):
    """Enforce an audit precondition.

    Args:
        condition (bool): Whether the required invariant holds.
        message (str): Failure detail.
        code (str): Stable diagnostic code.

    Raises:
        AuditError: The condition is false.
    """
    if not condition:
        raise AuditError(message, code)


def diagnostic(code, detail, distro=None, manager=None):
    """Describe a finding without changing its patch verdict.

    Args:
        code (str): Stable NEXT_STEPS key.
        detail (str): Finding detail; treated as data in text and JSON output.
        distro (tuple[str, str] | None): Audited OS ID and release.
        manager (str | None): Artifact package manager, when known.

    Returns:
        dict: Code, detail, next step and applicable update guidance URLs.
    """
    guide = GUIDANCE.get(manager) or GUIDANCE.get(distro[0] if distro else sys.platform)
    return {"code": code, "detail": detail, "next_step": NEXT_STEPS[code],
            "guidance": [guide] if guide else ["https://github.com/beardedeagle/php2shell-patch-audit#patching-guidance"]}


def error_diagnostic(error, distro=None, manager=None):
    """Convert an inspection error into an actionable diagnostic.

    Args:
        error (Exception): Inspection or validation error.
        distro (tuple[str, str] | None): Audited OS ID and release.
        manager (str | None): Package manager already identified for the artifact.

    Returns:
        dict: Diagnostic retaining the original error detail.
    """
    code = error.code if isinstance(error, AuditError) else "INSPECTION_FAILED"
    if isinstance(error, PermissionError):
        code = "ACCESS_DENIED"
    elif isinstance(error, FileNotFoundError):
        code = "FILE_MISSING"
    return diagnostic(code, str(error), distro, manager)


def explain_record(record, distro):
    """Attach unresolved conditions and restart guidance to an artifact record.

    Args:
        record (dict): Artifact assessment, updated in place.
        distro (tuple[str, str] | None): Audited OS ID and release.

    Returns:
        dict: The record with additive diagnostics; status remains unchanged.
    """
    findings = record.setdefault("diagnostics", [])
    if not findings and record["status"] != "PATCHED":
        code = "AFFECTED" if record["status"] == "AFFECTED" else (
            "VERSION_UNSUPPORTED" if "php_version" in record else "INSPECTION_FAILED")
        findings.append(diagnostic(code, record.get("detail", ""), distro, record.get("manager")))
    if record.get("restart_needed"):
        findings.append(diagnostic("RESTART_REQUIRED", "Running file was removed or replaced", distro, record.get("manager")))
    return record


def report_metadata(inventory=None, evidence=None):
    """Record the audited host and fingerprints of the supplied JSON documents.

    Args:
        inventory (dict | None): Parsed inventory, including its scope assertion.
        evidence (dict | None): Parsed evidence, including imported advisory rows.

    Returns:
        dict: UTC report time, tool identity, target OS/architecture and SHA-256
        fingerprints of canonical JSON; raw inputs are not retained.
    """
    def fingerprint(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                         allow_nan=False).encode()).hexdigest() if value is not None else None
    try:
        distro = os_release()
    except (OSError, AuditError):
        distro = None
    source_hash = globals().get("AUDIT_SOURCE_SHA256")
    if source_hash is None and "__file__" in globals():
        try:
            source_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        except OSError:
            source_hash = None
    return {"timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "tool_version": TOOL_VERSION, "tool_sha256": source_hash,
            "target": {"platform": sys.platform, "os_release": list(distro) if distro else None,
                       "os_version": platform.mac_ver()[0] if sys.platform == "darwin" else platform.version(),
                       "architecture": platform.machine()},
            "inventory_sha256": fingerprint(inventory), "evidence_sha256": fingerprint(evidence)}


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
                "Inventory needs scope and an explicit coverage_confirmed=true assertion", "INVENTORY_UNCONFIRMED")
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
    for field in ("vendor_fixes", "builds", "rpm_advisories", "package_archives"):
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
    seen = set()
    for row in evidence.get("package_archives", []):
        require(isinstance(row, dict) and row.get("manager") in ("homebrew", "macports"),
                "Package archive needs manager homebrew or macports")
        for field in ("package", "version", "php_version", "source"):
            require(isinstance(row.get(field), str) and row[field].strip(),
                    "Package archive needs " + field)
        require(absolute_path(row.get("path")) and isinstance(row.get("sha256"), str)
                and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]),
                "Package archive needs an absolute path and SHA-256")
        if "fixed_cves" in row:
            require(isinstance(row["fixed_cves"], list) and sorted(row["fixed_cves"]) == sorted(CVES),
                    "Package archive fixed_cves must cover both CVEs")
        key = row["manager"], row["package"], row["version"]
        require(key not in seen, "Duplicate package archive")
        seen.add(key)
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
    if sys.platform == "darwin":
        return discover_macos(inventory)
    require(sys.platform.startswith("linux"),
            "Process inspection supports Linux, macOS and Windows; use --files for other systems")
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


class MacOSProcesses:
    """Read process identities and mapped vnodes through libproc."""

    class BSDInfo(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint32) for name in (
            "flags", "status", "xstatus", "pid", "ppid", "uid", "gid", "ruid",
            "rgid", "svuid", "svgid", "reserved")]
        _fields_ += [("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)]
        _fields_ += [(name, ctypes.c_uint32) for name in ("nfiles", "pgid", "jobc", "tdev", "tpgid")]
        _fields_ += [("nice", ctypes.c_int32), ("seconds", ctypes.c_uint64), ("microseconds", ctypes.c_uint64)]

    class RegionInfo(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint32) for name in ("protection", "max_protection", "inheritance", "flags")]
        _fields_ += [("offset", ctypes.c_uint64)]
        _fields_ += [(name, ctypes.c_uint32) for name in (
            "behavior", "wired", "tag", "resident", "private_shared", "swapped", "dirty",
            "references", "shadow_depth", "share_mode", "private", "shared", "object_id", "depth")]
        _fields_ += [("address", ctypes.c_uint64), ("size", ctypes.c_uint64)]

    class VnodeStat(ctypes.Structure):
        _fields_ = [("device", ctypes.c_uint32), ("mode", ctypes.c_uint16), ("nlink", ctypes.c_uint16),
                    ("inode", ctypes.c_uint64), ("uid", ctypes.c_uint32), ("gid", ctypes.c_uint32)]
        _fields_ += [(name, ctypes.c_int64) for name in (
            "atime", "atime_ns", "mtime", "mtime_ns", "ctime", "ctime_ns",
            "birthtime", "birthtime_ns", "size", "blocks")]
        _fields_ += [("blocksize", ctypes.c_int32), ("flags", ctypes.c_uint32),
                    ("generation", ctypes.c_uint32), ("rdevice", ctypes.c_uint32),
                    ("reserved", ctypes.c_int64 * 2)]

    def __init__(self):
        class RegionPath(ctypes.Structure):
            _fields_ = [("region", MacOSProcesses.RegionInfo), ("stat", MacOSProcesses.VnodeStat),
                        ("type", ctypes.c_int), ("padding", ctypes.c_int),
                        ("fsid", ctypes.c_int32 * 2), ("path", ctypes.c_char * 1024)]
        self.region_type = RegionPath
        self.lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        self.lib.proc_listallpids.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self.lib.proc_listallpids.restype = ctypes.c_int
        self.lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        self.lib.proc_pidinfo.restype = ctypes.c_int
        self.lib.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        self.lib.proc_pidpath.restype = ctypes.c_int

    def pids(self):
        for _ in range(3):
            count = self.lib.proc_listallpids(None, 0)
            require(0 < count < 1000000, "Cannot enumerate macOS processes")
            buffer = (ctypes.c_int * (count + 128))()
            used = self.lib.proc_listallpids(buffer, ctypes.sizeof(buffer))
            require(used > 0, "Cannot enumerate macOS processes")
            if used < len(buffer):
                return sorted(set(pid for pid in buffer[:used] if pid > 0))
        raise AuditError("macOS process list kept growing during enumeration")

    def info(self, pid, flavor, data, address=0):
        ctypes.set_errno(0)
        size = self.lib.proc_pidinfo(pid, flavor, address, ctypes.byref(data), ctypes.sizeof(data))
        if size <= 0:
            code = ctypes.get_errno() or errno.EIO
            raise OSError(code, os.strerror(code))
        require(size == ctypes.sizeof(data), "Incomplete macOS process information")
        return data

    def identity(self, pid):
        data = self.info(pid, 3, self.BSDInfo())  # PROC_PIDTBSDINFO
        require(data.pid == pid, "macOS process identity mismatch")
        if data.status == 5:  # SZOMB
            raise ProcessLookupError(errno.ESRCH, "Process is a zombie")
        return f"{data.seconds}:{data.microseconds}"

    def executable(self, pid):
        buffer = ctypes.create_string_buffer(4096)
        ctypes.set_errno(0)
        size = self.lib.proc_pidpath(pid, buffer, len(buffer))
        if size <= 0:
            code = ctypes.get_errno() or errno.EIO
            raise OSError(code, os.strerror(code))
        path = os.fsdecode(buffer.value)
        require(absolute_path(path), "Invalid macOS executable path")
        return path

    def mappings(self, pid):
        address, mappings = 0, {}
        for index in range(100000):
            try:
                data = self.info(pid, 8, self.region_type(), address)  # PROC_PIDREGIONPATHINFO
            except OSError as exc:
                if exc.errno == errno.EINVAL and index:
                    return list(mappings.values())
                raise
            end = data.region.address + data.region.size
            require(data.region.address >= address and end > address and end < 2 ** 64,
                    "Invalid macOS memory region")
            address = end
            path = os.fsdecode(data.path)
            if path:
                require(absolute_path(path), "Invalid macOS mapped-file path")
                row = {"path": path, "device": data.stat.device, "inode": data.stat.inode,
                       "nlink": data.stat.nlink}
                key = path, row["device"], row["inode"]
                mappings[key] = row
        raise AuditError("macOS memory-region limit exceeded")


def discover_macos(inventory):
    api = MacOSProcesses()
    expected = {os.path.realpath(row["path"]): row["kind"] for row in (inventory or {}).get("runtimes", [])}
    runtimes, issues = [], []
    for pid in api.pids():
        try:
            started = api.identity(pid)
            exe = api.executable(pid)
            kind = expected.get(os.path.realpath(exe)) or executable_kind(exe)
            try:
                mappings = api.mappings(pid)
            except (OSError, AuditError) as exc:
                if kind:
                    runtimes.append(Runtime(pid, kind, exe, exe, started))
                raise AuditError("cannot inspect mapped files: " + str(exc)) from exc
            found = []
            for item in mappings:
                path = item["path"]
                module = re.fullmatch(r"(?:libphp|mod_php)[^/]*\.(?:so|dylib)(?:\.[0-9]+)*", Path(path).name, re.I)
                item_kind = expected.get(os.path.realpath(path)) or (kind if path == exe else None)
                if item_kind or module:
                    found.append(Runtime(pid, item_kind or "mod_php", path, path, started,
                                         item["nlink"] == 0, item["device"], item["inode"]))
            if kind and not any(r.kind == kind and r.path == exe for r in found):
                found.append(Runtime(pid, kind, exe, exe, started))
                issues.append(f"PID {pid}: executable mapping not available")
            require(api.identity(pid) == started, "Process identity changed during discovery")
            runtimes.extend(found)
        except ProcessLookupError:
            continue
        except (OSError, AuditError) as exc:
            issues.append(f"PID {pid}: macOS inspection incomplete: {exc}")
    return runtimes, issues


def hash_macos_runtime(runtime):
    api = MacOSProcesses()
    require(api.identity(runtime.pid) == runtime.start, "Process exited or PID was reused", "PROCESS_CHANGED")
    require(runtime.inode > 0 and not runtime.deleted, "Running macOS file has no readable vnode identity")
    with open(runtime.live_path, "rb") as stream:
        before = os.fstat(stream.fileno())
        require((before.st_dev, before.st_ino) == (runtime.device, runtime.inode),
                "macOS pathname no longer identifies the running mapping; restart and re-audit", "FILE_CHANGED")
        hashes, info = hash_stream(stream)
        mappings = api.mappings(runtime.pid)
        require(any((row["device"], row["inode"]) == (info.st_dev, info.st_ino) for row in mappings),
                "macOS mapping changed during inspection", "PROCESS_CHANGED")
        require(api.identity(runtime.pid) == runtime.start, "Process exited or PID was reused", "PROCESS_CHANGED")
        after = os.fstat(stream.fileno())
        require((info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns), "Running file changed during inspection", "FILE_CHANGED")
    try:
        current = os.stat(runtime.path)
        restart = (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino)
    except FileNotFoundError:
        restart = True
    return hashes, restart


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
            (after.st_size, after.st_mtime_ns, after.st_ctime_ns), "File changed while hashing", "FILE_CHANGED")
    return {name: digest.hexdigest() for name, digest in hashes.items()}, info


def hash_file(path):
    """Hash a stable installed file without executing it.

    Args:
        path (str): Absolute path on this host.

    Returns:
        dict[str, str]: File digests keyed by algorithm name.

    Raises:
        AuditError: The path is invalid, non-regular or changes while hashing.
        OSError: The file is missing or cannot be inspected.
    """
    require(absolute_path(path) and Path(path).is_absolute(), "File path must be absolute on this host")
    require(stat.S_ISREG(os.stat(path).st_mode), "File is not a regular file: " + path)
    with open(path, "rb") as stream:
        hashes, info = hash_stream(stream)
        # Windows stat/fstat can disagree on ctime semantics; compare open handles.
        with open(path, "rb") as current_stream:
            current = os.fstat(current_stream.fileno())
        require((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
                (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_ctime_ns),
                "File pathname changed while hashing", "FILE_CHANGED")
    return hashes


def hash_runtime(runtime):
    if sys.platform == "darwin":
        return hash_macos_runtime(runtime)
    require(start_time(runtime.pid) == runtime.start, "Process exited or PID was reused", "PROCESS_CHANGED")
    with ExitStack() as stack:
        try:
            stream = stack.enter_context(open(runtime.live_path, "rb"))
        except OSError as exc:
            # map_files may need extra capabilities. A pathname is acceptable only
            # when its device/inode proves it is the file in the inspected mapping.
            require(runtime.kind == "mod_php" and not runtime.deleted,
                    "Cannot read the running file", error_diagnostic(exc)["code"])
            stream = stack.enter_context(open(runtime.path, "rb"))
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode), "Running image is not a regular file")
        if runtime.kind == "mod_php":
            require((info.st_dev, info.st_ino) == (runtime.device, runtime.inode),
                    "Module pathname no longer identifies the running mapping", "FILE_CHANGED")
        hashes, info = hash_stream(stream)
    require(start_time(runtime.pid) == runtime.start, "Process exited or PID was reused", "PROCESS_CHANGED")
    if runtime.kind == "mod_php":
        mapped = False
        for line in Path(f"/proc/{runtime.pid}/maps").read_text().splitlines():
            fields = line.split(None, 5)
            if len(fields) == 6:
                device = os.makedev(*(int(part, 16) for part in fields[3].split(":")))
                if (device, int(fields[4])) == (info.st_dev, info.st_ino):
                    mapped = True
        require(mapped, "PHP module mapping changed during inspection", "PROCESS_CHANGED")
    else:
        current = os.stat(runtime.live_path)
        require((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino),
                "Process executable changed during inspection", "PROCESS_CHANGED")
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


def macos_package_metadata(path):
    target = Path(path).resolve(strict=True)
    for keg in target.parents:
        if keg.parent.parent.name != "Cellar":
            continue
        receipt = keg / "INSTALL_RECEIPT.json"
        data = load_json(receipt)
        require(isinstance(data, dict) and isinstance(data.get("source"), dict), "Invalid Homebrew receipt")
        tap = data["source"].get("tap")
        require(isinstance(tap, str) and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", tap),
                "Homebrew receipt has no valid source tap")
        return {"manager": "homebrew", "package": tap + "/" + keg.parent.name,
                "version": keg.name, "receipt": str(receipt),
                "archive_member": target.relative_to(keg.parent.parent).as_posix()}
    owners = []
    prefixes = set(target.parents) | {Path("/opt/local")}
    for prefix in sorted(prefixes):
        database = prefix / "var/macports/registry/registry.db"
        if not database.is_file():
            continue
        try:
            with ExitStack() as stack:
                connection = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=2)
                stack.callback(connection.close)
                connection.execute("PRAGMA query_only=ON")
                rows = connection.execute(
                    "SELECT p.name, p.epoch, p.version, p.revision, p.variants, f.path "
                    "FROM files AS f JOIN ports AS p ON p.id=f.id "
                    "WHERE f.actual_path=? AND f.active=1 AND p.state='installed'",
                    (str(target),)).fetchmany(2)
                for name, epoch, version, revision, variants, original in rows:
                    require(all(isinstance(value, str) for value in (name, version, variants))
                            and type(epoch) is int and type(revision) is int and absolute_path(original),
                            "Invalid MacPorts registry entry")
                    owners.append({"manager": "macports", "package": name,
                                   "version": f"{epoch}:{version}_{revision}{variants}",
                                   "receipt": str(database), "archive_member": original.lstrip("/")})
        except sqlite3.Error as exc:
            raise AuditError("Cannot read MacPorts registry: " + str(exc)) from exc
    require(len(owners) == 1, "No unique Homebrew/MacPorts owner; supply SHA-256 build evidence", "EVIDENCE_MISSING")
    return owners[0]


class BoundedArchiveReader:
    def __init__(self, stream):
        self.stream, self.remaining = stream, MAX_ARCHIVE

    def read(self, size=-1):
        size = self.remaining + 1 if size < 0 else min(size, self.remaining + 1)
        data = self.stream.read(size)
        require(len(data) <= self.remaining, "Package archive exceeds 512 MiB unpacked")
        self.remaining -= len(data)
        return data


class PackageTarInfo(tarfile.TarInfo):
    @classmethod
    def frombuf(cls, buf, encoding, errors):
        info = super().frombuf(buf, encoding, errors)
        require(0 <= info.size <= MAX_ARCHIVE, "Package archive member exceeds size limit")
        if info.type in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
            require(info.size <= MAX_CONFIG, "Package archive metadata exceeds 1 MiB")
        return info


def package_archive_digest(package, evidence, cache=None):
    """Verify one package member, reusing unchanged archives within an audit.

    Args:
        package (dict): Exact manager/package/version and archive member identity.
        evidence (dict): Validated operator-supplied archive evidence.
        cache (dict | None): Per-audit digest cache; never shared between audits.

    Returns:
        tuple[str, dict]: Member SHA-256 and the matching evidence entry.

    Raises:
        AuditError: Evidence, archive integrity or member identity is unresolved.
        OSError: The archive cannot be read or rechecked.
    """
    entries = [row for row in evidence.get("package_archives", [])
               if all(row[key] == package[key] for key in ("manager", "package", "version"))]
    require(len(entries) == 1,
            "Package ownership/version found, but no file checksum; supply a trusted package archive or build hash", "EVIDENCE_MISSING")
    entry = entries[0]
    key = (entry["path"], entry["sha256"], package["archive_member"])
    matches = []
    try:
        with ExitStack() as stack:
            stream = stack.enter_context(open(entry["path"], "rb"))
            require(os.fstat(stream.fileno()).st_size <= MAX_ARCHIVE, "Package archive exceeds 512 MiB")
            identity = file_signature(os.fstat(stream.fileno()))
            if cache is not None and key in cache and cache[key][0] == identity:
                with open(entry["path"], "rb") as current:
                    path_identity = file_signature(os.fstat(current.fileno()))
                require(path_identity == identity and
                        file_signature(os.fstat(stream.fileno())) == identity,
                        "Package archive changed while reading", "FILE_CHANGED")
                return cache[key][1], entry
            hashes, before = hash_stream(stream)
            require(hashes["sha256"] == entry["sha256"], "Package archive SHA-256 mismatch", "EVIDENCE_MISMATCH")
            stream.seek(0)
            magic = stream.read(6)
            stream.seek(0)
            decoded = stream
            if magic.startswith(b"\x1f\x8b"):
                decoded = stack.enter_context(gzip.GzipFile(fileobj=stream))
            elif magic.startswith(b"BZh"):
                decoded = stack.enter_context(bz2.BZ2File(stream))
            elif magic.startswith(b"\xfd7zXZ\x00"):
                decoded = stack.enter_context(lzma.LZMAFile(stream))
            with tarfile.open(fileobj=BoundedArchiveReader(decoded), mode="r|", tarinfo=PackageTarInfo) as archive:
                for count, member in enumerate(archive):
                    require(count < 100000 and member.offset_data + member.size <= MAX_ARCHIVE,
                            "Package archive exceeds unpacked size/member limit")
                    name = PurePosixPath(member.name)
                    require(not name.is_absolute() and ".." not in name.parts,
                            "Invalid package archive member path")
                    if str(name) != package["archive_member"]:
                        continue
                    require(member.isfile() and not member.issparse(), "Package artifact must be a regular archive file")
                    digest = hashlib.sha256()
                    with archive.extractfile(member) as source:
                        for block in iter(lambda: source.read(1024 * 1024), b""):
                            digest.update(block)
                    matches.append(digest.hexdigest())
            after = os.fstat(stream.fileno())
            with open(entry["path"], "rb") as current:
                path_identity = file_signature(os.fstat(current.fileno()))
            require(identity == file_signature(before) == file_signature(after) == path_identity,
                    "Package archive changed while reading", "FILE_CHANGED")
    except (tarfile.TarError, EOFError, lzma.LZMAError, zlib.error) as exc:
        raise AuditError("Invalid package tar archive: " + str(exc)) from exc
    require(len(matches) == 1, "Package archive has no unique matching file")
    if cache is not None:
        cache[key] = (identity, matches[0])
    return matches[0], entry


def file_signature(info):
    """Return the file identity and change markers used for archive reuse.

    Args:
        info (os.stat_result): Metadata from an open handle or pathname.

    Returns:
        tuple[int, ...]: Device, inode, size, modification and change times.
    """
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def package_metadata(path):
    if sys.platform == "darwin":
        return macos_package_metadata(path)
    require(sys.platform.startswith("linux"), "Use SHA-256 build evidence for this platform", "EVIDENCE_MISSING")
    if Path("/var/lib/dpkg/status").is_file():
        return dpkg_metadata(path)
    if Path("/lib/apk/db/installed").is_file():
        return apk_metadata(path)
    if Path("/var/lib/pacman/local").is_dir():
        return pacman_metadata(path)
    if any(Path(p).is_dir() for p in ("/var/lib/rpm", "/usr/lib/sysimage/rpm")):
        return rpm_metadata(path)
    raise AuditError("No supported package database; use SHA-256 build evidence for this build", "EVIDENCE_MISSING")


def fixed_rule(package, distro, evidence):
    """Select a fix threshold for the exact vendor/package scope.

    Args:
        package (dict): Installed package identity and metadata.
        distro (tuple[str, str]): Target OS ID and release.
        evidence (dict): Validated operator rules and imported advisories.

    Returns:
        dict: Fixed revision, source references and a built-in review date when known.

    Raises:
        AuditError: No applicable rule establishes fixes for both CVEs.
    """
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
                return {"fixed_version": version, "sources": sources, "verified_at": "2026-10-22"}
    if distro[0] == "alpine" and package["manager"] == "apk":
        release = re.fullmatch(r"(3\.(?:23|24))(?:\.[0-9]+)?", distro[1])
        for name, version in ALPINE_FIXES.items():
            if release and package["package"] in {name, name + "-fpm", name + "-cgi", name + "-apache2"}:
                return {"fixed_version": version, "verified_at": "2026-10-23",
                        "sources": ["https://secdb.alpinelinux.org/v" + release[1] + "/community.json"]}
    if distro == ("arch", "rolling") and package["manager"] == "pacman" and package["package"] in ARCH_FIXES:
        version, advisory = ARCH_FIXES[package["package"]]
        return {"fixed_version": version, "verified_at": "2026-10-23",
                "sources": ["https://security.archlinux.org/" + advisory]}
    if (distro[0] == "rhel" and package["manager"] == "rpm"
            and package.get("vendor") == "Red Hat, Inc."
            and package["package"] in {"php", "php-cli", "php-common", "php-fpm"}):
        if (distro[1] == "8.10" and (package.get("module") or "").startswith("php:7.4:")
                and package["version"].startswith("0:7.4.")):
            return {"fixed_version": "0:7.4.33-8.module+el8.10.0+25117+30337cca",
                    "sources": ["https://access.redhat.com/errata/RHSA-2026:87080"], "verified_at": "2026-10-22"}
        if distro[1] == "9.8" and package.get("module") == "" and package["version"].startswith("0:8.0."):
            return {"fixed_version": "0:8.0.30-8.el9_8.1",
                    "sources": ["https://access.redhat.com/errata/RHSA-2026:87151"], "verified_at": "2026-10-22"}
    imported = updateinfo_rule(package, distro, evidence)
    if imported:
        return imported
    raise AuditError("No vendor advisory rule for this OS/package; supply verified evidence", "VENDOR_RULE_MISSING")


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


def inspect_runtime(runtime, distro, evidence, archive_cache=None):
    """Assess a discovered artifact while preserving running-image uncertainty.

    Args:
        runtime (Runtime): Discovered process or module identity.
        distro (tuple[str, str] | None): Target OS ID and release.
        evidence (dict): Validated vendor, build and archive evidence.
        archive_cache (dict | None): Archive results shared only within this audit.

    Returns:
        dict: Status, restart flag, retained evidence and actionable diagnostics.
        Inspection failures remain UNKNOWN instead of clearing the artifact.
    """
    record = {"pid": runtime.pid, "kind": runtime.kind, "path": runtime.path,
              "status": "UNKNOWN", "restart_needed": runtime.deleted}
    try:
        if sys.platform == "win32":
            record.update(inspect_file({"kind": runtime.kind, "path": runtime.path}, distro, evidence, archive_cache))
            record.update(pid=runtime.pid, assessment_scope="observed-file")
            record["file_status"] = record["status"]
            record["status"] = "UNKNOWN"
            record["detail"] += "; Windows module paths do not prove loaded-image identity; file status is separate"
            record["diagnostics"].append(diagnostic("LOADED_IMAGE_UNVERIFIED", record["detail"], distro))
            return record
        if sys.platform == "darwin" and runtime.inode:
            try:
                current = os.stat(runtime.path)
                record["restart_needed"] |= (current.st_dev, current.st_ino) != (runtime.device, runtime.inode)
            except FileNotFoundError:
                record["restart_needed"] = True
        hashes, restart = hash_runtime(runtime)
        record.update(sha256=hashes["sha256"], restart_needed=restart)
        assess_file(record, hashes, distro, evidence, archive_cache)
    except (AuditError, OSError, ValueError, IndexError, EOFError, zlib.error) as exc:
        record["detail"] = str(exc)
        record["diagnostics"] = [error_diagnostic(exc, distro, record.get("manager"))]
    return explain_record(record, distro)


def assess_file(record, hashes, distro, evidence, archive_cache=None):
    """Match verified file bytes to trusted build or package evidence.

    Args:
        record (dict): Artifact record to update in place.
        hashes (dict[str, str]): Digests of the audited file.
        distro (tuple[str, str] | None): Target OS ID and release.
        evidence (dict): Validated operator evidence.
        archive_cache (dict | None): Per-audit archive results.

    Raises:
        AuditError: Ownership, checksums or applicable fix evidence are unresolved.
        OSError: Package metadata or an archive cannot be read.
    """
    record["sha256"] = hashes["sha256"]
    build = next((row for row in evidence.get("builds", []) if row["sha256"] == hashes["sha256"]), None)
    if build:
        record.update(status="PATCHED" if build.get("fixed_cves") else upstream_status(build["php_version"]), php_version=build["php_version"],
                      source=build["source"], detail="File SHA-256 matches operator-supplied build provenance")
        return
    package = package_metadata(record["path"])
    record.update(package=package["package"], package_version=package["version"])
    if package.get("manager") in ("homebrew", "macports"):
        record["manager"] = package["manager"]
        record["package_receipt"] = package["receipt"]
        expected, entry = package_archive_digest(package, evidence, archive_cache)
        require(hashes["sha256"] == expected,
                "File differs from package archive; relocated/modified builds require separate SHA-256 build evidence", "EVIDENCE_MISMATCH")
        record.update(status="PATCHED" if entry.get("fixed_cves") else upstream_status(entry["php_version"]),
                      php_version=entry["php_version"], source=entry["source"],
                      detail="File SHA-256 matches a file in the trusted package archive")
        return
    require(hashes[package["algorithm"]] == package["digest"],
            "File differs from installed package checksum; patch status unresolved", "EVIDENCE_MISMATCH")
    record["manager"] = package["manager"]
    require(distro is not None, "Cannot determine OS release for vendor comparison")
    rule = fixed_rule(package, distro, evidence)
    record.update(status=package_status(package, rule["fixed_version"]),
                  fixed_version=rule["fixed_version"], sources=rule["sources"],
                  detail="File checksum matches installed package metadata")
    if "verified_at" in rule:
        record["rule_verified_at"] = rule["verified_at"]


def inspect_file(item, distro, evidence, archive_cache=None):
    """Assess an installed file without asserting running-process coverage.

    Args:
        item (dict): Inventory kind and absolute file path.
        distro (tuple[str, str] | None): Target OS ID and release.
        evidence (dict): Validated operator evidence.
        archive_cache (dict | None): Per-audit archive results.

    Returns:
        dict: Installed-file verdict, evidence and unresolved-condition diagnostics.
    """
    record = {"pid": 0, "kind": item["kind"], "path": item["path"], "status": "UNKNOWN",
              "restart_needed": False, "assessment_scope": "installed-file"}
    try:
        assess_file(record, hash_file(item["path"]), distro, evidence, archive_cache)
    except (AuditError, OSError, ValueError, IndexError, EOFError, zlib.error) as exc:
        record["detail"] = str(exc)
        record["diagnostics"] = [error_diagnostic(exc, distro, record.get("manager"))]
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
    return explain_record(record, distro)


def finish(records, issues, mode="local", scope=None, diagnostics=None, metadata=None):
    """Summarize assessments without changing the established exit-code rules.

    Args:
        records (list[dict]): Artifact assessments.
        issues (list[str]): Coverage or inspection failures preventing clearance.
        mode (str): Local audit or transport/observation method.
        scope (str | None): Operator-supplied deployment scope.
        diagnostics (list[dict] | None): Structured explanations of report issues.
        metadata (dict | None): Target/input identity captured by the caller.

    Returns:
        dict: Schema-1 report with additive diagnostics and metadata.
    """
    if any(row["status"] == "AFFECTED" for row in records):
        status = 1
    elif (not records or issues or any(row["status"] != "PATCHED" or row["restart_needed"]
                                      for row in records)):
        status = 2
    else:
        status = 0
    if diagnostics is None:
        code = "TRANSPORT_FAILED" if mode in ("ssh", "container") else (
            "OBSERVATION_ONLY" if mode != "local" else "DISCOVERY_INCOMPLETE")
        diagnostics = [diagnostic(code, issue) for issue in issues]
    if not records and not diagnostics:
        diagnostics = [diagnostic("NO_RUNTIME_FOUND", "No runtime artifacts were assessed")]
    metadata = metadata if metadata is not None else report_metadata()
    metadata["host_role"] = "audit-target" if mode == "local" else "controller"
    return {"schema": 1, "completed": True, "mode": mode, "scope": scope,
            "cves": list(CVES), "verdict": {0: "PATCHED", 1: "AFFECTED", 2: "UNKNOWN"}[status],
            "exit_status": status, "runtimes": records, "issues": issues,
            "diagnostics": diagnostics, "metadata": metadata}


def audit_local(inventory, evidence, files=False):
    """Audit this namespace, keeping archive reuse confined to this invocation.

    Args:
        inventory (dict | None): Confirmed expected runtimes, if supplied.
        evidence (dict): Vendor, build and archive evidence.
        files (bool): Assess installed inventory files instead of running workers.

    Returns:
        dict: Audit report with input fingerprints and coverage diagnostics.

    Raises:
        AuditError: Configuration or file-mode requirements are invalid.
    """
    validate_config(inventory, evidence)
    metadata = report_metadata(inventory, evidence)
    archive_cache = {}
    key = os.path.realpath if sys.platform == "darwin" else path_key
    if inventory is not None:
        keys = {(row["kind"], key(row["path"])) for row in inventory["runtimes"]}
        require(len(keys) == len(inventory["runtimes"]), "Duplicate inventory runtime through path aliases")
    if files:
        require(inventory is not None, "--files requires an explicit --inventory")
        try:
            distro = os_release()
        except (OSError, AuditError):
            distro = None
        result = finish([inspect_file(row, distro, evidence, archive_cache) for row in inventory["runtimes"]], [],
                        scope=inventory["scope"], metadata=metadata)
        result["assessment_scope"] = "installed-files-only"
        result["limitations"] = ["Does not establish running-process patch status or deployment coverage beyond listed files"]
        return result
    try:
        runtimes, issues = discover(inventory)
    except (AuditError, OSError) as exc:
        return finish([], [str(exc)], diagnostics=[error_diagnostic(exc)], metadata=metadata)
    diagnostics = [diagnostic("DISCOVERY_INCOMPLETE", issue) for issue in issues]
    if inventory is None:
        issues.append("No confirmed inventory: automatic discovery cannot prove deployment coverage")
        diagnostics.append(diagnostic("INVENTORY_UNCONFIRMED", issues[-1]))
    else:
        expected = {(row["kind"], key(row["path"])): row["label"] for row in inventory["runtimes"]}
        found = {(r.kind, key(r.path)) for r in runtimes}
        for missing in expected.keys() - found:
            issues.append("Expected runtime not observed: " + expected[missing] + " (" + missing[1] + ")")
            diagnostics.append(diagnostic("EXPECTED_RUNTIME_MISSING", issues[-1]))
        for extra in found - expected.keys():
            issues.append("Runtime missing from inventory: " + extra[0] + " " + extra[1])
            diagnostics.append(diagnostic("UNEXPECTED_RUNTIME", issues[-1]))
    try:
        distro = os_release()
    except (OSError, AuditError):
        distro = None
    records = [inspect_runtime(runtime, distro, evidence, archive_cache) for runtime in runtimes]
    return finish(records, issues, scope=(inventory or {}).get("scope"), diagnostics=diagnostics, metadata=metadata)


def draft_inventory():
    """Discover candidate inventory paths without asserting deployment coverage.

    Returns:
        dict: UNKNOWN audit report containing an unconfirmed inventory draft.
        Discovery errors are retained; inactive and hidden runtimes need review.
    """
    try:
        runtimes, issues = discover(None)
    except (AuditError, OSError) as exc:
        runtimes, issues = [], [str(exc)]
    key = os.path.realpath if sys.platform == "darwin" else path_key
    paths = {(run.kind, key(run.path)): run.path for run in runtimes}
    draft = {"schema": 1, "scope": "REVIEW deployment scope", "coverage_confirmed": False,
             "runtimes": [{"label": kind + " " + path, "kind": kind, "path": path}
                          for (kind, _), path in sorted(paths.items())],
             "discovery_issues": issues,
             "review_required": "Add inactive, renamed and hidden deployments; confirm scope and coverage before auditing."}
    report = finish([], issues + ["Draft inventory requires operator review"],
                    diagnostics=[diagnostic("INVENTORY_UNCONFIRMED", draft["review_required"])] +
                    [diagnostic("DISCOVERY_INCOMPLETE", issue) for issue in issues])
    draft["metadata"] = report["metadata"]
    report["draft_inventory"] = draft
    return report


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
    # Ignore proxy environment variables and reject redirects.
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
            # Send one ordinary field, without a file or upload-progress payload.
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
        result = draft_inventory() if payload.get("draft", False) else audit_local(
            payload["inventory"], payload["evidence"], payload.get("files", False))
    except (AuditError, OSError, ValueError, TypeError, EOFError, zlib.error) as exc:
        result = finish([], ["Remote audit failed: " + str(exc)], diagnostics=[error_diagnostic(exc)])
    result["token"] = payload["token"]
    print(json.dumps(result))
    return result["exit_status"]


def valid_remote_result(result, token, rc):
    """Check a remote envelope before trusting its verdict or rendering findings.

    Args:
        result (object): Decoded remote JSON.
        token (str): Expected per-run result token.
        rc (int): Transport process exit status.

    Returns:
        bool: Whether identity, field types, verdict and exit status are consistent.
    """
    if not isinstance(result, dict) or result.get("token") != token:
        return False
    if result.get("schema") != 1 or result.get("completed") is not True:
        return False
    if result.get("cves") != list(CVES) or result.get("mode") != "local":
        return False
    records, issues = result.get("runtimes"), result.get("issues")
    if not isinstance(records, list) or not isinstance(issues, list) or not all(isinstance(x, str) for x in issues):
        return False
    if not valid_diagnostics(result.get("diagnostics", [])):
        return False
    metadata = result.get("metadata")
    if (not isinstance(metadata, dict) or not isinstance(metadata.get("target"), dict)
            or not isinstance(metadata.get("timestamp_utc"), str)
            or not isinstance(metadata.get("tool_version"), str)
            or not isinstance(metadata.get("tool_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", metadata["tool_sha256"])):
        return False
    for row in records:
        if (not isinstance(row, dict) or row.get("status") not in ("PATCHED", "AFFECTED", "UNKNOWN")
                or type(row.get("restart_needed")) is not bool or type(row.get("pid")) is not int
                or not isinstance(row.get("kind"), str) or row["kind"] not in KINDS
                or not isinstance(row.get("path"), str)
                or not valid_diagnostics(row.get("diagnostics", []))):
            return False
    expected = finish(records, issues)
    return rc == result.get("exit_status") == expected["exit_status"] and result.get("verdict") == expected["verdict"]


def valid_diagnostics(value):
    """Validate remote findings before rendering their fields.

    Args:
        value (object): Untrusted decoded JSON diagnostics value.

    Returns:
        bool: Whether all entries have known codes and safely renderable fields.
    """
    return isinstance(value, list) and all(
        isinstance(row, dict) and isinstance(row.get("code"), str) and row["code"] in NEXT_STEPS
        and isinstance(row.get("detail"), str) and isinstance(row.get("next_step"), str)
        and isinstance(row.get("guidance"), list)
        and all(isinstance(url, str) and url.startswith("https://") for url in row["guidance"])
        for row in value)


def remote_program(inventory, evidence, files=False, draft=False):
    """Serialize this script and configuration for an authenticated transport.

    Args:
        inventory (dict | None): Target inventory.
        evidence (dict): Target evidence; archive paths remain target-local.
        files (bool): Select installed-file assessment.
        draft (bool): Discover an unconfirmed inventory instead of assessing files.

    Returns:
        tuple[str, str]: Per-run result token and Python source sent over stdin.

    Raises:
        OSError: This script cannot be read for transfer.
    """
    token = secrets.token_hex(24)
    payload = {"token": token, "inventory": inventory, "evidence": evidence, "files": files, "draft": draft}
    source_bytes = Path(__file__).read_bytes()
    source = source_bytes.decode("utf-8")
    # repr embeds data as Python string literals; no target/config enters shell code.
    source_hash = hashlib.sha256(source_bytes).hexdigest()
    program = "import json\nns={'__name__':'php2shell_remote','AUDIT_SOURCE_SHA256':" + repr(source_hash) + "}\n"
    program += "exec(compile(" + ascii(source) + ",'<audit>','exec'),ns)\n"
    program += "raise SystemExit(ns['remote_main'](json.loads(" + repr(json.dumps(payload)) + ")))\n"
    return token, program


def run_remote(argv, mode, target, inventory, evidence, files=False, draft=False):
    """Run and validate one remote audit or inventory export.

    Args:
        argv (list[str]): Trusted utility and validated transport arguments.
        mode (str): SSH or container transport name.
        target (str): Validated target identifier.
        inventory (dict | None): Target inventory.
        evidence (dict): Target evidence.
        files (bool): Select installed-file assessment.
        draft (bool): Request an unconfirmed inventory draft.

    Returns:
        dict: Validated target report, or an UNKNOWN transport-failure report.
    """
    token, program = remote_program(inventory, evidence, files, draft)
    run = None
    try:
        run = command(argv, timeout=120, data=program)
        result = json.loads(run.stdout)
        require(valid_remote_result(result, token, run.returncode), "Remote result missing, incomplete, or inconsistent")
        result.pop("token")
        require(result.get("assessment_scope") == ("installed-files-only" if files else None),
                "Remote result has the wrong assessment scope")
        if draft:
            candidate = result.get("draft_inventory")
            require(isinstance(candidate, dict) and candidate.get("coverage_confirmed") is False
                    and isinstance(candidate.get("runtimes"), list) and result["exit_status"] == 2,
                    "Remote inventory draft missing or incorrectly confirmed")
        result["mode"] = mode
        result["target"] = target
        return result
    except (AuditError, ValueError, TypeError) as exc:
        result = finish([], [mode + "/setup/audit failure: " + str(exc)], mode)
        if run is not None:
            result["issues"].append(f"Transport exit {run.returncode}; stderr: {run.stderr.strip()[:2000]}")
        result["target"] = target
        return result


def audit_ssh(host, sudo, inventory, evidence, files=False, remote_os="linux", python=None, draft=False):
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
                       "-o", "StrictHostKeyChecking=yes", "--", host, remote], "ssh", host, inventory, evidence, files, draft)


def audit_container(container, engine, inventory, evidence, files=False, python=None, draft=False):
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", container), "Invalid container name or ID")
    require(engine in ("docker", "podman"), "Unsupported container engine")
    python = python or "/usr/bin/python3"
    require(absolute_path(python) and python.startswith("/"), "Container Python must be an absolute POSIX path")
    return run_remote([system_tool(engine), "exec", "-i", container, python, "-"],
                      "container", container, inventory, evidence, files, draft)


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
    parser.add_argument("--remote-os", choices=("linux", "macos", "windows"), default="linux")
    parser.add_argument("--remote-python", help="Absolute target Python path; required for Windows SSH")
    parser.add_argument("--probe-php", action="append", default=[], metavar="TRUSTED_BINARY",
                        help="Opt-in: execute this local trusted PHP binary with -n -v; hints only")
    parser.add_argument("--log", action="append", default=[], metavar="FILE", help="Review PHP/web-server error logs")
    parser.add_argument("--process-events", action="append", default=[], metavar="JSONL", help="Review exported process-watcher events")
    parser.add_argument("--updateinfo", action="append", default=[], metavar="XML_OR_GZ", help="Trusted RPM repository updateinfo metadata")
    parser.add_argument("--updateinfo-os", metavar="ID:VERSION", help="Exact target OS/release covered by supplied updateinfo")
    parser.add_argument("--inventory", help="Explicit expected runtime inventory JSON")
    parser.add_argument("--draft-inventory", action="store_true", help="Print an unconfirmed inventory JSON draft; exit 2 until reviewed")
    parser.add_argument("--evidence", help="Trusted vendor fixes, build hashes or package archives JSON")
    parser.add_argument("--json", action="store_true", help="Emit full machine-readable evidence")
    args = parser.parse_args(argv)
    try:
        require(sys.version_info >= (3, 9), "Python 3.9+ is required")
        require(not args.draft_inventory or (len(args.ssh) + len(args.container) <= 1 and not any((
            args.inventory, args.evidence, args.files, args.http, args.http_details, args.multipart_check,
            args.targets_file, args.probe_php, args.log, args.process_events, args.updateinfo))),
            "--draft-inventory requires discovery only, for one local host or one SSH/container target")
        require(not args.sudo or args.ssh, "--sudo requires --ssh")
        require(not args.inventory or len(args.ssh) + len(args.container) <= 1,
                "Use one remote host/container per invocation with its own inventory")
        require(not args.probe_php or not (args.ssh or args.container), "--probe-php executes locally; use a separate invocation")
        require(not args.files or args.inventory, "--files requires --inventory")
        require(not args.remote_python or args.ssh or args.container, "--remote-python requires --ssh or --container")
        require(args.remote_os == "linux" or (args.ssh and not args.container),
                "--remote-os macos/windows requires SSH, not container transport")
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
                                             args.files, args.remote_os, args.remote_python, args.draft_inventory))
                elif mode == "container":
                    reports.append(audit_container(target, args.engine, inventory, evidence, args.files, args.remote_python, args.draft_inventory))
                elif mode in ("http", "http-details", "multipart"):
                    reports.append(audit_http(target, mode == "http-details", mode == "multipart"))
                elif mode == "probe":
                    reports.append(audit_probe(target))
                else:
                    reports.append(audit_logs(target, events=mode == "process-events"))
            except (AuditError, OSError, ValueError, TypeError) as exc:
                failure = finish([], [str(exc)], mode, diagnostics=[error_diagnostic(exc)])
                failure["target"] = target
                reports.append(failure)
        if not reports or (args.files and not (args.ssh or args.container)):
            reports.append(draft_inventory() if args.draft_inventory else audit_local(inventory, evidence, args.files))
    except (AuditError, OSError, ValueError, TypeError, EOFError, zlib.error) as exc:
        reports = [finish([], [str(exc)], diagnostics=[error_diagnostic(exc)])]
    status = 1 if any(r["exit_status"] == 1 for r in reports) else (
        2 if any(r["exit_status"] == 2 for r in reports) else 0)
    if args.draft_inventory and len(reports) == 1 and "draft_inventory" in reports[0]:
        print(json.dumps(reports[0]["draft_inventory"], indent=2))
    elif args.json:
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
                if row.get("manager") in ("homebrew", "macports"):
                    print("    Package: " + json.dumps(row["manager"] + " " + row["package"] + " " + row["package_version"]))
                if "file_status" in row:
                    print("    Installed file: " + row["file_status"] + "; loaded image unverified")
                if row.get("version_hint"):
                    print("    Version resource (hint): " + json.dumps(row["version_hint"]))
                if row["restart_needed"]:
                    print("    RESTART REQUIRED: running file was removed/replaced; re-audit afterward")
                for finding in row.get("diagnostics", []):
                    print("    " + finding["code"] + ": " + json.dumps(finding["next_step"]))
                    print("    Guidance: " + json.dumps(finding["guidance"]))
            for issue in report["issues"]:
                print("  " + json.dumps(issue))
            for finding in report.get("diagnostics", []):
                print("  " + finding["code"] + ": " + json.dumps(finding["next_step"]))
            if report["mode"] == "http":
                print("  HTTP evidence: " + json.dumps(report.get("headers", {})))
            for field in ("version_hints", "phpinfo_settings", "cms_hints", "multipart", "counts", "observations", "limitations"):
                if report.get(field):
                    print("  " + field + ": " + json.dumps(report[field]))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
