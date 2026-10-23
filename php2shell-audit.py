#!/usr/bin/env python3
"""Read-only PHP2Shell patch audit. Python 3.9+; local inspection requires Linux."""

import argparse
import hashlib
import http.client
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

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


class AuditError(Exception):
    pass


def command(argv, timeout=15, data=None):
    """Only callers supplying fixed system utilities may execute commands."""
    environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
    if Path(argv[0]).name == "ssh" and "SSH_AUTH_SOCK" in os.environ:
        environment["SSH_AUTH_SOCK"] = os.environ["SSH_AUTH_SOCK"]
    try:
        return subprocess.run(argv, input=data, text=True, capture_output=True,
                              timeout=timeout, check=False,
                              env=environment)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AuditError("Command failed or timed out: " + argv[0]) from exc


def system_tool(name):
    for directory in ("/usr/bin", "/bin"):
        path = Path(directory) / name
        try:
            info = path.stat()
            if (stat.S_ISREG(info.st_mode) and info.st_uid == 0
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
            require(item.get("kind") in KINDS and isinstance(item.get("path"), str)
                    and item["path"].startswith("/") and "\n" not in item["path"],
                    "Inventory entry needs a supported kind and absolute runtime path")
            key = (item["kind"], item["path"])
            require(key not in keys, "Duplicate inventory runtime")
            keys.add(key)
    require(isinstance(evidence, dict) and evidence.get("schema") == 1,
            "Evidence must have schema=1")
    for field in ("vendor_fixes", "builds"):
        require(isinstance(evidence.get(field, []), list), "Invalid evidence list: " + field)
    seen = set()
    for row in evidence.get("vendor_fixes", []):
        require(isinstance(row, dict), "Invalid vendor rule")
        for key in ("os_id", "os_version", "package", "fixed_version"):
            require(isinstance(row.get(key), str) and
                    re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+:~^_-]*", row[key]),
                    "Invalid vendor rule field: " + key)
        require(row.get("manager") in ("dpkg", "rpm") and
                sorted(row.get("cves", [])) == sorted(CVES),
                "Each vendor rule must cover both CVEs and name dpkg or rpm")
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
        seen.add(row["sha256"])


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
    for line in Path("/etc/os-release").read_text().splitlines():
        match = re.fullmatch(r'(ID|VERSION_ID)=["\']?([A-Za-z0-9._-]+)["\']?', line)
        if match:
            values[match[1]] = match[2]
    require("ID" in values and "VERSION_ID" in values, "Cannot determine OS release")
    return values["ID"], values["VERSION_ID"]


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
    require(sys.platform.startswith("linux"), "Local inspection supports Linux only")
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
        hashes = {name: hashlib.new(name, usedforsecurity=False)
                  for name in ("md5", "sha1", "sha256", "sha384", "sha512")}
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            for digest in hashes.values():
                digest.update(block)
        after = os.fstat(stream.fileno())
        require((info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                "Running file changed while hashing")
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
    return {name: digest.hexdigest() for name, digest in hashes.items()}, restart


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
    return {"manager": "rpm", "package": package, "version": f"{epoch}:{version}-{release}",
            "algorithm": algorithm, "digest": digests[0]}


def package_metadata(path):
    if Path("/var/lib/dpkg/status").is_file():
        return dpkg_metadata(path)
    return rpm_metadata(path)


def fixed_rule(package, distro, evidence):
    for rule in evidence.get("vendor_fixes", []):
        if (rule["os_id"], rule["os_version"], rule["manager"], rule["package"]) == (
                *distro, package["manager"], package["package"]):
            return rule
    if distro[0] == "ubuntu" and package["manager"] == "dpkg":
        for (release, source), version in UBUNTU_FIXES.items():
            # Only PHP runtime packages are covered, not arbitrary name prefixes.
            names = {source + suffix for suffix in ("-fpm", "-cgi", "-cli", "-common")}
            names.add("libapache2-mod-" + source)
            if distro[1] == release and package["package"] in names:
                return {"fixed_version": version, "sources": UBUNTU_SOURCES}
    raise AuditError("No vendor advisory rule for this OS/package; supply verified evidence")


def package_status(package, fixed):
    if package["manager"] == "dpkg":
        result = command([system_tool("dpkg"), "--compare-versions", package["version"], "ge", fixed])
        require(result.returncode in (0, 1), "Package version comparison failed")
        return "PATCHED" if result.returncode == 0 else "AFFECTED"
    # Constrained values cannot inject Lua, RPM macros, or shell syntax.
    for value in (package["version"], fixed):
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+:~^_-]*", value), "Invalid RPM version")
    expression = '%{lua:print(rpm.vercmp("' + package["version"] + '","' + fixed + '"))}'
    result = command([system_tool("rpm"), "--eval", expression])
    require(result.returncode == 0 and result.stdout.strip() in ("-1", "0", "1"),
            "RPM version comparison unavailable")
    return "AFFECTED" if result.stdout.strip() == "-1" else "PATCHED"


def inspect_runtime(runtime, distro, evidence):
    record = {"pid": runtime.pid, "kind": runtime.kind, "path": runtime.path,
              "status": "UNKNOWN", "restart_needed": runtime.deleted}
    try:
        hashes, restart = hash_runtime(runtime)
        record.update(sha256=hashes["sha256"], restart_needed=restart)
        build = next((row for row in evidence.get("builds", []) if row["sha256"] == hashes["sha256"]), None)
        if build:
            record.update(status=upstream_status(build["php_version"]),
                          php_version=build["php_version"], source=build["source"],
                          detail="Running-file SHA-256 matches operator-supplied build provenance")
        else:
            package = package_metadata(runtime.path)
            record["package"] = package["package"]
            record["package_version"] = package["version"]
            require(hashes[package["algorithm"]] == package["digest"],
                    "Running file differs from installed package checksum; patch status unresolved")
            require(distro is not None, "Cannot determine OS release for vendor comparison")
            rule = fixed_rule(package, distro, evidence)
            record.update(status=package_status(package, rule["fixed_version"]),
                          fixed_version=rule["fixed_version"], sources=rule["sources"],
                          detail="Running-file checksum matches installed package metadata")
    except (AuditError, OSError, ValueError, IndexError) as exc:
        record["detail"] = str(exc)
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


def audit_local(inventory, evidence):
    validate_config(inventory, evidence)
    try:
        runtimes, issues = discover(inventory)
    except (AuditError, OSError) as exc:
        return finish([], [str(exc)])
    if inventory is None:
        issues.append("No confirmed inventory: automatic discovery cannot prove deployment coverage")
    else:
        expected = {(row["kind"], row["path"]): row["label"] for row in inventory["runtimes"]}
        found = {(r.kind, r.path) for r in runtimes}
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


def audit_http(target):
    if "://" not in target:
        target = "https://" + target
    parsed = urllib.parse.urlsplit(target)
    require(parsed.scheme in ("http", "https") and parsed.hostname and not parsed.username
            and not parsed.password, "HTTP target must be an http(s) URL without credentials")
    # Avoid ambient proxies and cross-origin redirects; neither is inventory evidence.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    result = finish([], ["HTTP banners are hints only; authenticated runtime evidence is required"], "http")
    result["target"] = target
    try:
        request = urllib.request.Request(target, method="HEAD", headers={"User-Agent": "PHP2Shell-Patch-Audit/1"})
        try:
            response = opener.open(request, timeout=10)
        except urllib.error.HTTPError as exc:
            response = exc  # Headers from errors/redirects remain attributable to this URL.
        with response:
            result["http_status"] = response.code
            result["headers"] = {key: response.headers.get_all(key, [])
                                 for key in ("Server", "X-Powered-By", "Location")}
            banners = " ".join(value for key in ("Server", "X-Powered-By")
                               for value in result["headers"][key])
            result["reported_versions"] = re.findall(r"PHP/([^\s;,]+)", banners, re.IGNORECASE)
    except (OSError, urllib.error.URLError, ValueError, http.client.HTTPException) as exc:
        result["issues"].append("HTTP probe failed: " + str(exc))
    return result


def remote_main(payload):
    try:
        require(sys.version_info >= (3, 9), "Python 3.9+ is required")
        result = audit_local(payload["inventory"], payload["evidence"])
    except (AuditError, OSError, ValueError, TypeError) as exc:
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


def audit_ssh(host, sudo, inventory, evidence):
    require(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@:\[\]-]*", host), "Invalid SSH destination")
    token = secrets.token_hex(24)
    payload = {"token": token, "inventory": inventory, "evidence": evidence}
    source = Path(__file__).read_text()
    # repr embeds data as Python string literals; no target/config enters shell code.
    program = "import json\nns={'__name__':'php2shell_remote'}\n"
    program += "exec(compile(" + repr(source) + ",'<audit>','exec'),ns)\n"
    program += "raise SystemExit(ns['remote_main'](json.loads(" + repr(json.dumps(payload)) + ")))\n"
    remote = "/usr/bin/python3 -"
    if sudo:
        remote = "/usr/bin/sudo -n -- " + remote
    run = None
    try:
        run = command([system_tool("ssh"), "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                       "-o", "StrictHostKeyChecking=yes", "--", host, remote], timeout=120, data=program)
        result = json.loads(run.stdout)
        require(valid_remote_result(result, token, run.returncode), "Remote result missing, incomplete, or inconsistent")
        result.pop("token")
        result["mode"] = "ssh"
        result["target"] = host
        return result
    except (AuditError, ValueError, TypeError) as exc:
        result = finish([], ["SSH/setup/audit failure: " + str(exc)], "ssh")
        if run is not None:
            result["issues"].append(f"SSH exit {run.returncode}; stderr: {run.stderr.strip()[:2000]}")
        result["target"] = host
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-s", "--ssh", action="append", default=[], metavar="USER@HOST")
    parser.add_argument("--sudo", action="store_true", help="Noninteractive remote sudo")
    parser.add_argument("-u", "--http", "--url", action="append", default=[], metavar="URL")
    parser.add_argument("--inventory", help="Explicit expected runtime inventory JSON")
    parser.add_argument("--evidence", help="Trusted vendor fixes/custom-build provenance JSON")
    parser.add_argument("--json", action="store_true", help="Emit full machine-readable evidence")
    args = parser.parse_args(argv)
    try:
        require(sys.version_info >= (3, 9), "Python 3.9+ is required")
        require(not args.sudo or args.ssh, "--sudo requires --ssh")
        require(not args.inventory or len(args.ssh) <= 1,
                "Use one SSH host per invocation with its own inventory")
        inventory = load_json(args.inventory) if args.inventory else None
        evidence = load_json(args.evidence) if args.evidence else {"schema": 1}
        validate_config(inventory, evidence)
        reports = []
        targets = [("ssh", host) for host in args.ssh] + [("http", url) for url in args.http]
        for mode, target in targets:
            try:
                reports.append(audit_ssh(target, args.sudo, inventory, evidence) if mode == "ssh"
                               else audit_http(target))
            except (AuditError, OSError, ValueError, TypeError) as exc:
                failure = finish([], [str(exc)], mode)
                failure["target"] = target
                reports.append(failure)
        if not reports:
            reports.append(audit_local(inventory, evidence))
    except (AuditError, OSError, ValueError, TypeError) as exc:
        reports = [finish([], [str(exc)])]
    status = 1 if any(r["exit_status"] == 1 for r in reports) else (
        2 if any(r["exit_status"] == 2 for r in reports) else 0)
    if args.json:
        print(json.dumps({"schema": 1, "exit_status": status, "reports": reports}, indent=2))
    else:
        for report in reports:
            label = json.dumps(report.get("target", report.get("scope") or "local namespace"))
            print(f'[{report["verdict"]}] {label}')
            for row in report["runtimes"]:
                print(f'  {row["status"]}: PID {row["pid"]} {row["kind"]} {json.dumps(row["path"])}')
                print("    " + json.dumps(row.get("detail", "")))
                if row["restart_needed"]:
                    print("    RESTART REQUIRED: running file was removed/replaced; re-audit afterward")
            for issue in report["issues"]:
                print("  " + json.dumps(issue))
            if report["mode"] == "http":
                print("  HTTP evidence: " + json.dumps(report.get("headers", {})))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
