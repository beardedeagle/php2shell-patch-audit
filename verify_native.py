"""Run inside a disposable Linux container: native package and procfs checks.

Uses a copied system sleep executable as a synthetic PHP process. No PHP runs.
"""
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

spec = importlib.util.spec_from_file_location("audit", Path(__file__).with_name("php2shell-audit.py"))
audit = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = audit
spec.loader.exec_module(audit)


def main():
    assert sys.platform.startswith("linux"), "Run only in a disposable Linux test environment"
    artifact = next(path for marker, path in (
        ("/var/lib/dpkg/status", "/usr/bin/dpkg"),
        ("/lib/apk/db/installed", "/bin/busybox"),
        ("/var/lib/pacman/local", "/usr/bin/pacman"),
        ("/var/lib/rpm", "/usr/bin/rpm"),
        ("/usr/lib/sysimage/rpm", "/usr/bin/rpm")) if Path(marker).exists())
    metadata = audit.package_metadata(artifact)
    hashes = audit.hash_file(artifact)
    assert hashes[metadata["algorithm"]] == metadata["digest"], metadata
    assert audit.package_status(metadata, metadata["version"]) == "PATCHED"
    with tempfile.TemporaryDirectory() as directory:
        binary = Path(directory) / "php-fpm"
        source = shutil.which("sleep")
        arguments = ["sleep", "60"]
        if Path(source).read_bytes().startswith(b"#!/usr/bin/coreutils"):
            source = "/usr/bin/coreutils"
            arguments = ["coreutils", "--coreutils-prog=sleep", "60"]
        shutil.copyfile(source, binary)
        binary.chmod(0o755)
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        evidence = {"schema": 1, "builds": [{"sha256": digest, "php_version": "8.3.36", "source": "synthetic sleep fixture, not PHP"}]}
        inventory = {"schema": 1, "scope": "synthetic container fixture", "coverage_confirmed": True,
                     "runtimes": [{"label": "fixture", "kind": "fpm", "path": str(binary)}]}
        assert audit.audit_local(inventory, evidence, files=True)["exit_status"] == 0
        process = subprocess.Popen(arguments, executable=str(binary))
        try:
            runs, issues = audit.discover(inventory)
            instance = next(run for run in runs if run.pid == process.pid)
            assert audit.inspect_runtime(instance, audit.os_release(), evidence)["status"] == "PATCHED"
            os.rename(binary, str(binary) + ".old")
            binary.write_bytes(b"replacement")
            assert audit.hash_runtime(instance)[1] is True
        finally:
            process.terminate()
            process.wait(timeout=10)
    print(json.dumps({"platform": audit.os_release(), "manager": metadata["manager"],
                      "native_digest": "passed", "native_comparison": "passed",
                      "procfs_identity_and_replacement": "passed"}))


if __name__ == "__main__":
    main()
