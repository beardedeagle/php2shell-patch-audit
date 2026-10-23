"""Check libproc and package evidence with temporary macOS fixtures.

Requires Apple Command Line Tools. No PHP or package manager is run or installed.
"""
import hashlib
import json
import platform
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from unittest.mock import patch

from test_macos import audit, make_brew, make_port, archive_evidence


def main():
    assert sys.platform == "darwin", "Run on macOS with Python 3.9+ and Apple Command Line Tools"
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory).resolve()
        binary = make_brew(root)
        binary = binary.rename(binary.with_name("php-fpm"))
        module = binary.parent / "libphp.so"
        source = root / "fixture.c"
        source.write_text("#include <dlfcn.h>\n#include <stdio.h>\n#include <unistd.h>\n"
                          "int main(int argc, char **argv) {\n"
                          "if (argc != 2 || !dlopen(argv[1], RTLD_NOW)) return 1;\n"
                          "puts(\"ready\"); fflush(stdout); sleep(60); return 0; }\n")
        library_source = root / "module.c"
        library_source.write_text("int fixture(void) { return 1; }\n")
        for command in (("/usr/bin/clang", "-dynamiclib", str(library_source), "-o", str(module)),
                        ("/usr/bin/clang", str(source), "-o", str(binary))):
            subprocess.run(command, check=True, capture_output=True, timeout=30)
        archive = root / "package.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for path in (binary, module):
                tar.add(path, arcname=audit.macos_package_metadata(str(path))["archive_member"])
        package = audit.macos_package_metadata(str(binary))
        proof = {"schema": 1, "package_archives": [{
            "manager": package["manager"], "package": package["package"], "version": package["version"],
            "path": str(archive), "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "php_version": "8.3.36", "source": "synthetic native test; these files are not PHP"}]}
        alias = root / "php-fpm"
        alias.symlink_to(binary)
        inventory = {"schema": 1, "scope": "temporary macOS fixtures; not PHP", "coverage_confirmed": True,
                     "runtimes": [{"kind": kind, "path": str(path), "label": "test fixture"}
                                  for kind, path in (("fpm", alias), ("mod_php", module))]}
        with subprocess.Popen([str(binary), str(module)], stdout=subprocess.PIPE, text=True) as process:
            try:
                assert process.stdout.readline().strip() == "ready", "Fixture failed to load module"
                assert process.pid in audit.MacOSProcesses().pids()
                # Keep this test limited to its child; all other libproc calls are native.
                with patch.object(audit.MacOSProcesses, "pids", return_value=[process.pid]):
                    runs, issues = audit.discover(None)
                    assert not issues, issues
                    assert {run.kind for run in runs} == {"fpm", "mod_php"}, runs
                    result = audit.audit_local(inventory, proof)
                assert result["exit_status"] == 0, result
                module_run = next(run for run in runs if run.kind == "mod_php")
                replacement = root / "replacement"
                replacement.write_bytes(module.read_bytes())
                replacement.replace(module)
                replaced = audit.inspect_runtime(module_run, None, proof)
                assert replaced["status"] == "UNKNOWN" and replaced["restart_needed"], replaced
            finally:
                process.terminate()
                process.wait(timeout=10)
        port, _ = make_port(root / "ports")
        port_package = audit.macos_package_metadata(str(port))
        port_proof = archive_evidence(root / "ports", port_package)
        result = audit.inspect_file({"path": str(port), "kind": "php"}, None, port_proof)
        assert result["status"] == "PATCHED", result
    print(json.dumps({"macos": platform.mac_ver()[0], "arch": platform.machine(),
                      "process_and_module_discovery": "passed", "mapped_file_identity": "passed",
                      "replacement_detection": "passed", "homebrew_archive_fixture": "passed",
                      "macports_registry_archive_fixture": "passed", "real_php_tested": False}))


if __name__ == "__main__":
    main()
