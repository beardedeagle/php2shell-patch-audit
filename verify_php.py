"""Exercise real PHP only inside a disposable Docker container or hosted CI."""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("audit", Path(__file__).with_name("php2shell-audit.py"))
audit = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = audit
spec.loader.exec_module(audit)


def stop(process):
    """Terminate and reap a fixture process.

    Args:
        process (subprocess.Popen): Process owned by this test.
    """
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main():
    """Check real file, process, module and stale-worker assessments.

    Raises:
        RuntimeError: The test was invoked outside a disposable test environment.
        AssertionError: Isolation, trusted fixture identity or an audit invariant fails.
        subprocess.SubprocessError: A fixture executable fails or times out.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--php", default="/usr/local/bin/php")
    parser.add_argument("--version", required=True)
    parser.add_argument("--source", required=True, help="Trusted fixture image or release identity")
    parser.add_argument("--sapi", choices=("cli", "fpm", "apache"), default="cli")
    parser.add_argument("--replacement", help="Trusted fixed CLI artifact; never executed by this test")
    args = parser.parse_args()
    isolated = Path("/.dockerenv").is_file() or (os.environ.get("GITHUB_ACTIONS") == "true"
                                               and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted")
    if not isolated:
        raise RuntimeError("Run only inside disposable Docker containers or hosted CI; never on a workstation")
    php = Path(args.php).resolve(strict=True)
    actual = subprocess.run([str(php), "-n", "-r", "echo PHP_VERSION;"],
                            capture_output=True, text=True, check=True, timeout=15).stdout
    assert actual == args.version, (actual, args.version)
    expected = audit.upstream_status(args.version)
    assert expected in ("PATCHED", "AFFECTED"), expected
    with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
        root = Path(directory).resolve()
        second = root / php.name
        shutil.copy2(php, second)
        if sys.platform == "win32":
            for library in php.parent.glob("*.dll"):
                shutil.copy2(library, root / library.name)
        paths = {str(php): "php", str(second): "php"}
        processes = []
        for binary in (php, second):
            process = subprocess.Popen([str(binary), "-n", "-r", "while (true) { usleep(100000); }"],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            stack.callback(stop, process)
            processes.append(process)
        if args.sapi == "fpm":
            config = root / "fpm.conf"
            config.write_text(f"[global]\nerror_log = {root}/fpm.log\n[www]\n"
                              "user = root\ngroup = root\nlisten = 127.0.0.1:9000\n"
                              "pm = static\npm.max_children = 4\n")
            process = subprocess.Popen(["/usr/local/sbin/php-fpm", "-F", "-R", "-y", str(config)],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            stack.callback(stop, process)
            processes.append(process)
            paths["/usr/local/sbin/php-fpm"] = "fpm"
        elif args.sapi == "apache":
            process = subprocess.Popen(["apache2-foreground"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            stack.callback(stop, process)
            processes.append(process)
            paths["/usr/lib/apache2/modules/libphp.so"] = "mod_php"
        if sys.platform == "win32":
            for parent in (php.parent, root):
                for library in parent.glob("php[0-9]*.dll"):
                    # CLI workers load the core DLL, not debugger or Apache DLLs.
                    if re.fullmatch(r"php[0-9]+(?:ts)?\.dll", library.name, re.I):
                        paths[str(library)] = "mod_php"
        config = {"schema": 1, "scope": "disposable real-PHP fixtures", "coverage_confirmed": True,
                  "runtimes": [{"label": path, "path": path, "kind": kind} for path, kind in paths.items()]}
        builds = {audit.hash_file(path)["sha256"]: args.version for path in paths}
        if args.replacement:
            builds[audit.hash_file(args.replacement)["sha256"]] = "8.3.36"
        proof = {"schema": 1, "builds": [{"sha256": digest, "php_version": version, "source": args.source}
                                        for digest, version in builds.items()]}
        deadline = time.monotonic() + 15
        while True:
            assert all(process.poll() is None for process in processes), "PHP fixture exited"
            runs, issues = audit.discover(config)
            selected = [run for run in runs if run.path in paths]
            ready = set(paths) <= {run.path for run in selected}
            if args.sapi == "fpm":
                ready = ready and sum(run.kind == "fpm" for run in selected) >= 5
            if ready:
                break
            assert time.monotonic() < deadline, (paths, selected, issues)
            time.sleep(0.1)
        files = audit.audit_local(config, proof, files=True)
        assert files["verdict"] == expected, files
        records = [audit.inspect_runtime(run, None, proof) for run in selected]
        if sys.platform == "win32":
            assert all(row["status"] == "UNKNOWN" and row["file_status"] == expected for row in records), records
        else:
            assert all(row["status"] == expected for row in records), records
        unknown = audit.audit_local(config, {"schema": 1}, files=True)
        assert unknown["verdict"] == "UNKNOWN", unknown
        if sys.platform.startswith("linux"):
            report = audit.audit_local(config, proof)
            assert report["verdict"] == expected and not report["issues"], report
            missing = dict(config, runtimes=config["runtimes"] + [{"label": "inactive", "kind": "php", "path": "/absent/php"}])
            assert any(d["code"] == "EXPECTED_RUNTIME_MISSING"
                       for d in audit.audit_local(missing, proof)["diagnostics"])
        reuse = None
        if args.sapi == "fpm":
            archive = root / "php.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                tar.add("/usr/local/sbin/php-fpm", arcname="php/bin/php-fpm")
            package = {"manager": "homebrew", "package": "fixture/php", "version": args.version,
                       "archive_member": "php/bin/php-fpm"}
            archive_proof = {"schema": 1, "package_archives": [{
                "manager": package["manager"], "package": package["package"], "version": args.version,
                "path": str(archive), "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                "php_version": args.version, "source": "archive benchmark of the trusted container fixture"}]}
            workers = sum(run.kind == "fpm" for run in selected)
            reuse = {"workers": workers}
            for label, cache in (("uncached", None), ("cached", {})):
                start = time.monotonic()
                with patch.object(audit, "hash_stream", wraps=audit.hash_stream) as hashing:
                    results = [audit.package_archive_digest(package, archive_proof, cache)[0] for _ in range(workers)]
                    reuse[label + "_hashes"] = hashing.call_count
                reuse[label + "_seconds"] = round(time.monotonic() - start, 4)
                assert set(results) == {audit.hash_file("/usr/local/sbin/php-fpm")["sha256"]}
            assert reuse["uncached_hashes"] == workers and reuse["cached_hashes"] == 1, reuse
        stale_checked = False
        if sys.platform != "win32":
            old = next(run for run in selected if run.path == str(second))
            replacement = root / "replacement"
            shutil.copy2(args.replacement or php, replacement)
            replacement.replace(second)
            stale = audit.inspect_runtime(old, None, proof)
            assert stale["restart_needed"], stale
            assert audit.finish([stale], [])["exit_status"] != 0, stale
            if sys.platform.startswith("linux"):
                assert stale["status"] == expected, stale
            else:
                assert stale["status"] == "UNKNOWN", stale
            if args.replacement:
                installed = audit.inspect_file({"path": str(second), "kind": "php"}, None, proof)
                assert installed["status"] == "PATCHED", installed
            stale_checked = True
        print(json.dumps({"platform": sys.platform, "php_version": actual, "sapi": args.sapi,
                          "expected_status": expected, "runtime_records": len(records),
                          "loaded_image_verified": sys.platform != "win32", "stale_worker_checked": stale_checked,
                          "archive_reuse": reuse, "discovery_issues": issues, "source": args.source}))


if __name__ == "__main__":
    main()
