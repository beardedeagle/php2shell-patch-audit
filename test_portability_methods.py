"""Offline regressions for platform boundaries and supplementary observations."""
import base64
import contextlib
import gzip
import hashlib
import io
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from test_php2shell_audit import audit, EMPTY, runtime


def inventory(path, kind="php"):
    return {"schema": 1, "scope": "test files", "coverage_confirmed": True,
            "runtimes": [{"label": "test", "kind": kind, "path": str(path)}]}


def evidence(data=b"test", version="8.3.36"):
    return {"schema": 1, "builds": [{"sha256": hashlib.sha256(data).hexdigest(),
                                    "php_version": version, "source": "synthetic test build"}]}


class DistributionTests(unittest.TestCase):
    def test_debian_baselines_do_not_leak_to_derivatives(self):
        package = {"manager": "dpkg", "package": "php8.2-fpm"}
        self.assertEqual(audit.fixed_rule(package, ("debian", "12"), EMPTY)["fixed_version"], "8.2.35-1~deb12u1")
        for distro in (("raspbian", "12"), ("ubuntu", "12"), ("debian", "13")):
            with self.assertRaises(audit.AuditError):
                audit.fixed_rule(package, distro, EMPTY)

    def test_rhel_baseline_requires_vendor_release_and_stream(self):
        package = {"manager": "rpm", "package": "php-fpm", "version": "0:7.4.33-7.el8",
                   "vendor": "Red Hat, Inc.", "module": "php:7.4:123:context"}
        self.assertIn("7.4.33-8.module", audit.fixed_rule(package, ("rhel", "8.10"), EMPTY)["fixed_version"])
        for changed, distro in ((dict(package, vendor="Rocky"), ("rhel", "8.10")),
                                (dict(package, module="php:8.0:123:context"), ("rhel", "8.10")),
                                (package, ("almalinux", "8.10")), (package, ("rhel", "8.9"))):
            with self.assertRaises(audit.AuditError):
                audit.fixed_rule(changed, distro, EMPTY)

    def test_rolling_distribution_can_be_identified(self):
        with patch.object(Path, "is_file", return_value=True), patch.object(Path, "read_text", return_value='ID=arch\nNAME="Arch Linux"\n'):
            self.assertEqual(audit.os_release(), ("arch", "rolling"))

    def test_any_distribution_can_use_hash_bound_backport_evidence(self):
        build = evidence(version="7.4.33")
        build["builds"][0]["fixed_cves"] = list(audit.CVES)
        audit.validate_config(None, build)
        record = {"path": "/custom/php"}
        with patch.object(audit, "package_metadata", side_effect=AssertionError("No package lookup")):
            audit.assess_file(record, {"sha256": hashlib.sha256(b"test").hexdigest()}, ("gentoo", "rolling"), build)
        self.assertEqual(record["status"], "PATCHED")
        build["builds"][0]["fixed_cves"].pop()
        with self.assertRaises(audit.AuditError):
            audit.validate_config(None, build)

    def test_alpine_checksum_is_file_specific(self):
        checksum = "Q1" + base64.b64encode(bytes.fromhex("ab" * 20)).decode()
        database = f"P:php83\nV:8.3.36-r0\nF:usr/bin\nR:php83-other\nZ:{checksum}\nR:php83\nZ:{checksum}\n"
        with patch.object(Path, "read_text", return_value=database):
            result = audit.apk_metadata("/usr/bin/php83")
            self.assertEqual(result["digest"], "ab" * 20)
            self.assertEqual(result["version"], "8.3.36-r0")
            with self.assertRaises(audit.AuditError):
                audit.apk_metadata("/usr/bin/php8")
        with patch.object(Path, "read_text", return_value=database.replace("Q1", "Q9")):
            with self.assertRaises(audit.AuditError):
                audit.apk_metadata("/usr/bin/php83")

    def test_pacman_uses_owned_package_mtree_digest(self):
        replies = [subprocess.CompletedProcess([], 0, "php\n", ""),
                   subprocess.CompletedProcess([], 0, "php 8.4.27-1\n", "")]
        mtree = "#mtree\n/set type=file\n./usr/bin/php type=file sha256digest=" + "a" * 64 + "\n"
        with patch.object(audit, "system_tool", return_value="/usr/bin/pacman"), \
                patch.object(audit, "command", side_effect=replies), \
                patch.object(gzip, "open", return_value=io.StringIO(mtree)):
            self.assertEqual(audit.pacman_metadata("/usr/bin/php")["digest"], "a" * 64)

    def test_alpine_arch_use_native_ordering_and_fail_on_errors(self):
        for manager, output in (("apk", "<"), ("pacman", "-7")):
            with patch.object(audit, "system_tool", return_value="/native"), \
                    patch.object(audit, "command", return_value=subprocess.CompletedProcess([], 0, output, "")):
                self.assertEqual(audit.package_status({"manager": manager, "version": "8.3.35-r1"}, "8.3.36-r0"), "AFFECTED")
            with patch.object(audit, "system_tool", return_value="/native"), \
                    patch.object(audit, "command", return_value=subprocess.CompletedProcess([], 1, "", "failed")):
                with self.assertRaises(audit.AuditError):
                    audit.package_status({"manager": manager, "version": "8.3.36-r0"}, "8.3.36-r0")

    def test_unknown_package_manager_does_not_fall_through_to_rpm(self):
        with patch.object(audit.sys, "platform", "linux"), patch.object(Path, "is_file", return_value=False), \
                patch.object(Path, "is_dir", return_value=False), patch.object(audit, "rpm_metadata", side_effect=AssertionError):
            with self.assertRaisesRegex(audit.AuditError, "build evidence"):
                audit.package_metadata("/custom/php")

    def test_missing_rpm_module_tag_does_not_mean_nonmodular(self):
        replies = [subprocess.CompletedProcess([], 0, "php-fpm\t0\t8.0.30\t8.el9_8.1\t8\n", ""),
                   subprocess.CompletedProcess([], 0, "/usr/sbin/php-fpm\t" + "b" * 64 + "\n", ""),
                   subprocess.CompletedProcess([], 0, "x86_64\tRed Hat, Inc.\n", ""),
                   subprocess.CompletedProcess([], 1, "", "unknown tag")]
        with patch.object(audit, "system_tool", return_value="/usr/bin/rpm"), \
                patch.object(audit, "command", side_effect=replies):
            package = audit.rpm_metadata("/usr/sbin/php-fpm")
        self.assertIsNone(package["module"])
        with self.assertRaises(audit.AuditError):
            audit.fixed_rule(package, ("rhel", "9.8"), EMPTY)


class FileAndWindowsTests(unittest.TestCase):
    def test_file_hash_uses_consistent_handle_metadata_but_rejects_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "php"
            path.write_bytes(b"test")
            with path.open("rb") as stream:
                info = audit.os.fstat(stream.fileno())
            fields = {key: getattr(info, key) for key in (
                "st_mode", "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")}
            # Python on Windows can expose creation time via stat and change time via fstat.
            with patch.object(audit.os, "stat", return_value=SimpleNamespace(**dict(fields, st_ctime_ns=0))):
                self.assertEqual(audit.hash_file(str(path))["sha256"], hashlib.sha256(b"test").hexdigest())
            replacement = SimpleNamespace(**dict(fields, st_ino=info.st_ino + 1))
            with patch.object(audit.os, "fstat", side_effect=[info, info, replacement]), \
                    self.assertRaisesRegex(audit.AuditError, "pathname changed"):
                audit.hash_file(str(path))

    def test_file_audit_is_explicitly_scoped_and_never_executes_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "php"
            path.write_bytes(b"test")
            with patch.object(audit, "discover", side_effect=AssertionError), patch.object(audit, "command", side_effect=AssertionError):
                result = audit.audit_local(inventory(path), evidence(), files=True)
            self.assertEqual(result["exit_status"], 0)
            self.assertEqual(result["assessment_scope"], "installed-files-only")
            path.unlink()
            self.assertEqual(audit.audit_local(inventory(path), evidence(), files=True)["exit_status"], 2)

    def test_windows_paths_casefold_and_reject_ambiguous_paths(self):
        audit.validate_config(inventory(r"C:\PHP\php.exe"), EMPTY)
        self.assertEqual(audit.path_key(r"C:\PHP\php.exe"), audit.path_key("c:/php/PHP.EXE"))
        for path in (r"C:php.exe", r"\\server\share\php.exe", r"C:\php.exe:stream", "/tmp/php\n"):
            with self.subTest(path=path), self.assertRaises(audit.AuditError):
                audit.validate_config(inventory(path), EMPTY)

    def test_windows_discovers_cgi_and_engine_dll_and_preserves_errors(self):
        snapshot = {"processes": [{"pid": 99, "path": r"C:\PHP\php-cgi.exe", "start": "123",
                                  "modules": [{"path": r"C:\PHP\php8.dll"}]}], "issues": ["PID 100: access denied"]}
        with patch.object(audit.sys, "platform", "win32"), patch.object(audit, "powershell_json", return_value=snapshot):
            runs, issues = audit.discover(None)
        self.assertEqual({r.kind for r in runs}, {"cgi", "mod_php"})
        self.assertEqual(issues, snapshot["issues"])

    def test_windows_disk_evidence_cannot_clear_a_running_process(self):
        with patch.object(audit.sys, "platform", "win32"), patch.object(audit, "hash_file", return_value={"sha256": hashlib.sha256(b"test").hexdigest()}):
            result = audit.inspect_runtime(runtime(path=r"C:\PHP\php.exe"), None, evidence())
        self.assertEqual(result["file_status"], "PATCHED")
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(result["pid"], 101)

    def test_windows_version_resource_is_only_a_hint(self):
        with patch.object(audit.sys, "platform", "win32"), patch.object(audit, "hash_file", return_value={"sha256": "a" * 64}), \
                patch.object(audit, "powershell_json", return_value={"product_version": "8.3.36"}):
            result = audit.inspect_file({"kind": "php", "path": r"C:\PHP\php.exe"}, None, EMPTY)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(result["version_hint"]["product_version"], "8.3.36")

    def test_remote_file_protocol_runs_real_serialized_program(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "php"
            path.write_bytes(b"test")
            def transport(argv, timeout, data):
                return subprocess.run([sys.executable, "-"], input=data, text=True, capture_output=True, timeout=timeout)
            with patch.object(audit, "command", side_effect=transport), patch.object(audit, "system_tool", return_value="/usr/bin/ssh"):
                result = audit.audit_ssh("test.invalid", False, inventory(path), evidence(), files=True)
            self.assertEqual(result["exit_status"], 0, result)
            self.assertEqual(result["assessment_scope"], "installed-files-only")

    def test_windows_remote_path_is_encoded_as_data(self):
        path = "C:\\Python's folder\\python.exe"
        with patch.object(audit, "system_tool", return_value="/usr/bin/ssh"), \
                patch.object(audit, "run_remote", return_value={}) as remote:
            audit.audit_ssh("host", False, None, EMPTY, remote_os="windows", python=path)
        command = remote.call_args.args[0][-1]
        script = base64.b64decode(command.split()[-1]).decode("utf-16le")
        self.assertIn("Python''s folder", script)
        with self.assertRaises(audit.AuditError):
            audit.audit_ssh("host", True, None, EMPTY, remote_os="windows", python=path)

    def test_container_audit_executes_python_without_installing_or_running_php(self):
        with patch.object(audit, "system_tool", return_value="/usr/bin/docker"), patch.object(audit, "run_remote", return_value={}) as remote:
            audit.audit_container("php-app", "docker", None, EMPTY)
        self.assertEqual(remote.call_args.args[0], ["/usr/bin/docker", "exec", "-i", "php-app", "/usr/bin/python3", "-"])
        with self.assertRaises(audit.AuditError):
            audit.audit_container("--privileged", "docker", None, EMPTY)


class UpdateinfoTests(unittest.TestCase):
    def xml(self, second=True):
        refs = ''.join('<reference type="cve" id="' + cve + '"/>' for cve in audit.CVES[:2 if second else 1])
        return '<updates><update><id>TEST-1</id><references>' + refs + '</references><pkglist><collection><package name="php-fpm" version="8.3.36" release="1.el9" epoch="0" arch="x86_64"/></collection></pkglist></update></updates>'

    def test_updateinfo_exact_os_arch_branch_and_both_cves(self):
        package = {"manager": "rpm", "package": "php-fpm", "arch": "x86_64", "module": "", "version": "0:8.3.35-1.el9"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "updateinfo.xml.gz"
            with gzip.open(path, "wt") as stream:
                stream.write(self.xml())
            records = audit.load_updateinfo(path, ("rocky", "9.6"))
            bundle = {"schema": 1, "rpm_advisories": records}
            with patch.object(audit, "package_status", return_value="PATCHED"):
                rule = audit.fixed_rule(package, ("rocky", "9.6"), bundle)
                self.assertEqual(rule["fixed_version"], "0:8.3.36-1.el9")
                for changed, distro in ((package, ("alma", "9.6")), (dict(package, arch="aarch64"), ("rocky", "9.6")),
                                       (dict(package, version="0:8.2.1-1.el9"), ("rocky", "9.6")),
                                       (dict(package, module="php:8.3:123:ctx"), ("rocky", "9.6"))):
                    with self.assertRaises(audit.AuditError):
                        audit.fixed_rule(changed, distro, bundle)
                records[0]["cves"] = [audit.CVES[0]]
                with self.assertRaises(audit.AuditError):
                    audit.fixed_rule(package, ("rocky", "9.6"), bundle)

    def test_xml_entities_are_not_expanded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "updateinfo.xml"
            path.write_text('<!DOCTYPE updates [<!ENTITY e "bad">]><updates/>')
            with self.assertRaisesRegex(audit.AuditError, "declarations"):
                audit.load_updateinfo(path, ("rhel", "9.6"))

    def test_separate_advisories_require_the_later_of_both_fix_thresholds(self):
        package = {"manager": "rpm", "package": "php-fpm", "arch": "x86_64",
                   "module": "php:8.3:20261022:ctx", "version": "0:8.3.36-2.el9"}
        records = [dict(os_id="rocky", os_version="9.6", package="php-fpm", arch="x86_64",
                        module="php:8.3:ctx", version=f"0:8.3.36-{release}.el9",
                        cves=[cve], source=f"fixture-{release}")
                   for release, cve in ((2, audit.CVES[0]), (5, audit.CVES[0]), (3, audit.CVES[1]))]
        def compare(row, fixed):
            return "PATCHED" if row["version"] >= fixed else "AFFECTED"
        with patch.object(audit, "package_status", side_effect=compare):
            rule = audit.updateinfo_rule(package, ("rocky", "9.6"), {"rpm_advisories": records})
            self.assertEqual(rule["fixed_version"], "0:8.3.36-3.el9")
            self.assertIsNone(audit.updateinfo_rule(dict(package, module="php:8.3:20261022:other"),
                                                  ("rocky", "9.6"), {"rpm_advisories": records}))

    def test_damaged_gzip_returns_unknown_without_starting_discovery(self):
        compressed = gzip.compress(self.xml().encode())
        for data in (compressed[:-5], compressed[:10] + b"\x07" + compressed[11:]):
            with self.subTest(data_length=len(data)), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "updateinfo.xml.gz"
                path.write_bytes(data)
                output = io.StringIO()
                with contextlib.redirect_stdout(output), patch.object(audit, "discover", side_effect=AssertionError):
                    status = audit.main(["--updateinfo", str(path), "--updateinfo-os", "rocky:9.6", "--json"])
                self.assertEqual(status, 2)
                self.assertEqual(json.loads(output.getvalue())["reports"][0]["verdict"], "UNKNOWN")


class CliScopeTests(unittest.TestCase):
    def test_files_plus_http_still_checks_the_inventory_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "php"
            path.write_bytes(b"test")
            inv = Path(directory) / "inventory.json"
            inv.write_text(json.dumps(inventory(path)))
            builds = Path(directory) / "builds.json"
            builds.write_text(json.dumps(evidence()))
            output = io.StringIO()
            with contextlib.redirect_stdout(output), patch.object(audit, "audit_http", return_value=audit.finish([], [], "http")):
                status = audit.main(["--files", "--inventory", str(inv), "--evidence", str(builds),
                                     "--http", "example.invalid", "--json"])
            reports = json.loads(output.getvalue())["reports"]
            self.assertEqual(status, 2)
            self.assertEqual(len(reports), 2)
            self.assertEqual(reports[1]["exit_status"], 0)
            self.assertEqual(reports[1]["assessment_scope"], "installed-files-only")

    def test_targets_file_ignores_comments_and_never_starts_local_discovery(self):
        with tempfile.TemporaryDirectory() as directory:
            targets = Path(directory) / "targets.txt"
            targets.write_text("# comment\n\nexample.invalid\nhttps://example.invalid/info.php\n")
            with contextlib.redirect_stdout(io.StringIO()), \
                    patch.object(audit, "audit_http", return_value=audit.finish([], [], "http")) as http, \
                    patch.object(audit, "discover", side_effect=AssertionError):
                self.assertEqual(audit.main(["--targets-file", str(targets), "--json"]), 2)
            self.assertEqual([call.args[0] for call in http.call_args_list],
                             ["example.invalid", "https://example.invalid/info.php"])


class HttpMethodTests(unittest.TestCase):
    @contextlib.contextmanager
    def server(self, mode):
        calls = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_HEAD(self):
                calls.append(("HEAD", b""))
                self.send_response(405)
                self.end_headers()
            def do_GET(self):
                calls.append(("GET", b""))
                self.send_response(403 if mode == "denied" else 200)
                self.send_header("X-Powered-By", "PHP/8.3.36")
                self.send_header("Set-Cookie", "PHPSESSID=secret-cookie")
                self.end_headers()
                self.wfile.write(b'<h1>PHP Version 8.3.36</h1><table><tr><td>memory_limit</td><td>128M</td><td>256M</td></tr><tr><td>PASSWORD</td><td>secret-env</td></tr></table>MULTIPART_REACHED_PHP')
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                calls.append(("POST", body))
                self.send_response(403)
                self.end_headers()
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            yield "http://127.0.0.1:" + str(server.server_port), calls
        finally:
            server.shutdown()
            server.server_close()
            worker.join()

    def test_head_fallback_is_bounded_and_never_patch_clearance(self):
        with self.server("ok") as (url, calls):
            result = audit.audit_http(url)
        self.assertEqual([c[0] for c in calls], ["HEAD", "GET"])
        self.assertEqual(result["verdict"], "UNKNOWN")
        self.assertEqual(result["reported_versions"], ["8.3.36"])
        self.assertNotIn("secret-cookie", json.dumps(result))

    def test_selected_phpinfo_fields_preserve_local_master_without_secrets(self):
        with self.server("ok") as (url, calls):
            result = audit.audit_http(url, details=True)
        self.assertEqual(result["phpinfo_settings"]["memory_limit"], ["128M", "256M"])
        self.assertNotIn("secret-env", json.dumps(result))
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["exit_status"], 2)

    def test_multipart_block_requires_successful_marker_control(self):
        for mode, expected in (("ok", "blocked_for_this_request"), ("denied", "unknown")):
            with self.server(mode) as (url, calls):
                result = audit.audit_http(url, multipart=True)
            self.assertEqual(result["multipart"]["observation"], expected)
            self.assertEqual([c[0] for c in calls], ["GET", "POST"])
            self.assertLess(len(calls[-1][1]), 512)
            self.assertNotIn(b"PHP_SESSION_UPLOAD_PROGRESS", calls[-1][1])
            self.assertEqual(result["exit_status"], 2)

    def test_body_versions_require_php_marker_and_preserve_unknown_patch(self):
        details = audit.http_details("WordPress 6.8.11 PHP/8.4 PHP/8.3.36RC1")
        self.assertEqual(details["body_versions"], ["8.4", "8.3.36RC1"])
        self.assertTrue(all(audit.upstream_status(v) == "UNKNOWN" for v in details["body_versions"]))


class SupplementaryEvidenceTests(unittest.TestCase):
    def test_log_limits_preserve_counts_and_report_incomplete_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "error.log"
            path.write_text("zend_mm_heap corrupted\n" * 102)
            result = audit.audit_logs(path)
            self.assertEqual(result["counts"]["heap_corruption"], 102)
            self.assertEqual(len(result["observations"]), 100)
            path.write_bytes(b"secret " + b"x" * audit.MAX_CONFIG)
            result = audit.audit_logs(path)
            self.assertEqual(result["exit_status"], 2)
            self.assertTrue(any("line limit" in issue for issue in result["issues"]))
            self.assertNotIn("secret", json.dumps(result))

    def test_log_signals_never_prove_compromise_or_patch(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "error.log"
            path.write_text("Allowed memory size of 123 bytes exhausted secret\nzend_mm_heap corrupted\n")
            result = audit.audit_logs(path)
        self.assertEqual(result["counts"], {"memory_exhaustion": 1, "heap_corruption": 1})
        self.assertNotIn("secret", json.dumps(result))
        self.assertEqual(result["verdict"], "UNKNOWN")

    def test_process_events_deduplicate_detect_gaps_and_omit_argv(self):
        event = {"schema_version": 1, "event_id": "one", "agent_instance_id": "agent", "sequence": 1,
                 "event_type": "process.exec", "root": {"image": "php-fpm8.3"},
                 "process": {"image": "bash", "argv": ["credential"]},
                 "lineage": {"role": "descendant", "complete": True}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text('\n'.join(json.dumps(row) for row in (event, event, dict(event, event_id="two", sequence=3))))
            result = audit.audit_logs(path, events=True)
        self.assertEqual(result["counts"], {"php_descendant_exec": 2, "observation_gap": 1})
        self.assertTrue(result["observations"][0]["review_required"])
        self.assertNotIn("credential", json.dumps(result))
        self.assertEqual(result["exit_status"], 2)

    def test_trusted_binary_probe_is_explicit_and_only_a_hint(self):
        with patch.object(audit, "hash_file", return_value={"sha256": "a" * 64}), \
                patch.object(audit, "command", return_value=subprocess.CompletedProcess([], 0, "PHP 8.3.36 (cli)", "")) as run:
            result = audit.audit_probe("/trusted/php")
        self.assertEqual(run.call_args.args[0], ["/trusted/php", "-n", "-v"])
        self.assertEqual(result["version_hints"][0]["upstream_comparison"], "PATCHED")
        self.assertEqual(result["exit_status"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
