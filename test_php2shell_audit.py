"""Offline regressions: no PHP binaries, network requests, or SSH connections."""
import contextlib
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("audit", Path(__file__).with_name("php2shell-audit.py"))
audit = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = audit
spec.loader.exec_module(audit)

EMPTY = {"schema": 1}
INVENTORY = {"schema": 1, "scope": "test namespace", "coverage_confirmed": True,
             "runtimes": [{"label": "web", "kind": "fpm", "path": "/usr/sbin/php-fpm8.3"}]}


def row(status="PATCHED", restart=False, path="/usr/sbin/php-fpm8.3", kind="fpm", pid=101):
    return {"status": status, "restart_needed": restart, "path": path, "kind": kind, "pid": pid}


def runtime(pid=101, kind="fpm", path="/usr/sbin/php-fpm8.3", deleted=False):
    return audit.Runtime(pid, kind, path, f"/proc/{pid}/exe", "100", deleted)


class VerdictTests(unittest.TestCase):
    def test_patched_plus_unknown_is_unknown(self):
        self.assertEqual(audit.finish([row(), row("UNKNOWN")], [])["exit_status"], 2)

    def test_affected_wins_but_unknown_evidence_is_retained(self):
        result = audit.finish([row("AFFECTED"), row("UNKNOWN")], ["incomplete"])
        self.assertEqual(result["exit_status"], 1)
        self.assertEqual(result["issues"], ["incomplete"])

    def test_restart_is_separate_from_vulnerability(self):
        result = audit.finish([row(restart=True)], [])
        self.assertEqual(result["exit_status"], 2)
        self.assertEqual(result["runtimes"][0]["status"], "PATCHED")

    def test_no_runtimes_or_discovery_failure_never_clears(self):
        self.assertEqual(audit.finish([], [])["exit_status"], 2)
        self.assertEqual(audit.finish([row()], ["permission denied"])["exit_status"], 2)

    def test_verified_inventory_and_patched_runtime_can_clear(self):
        with patch.object(audit, "discover", return_value=([runtime()], [])), \
                patch.object(audit, "inspect_runtime", return_value=row()), \
                patch.object(audit, "os_release", return_value=("ubuntu", "24.04")):
            self.assertEqual(audit.audit_local(INVENTORY, EMPTY)["exit_status"], 0)
            self.assertEqual(audit.audit_local(None, EMPTY)["exit_status"], 2)

    def test_missing_expected_runtime_blocks_clearance(self):
        with patch.object(audit, "discover", return_value=([runtime(path="/different")], [])), \
                patch.object(audit, "inspect_runtime", return_value=row(path="/different")), \
                patch.object(audit, "os_release", return_value=("ubuntu", "24.04")):
            result = audit.audit_local(INVENTORY, EMPTY)
        self.assertEqual(result["exit_status"], 2)
        self.assertEqual(len(result["issues"]), 2)

    def test_discovery_exception_is_unknown(self):
        with patch.object(audit, "discover", side_effect=audit.AuditError("cannot enumerate")):
            self.assertEqual(audit.audit_local(INVENTORY, EMPTY)["exit_status"], 2)

    def test_later_bad_target_does_not_discard_an_affected_host(self):
        output = io.StringIO()
        with patch.object(audit, "audit_ssh", side_effect=[audit.finish([row("AFFECTED")], []),
                                                         audit.AuditError("Invalid destination")]), \
                contextlib.redirect_stdout(output):
            status = audit.main(["--ssh", "host1", "--ssh", "host2", "--json"])
        self.assertEqual(status, 1)
        self.assertEqual(len(json.loads(output.getvalue())["reports"]), 2)


class VersionTests(unittest.TestCase):
    def test_all_four_upstream_boundaries(self):
        for (major, minor), fixed in audit.BASELINES.items():
            with self.subTest(minor=minor):
                self.assertEqual(audit.upstream_status(f"{major}.{minor}.{fixed-1}"), "AFFECTED")
                self.assertEqual(audit.upstream_status(f"{major}.{minor}.{fixed}"), "PATCHED")

    def test_unverified_versions_are_unknown(self):
        for version in ("8.3.36RC1", "8.6.0-dev", "8.6.0", "9.0.0", "8.3", "8.03.36",
                        "8.1.2", "", "8.3.36-vendor", "8.3.36\n"):
            with self.subTest(version=version):
                self.assertEqual(audit.upstream_status(version), "UNKNOWN")

    def test_ubuntu_backport_uses_full_vendor_version(self):
        package = {"manager": "dpkg", "package": "php8.3-fpm", "version": "8.3.6-0ubuntu0.24.04.13"}
        rule = audit.fixed_rule(package, ("ubuntu", "24.04"), EMPTY)
        self.assertEqual(rule["fixed_version"], package["version"])
        with patch.object(audit, "system_tool", return_value="/usr/bin/dpkg"), \
                patch.object(audit, "command", return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            self.assertEqual(audit.package_status(package, rule["fixed_version"]), "PATCHED")
        self.assertEqual(run.call_args.args[0], ["/usr/bin/dpkg", "--compare-versions",
                                               package["version"], "ge", rule["fixed_version"]])

    def test_ubuntu_older_branch_backport(self):
        package = {"manager": "dpkg", "package": "libapache2-mod-php8.1"}
        self.assertEqual(audit.fixed_rule(package, ("ubuntu", "22.04"), EMPTY)["fixed_version"],
                         "8.1.2-1ubuntu2.28")

    def test_unknown_vendor_requires_evidence(self):
        with self.assertRaises(audit.AuditError):
            audit.fixed_rule({"manager": "rpm", "package": "php-fpm"}, ("rhel", "9.6"), EMPTY)

    def test_rpm_native_comparison_and_macro_injection_rejection(self):
        package = {"manager": "rpm", "version": "0:8.3.6-2.el9"}
        with patch.object(audit, "system_tool", return_value="/usr/bin/rpm"), \
                patch.object(audit, "command", return_value=subprocess.CompletedProcess([], 0, "-1\n", "")):
            self.assertEqual(audit.package_status(package, "0:8.3.6-3.el9"), "AFFECTED")
        with self.assertRaises(audit.AuditError):
            audit.package_status(package, '%{lua:os.execute("bad")}')


class IdentityTests(unittest.TestCase):
    def setUp(self):
        platform = patch.object(audit.sys, "platform", "linux")
        platform.start()
        self.addCleanup(platform.stop)

    def test_supported_executables(self):
        for filename, kind in (("php-fpm8.3", "fpm"), ("php-cgi8.3", "cgi"),
                               ("lsphp83", "lsphp"), ("frankenphp", "frankenphp"),
                               ("php8.3", "php"), ("caddy", "embedded")):
            self.assertEqual(audit.executable_kind("/usr/bin/" + filename), kind)

    def test_deleted_and_escaped_paths(self):
        self.assertEqual(audit.proc_path(r"/usr/bin/php\040test (deleted)"), ("/usr/bin/php test", True))

    def test_all_litespeed_processes_and_apache_alongside_fpm_are_inspected(self):
        runs = [runtime(), runtime(102, "lsphp", "/a/lsphp"),
                runtime(103, "lsphp", "/b/lsphp", True),
                runtime(104, "mod_php", "/usr/lib/apache2/libphp.so")]
        with patch.object(audit, "discover", return_value=(runs, [])), \
                patch.object(audit, "os_release", return_value=("ubuntu", "24.04")), \
                patch.object(audit, "inspect_runtime", side_effect=lambda r, *_: row(pid=r.pid, kind=r.kind, path=r.path)) as inspect:
            audit.audit_local(None, EMPTY)
        self.assertEqual(inspect.call_count, 4)

    def test_checksum_mismatch_does_not_inherit_installed_package_status(self):
        with patch.object(audit, "hash_runtime", return_value=({"sha256": "a"*64, "md5": "a"*32}, True)), \
                patch.object(audit, "package_metadata", return_value={"package": "php8.3-fpm", "version": "fixed",
                                                                      "algorithm": "md5", "digest": "b"*32}):
            result = audit.inspect_runtime(runtime(), ("ubuntu", "24.04"), EMPTY)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertTrue(result["restart_needed"])

    def test_hash_matched_custom_build_requires_supported_stable_version(self):
        for version, expected in (("8.3.36", "PATCHED"), ("8.3.35", "AFFECTED"), ("8.3.36RC1", "UNKNOWN")):
            evidence = {"schema": 1, "builds": [{"sha256": "a"*64, "php_version": version, "source": "CI record"}]}
            with patch.object(audit, "hash_runtime", return_value=({"sha256": "a"*64}, False)), \
                    patch.object(audit, "command", side_effect=AssertionError("Must not execute anything")):
                self.assertEqual(audit.inspect_runtime(runtime(), None, evidence)["status"], expected)

    def test_running_file_is_read_not_executed(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "php-fpm"
            binary.write_bytes(b"#!/bin/sh\nexit 99\n")
            binary.chmod(0o755)
            instance = audit.Runtime(1, "fpm", str(binary), str(binary), "100")
            with patch.object(audit, "start_time", return_value="100"), \
                    patch.object(audit, "command", side_effect=AssertionError("Binary execution forbidden")):
                hashes, restart = audit.hash_runtime(instance)
            self.assertEqual(hashes["sha256"], hashlib.sha256(binary.read_bytes()).hexdigest())
            self.assertFalse(restart)

    def test_replaced_litespeed_image_keeps_restart_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            live, disk = Path(directory)/"old", Path(directory)/"new"
            live.write_bytes(b"old")
            disk.write_bytes(b"new")
            instance = audit.Runtime(1, "lsphp", str(disk), str(live), "100")
            with patch.object(audit, "start_time", return_value="100"):
                _, restart = audit.hash_runtime(instance)
            self.assertTrue(restart)

    def test_pid_reuse_rejects_evidence(self):
        with patch.object(audit, "start_time", return_value="200"), self.assertRaises(audit.AuditError):
            audit.hash_runtime(runtime())

    def test_module_path_fallback_requires_exact_inode(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory)/"libphp.so"
            binary.write_bytes(b"new module")
            instance = audit.Runtime(1, "mod_php", str(binary), "/does-not-exist", "100", False, 0, 0)
            with patch.object(audit, "start_time", return_value="100"), \
                    self.assertRaisesRegex(audit.AuditError, "mapping"):
                audit.hash_runtime(instance)


class DiscoveryTests(unittest.TestCase):
    def simulate(self, foreign=False, denied=False):
        def read_text(path, *args, **kwargs):
            if path.name == "maps":
                if denied:
                    raise PermissionError()
                return "1000-2000 r-xp 0 08:01 88 /usr/lib/libphp8.3.so\n"
            raise AssertionError(str(path))
        with patch.object(audit.sys, "platform", "linux"), \
                patch.object(Path, "iterdir", return_value=iter([Path("/proc/101"), Path("/proc/102")])), \
                patch.object(audit, "start_time", return_value="100"), \
                patch.object(audit.os, "readlink", return_value="/usr/sbin/php-fpm8.3"), \
                patch.object(audit.os, "makedev", return_value=2049, create=True), \
                patch.object(Path, "read_text", read_text), \
                patch.object(audit, "same_namespace", return_value=not foreign):
            return audit.discover(None)

    def test_discovery_collects_all_processes_and_modules(self):
        runs, issues = self.simulate()
        self.assertEqual(len(runs), 4)
        self.assertEqual(issues, [])
        self.assertEqual({r.kind for r in runs}, {"fpm", "mod_php"})

    def test_foreign_namespace_is_unknown_not_host_binary(self):
        runs, issues = self.simulate(foreign=True)
        self.assertEqual(runs, [])
        self.assertEqual(len(issues), 2)

    def test_unreadable_process_maps_is_coverage_failure(self):
        runs, issues = self.simulate(denied=True)
        self.assertEqual(runs, [])
        self.assertEqual(len(issues), 2)


class HttpTests(unittest.TestCase):
    def test_redirects_are_never_followed(self):
        self.assertIsNone(audit.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.invalid"))

    def test_banner_is_only_hint_and_suffix_survives(self):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.code = 302
        response.headers.get_all.side_effect = lambda name, default: {
            "X-Powered-By": ["PHP/8.3.36RC1"], "Location": ["https://other.invalid"]}.get(name, default)
        opener = Mock()
        opener.open.return_value = response
        with patch.object(audit.urllib.request, "build_opener", return_value=opener):
            result = audit.audit_http("https://example.invalid")
        self.assertEqual(result["exit_status"], 2)
        self.assertEqual(result["reported_versions"], ["8.3.36RC1"])
        self.assertEqual(opener.open.call_count, 1)

    def test_network_failure_stays_unknown(self):
        with patch.object(audit.urllib.request, "build_opener") as builder:
            builder.return_value.open.side_effect = OSError("no connection")
            self.assertEqual(audit.audit_http("example.invalid")["exit_status"], 2)

    def test_non_http_and_credential_urls_rejected(self):
        for target in ("file:///etc/passwd", "https://user:password@example.invalid"):
            with self.assertRaises(audit.AuditError):
                audit.audit_http(target)


class SshTests(unittest.TestCase):
    def test_setup_exit_one_is_unknown(self):
        with patch.object(audit, "system_tool", return_value="/usr/bin/ssh"), \
                patch.object(audit, "command", return_value=subprocess.CompletedProcess([], 1, "", "sudo denied")) as run:
            result = audit.audit_ssh("user@example.invalid", True, INVENTORY, EMPTY)
        self.assertEqual(result["exit_status"], 2)
        self.assertEqual(run.call_args.args[0][-1], "/usr/bin/sudo -n -- /usr/bin/python3 -")

    def test_protocol_requires_token_completion_and_consistent_status(self):
        result = audit.finish([row()], [])
        result["token"] = "nonce"
        self.assertTrue(audit.valid_remote_result(result, "nonce", 0))
        self.assertFalse(audit.valid_remote_result(result, "wrong", 0))
        self.assertFalse(audit.valid_remote_result(result, "nonce", 1))
        result["completed"] = False
        self.assertFalse(audit.valid_remote_result(result, "nonce", 0))

    def test_remote_patched_plus_unknown_cannot_claim_success(self):
        result = audit.finish([row(), row("UNKNOWN")], [])
        result.update(token="nonce", exit_status=0, verdict="PATCHED")
        self.assertFalse(audit.valid_remote_result(result, "nonce", 0))

    def test_malformed_remote_runtime_is_rejected(self):
        result = audit.finish([row()], [])
        result["token"] = "nonce"
        result["runtimes"][0]["kind"] = []
        self.assertFalse(audit.valid_remote_result(result, "nonce", 0))

    def test_remote_program_executes_with_transmitted_inventory(self):
        def fake_ssh(argv, timeout, data):
            # Execute only the generated transport wrapper; replace the audit body
            # with a stub so this test never inspects the host or launches processes.
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured), self.assertRaises(SystemExit):
                exec(data, {})  # noqa: S102 -- exercise only the locally generated transport stub
            self.assertEqual(json.loads(captured.getvalue())["received"], INVENTORY)
            return subprocess.CompletedProcess(argv, 0, captured.getvalue(), "")
        stub = "def remote_main(payload):\n import json\n print(json.dumps({'received': payload['inventory']}))\n return 0\n"
        with patch.object(audit.Path, "read_bytes", return_value=stub.encode()), \
                patch.object(audit, "system_tool", return_value="/usr/bin/ssh"), \
                patch.object(audit, "command", side_effect=fake_ssh):
            result = audit.audit_ssh("example.invalid", False, INVENTORY, EMPTY)
        # An incomplete envelope is rejected even if the remote process exits zero.
        self.assertEqual(result["exit_status"], 2)

    def test_ssh_option_injection_rejected_before_execution(self):
        with patch.object(audit, "command", side_effect=AssertionError("Must not execute")), \
                self.assertRaises(audit.AuditError):
            audit.audit_ssh("-oProxyCommand=anything", False, None, EMPTY)


class PackageMetadataTests(unittest.TestCase):
    def test_dpkg_owner_version_and_checksum_are_preserved(self):
        replies = [subprocess.CompletedProcess([], 0, "php8.3-fpm: /usr/sbin/php-fpm8.3\n", ""),
                   subprocess.CompletedProcess([], 0, "php8.3-fpm\t8.3.6-0ubuntu0.24.04.13\tinstalled\n", "")]
        with patch.object(audit, "system_tool", return_value="/usr/bin/dpkg-query"), \
                patch.object(audit, "command", side_effect=replies), \
                patch.object(Path, "is_file", return_value=True), \
                patch.object(Path, "read_text", return_value="a"*32 + "  usr/sbin/php-fpm8.3\n"):
            package = audit.dpkg_metadata("/usr/sbin/php-fpm8.3")
        self.assertEqual(package["version"], "8.3.6-0ubuntu0.24.04.13")
        self.assertEqual(package["digest"], "a"*32)

    def test_dpkg_does_not_accept_other_file_from_pattern_match(self):
        with patch.object(audit, "system_tool", return_value="/usr/bin/dpkg-query"), \
                patch.object(audit, "command", return_value=subprocess.CompletedProcess([], 0, "php8.3-fpm: /other/file\n", "")), \
                self.assertRaises(audit.AuditError):
            audit.dpkg_metadata("/usr/sbin/php-fpm8.3")

    def test_rpm_epoch_release_and_digest(self):
        replies = [subprocess.CompletedProcess([], 0, "php-fpm\t1\t8.3.6\t2.el9\t8\n", ""),
                   subprocess.CompletedProcess([], 0, "/usr/sbin/php-fpm\t" + "b"*64 + "\n", ""),
                   subprocess.CompletedProcess([], 0, "x86_64\tRed Hat, Inc.\n", ""),
                   subprocess.CompletedProcess([], 0, "(none)", "")]
        with patch.object(audit, "system_tool", return_value="/usr/bin/rpm"), \
                patch.object(audit, "command", side_effect=replies):
            package = audit.rpm_metadata("/usr/sbin/php-fpm")
        self.assertEqual(package["version"], "1:8.3.6-2.el9")
        self.assertEqual(package["algorithm"], "sha256")
        self.assertEqual(package["digest"], "b"*64)

    def test_unknown_rpm_digest_fails_closed(self):
        with patch.object(audit, "system_tool", return_value="/usr/bin/rpm"), \
                patch.object(audit, "command", return_value=subprocess.CompletedProcess([], 0, "php-fpm\t0\t8.3.6\t2.el9\t999\n", "")), \
                self.assertRaises(audit.AuditError):
            audit.rpm_metadata("/usr/sbin/php-fpm")


class ConfigTests(unittest.TestCase):
    def test_coverage_must_be_explicit(self):
        inventory = dict(INVENTORY, coverage_confirmed=False)
        with self.assertRaises(audit.AuditError):
            audit.validate_config(inventory, EMPTY)

    def test_vendor_rule_must_cover_both_cves(self):
        evidence = {"schema": 1, "vendor_fixes": [{"os_id": "rhel", "os_version": "9.6", "manager": "rpm",
                    "package": "php-fpm", "fixed_version": "0:8.3.6-1.el9", "cves": [audit.CVES[0]],
                    "sources": ["https://example.invalid/advisory"]}]}
        with self.assertRaises(audit.AuditError):
            audit.validate_config(None, evidence)

    def test_no_bash_dependency(self):
        source = Path(audit.__file__).read_text()
        self.assertNotIn("bash -s", source)
        self.assertNotIn("declare -A", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
