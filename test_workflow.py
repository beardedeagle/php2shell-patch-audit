"""Regressions for actionable findings, evidence identity and inventory drafts."""
import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_php2shell_audit import audit, EMPTY, INVENTORY, row, runtime
from test_portability_methods import evidence, inventory
from test_macos import make_brew, archive_evidence


class FindingTests(unittest.TestCase):
    def test_php_fixture_refuses_workstations_and_self_hosted_runners(self):
        import verify_php
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"}), \
                patch.object(verify_php.Path, "is_file", return_value=False), \
                patch.object(verify_php.sys, "argv", ["verify_php.py", "--version", "8.3.36", "--source", "fixture"]), \
                patch.object(verify_php.subprocess, "run", side_effect=AssertionError("Must not execute PHP")), \
                self.assertRaisesRegex(RuntimeError, "Run only inside disposable"):
            verify_php.main()

    def test_real_file_inspection_keeps_permission_errors_distinct_from_missing_paths(self):
        path = str(Path(tempfile.gettempdir()) / "php-fixture")
        with patch.object(audit.os, "stat", side_effect=PermissionError("denied")):
            result = audit.inspect_file({"kind": "php", "path": path}, None, EMPTY)
        self.assertEqual(result["diagnostics"][0]["code"], "ACCESS_DENIED")

    def test_access_missing_evidence_and_restart_are_distinct(self):
        with patch.object(audit.sys, "platform", "linux"), \
                patch.object(audit, "hash_runtime", side_effect=PermissionError("denied")):
            result = audit.inspect_runtime(runtime(), ("ubuntu", "24.04"), EMPTY)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(result["diagnostics"][0]["code"], "ACCESS_DENIED")
        self.assertEqual(result["diagnostics"][0]["guidance"], [audit.GUIDANCE["ubuntu"]])
        with patch.object(audit.sys, "platform", "linux"), \
                patch.object(audit, "hash_runtime", return_value=({"sha256": hashlib.sha256(b"test").hexdigest()}, True)):
            result = audit.inspect_runtime(runtime(), None, evidence())
        self.assertEqual(result["status"], "PATCHED")
        self.assertEqual(result["diagnostics"][0]["code"], "RESTART_REQUIRED")
        self.assertEqual(audit.finish([result], [])["exit_status"], 2)

    def test_unknown_build_version_and_missing_vendor_rule_have_next_steps(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "php"
            path.write_bytes(b"test")
            result = audit.inspect_file(inventory(path)["runtimes"][0], None, evidence(version="8.3.36RC1"))
        self.assertEqual(result["diagnostics"][0]["code"], "VERSION_UNSUPPORTED")
        with self.assertRaises(audit.AuditError) as error:
            audit.fixed_rule({"manager": "rpm", "package": "php-fpm"}, ("fedora", "99"), EMPTY)
        self.assertEqual(error.exception.code, "VENDOR_RULE_MISSING")

    def test_inventory_gaps_keep_exit_codes_and_explain_each_gap(self):
        with patch.object(audit, "discover", return_value=([runtime(path="/unexpected")], ["denied process"])), \
                patch.object(audit, "inspect_runtime", return_value=row(path="/unexpected")):
            report = audit.audit_local(INVENTORY, EMPTY)
        self.assertEqual(report["exit_status"], 2)
        self.assertEqual({d["code"] for d in report["diagnostics"]},
                         {"EXPECTED_RUNTIME_MISSING", "UNEXPECTED_RUNTIME", "DISCOVERY_INCOMPLETE"})
        self.assertEqual(len(report["issues"]), 3)


class MetadataAndDraftTests(unittest.TestCase):
    def test_missing_source_fingerprint_does_not_hide_affected_artifacts(self):
        with patch.object(audit.Path, "read_bytes", side_effect=FileNotFoundError("script moved")):
            report = audit.finish([row("AFFECTED")], [])
        self.assertEqual(report["exit_status"], 1)
        self.assertIsNone(report["metadata"]["tool_sha256"])

    def test_malformed_remote_diagnostics_and_metadata_are_rejected(self):
        report = audit.finish([row()], [])
        report["token"] = "nonce"
        self.assertTrue(audit.valid_remote_result(report, "nonce", 0))
        for value in (None, ["text"], [{"code": []}], [{"code": "UNRECOGNIZED"}]):
            with self.subTest(value=value):
                report["diagnostics"] = value
                self.assertFalse(audit.valid_remote_result(report, "nonce", 0))
        report["diagnostics"] = []
        report["metadata"]["tool_sha256"] = "invalid"
        self.assertFalse(audit.valid_remote_result(report, "nonce", 0))

    def test_fingerprints_are_canonical_and_change_with_evidence(self):
        first = audit.report_metadata(INVENTORY, {"schema": 1, "builds": []})
        second = audit.report_metadata(dict(reversed(list(INVENTORY.items()))), {"builds": [], "schema": 1})
        self.assertEqual(first["inventory_sha256"], second["inventory_sha256"])
        self.assertEqual(first["evidence_sha256"], second["evidence_sha256"])
        self.assertNotEqual(first["evidence_sha256"], audit.report_metadata(INVENTORY, evidence())["evidence_sha256"])
        self.assertEqual(first["tool_sha256"], hashlib.sha256(Path(audit.__file__).read_bytes()).hexdigest())
        self.assertTrue(first["timestamp_utc"].endswith("+00:00"))
        self.assertNotIn("runtimes", first)

    def test_draft_deduplicates_workers_preserves_errors_and_cannot_clear(self):
        with patch.object(audit, "discover", return_value=([runtime(), runtime(102)], ["unreadable PID"])), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            status = audit.main(["--draft-inventory"])
        draft = json.loads(output.getvalue())
        self.assertEqual(status, 2)
        self.assertEqual(len(draft["runtimes"]), 1)
        self.assertIs(draft["coverage_confirmed"], False)
        self.assertEqual(draft["discovery_issues"], ["unreadable PID"])
        with self.assertRaises(audit.AuditError):
            audit.validate_config(draft, EMPTY)

    def test_draft_rejects_observation_and_file_modes(self):
        for args in (["--files"], ["--http", "https://example.invalid"], ["--ssh", "one", "--ssh", "two"]):
            with self.subTest(args=args), contextlib.redirect_stdout(io.StringIO()) as output, \
                    patch.object(audit, "discover", side_effect=AssertionError("Must validate first")):
                self.assertEqual(audit.main(["--draft-inventory", "--json"] + args), 2)
            self.assertNotIn("coverage_confirmed", json.loads(output.getvalue()))

    def test_remote_draft_scope_is_validated_and_target_metadata_is_retained(self):
        report = audit.finish([], ["review draft"])
        report["metadata"]["target"]["platform"] = "test-target"
        report["draft_inventory"] = {"schema": 1, "coverage_confirmed": False, "runtimes": []}
        report["token"] = "token"
        def transport(*args, **kwargs):
            return audit.subprocess.CompletedProcess([], 2, json.dumps(report), "")
        with patch.object(audit, "remote_program", return_value=("token", "source")), \
                patch.object(audit, "command", side_effect=transport):
            result = audit.run_remote([], "ssh", "target", None, EMPTY, draft=True)
            self.assertEqual(result["metadata"]["target"]["platform"], "test-target")
            report["draft_inventory"]["coverage_confirmed"] = True
            result = audit.run_remote([], "ssh", "target", None, EMPTY, draft=True)
        self.assertEqual(result["diagnostics"][0]["code"], "TRANSPORT_FAILED")
        self.assertEqual(result["metadata"]["host_role"], "controller")


class ArchiveReuseTests(unittest.TestCase):
    def test_reuse_avoids_rehash_but_checks_replacement_and_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            package = audit.macos_package_metadata(str(make_brew(root)))
            proof = archive_evidence(root, package)
            path = Path(proof["package_archives"][0]["path"])
            cache = {}
            with patch.object(audit, "hash_stream", wraps=audit.hash_stream) as hashing:
                expected = audit.package_archive_digest(package, proof, cache)
                for _ in range(20):
                    self.assertEqual(audit.package_archive_digest(package, proof, cache), expected)
                self.assertEqual(hashing.call_count, 1)
                replacement = root / "replacement"
                replacement.write_bytes(path.read_bytes())
                replacement.replace(path)
                self.assertEqual(audit.package_archive_digest(package, proof, cache), expected)
                self.assertEqual(hashing.call_count, 2)
                before = path.stat()
                path.write_bytes(b"modified archive")
                os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
                with self.assertRaises(audit.AuditError):
                    audit.package_archive_digest(package, proof, cache)

    def test_cache_hit_does_not_ignore_change_during_recheck(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            package = audit.macos_package_metadata(str(make_brew(root)))
            proof = archive_evidence(root, package)
            cache = {}
            audit.package_archive_digest(package, proof, cache)
            path = Path(proof["package_archives"][0]["path"])
            other = root / "other"
            other.write_bytes(b"other")
            with path.open("rb") as first, other.open("rb") as second:
                identities = [audit.file_signature(os.fstat(stream.fileno())) for stream in (first, second)]
            with patch.object(audit, "file_signature", side_effect=[
                    *identities]), self.assertRaises(audit.AuditError):
                audit.package_archive_digest(package, proof, cache)
            self.assertTrue(path.exists())


class VendorRuleTests(unittest.TestCase):
    def test_arch_rules_require_exact_vendor_package_and_rolling_release(self):
        for name, (version, advisory) in audit.ARCH_FIXES.items():
            package = {"manager": "pacman", "package": name}
            rule = audit.fixed_rule(package, ("arch", "rolling"), EMPTY)
            self.assertEqual(rule["fixed_version"], version)
            self.assertEqual(rule["sources"], ["https://security.archlinux.org/" + advisory])
            for distro in (("manjaro", "rolling"), ("arch", "2026.10")):
                with self.assertRaises(audit.AuditError):
                    audit.fixed_rule(package, distro, EMPTY)
        with self.assertRaises(audit.AuditError):
            audit.fixed_rule({"manager": "pacman", "package": "php-unrelated"}, ("arch", "rolling"), EMPTY)

    def test_alpine_rules_are_release_and_runtime_package_scoped(self):
        for release in ("3.23", "3.23.4", "3.24.2"):
            for name, version in audit.ALPINE_FIXES.items():
                for suffix in ("", "-fpm", "-cgi", "-apache2"):
                    rule = audit.fixed_rule({"manager": "apk", "package": name + suffix}, ("alpine", release), EMPTY)
                    self.assertEqual(rule["fixed_version"], version)
                    self.assertEqual(rule["verified_at"], "2026-10-23")
        for distro, package in ((("alpine", "edge"), "php83"), (("alpine", "3.22.1"), "php83"),
                                (("postmarketos", "3.24.2"), "php83"), (("alpine", "3.24.2"), "php83-dev")):
            with self.subTest(distro=distro, package=package), self.assertRaises(audit.AuditError):
                audit.fixed_rule({"manager": "apk", "package": package}, distro, EMPTY)


if __name__ == "__main__":
    unittest.main()
