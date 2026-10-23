"""macOS discovery, file identity and package archive checks."""
import errno
from contextlib import closing
import hashlib
import io
import json
import sqlite3
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from test_php2shell_audit import audit, EMPTY
from test_portability_methods import evidence, inventory


def make_brew(root, data=b"test"):
    keg = root / "Cellar/php/8.3.36_1"
    binary = keg / "bin/php"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(data)
    (keg / "INSTALL_RECEIPT.json").write_text(json.dumps({"source": {"tap": "homebrew/core"}}))
    return binary


def make_port(root, data=b"test"):
    binary = root / "bin/php83"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(data)
    db = root / "var/macports/registry/registry.db"
    db.parent.mkdir(parents=True)
    with closing(sqlite3.connect(db)) as connection, connection:
        connection.executescript("""
            CREATE TABLE ports (id INTEGER, name TEXT, epoch INTEGER, version TEXT,
                                revision INTEGER, variants TEXT, state TEXT);
            CREATE TABLE files (id INTEGER, path TEXT, actual_path TEXT, active INTEGER);
        """)
        connection.execute("INSERT INTO ports VALUES (1,'php83',0,'8.3.36',1,'+openssl','installed')")
        connection.execute("INSERT INTO files VALUES (1,?,?,1)", (str(binary), str(binary)))
    return binary, db


def archive_evidence(root, package, data=b"test", members=None):
    archive = root / "package.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for name, content, kind in members or [(package["archive_member"], data, tarfile.REGTYPE)]:
            info = tarfile.TarInfo(name)
            info.type, info.size = kind, len(content)
            if kind == tarfile.SYMTYPE:
                info.linkname = "elsewhere"
            tar.addfile(info, io.BytesIO(content))
    return {"schema": 1, "package_archives": [{
        "manager": package["manager"], "package": package["package"], "version": package["version"],
        "path": str(archive), "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "php_version": "8.3.36", "source": "synthetic test archive; not PHP"}]}


class MacOSPackageTests(unittest.TestCase):
    def setUp(self):
        platform = patch.object(audit.sys, "platform", "darwin")
        platform.start()
        self.addCleanup(platform.stop)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()

    def test_homebrew_symlinks_resolve_to_installed_keg_and_tap(self):
        binary = make_brew(self.root)
        alias = self.root / "php"
        alias.symlink_to(binary)
        package = audit.package_metadata(str(alias))
        self.assertEqual(package["package"], "homebrew/core/php")
        self.assertEqual(package["version"], "8.3.36_1")
        self.assertEqual(package["archive_member"], "php/8.3.36_1/bin/php")
        with self.assertRaisesRegex(audit.AuditError, "Duplicate inventory"):
            config = inventory(binary)
            config["runtimes"].append(dict(config["runtimes"][0], path=str(alias)))
            audit.audit_local(config, EMPTY, files=True)

    def test_package_version_alone_cannot_clear_file(self):
        binary = make_brew(self.root)
        record = audit.inspect_file(inventory(binary)["runtimes"][0], None, EMPTY)
        self.assertEqual(record["status"], "UNKNOWN")
        self.assertEqual(record["manager"], "homebrew")
        self.assertEqual(record["package_version"], "8.3.36_1")
        self.assertIn("no file checksum", record["detail"])

    def test_both_managers_verify_file_against_pinned_archive(self):
        for manager in ("homebrew", "macports"):
            with self.subTest(manager=manager):
                root = self.root / manager
                binary = make_brew(root) if manager == "homebrew" else make_port(root)[0]
                package = audit.package_metadata(str(binary))
                proof = archive_evidence(root, package)
                result = audit.audit_local(inventory(binary), proof, files=True)
                self.assertEqual(result["exit_status"], 0, result)
                self.assertEqual(result["runtimes"][0]["manager"], manager)
                binary.write_bytes(b"modified")
                result = audit.audit_local(inventory(binary), proof, files=True)
                self.assertEqual(result["exit_status"], 2)
                self.assertIn("differs from package archive", result["runtimes"][0]["detail"])

    def test_archives_require_exact_package_version_and_checksum(self):
        binary = make_brew(self.root)
        package = audit.package_metadata(str(binary))
        proof = archive_evidence(self.root, package)
        for field, value in (("package", "another/tap/php"), ("version", "8.3.36"),
                             ("manager", "macports"), ("sha256", "0" * 64)):
            changed = {"schema": 1, "package_archives": [dict(proof["package_archives"][0], **{field: value})]}
            with self.subTest(field=field), self.assertRaises(audit.AuditError):
                audit.package_archive_digest(package, changed)

    def test_archive_links_duplicates_and_traversal_are_rejected(self):
        package = audit.package_metadata(str(make_brew(self.root)))
        name = package["archive_member"]
        cases = [[(name, b"test", tarfile.SYMTYPE)],
                 [(name, b"test", tarfile.REGTYPE)] * 2,
                 [("../" + name, b"test", tarfile.REGTYPE)],
                 [("/" + name, b"test", tarfile.REGTYPE)],
                 [("different/file", b"test", tarfile.REGTYPE)]]
        for members in cases:
            with self.subTest(members=members), self.assertRaises(audit.AuditError):
                audit.package_archive_digest(package, archive_evidence(self.root, package, members=members))

    def test_archive_changes_and_limits_fail_closed(self):
        package = audit.package_metadata(str(make_brew(self.root)))
        proof = archive_evidence(self.root, package)
        with patch.object(audit, "MAX_ARCHIVE", 1), self.assertRaises(audit.AuditError):
            audit.package_archive_digest(package, proof)
        original = audit.hash_stream
        def mutate(stream):
            result = original(stream)
            with open(proof["package_archives"][0]["path"], "ab") as other:
                other.write(b"changed")
            return result
        with patch.object(audit, "hash_stream", side_effect=mutate), self.assertRaisesRegex(audit.AuditError, "changed"):
            audit.package_archive_digest(package, proof)

    def test_compressed_archives_and_extended_headers_have_unpacking_limits(self):
        package = audit.package_metadata(str(make_brew(self.root)))
        proof = archive_evidence(self.root, package)
        with patch.object(audit, "MAX_ARCHIVE", 4096), self.assertRaisesRegex(audit.AuditError, "unpacked"):
            audit.package_archive_digest(package, proof)
        info = tarfile.TarInfo("extended")
        info.type, info.size = tarfile.XHDTYPE, audit.MAX_CONFIG + 1
        with self.assertRaisesRegex(audit.AuditError, "metadata"):
            audit.PackageTarInfo.frombuf(info.tobuf(), "utf-8", "strict")

    def test_archive_compression_formats_and_invalid_data(self):
        package = audit.package_metadata(str(make_brew(self.root)))
        proof = archive_evidence(self.root, package)
        entry = proof["package_archives"][0]
        archive = Path(entry["path"])
        for mode in ("w:", "w:gz", "w:bz2", "w:xz"):
            with self.subTest(mode=mode):
                with tarfile.open(archive, mode) as tar:
                    info = tarfile.TarInfo(package["archive_member"])
                    info.size = 4
                    tar.addfile(info, io.BytesIO(b"test"))
                entry["sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
                digest, _ = audit.package_archive_digest(package, proof)
                self.assertEqual(digest, hashlib.sha256(b"test").hexdigest())
        for content in (b"not a tar", b"\x1f\x8btruncated", b"BZhbroken", b"\xfd7zXZ\x00broken"):
            with self.subTest(content=content):
                archive.write_bytes(content)
                entry["sha256"] = hashlib.sha256(content).hexdigest()
                with self.assertRaises((audit.AuditError, OSError)):
                    audit.package_archive_digest(package, proof)

    def test_remote_inventory_validation_does_not_resolve_controller_symlinks(self):
        binary = make_brew(self.root)
        alias = self.root / "remote-php"
        alias.symlink_to(binary)
        config = inventory(binary)
        config["runtimes"].append(dict(config["runtimes"][0], path=str(alias)))
        audit.validate_config(config, EMPTY)
        with self.assertRaisesRegex(audit.AuditError, "aliases"):
            audit.audit_local(config, EMPTY, files=True)

    def test_macports_uses_one_active_owner_without_writing_registry(self):
        binary, database = make_port(self.root)
        before = database.read_bytes()
        package = audit.package_metadata(str(binary))
        self.assertEqual(package["version"], "0:8.3.36_1+openssl")
        self.assertEqual(database.read_bytes(), before)
        with closing(sqlite3.connect(database)) as connection, connection:
            connection.execute("INSERT INTO ports SELECT 2,name,epoch,version,revision,variants,state FROM ports")
            connection.execute("INSERT INTO files SELECT 2,path,actual_path,1 FROM files")
        with self.assertRaisesRegex(audit.AuditError, "unique"):
            audit.package_metadata(str(binary))
        with closing(sqlite3.connect(database)) as connection, connection:
            connection.execute("UPDATE files SET active=0")
        with self.assertRaises(audit.AuditError):
            audit.package_metadata(str(binary))

    def test_corrupt_receipt_or_registry_cannot_be_ignored(self):
        binary = make_brew(self.root)
        receipt = binary.parent.parent / "INSTALL_RECEIPT.json"
        receipt.write_text('{"source":{}}')
        with self.assertRaises(audit.AuditError):
            audit.package_metadata(str(binary))
        other, db = make_port(self.root / "ports")
        db.write_bytes(b"invalid database")
        with self.assertRaisesRegex(audit.AuditError, "registry"):
            audit.package_metadata(str(other))

    def test_archive_versions_and_backports_use_existing_verdict_rules(self):
        binary = make_brew(self.root)
        proof = archive_evidence(self.root, audit.package_metadata(str(binary)))
        row = proof["package_archives"][0]
        for version, expected in (("8.3.35", 1), ("8.3.36RC1", 2), ("7.4.33", 2)):
            row["php_version"] = version
            self.assertEqual(audit.audit_local(inventory(binary), proof, files=True)["exit_status"], expected)
        row["fixed_cves"] = list(audit.CVES)
        self.assertEqual(audit.audit_local(inventory(binary), proof, files=True)["exit_status"], 0)
        row["fixed_cves"].pop()
        with self.assertRaises(audit.AuditError):
            audit.validate_config(None, proof)
        del row["fixed_cves"]
        proof["package_archives"].append(dict(row))
        with self.assertRaisesRegex(audit.AuditError, "Duplicate"):
            audit.validate_config(None, proof)


class MacOSProcessTests(unittest.TestCase):
    def setUp(self):
        platform = patch.object(audit.sys, "platform", "darwin")
        platform.start()
        self.addCleanup(platform.stop)
        self.api = Mock()
        self.api.pids.return_value = [10]
        self.api.identity.return_value = "100:5"
        self.api.executable.return_value = "/php-fpm"
        self.api.mappings.return_value = [self.mapping("/php-fpm"), self.mapping("/libphp.so", 2)]
        api = patch.object(audit, "MacOSProcesses", return_value=self.api)
        api.start()
        self.addCleanup(api.stop)

    @staticmethod
    def mapping(path, inode=1):
        return {"path": path, "device": 5, "inode": inode, "nlink": 1}

    def test_discovers_executables_and_modules_in_renamed_hosts(self):
        runs, issues = audit.discover(None)
        self.assertEqual({r.kind for r in runs}, {"fpm", "mod_php"})
        self.assertEqual(issues, [])
        self.api.executable.return_value = "/renamed-server"
        runs, issues = audit.discover(None)
        self.assertEqual([r.kind for r in runs], ["mod_php"])

    def test_permission_failures_missing_mappings_and_pid_reuse_block_clearance(self):
        self.api.mappings.side_effect = PermissionError(errno.EPERM, "denied")
        runs, issues = audit.discover(None)
        self.assertTrue(issues)
        self.assertEqual(runs[0].inode, 0)
        self.api.mappings.side_effect = None
        self.api.mappings.return_value = []
        runs, issues = audit.discover(None)
        self.assertTrue(issues)
        self.api.identity.side_effect = ["100:5", "200:5"]
        runs, issues = audit.discover(None)
        self.assertEqual(runs, [])
        self.assertTrue(issues)

    def test_exited_processes_are_skipped(self):
        self.api.identity.side_effect = ProcessLookupError(errno.ESRCH, "gone")
        self.assertEqual(audit.discover(None), ([], []))

    def test_runtime_requires_stable_pid_and_mapped_inode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "php"
            path.write_bytes(b"test")
            info = path.stat()
            run = audit.Runtime(10, "php", str(path), str(path), "100:5", False, info.st_dev, info.st_ino)
            self.api.mappings.return_value = [dict(self.mapping(str(path)), device=info.st_dev, inode=info.st_ino)]
            record = audit.inspect_runtime(run, None, evidence())
            self.assertEqual(record["status"], "PATCHED", record)
            self.api.identity.side_effect = ["100:5", "100:6"]
            self.assertEqual(audit.inspect_runtime(run, None, evidence())["status"], "UNKNOWN")
            self.api.identity.side_effect = None
            self.api.mappings.return_value = []
            self.assertEqual(audit.inspect_runtime(run, None, evidence())["status"], "UNKNOWN")
            replacement = path.with_suffix(".new")
            replacement.write_bytes(b"test")
            replacement.replace(path)
            record = audit.inspect_runtime(run, None, evidence())
            self.assertEqual(record["status"], "UNKNOWN")
            self.assertTrue(record["restart_needed"])

    def test_mapped_file_change_after_hashing_is_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "php"
            path.write_bytes(b"test")
            info = path.stat()
            run = audit.Runtime(10, "php", str(path), str(path), "100:5", False, info.st_dev, info.st_ino)
            def change(pid):
                path.write_bytes(b"changed after hashing")
                return [{"device": info.st_dev, "inode": info.st_ino}]
            self.api.mappings.side_effect = change
            result = audit.inspect_runtime(run, None, evidence())
            self.assertEqual(result["status"], "UNKNOWN")
            self.assertIn("changed", result["detail"])

    def test_macos_ssh_uses_existing_posix_transport(self):
        with patch.object(audit, "system_tool", return_value="/usr/bin/ssh"), \
                patch.object(audit, "run_remote", return_value={}) as remote:
            audit.audit_ssh("user@mac", False, None, EMPTY, remote_os="macos", python="/opt/homebrew/bin/python3")
        self.assertEqual(remote.call_args.args[0][-1], "/opt/homebrew/bin/python3 -")


class MacOSAPITests(unittest.TestCase):
    def test_incomplete_native_results_are_rejected(self):
        api = audit.MacOSProcesses.__new__(audit.MacOSProcesses)
        api.lib = Mock()
        api.lib.proc_pidinfo.return_value = 1
        with self.assertRaisesRegex(audit.AuditError, "Incomplete"):
            api.info(10, 3, api.BSDInfo())

    def test_process_list_growth_is_bounded(self):
        api = audit.MacOSProcesses.__new__(audit.MacOSProcesses)
        api.lib = Mock()
        api.lib.proc_listallpids.side_effect = [1, 129] * 3
        with self.assertRaisesRegex(audit.AuditError, "growing"):
            api.pids()

    def test_empty_region_scan_is_not_success(self):
        api = audit.MacOSProcesses.__new__(audit.MacOSProcesses)
        api.region_type = Mock()
        api.info = Mock(side_effect=OSError(errno.EINVAL, "no region"))
        with self.assertRaises(OSError):
            api.mappings(10)


if __name__ == "__main__":
    unittest.main()
