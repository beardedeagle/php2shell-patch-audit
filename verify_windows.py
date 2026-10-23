"""Check Windows file hashes, version resources and process discovery.

Uses this Python interpreter and DLL as fixtures; no PHP runtime is tested.
"""
import ctypes
import importlib.util
import json
import os
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("audit", Path(__file__).with_name("php2shell-audit.py"))
audit = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = audit
spec.loader.exec_module(audit)


def main():
    assert sys.platform == "win32", "Run on Windows with Python 3.9+"
    buffer = ctypes.create_unicode_buffer(32768)
    get_name = ctypes.windll.kernel32.GetModuleFileNameW
    get_name.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32]
    size = get_name(ctypes.pythonapi._handle, buffer, len(buffer))
    assert 0 < size < len(buffer), "Cannot locate this interpreter's loaded DLL"
    paths = [("embedded", sys.executable), ("mod_php", buffer.value)]
    inventory = {"schema": 1, "scope": "synthetic Python fixture, not a PHP deployment",
                 "coverage_confirmed": True,
                 "runtimes": [{"kind": kind, "path": path, "label": "test interpreter"}
                              for kind, path in paths]}
    evidence = {"schema": 1, "builds": [
        {"sha256": audit.hash_file(path)["sha256"], "php_version": "8.3.36",
         "source": "synthetic test only; this executable/DLL is not PHP"}
        for _, path in paths]}
    files = audit.audit_local(inventory, evidence, files=True)
    assert files["exit_status"] == 0 and files["assessment_scope"] == "installed-files-only", files
    upper = dict(inventory, runtimes=[dict(row, path=row["path"].upper()) for row in inventory["runtimes"]])
    assert audit.audit_local(upper, evidence, files=True)["exit_status"] == 0
    unknown = audit.inspect_file(inventory["runtimes"][0], None, {"schema": 1})
    assert unknown["status"] == "UNKNOWN" and unknown["version_hint"].get("product_version"), unknown
    runs, issues = audit.discover(inventory)
    own = [run for run in runs if run.pid == os.getpid()]
    assert {(run.kind, audit.path_key(run.path)) for run in own} == {
        (kind, audit.path_key(path)) for kind, path in paths}, own
    for run in own:
        result = audit.inspect_runtime(run, None, evidence)
        assert result["status"] == "UNKNOWN" and result["file_status"] == "PATCHED", result
    print(json.dumps({"platform": sys.getwindowsversion().build, "python": sys.version.split()[0],
                      "file_hash_evidence": "passed", "case_insensitive_paths": "passed",
                      "version_resource_hint": "passed", "process_and_dll_discovery": "passed",
                      "loaded_image_uncertainty": "preserved", "discovery_issue_count": len(issues)}))


if __name__ == "__main__":
    main()
