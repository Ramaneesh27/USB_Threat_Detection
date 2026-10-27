"""
Quarantine page + auto-quarantine tests (pure logic - no Windows needed):

  * auto rule: risk score >= 75 is quarantined, 74 is not
  * manual quarantine: validation, protected folders, DB record, scan record
  * HTTP API: header guard, file browser
  * PDF report mentions auto / manual quarantine
  * the whole code base still parses as Python 3.10
"""
import ast
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import app as app_module            # noqa: E402
import config                       # noqa: E402
import database                     # noqa: E402
import report_generator             # noqa: E402
from scanners import quarantine     # noqa: E402
from sandbox.vmware import _diff_guest_snapshots  # noqa: E402


class _Sandboxed(unittest.TestCase):
    """Every test gets its own database, quarantine folder and reports folder."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / "q").mkdir()
        (self.tmp / "reports").mkdir()
        (self.tmp / "files").mkdir()
        patches = [
            mock.patch.object(config, "DATABASE_PATH", self.tmp / "history.db"),
            mock.patch.object(config, "QUARANTINE_DIR", self.tmp / "q"),
            mock.patch.object(config, "REPORTS_DIR", self.tmp / "reports"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        database.init_db()
        self.client = app_module.app.test_client()

    def make_file(self, name="sample.txt", content="hello"):
        path = self.tmp / "files" / name
        path.write_text(content)
        return path


class AutoQuarantineRuleTests(_Sandboxed):
    def test_threshold_is_75(self):
        self.assertEqual(config.AUTO_QUARANTINE_THRESHOLD, 75)

    def _result(self, score):
        return {"risk_score": score, "reasons": ["r"], "explanations": [], "quarantined": False}

    def test_74_is_not_quarantined(self):
        f = self.make_file()
        res = self._result(74)
        self.assertFalse(app_module.auto_quarantine_if_needed("scan_t", f, res))
        self.assertTrue(f.exists())
        self.assertFalse(res["quarantined"])

    def test_75_is_quarantined_and_marked_auto(self):
        f = self.make_file()
        database.create_scan("scan_t", "usb", "E:\\", 0, "FAT32")
        res = self._result(75)
        self.assertTrue(app_module.auto_quarantine_if_needed("scan_t", f, res))
        self.assertFalse(f.exists())
        self.assertTrue(res["quarantined"])
        self.assertEqual(res["quarantine_mode"], "auto")
        item = database.get_quarantine_item(res["quarantine_id"])
        self.assertEqual(item["source"], "auto")
        self.assertEqual(item["risk_score"], 75)
        self.assertTrue(Path(item["quarantine_path"]).exists())

    def test_high_score_in_protected_folder_is_not_moved_and_says_why(self):
        win = self.tmp / "Windows"
        (win / "System32").mkdir(parents=True)
        f = win / "System32" / "x.dll"
        f.write_text("x")
        res = self._result(90)
        with mock.patch.dict(os.environ, {"WINDIR": str(win), "SystemRoot": str(win)}):
            self.assertFalse(app_module.auto_quarantine_if_needed("scan_t", f, res))
        self.assertTrue(f.exists())
        self.assertTrue(any("Auto-quarantine was not possible" in r for r in res["reasons"]))


class AutoSandboxRuleTests(_Sandboxed):
    def test_below_threshold_does_not_detect_or_run_sandbox(self):
        with mock.patch.object(app_module.sandbox_manager, "detect_available_sandboxes") as detect, \
             mock.patch.object(app_module.sandbox_manager, "run_analysis") as run:
            self.assertIsNone(app_module.auto_sandbox_if_needed(
                "scan_t", self.make_file(), {"risk_score": 74, "reasons": []}))
        detect.assert_not_called()
        run.assert_not_called()

    def test_threshold_selects_ready_vmware_before_quarantine(self):
        vmx_path = self.make_file("analysis.vmx")
        result = {"risk_score": 75, "reasons": []}
        with mock.patch.object(app_module.sandbox_manager, "detect_available_sandboxes", return_value={
            "vmware": {"ready": True, "vms": [str(vmx_path)]},
            "windows_sandbox": {"ready": True}, "virtualbox": {"ready": False, "vms": []},
        }), mock.patch.object(app_module.sandbox_manager, "run_analysis", return_value={
            "status": "completed", "sandbox_type": "VMware",
        }) as run:
            used = app_module.auto_sandbox_if_needed("scan_t", self.make_file(), result)
        self.assertEqual(used, "VMware")
        self.assertEqual(result["sandbox_status"], "completed")
        self.assertEqual(run.call_args.args[2:], ("vmware", str(vmx_path)))


class ManualSandboxApiTests(_Sandboxed):
    def test_native_path_analysis_generates_report(self):
        path = self.make_file("sample.txt")
        result = {"file_name": path.name, "extension": ".txt", "absolute_path": str(path),
                  "size_bytes": path.stat().st_size, "sha256": "a" * 64, "mime_type": "text/plain",
                  "created_date": "", "modified_date": "", "level": 1, "risk_score": 10,
                  "risk_level": "Low", "reasons": [], "explanations": [], "quarantined": False}
        with mock.patch.object(app_module, "_analyze_single_file", return_value=result), \
             mock.patch.object(app_module.sandbox_manager, "run_analysis", return_value={
                 "status": "completed", "sandbox_type": "VMware", "verdict_notes": "No changes",
                 "before_snapshot": {}, "after_snapshot": {}, "diff": {"summary": {}},
             }):
            response = self.client.post("/api/sandbox/analyze", json={
                "path": str(path), "sandbox_type": "vmware", "vm_name": str(self.make_file("vm.vmx")),
            }, headers={"X-UTA-Request": "1"})
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["status"], "completed")
        report_path = Path(database.get_scan(payload["scan_id"])["report_path"])
        self.assertTrue(report_path.exists())
        downloaded = self.client.get(payload["report_url"])
        self.assertEqual(downloaded.status_code, 200)
        self.assertEqual(downloaded.mimetype, "application/pdf")


class VMwareSnapshotDiffTests(unittest.TestCase):
    def test_diff_covers_objects_registry_ports_and_encryption(self):
        before = {
            "files": ["C:/sample.txt"], "folders": [],
            "processes": [{"ProcessId": 1, "Name": "old.exe"}],
            "registry_run_keys": {"HKCU/Run/sample": "old.exe"},
            "network_connections": [], "open_ports": ["TCP:127.0.0.1:80"],
            "encrypted_files": [], "locked_files": [],
        }
        after = {
            "files": ["C:/sample.txt", "C:/new.txt"], "folders": ["C:/new"],
            "processes": [{"ProcessId": 1, "Name": "old.exe"},
                          {"ProcessId": 2, "Name": "sample.exe"}],
            "registry_run_keys": {"HKCU/Run/sample": "new.exe"},
            "network_connections": [{"protocol": "TCP", "status": "ESTABLISHED"}],
            "open_ports": ["TCP:127.0.0.1:443"],
            "encrypted_files": ["C:/new.txt"], "locked_files": [],
        }
        diff = _diff_guest_snapshots(before, after)
        self.assertEqual(diff["new_files"], ["C:/new.txt"])
        self.assertEqual(diff["new_folders"], ["C:/new"])
        self.assertTrue(diff["new_processes"])
        self.assertTrue(diff["registry_changes"])
        self.assertTrue(diff["new_network_connections"])
        self.assertEqual(diff["new_open_ports"], ["TCP:127.0.0.1:443"])
        self.assertEqual(diff["encrypted_or_locked_changes"][0]["path"], "C:/new.txt")


class EnsureQuarantinableTests(_Sandboxed):
    def test_rejects_relative_missing_and_folders(self):
        for bad in ("relative.txt", str(self.tmp / "nope.txt"), str(self.tmp / "files")):
            with self.assertRaises(quarantine.QuarantineError, msg=bad):
                quarantine.ensure_quarantinable(bad)

    def test_rejects_windows_directory_and_quarantine_folder(self):
        win = self.tmp / "Windows"
        win.mkdir()
        sysfile = win / "notepad.exe"
        sysfile.write_text("x")
        inside_q = self.tmp / "q" / "scan_1" / "a.exe"
        inside_q.parent.mkdir(parents=True)
        inside_q.write_text("x")
        with mock.patch.dict(os.environ, {"WINDIR": str(win), "SystemRoot": str(win)}):
            with self.assertRaises(quarantine.QuarantineError) as ctx:
                quarantine.ensure_quarantinable(sysfile)
            self.assertIn("protected", str(ctx.exception))
            with self.assertRaises(quarantine.QuarantineError) as ctx:
                quarantine.ensure_quarantinable(inside_q)
            self.assertIn("already inside quarantine", str(ctx.exception))

    def test_accepts_normal_file(self):
        f = self.make_file()
        self.assertEqual(quarantine.ensure_quarantinable(f), f)


class ManualQuarantineTests(_Sandboxed):
    def test_manual_quarantine_moves_file_and_records_it(self):
        f = self.make_file("notes.txt", "some text")
        out = app_module.manual_quarantine([str(f)])
        self.assertEqual(len(out["quarantined"]), 1)
        self.assertEqual(out["failed"], [])
        self.assertFalse(f.exists())
        item = database.get_quarantine_item(out["quarantined"][0]["id"])
        self.assertEqual(item["source"], "manual")
        self.assertEqual(item["original_path"], str(f))
        self.assertTrue(Path(item["quarantine_path"]).exists())
        # recorded as its own scan, with the file row flagged quarantined
        scan = database.get_scan(out["scan_id"])
        self.assertEqual(scan["usb_name"], "Manual quarantine")
        self.assertEqual(scan["status"], "completed")
        rows = database.list_files_for_scan(out["scan_id"])
        self.assertEqual(rows[0]["quarantined"], 1)
        self.assertTrue(rows[0]["reasons"][0].startswith("Quarantined manually"))

    def test_partial_failure_is_reported_per_file(self):
        good = self.make_file("a.txt")
        out = app_module.manual_quarantine([str(good), str(self.tmp / "missing.txt"), "relative.txt"])
        self.assertEqual(len(out["quarantined"]), 1)
        self.assertEqual(len(out["failed"]), 2)

    def test_nothing_valid_creates_no_scan(self):
        out = app_module.manual_quarantine([str(self.tmp / "missing.txt")])
        self.assertIsNone(out["scan_id"])
        self.assertEqual(database.list_scans(), [])

    def test_duplicates_are_quarantined_once(self):
        f = self.make_file()
        out = app_module.manual_quarantine([str(f), str(f)])
        self.assertEqual(len(out["quarantined"]), 1)

    def test_restore_brings_it_back(self):
        f = self.make_file()
        out = app_module.manual_quarantine([str(f)])
        with mock.patch.object(config, "QUARANTINE_REQUIRE_OS_AUTH", False):
            quarantine.restore_file(out["quarantined"][0]["id"])
        self.assertTrue(f.exists())

    def test_old_database_is_migrated(self):
        old = self.tmp / "old.db"
        con = sqlite3.connect(old)
        con.executescript("""CREATE TABLE quarantine (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL,
            original_path TEXT, quarantine_path TEXT, sha256 TEXT, risk_score INTEGER, reasons_json TEXT,
            quarantined_at TEXT, status TEXT DEFAULT 'quarantined', explanations_json TEXT);
            INSERT INTO quarantine (scan_id, original_path, reasons_json) VALUES ('s', 'C:\\\\x', '[]');""")
        con.commit()
        con.close()
        with mock.patch.object(config, "DATABASE_PATH", old):
            database.init_db()
            self.assertEqual(database.list_quarantine()[0]["source"], "auto")


class ApiTests(_Sandboxed):
    def post(self, paths, header=True):
        headers = {"X-UTA-Request": "1"} if header else {}
        return self.client.post("/api/quarantine/add", data=json.dumps({"paths": paths}),
                                content_type="application/json", headers=headers)

    def test_add_requires_app_header(self):
        f = self.make_file()
        self.assertEqual(self.post([str(f)], header=False).status_code, 403)
        self.assertTrue(f.exists())

    def test_add_ok_and_error_shapes(self):
        f = self.make_file()
        r = self.post([str(f)])
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.get_json()["quarantined"]), 1)
        self.assertEqual(self.post([str(self.tmp / "gone.txt")]).status_code, 400)
        self.assertEqual(self.post([]).status_code, 400)
        listed = self.client.get("/api/quarantine").get_json()
        self.assertEqual(listed[0]["source"], "manual")

    def test_file_browser_lists_folder_dirs_first(self):
        (self.tmp / "files" / "sub").mkdir()
        self.make_file("b.txt")
        data = self.client.get("/api/fs/list", query_string={"path": str(self.tmp / "files")}).get_json()
        self.assertEqual([e["name"] for e in data["entries"]], ["sub", "b.txt"])
        self.assertTrue(data["entries"][0]["is_dir"])
        self.assertEqual(data["parent"], str(self.tmp))

    def test_file_browser_rejects_relative_and_missing(self):
        self.assertEqual(self.client.get("/api/fs/list", query_string={"path": "relative"}).status_code, 400)
        self.assertEqual(self.client.get("/api/fs/list",
                                         query_string={"path": str(self.tmp / "nope")}).status_code, 400)

    def test_roots_and_page_render(self):
        self.assertEqual(self.client.get("/api/fs/roots").status_code, 200)
        page = self.client.get("/").get_data(as_text=True)
        self.assertIn('data-view="quarantine"', page)
        self.assertIn('data-view="sandbox"', page)
        self.assertIn('id="sandboxFileInput"', page)
        self.assertIn('data-auto-threshold="75"', page)
        self.assertIn("75 or higher", page)


class ReportTests(_Sandboxed):
    def _scan_with(self, score, name):
        scan_id = "scan_report"
        database.create_scan(scan_id, "TESTUSB", "E:\\", 1024 ** 3, "FAT32")
        f = self.make_file(name)
        result = {"file_name": name, "extension": ".exe", "absolute_path": str(f), "size_bytes": 5,
                  "sha256": "a" * 64, "mime_type": "", "created_date": "", "modified_date": "", "level": 3,
                  "risk_score": score, "risk_level": "High", "reasons": ["Packed executable"],
                  "explanations": [], "quarantined": False}
        app_module.auto_quarantine_if_needed(scan_id, f, result)
        database.insert_file_result(scan_id, result)
        database.finish_scan(scan_id, 1, 1, score, None, None)
        return scan_id

    def test_summary_counts(self):
        scan_id = self._scan_with(80, "evil.exe")
        files = database.list_files_for_scan(scan_id)
        q = database.list_quarantine_for_scan(scan_id)
        summary = report_generator._quarantine_summary(files, q)
        self.assertEqual((len(summary["auto"]), len(summary["manual"])), (1, 0))
        self.assertEqual(summary["not_quarantined"], [])
        marker = report_generator._quarantine_marker(summary["by_path"][
            report_generator._path_key(files[0]["absolute_path"])], 75)
        self.assertIn("automatically (risk score 75+)", marker)

    def test_report_text_mentions_auto_quarantine(self):
        scan_id = self._scan_with(80, "evil&co.exe")        # '&' must not break the PDF markup
        path = report_generator.generate_report(scan_id)
        self.assertTrue(Path(path).stat().st_size > 1000)
        if not shutil.which("pdftotext"):
            self.skipTest("pdftotext not installed - PDF text not inspected")
        text = subprocess.run(["pdftotext", "-layout", path, "-"], capture_output=True, text=True).stdout
        flat = " ".join(text.split())
        self.assertIn("Quarantine Actions", flat)
        self.assertIn("automatically quarantined", flat)
        self.assertIn("1 automatically, 0 manually", flat)
        self.assertIn("Risk score 75 or higher", flat)

    def test_report_lists_file_that_could_not_be_quarantined(self):
        scan_id = "scan_stuck"
        database.create_scan(scan_id, "TESTUSB", "E:\\", 1, "FAT32")
        database.insert_file_result(scan_id, {
            "file_name": "locked.exe", "extension": ".exe", "absolute_path": "E:\\locked.exe", "size_bytes": 1,
            "sha256": "b" * 64, "level": 3, "risk_score": 90, "risk_level": "Critical",
            "reasons": ["Auto-quarantine was not possible: file in use"], "explanations": [], "quarantined": False})
        database.finish_scan(scan_id, 1, 1, 90, None, None)
        path = report_generator.generate_report(scan_id)
        self.assertTrue(Path(path).exists())
        summary = report_generator._quarantine_summary(database.list_files_for_scan(scan_id), [])
        self.assertEqual(len(summary["not_quarantined"]), 1)


class PythonCompatibilityTests(unittest.TestCase):
    def test_minimum_version_declared(self):
        self.assertEqual(config.MIN_PYTHON, (3, 10))
        self.assertGreaterEqual(sys.version_info[:2], (3, 10))

    def test_every_python_file_parses_as_python_3_10(self):
        for path in ROOT.rglob("*.py"):
            if ".build_venv" in path.parts or "venv" in path.parts:
                continue
            try:
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path), feature_version=(3, 10))
            except SyntaxError as exc:   # pragma: no cover - only on a regression
                self.fail(f"{path.relative_to(ROOT)} uses syntax newer than Python 3.10: {exc}")


if __name__ == "__main__":
    unittest.main()
