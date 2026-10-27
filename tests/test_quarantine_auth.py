"""Release-protection tests: nothing leaves quarantine unless Windows verification succeeds."""
import sys, tempfile, unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanners import quarantine
from utils import credential_prompt as cp


class QuarantineAuthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.qfile = self.tmp / "abc_evil.exe"; self.qfile.write_text("x")
        self.item = {"id": 7, "quarantine_path": str(self.qfile),
                     "original_path": str(self.tmp / "orig" / "evil.exe"), "sha256": "a" * 64}
        self.db = mock.patch.multiple("scanners.quarantine.database",
                                      get_quarantine_item=mock.Mock(return_value=self.item),
                                      update_quarantine_status=mock.DEFAULT)
        self.db.start(); self.addCleanup(self.db.stop)

    def patch_auth(self, verified, outcome=cp.OK):
        m = mock.patch.object(cp, "verify_current_user",
                              return_value=cp.AuthResult(verified, outcome, "msg"))
        mock_obj = m.start(); self.addCleanup(m.stop); return mock_obj

    def test_restore_denied_leaves_file(self):
        self.patch_auth(False, cp.FAILED)
        with self.assertRaises(quarantine.QuarantineAuthError):
            quarantine.restore_file(7)
        self.assertTrue(self.qfile.exists())
        self.assertFalse(Path(self.item["original_path"]).exists())

    def test_restore_allowed_moves_file(self):
        m = self.patch_auth(True)
        target = quarantine.restore_file(7)
        self.assertTrue(Path(target).exists()); self.assertFalse(self.qfile.exists())
        self.assertEqual(m.call_count, 1)

    def test_delete_denied_and_allowed(self):
        self.patch_auth(False, cp.CANCELLED)
        with self.assertRaises(quarantine.QuarantineAuthError) as ctx:
            quarantine.delete_permanently(7)
        self.assertEqual(ctx.exception.outcome, cp.CANCELLED); self.assertTrue(self.qfile.exists())
        cp.verify_current_user.return_value = cp.AuthResult(True, cp.OK)
        quarantine.delete_permanently(7); self.assertFalse(self.qfile.exists())

    def test_export_denied(self):
        self.patch_auth(False)
        with self.assertRaises(quarantine.QuarantineAuthError):
            quarantine.export_sample(7, self.tmp / "out")
        self.assertFalse((self.tmp / "out").exists())

    def test_non_windows_is_a_denial_not_a_pass(self):
        with mock.patch.object(cp, "IS_WINDOWS", False):
            r = cp.verify_current_user("t", "m")
        self.assertFalse(r.verified); self.assertEqual(r.outcome, cp.UNAVAILABLE)

    def test_prompt_flow_attempts_and_cooldown(self):
        class FakeCred:
            wiped = 0
            def wipe(self): FakeCred.wiped += 1
        cp._last_failure_at = 0.0
        with mock.patch.object(cp, "IS_WINDOWS", True), \
             mock.patch.object(cp, "_show_prompt", side_effect=lambda *a: FakeCred()) as show, \
             mock.patch.object(cp, "_validate", side_effect=[False, False, True]):
            self.assertTrue(cp.verify_current_user("t", "m").verified)
            self.assertEqual(show.call_count, 3)
            self.assertEqual(FakeCred.wiped, 3)                       # every buffer wiped
        with mock.patch.object(cp, "IS_WINDOWS", True), \
             mock.patch.object(cp, "_show_prompt", side_effect=lambda *a: FakeCred()), \
             mock.patch.object(cp, "_validate", return_value=False):
            r = cp.verify_current_user("t", "m")
            self.assertEqual(r.outcome, cp.FAILED)
            self.assertEqual(cp.verify_current_user("t", "m").outcome, cp.BUSY)   # cool-down
        cp._last_failure_at = 0.0
        with mock.patch.object(cp, "IS_WINDOWS", True), mock.patch.object(cp, "_show_prompt", return_value=None):
            self.assertEqual(cp.verify_current_user("t", "m").outcome, cp.CANCELLED)


if __name__ == "__main__":
    unittest.main()
