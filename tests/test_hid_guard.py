"""HID guard logic tests (pure Python; the Win32 layer needs a real Windows box)."""
import sys, unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scanners import hid_guard as hg

A = 0x41  # virtual-key codes are irrelevant to speed; any non-modifier works


def type_keys(tracker, dev, times, vk_cycle=range(0x41, 0x5A)):
    """Feed key press+release pairs at the given timestamps; return first verdict (or None)."""
    vks = list(vk_cycle)
    for i, t in enumerate(times):
        vk = vks[i % len(vks)]
        v = tracker.on_key(dev, vk, False, t)
        tracker.on_key(dev, vk, True, t + 0.001)
        if v:
            return v
    return None


class TrackerTests(unittest.TestCase):
    def test_normal_typist_60wpm_never_flagged(self):
        t = hg.TypingSpeedTracker()
        self.assertIsNone(type_keys(t, "kb", [i * 0.2 for i in range(300)]))       # 5 keys/s = 60 WPM

    def test_fast_human_short_burst_not_flagged(self):
        t = hg.TypingSpeedTracker()
        self.assertIsNone(type_keys(t, "kb", [i * 0.11 for i in range(18)]))       # ~110 WPM for under 2 s

    def test_sustained_120wpm_flagged(self):
        t = hg.TypingSpeedTracker()
        v = type_keys(t, "kb", [i * 0.1 for i in range(100)])                      # 10 keys/s = 120 WPM
        self.assertIsNotNone(v); self.assertEqual(v.rule, "sustained_wpm"); self.assertGreater(v.wpm, 100)

    def test_just_under_100wpm_not_flagged(self):
        t = hg.TypingSpeedTracker()
        self.assertIsNone(type_keys(t, "kb", [i * 0.125 for i in range(200)]))     # 8 keys/s = 96 WPM, sustained

    def test_rubber_ducky_caught_after_ten_keys(self):
        t = hg.TypingSpeedTracker()
        v = type_keys(t, "kb", [i * 0.002 for i in range(200)])                    # 500 keys/s
        self.assertEqual(v.rule, "burst"); self.assertLessEqual(v.keystrokes, 10)

    def test_slow_ducky_above_threshold_caught_by_wpm_rule(self):
        t = hg.TypingSpeedTracker()
        v = type_keys(t, "kb", [i * 0.05 for i in range(200)])                     # 20 keys/s = 240 WPM
        self.assertEqual(v.rule, "sustained_wpm")

    def test_held_key_autorepeat_ignored(self):
        t = hg.TypingSpeedTracker()
        for i in range(300):                                                       # 30 repeats/s, no release
            self.assertIsNone(t.on_key("kb", A, False, i / 30))

    def test_modifiers_ignored(self):
        t = hg.TypingSpeedTracker()
        for i in range(200):
            self.assertIsNone(t.on_key("kb", 0xA0, False, i * 0.001))              # left shift spam

    def test_devices_tracked_independently(self):
        t = hg.TypingSpeedTracker()
        slow = [i * 0.3 for i in range(100)]
        for i, ts in enumerate(slow):
            self.assertIsNone(t.on_key("human", 0x41 + i % 20, False, ts))
            t.on_key("human", 0x41 + i % 20, True, ts + .01)
        self.assertIsNotNone(type_keys(t, "ducky", [100 + i * 0.002 for i in range(50)]))


class ParseTests(unittest.TestCase):
    def test_usb_hid_path(self):
        p = hg.parse_device_path(r"\\?\HID#VID_046D&PID_C52B&MI_00#7&2a1b3c&0&0000#{884b96c3-56ef-11d1-bc8c-00a0c91405dd}")
        self.assertEqual(p["vid_pid"], "VID_046D&PID_C52B")
        self.assertEqual(p["instance_id"], r"HID\VID_046D&PID_C52B&MI_00\7&2A1B3C&0&0000")
        self.assertTrue(p["is_usb"] and hg._SAFE_INSTANCE_RE.match(p["instance_id"]))

    def test_non_usb_keyboard_is_not_watched(self):
        self.assertFalse(hg.parse_device_path(r"\\?\ACPI#MSFT0001#3&13c0b0c5&0#{884b96c3}")["is_usb"])

    def test_pnputil_refuses_when_not_elevated_or_unsafe(self):
        with mock.patch.object(hg, "IS_WINDOWS", True), mock.patch.object(hg, "is_elevated", return_value=False):
            ok, msg = hg._pnputil("/disable-device", r"USB\VID_1&PID_2\x")
            self.assertFalse(ok); self.assertIn("Administrator", msg)
        with mock.patch.object(hg, "IS_WINDOWS", True), mock.patch.object(hg, "is_elevated", return_value=True):
            self.assertFalse(hg._pnputil("/disable-device", "x & calc.exe")[0])


class GuardFlowTests(unittest.TestCase):
    def setUp(self):
        self.store = {}
        for name, val in (("_load_list", lambda k: list(self.store.get(k, []))),
                          ("_save_list", lambda k, v: self.store.__setitem__(k, v))):
            p = mock.patch.object(hg, name, side_effect=val); p.start(); self.addCleanup(p.stop)
        self.alerts = []
        self.g = hg.HIDGuard(on_alert=self.alerts.append)
        self.g._engage_lockdown = mock.Mock()
        self.g._disable_and_notify = lambda alert: self.alerts.append(alert)   # skip pnputil thread

    def add(self, handle, **kw):
        dev = {"handle": handle, "path": "p", "vid_pid": "VID_1&PID_2", "instance_id": r"HID\VID_1&PID_2\x",
               "is_usb": True, "arrived_at": __import__("time").monotonic(), "watched": True,
               "flagged": False, "previously_blocked": False, **kw}
        self.g._devices[handle] = dev; return dev

    def blast(self, handle, n=40):
        for i in range(n):
            self.g._on_key(handle, 0x41 + i % 20, False); self.g._on_key(handle, 0x41 + i % 20, True)

    def test_new_fast_keyboard_is_flagged_and_locked_down(self):
        dev = self.add(1); self.blast(1)
        self.assertTrue(dev["flagged"]); self.g._engage_lockdown.assert_called()
        self.assertEqual(len(self.g.alerts()), 1)
        self.assertIn("VID_1&PID_2", self.store["hid_blocked_devices"])

    def test_baseline_keyboard_never_flagged(self):
        dev = self.add(2, watched=False); self.blast(2)
        self.assertFalse(dev["flagged"]); self.assertEqual(self.g.alerts(), [])

    def test_flagged_device_keeps_locking_down(self):
        self.add(3); self.blast(3); calls = self.g._engage_lockdown.call_count
        self.g._on_key(3, 0x41, False)
        self.assertGreater(self.g._engage_lockdown.call_count, calls)

    def test_previously_blocked_device_flagged_on_first_key(self):
        dev = self.add(4, previously_blocked=True); self.g._on_key(4, 0x41, False)
        self.assertTrue(dev["flagged"])

    def test_trust_clears_block(self):
        self.add(5); self.blast(5)
        aid = self.g.alerts()[0]["id"]
        with mock.patch.object(hg, "_pnputil", return_value=(True, "")):
            self.assertTrue(self.g.trust_device(aid)["success"])
        self.assertIn("VID_1&PID_2", self.store["hid_trusted_devices"])
        self.assertNotIn("VID_1&PID_2", self.store["hid_blocked_devices"])
        self.assertFalse(self.g._devices[5]["watched"])


if __name__ == "__main__":
    unittest.main()
