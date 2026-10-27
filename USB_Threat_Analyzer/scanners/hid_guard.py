"""
BadUSB / HID keystroke-injection guard.

A "Rubber Ducky" or similar BadUSB device enumerates as an ordinary keyboard and then
types a payload far faster than any person can. This module watches every keyboard that
appears AFTER the app started and flags one that types faster than
config.HID_WPM_THRESHOLD (default 100 WPM).

How it works
------------
* Windows Raw Input (RegisterRawInputDevices with RIDEV_INPUTSINK | RIDEV_DEVNOTIFY) gives
  two things no hook can: a notification the moment a new keyboard is enumerated, and the
  identity of the DEVICE behind every keystroke, so a fast rogue keyboard is told apart from
  the user's own.
* Only timing is used. Key contents are never stored or logged; the virtual-key code is used
  solely to ignore modifiers and held-key auto-repeat.
* Detection lives in TypingSpeedTracker (pure Python, no Windows calls, unit-tested).

What "block" means - read this, it is a real limit of user-mode software
-------------------------------------------------------------------------
Windows gives a normal program no way to drop one specific keyboard's keystrokes while
letting another through. So the response is layered:

 1. Instant lockdown (always): for HID_LOCKDOWN_SECONDS a temporary low-level keyboard hook
    swallows HARDWARE keystrokes system-wide. Software-injected input (the on-screen
    keyboard, SendInput) is NOT swallowed, so the user can still work with mouse + OSK.
    The hook exists only during a lockdown, never permanently. It is re-armed whenever a
    flagged device types again.
 2. Disable the device (only if this process is elevated): `pnputil /disable-device` on the
    physical USB device, which stops the keystrokes for good. This app deliberately does NOT
    pop a UAC prompt mid-attack: the attacking keyboard is real hardware and could answer
    "Yes" on the secure desktop. To enable this layer, run the app as Administrator
    (or build the EXE with uac_admin=True).
 3. Remember the VID/PID, so the same device is treated as hostile the moment it is plugged
    in again. The user can override with trust_device().

Unavoidable: the keystrokes typed BEFORE detection get through (at most ~10 for a typical
Rubber Ducky, up to one window's worth for a slower one). No user-mode tool can change that;
only a kernel filter driver could.
"""

from __future__ import annotations

import ctypes
import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Optional

import config
from utils.logger import get_logger

logger = get_logger(__name__)

IS_WINDOWS = sys.platform == "win32"

# Virtual keys that never produce a character (modifiers / locks). Ignored for WPM.
_NON_CHAR_VKS = frozenset({0x10, 0x11, 0x12, 0x14, 0x5B, 0x5C, 0x90, 0x91,
                           0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xFF})

_MASK64 = (1 << 64) - 1
_VIDPID_RE = re.compile(r"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", re.I)
_SAFE_INSTANCE_RE = re.compile(r"^[A-Za-z0-9_&\\\-\.\{\}]+$")


# ---------------------------------------------------------------------------
# Pure logic - no Windows calls
# ---------------------------------------------------------------------------
@dataclass
class SpeedVerdict:
    rule: str            # "sustained_wpm" or "burst"
    wpm: int
    keystrokes: int
    span_seconds: float


class TypingSpeedTracker:
    """
    Per-device typing-speed detector.

    Rule 1 (the requirement): more than `wpm_threshold` words per minute sustained over
    `window_seconds`. Standard definition: 1 word = 5 characters.
        wpm = (keys_in_window / 5) * (60 / window_seconds)
    With the defaults (100 WPM, 3 s window) that means 26+ key presses inside 3 seconds,
    and at least `min_keys` of them, so a short burst from a fast typist never trips it.

    Rule 2 (early catch for extreme devices): `burst_keys` key presses whose average gap is
    under `burst_max_gap` seconds (about 800+ WPM, physically impossible for a person).
    A Rubber Ducky at full speed is caught after ~10 characters instead of ~26.

    Held-key auto-repeat, modifier keys and key releases are not counted.
    """

    def __init__(self, wpm_threshold: float = config.HID_WPM_THRESHOLD,
                 window_seconds: float = config.HID_WINDOW_SECONDS,
                 min_keys: int = config.HID_MIN_KEYSTROKES,
                 burst_keys: int = 10, burst_max_gap: float = 0.015) -> None:
        self.wpm_threshold = wpm_threshold
        self.window = window_seconds
        self.min_keys = min_keys
        self.burst_keys = burst_keys
        self.burst_max_gap = burst_max_gap
        self._stamps: dict[object, deque] = {}
        self._down: dict[object, set] = {}

    def forget(self, device: object) -> None:
        self._stamps.pop(device, None)
        self._down.pop(device, None)

    def on_key(self, device: object, vk: int, is_break: bool, now: float) -> Optional[SpeedVerdict]:
        down = self._down.setdefault(device, set())
        if is_break:
            down.discard(vk)
            return None
        if vk in _NON_CHAR_VKS:
            return None
        if vk in down:               # auto-repeat of a key that is still held
            return None
        down.add(vk)

        stamps = self._stamps.setdefault(device, deque())
        stamps.append(now)
        while stamps and now - stamps[0] >= self.window:   # half-open window (now-W, now]
            stamps.popleft()

        n = len(stamps)
        span = max(stamps[-1] - stamps[0], 0.001)
        wpm_window = (n / 5.0) * (60.0 / self.window)
        if n >= self.min_keys and wpm_window > self.wpm_threshold:
            return SpeedVerdict("sustained_wpm", int(wpm_window), n, round(span, 3))
        if n >= self.burst_keys:
            recent = list(stamps)[-self.burst_keys:]
            gap = (recent[-1] - recent[0]) / (self.burst_keys - 1)
            if gap < self.burst_max_gap:
                est = int((self.burst_keys / 5.0) * 60.0 / max(recent[-1] - recent[0], 0.001))
                return SpeedVerdict("burst", est, self.burst_keys, round(recent[-1] - recent[0], 4))
        return None


def parse_device_path(path: str) -> dict:
    """
    '\\\\?\\HID#VID_046D&PID_C52B&MI_00#7&2a1b3c&0&0000#{guid}'
        -> {'vid_pid': 'VID_046D&PID_C52B', 'instance_id': 'HID\\VID_046D&PID_C52B&MI_00\\7&2A1B3C&0&0000',
            'is_usb': True}
    """
    cleaned = path[4:] if path.startswith("\\\\?\\") else path
    parts = cleaned.split("#")
    m = _VIDPID_RE.search(cleaned)
    instance = "\\".join(parts[:3]).upper() if len(parts) >= 3 else ""
    return {
        "vid_pid": f"VID_{m.group(1).upper()}&PID_{m.group(2).upper()}" if m else "",
        "instance_id": instance,
        "is_usb": bool(m),
    }


# ---------------------------------------------------------------------------
# Device disabling (needs Administrator)
# ---------------------------------------------------------------------------
def is_elevated() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return False


def _physical_usb_instance(instance_id: str) -> str:
    """Walk up the device tree from the HID interface to the physical USB device (kills all interfaces)."""
    try:
        cfg = ctypes.WinDLL("cfgmgr32")  # type: ignore[attr-defined]
        devinst = ctypes.c_uint32()
        if cfg.CM_Locate_DevNodeW(ctypes.byref(devinst), ctypes.c_wchar_p(instance_id), 0) != 0:
            return instance_id
        best = instance_id
        for _ in range(4):
            parent = ctypes.c_uint32()
            if cfg.CM_Get_Parent(ctypes.byref(parent), devinst, 0) != 0:
                break
            buf = ctypes.create_unicode_buffer(400)
            if cfg.CM_Get_Device_IDW(parent, buf, 400, 0) != 0:
                break
            if buf.value.upper().startswith("USB\\VID_") and "&MI_" not in buf.value.upper():
                best = buf.value
                break
            devinst = parent
        return best
    except Exception:  # noqa: BLE001
        logger.debug("Could not resolve parent USB device", exc_info=True)
        return instance_id


def _pnputil(flag: str, instance_id: str) -> tuple[bool, str]:
    if not IS_WINDOWS:
        return False, "Device control is only available on Windows."
    if not is_elevated():
        return False, "Run USB Threat Analyzer as Administrator to let it disable devices."
    if not _SAFE_INSTANCE_RE.match(instance_id or ""):
        return False, "Refusing to act on an unexpected device ID."
    exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "pnputil.exe")
    try:
        done = subprocess.run([exe, flag, instance_id], capture_output=True, text=True, timeout=30,
                              creationflags=0x08000000)  # CREATE_NO_WINDOW
        return done.returncode == 0, (done.stdout + done.stderr).strip()[:300]
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)


# ---------------------------------------------------------------------------
# Guard
# ---------------------------------------------------------------------------
class HIDGuard:
    def __init__(self, on_alert: Optional[Callable[[dict], None]] = None,
                 on_new_keyboard: Optional[Callable[[dict], None]] = None) -> None:
        self._on_alert = on_alert
        self._on_new_keyboard = on_new_keyboard
        self._tracker = TypingSpeedTracker()
        self._devices: dict[int, dict] = {}
        self._alerts: deque = deque(maxlen=50)
        self._lock = threading.RLock()
        self._thread: Optional[threading.Thread] = None
        self._ready = threading.Event()
        self._hwnd = None
        self._lockdown_until = 0.0
        self._hook = None
        self._running = False

    # ---- public API -------------------------------------------------------
    def start(self) -> bool:
        if not (IS_WINDOWS and config.HID_GUARD_ENABLED):
            logger.info("HID guard not started (Windows-only / disabled in config)")
            return False
        if self._thread and self._thread.is_alive():
            return True
        self._running = True
        self._thread = threading.Thread(target=self._run, name="HIDGuardThread", daemon=True)
        self._thread.start()
        return self._ready.wait(5)

    def stop(self) -> None:
        self._running = False
        if IS_WINDOWS and self._hwnd:
            _u32.PostMessageW(self._hwnd, 0x0010, 0, 0)  # WM_CLOSE
        if self._thread:
            self._thread.join(timeout=3)

    def alerts(self) -> list[dict]:
        with self._lock:
            return list(self._alerts)

    def status(self) -> dict:
        with self._lock:
            watching = [{"vid_pid": d["vid_pid"], "path": d["path"]} for d in self._devices.values()
                        if d["watched"] and not d["flagged"]]
        return {"running": self._running and bool(self._thread and self._thread.is_alive()),
                "can_disable_devices": is_elevated(), "watching": watching,
                "lockdown_active": time.monotonic() < self._lockdown_until,
                "wpm_threshold": config.HID_WPM_THRESHOLD}

    def trust_device(self, alert_id: str) -> dict:
        """User says 'this is my keyboard': trust its VID/PID and re-enable it if we disabled it."""
        with self._lock:
            alert = next((a for a in self._alerts if a["id"] == alert_id), None)
            if not alert:
                return {"success": False, "message": "Unknown alert."}
            vid_pid = alert["vid_pid"]
            for dev in self._devices.values():
                if dev["vid_pid"] == vid_pid:
                    dev.update(flagged=False, watched=False)
                    self._tracker.forget(dev["handle"])
        _save_list(_TRUSTED_KEY, sorted(set(_load_list(_TRUSTED_KEY)) | {vid_pid}))
        _save_list(_BLOCKED_KEY, [v for v in _load_list(_BLOCKED_KEY) if v != vid_pid])
        message = "Device trusted."
        if alert.get("disabled"):
            ok, detail = _pnputil("/enable-device", alert.get("disabled_instance", ""))
            message += " Device re-enabled." if ok else f" Could not re-enable it automatically ({detail}); replug it."
        alert["trusted"] = True
        return {"success": True, "message": message}

    # ---- event handling (runs on the guard thread) -----------------------
    def _register_device(self, handle: int, *, baseline: bool) -> Optional[dict]:
        handle &= _MASK64
        path = _device_name(handle)
        if not path:
            return None
        info = parse_device_path(path)
        trusted = info["vid_pid"] in _load_list(_TRUSTED_KEY)
        blocked = info["vid_pid"] in _load_list(_BLOCKED_KEY)
        dev = {"handle": handle, "path": path, **info, "arrived_at": time.monotonic(),
               "watched": bool(info["is_usb"] and not baseline and not trusted),
               "flagged": False, "previously_blocked": blocked and not trusted}
        with self._lock:
            self._devices[handle] = dev
        if dev["watched"]:
            logger.info("New USB keyboard %s - monitoring its typing speed", info["vid_pid"])
            if self._on_new_keyboard:
                self._safe(self._on_new_keyboard, {"vid_pid": info["vid_pid"]})
        return dev

    def _on_key(self, handle: int, vk: int, is_break: bool) -> None:
        handle &= _MASK64
        with self._lock:
            dev = self._devices.get(handle)
        if dev is None:
            # A device we never saw arrive: treat as pre-existing (never lock the user's own keyboard).
            dev = self._register_device(handle, baseline=True)
            if dev is None:
                return
        if dev["flagged"]:
            if not is_break:
                self._engage_lockdown()          # still typing: keep swallowing
            return
        if not dev["watched"]:
            return
        if config.HID_WATCH_SECONDS and time.monotonic() - dev["arrived_at"] > config.HID_WATCH_SECONDS:
            dev["watched"] = False
            self._tracker.forget(handle)
            return
        if dev["previously_blocked"] and not is_break:
            self._flag(dev, SpeedVerdict("known_bad_device", 0, 0, 0.0))
            return
        verdict = self._tracker.on_key(handle, vk, is_break, time.monotonic())
        if verdict:
            self._flag(dev, verdict)

    def _flag(self, dev: dict, verdict: SpeedVerdict) -> None:
        dev["flagged"] = True
        self._engage_lockdown()
        alert = {
            "id": uuid.uuid4().hex[:10], "time": datetime.now().isoformat(timespec="seconds"),
            "vid_pid": dev["vid_pid"], "instance_id": dev["instance_id"], "device_path": dev["path"],
            "rule": verdict.rule, "wpm": verdict.wpm, "keystrokes": verdict.keystrokes,
            "message": (f"A keyboard that was just plugged in ({dev['vid_pid']}) typed at about "
                        f"{verdict.wpm} WPM - faster than any person can. Treated as a rogue "
                        f"(BadUSB) device.") if verdict.rule != "known_bad_device" else
                       f"A previously blocked device ({dev['vid_pid']}) was plugged in again.",
            "actions": ["Keyboard input locked down briefly"], "disabled": False, "trusted": False,
        }
        with self._lock:
            self._alerts.appendleft(alert)
        _save_list(_BLOCKED_KEY, sorted(set(_load_list(_BLOCKED_KEY)) | {dev["vid_pid"]}))
        logger.warning("ROGUE HID DEVICE %s flagged (%s, ~%d WPM, %d keys)",
                       dev["vid_pid"], verdict.rule, verdict.wpm, verdict.keystrokes)
        threading.Thread(target=self._disable_and_notify, args=(alert,), daemon=True,
                         name="HIDDisableThread").start()

    def _disable_and_notify(self, alert: dict) -> None:
        target = _physical_usb_instance(alert["instance_id"]) if alert["instance_id"] else ""
        ok, detail = _pnputil("/disable-device", target) if target else (False, "No device ID available.")
        if ok:
            alert.update(disabled=True, disabled_instance=target)
            alert["actions"].append("Device disabled in Windows")
            alert["message"] += " The device has been disabled."
        else:
            alert["actions"].append("Could not disable device automatically")
            alert["message"] += f" Unplug it now. ({detail})"
        if self._on_alert:
            self._safe(self._on_alert, alert)

    @staticmethod
    def _safe(fn, *args) -> None:
        try:
            fn(*args)
        except Exception:  # noqa: BLE001 - a UI callback must never kill the guard
            logger.exception("HID guard callback failed")

    # ---- lockdown hook (only exists while a lockdown is active) ----------
    def _engage_lockdown(self) -> None:
        self._lockdown_until = time.monotonic() + config.HID_LOCKDOWN_SECONDS
        if self._hook:
            return
        self._hook_proc = _HOOKPROC(self._ll_keyboard)           # keep a reference
        self._hook = _u32.SetWindowsHookExW(13, self._hook_proc, _k32.GetModuleHandleW(None), 0)  # WH_KEYBOARD_LL
        if not self._hook:
            logger.error("Could not install lockdown hook (error %d)", ctypes.get_last_error())

    def _release_lockdown_if_due(self) -> None:
        if self._hook and time.monotonic() >= self._lockdown_until:
            _u32.UnhookWindowsHookEx(self._hook)
            self._hook = None
            logger.info("Keyboard lockdown released")

    def _ll_keyboard(self, n_code, w_param, l_param):
        if n_code == 0 and time.monotonic() < self._lockdown_until:
            flags = ctypes.cast(l_param, ctypes.POINTER(_KBDLLHOOKSTRUCT))[0].flags
            if not flags & 0x10:          # LLKHF_INJECTED: let on-screen keyboard / SendInput through
                return 1
        return _u32.CallNextHookEx(None, n_code, w_param, l_param)

    # ---- Win32 message window --------------------------------------------
    def _run(self) -> None:
        wnd_proc = _WNDPROC(self._wnd_proc)
        hinst = _k32.GetModuleHandleW(None)
        wc = _WNDCLASSW()
        wc.lpfnWndProc, wc.hInstance, wc.lpszClassName = wnd_proc, hinst, "USBThreatAnalyzerHID"
        _u32.RegisterClassW(ctypes.byref(wc))
        self._hwnd = _u32.CreateWindowExW(0, wc.lpszClassName, "hid", 0, 0, 0, 0, 0,
                                            ctypes.c_void_p(-3), None, hinst, None)  # HWND_MESSAGE
        if not self._hwnd:
            logger.error("HID guard could not create its message window")
            self._ready.set()
            return

        rid = _RAWINPUTDEVICE(0x01, 0x06, 0x100 | 0x2000, self._hwnd)   # keyboards, INPUTSINK | DEVNOTIFY
        if not _u32.RegisterRawInputDevices(ctypes.byref(rid), 1, ctypes.sizeof(rid)):
            logger.error("RegisterRawInputDevices failed (error %d)", ctypes.get_last_error())
            self._ready.set()
            return

        for handle in _list_keyboards():                   # baseline: keyboards already attached are never watched
            self._register_device(handle, baseline=True)
        _u32.SetTimer(self._hwnd, 1, 250, None)          # lockdown expiry check
        logger.info("HID guard running (%d baseline keyboard(s), threshold %d WPM)",
                    len(self._devices), config.HID_WPM_THRESHOLD)
        self._ready.set()

        msg = _MSG()
        while _u32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            _u32.TranslateMessage(ctypes.byref(msg))
            _u32.DispatchMessageW(ctypes.byref(msg))
        if self._hook:
            _u32.UnhookWindowsHookEx(self._hook)
            self._hook = None

    def _wnd_proc(self, hwnd, msg, w_param, l_param):
        try:
            if msg == 0x00FF:                                     # WM_INPUT
                self._handle_raw_input(l_param)
            elif msg == 0x00FE:                                   # WM_INPUT_DEVICE_CHANGE
                if w_param == 1:                                  # GIDC_ARRIVAL
                    self._register_device(l_param, baseline=False)
                elif w_param == 2:                                # GIDC_REMOVAL
                    with self._lock:
                        self._devices.pop(l_param & _MASK64, None)
                    self._tracker.forget(l_param & _MASK64)
            elif msg == 0x0113:                                   # WM_TIMER
                self._release_lockdown_if_due()
            elif msg == 0x0002:                                   # WM_DESTROY
                _u32.PostQuitMessage(0)
                return 0
            elif msg == 0x0010:                                   # WM_CLOSE
                _u32.DestroyWindow(hwnd)
                return 0
        except Exception:  # noqa: BLE001 - never let an exception unwind into Win32
            logger.exception("HID guard message handler error")
        return _u32.DefWindowProcW(hwnd, msg, w_param, l_param)

    def _handle_raw_input(self, h_raw) -> None:
        size = ctypes.c_uint(0)
        hdr = ctypes.sizeof(_RAWINPUTHEADER)
        _u32.GetRawInputData(h_raw, 0x10000003, None, ctypes.byref(size), hdr)   # RID_INPUT
        if not size.value:
            return
        buf = ctypes.create_string_buffer(size.value)
        if _u32.GetRawInputData(h_raw, 0x10000003, buf, ctypes.byref(size), hdr) != size.value:
            return
        raw = ctypes.cast(buf, ctypes.POINTER(_RAWINPUT))[0]
        if raw.header.dwType != 1:                                # RIM_TYPEKEYBOARD
            return
        self._on_key(raw.header.hDevice or 0, raw.keyboard.VKey, bool(raw.keyboard.Flags & 1))  # RI_KEY_BREAK


# ---------------------------------------------------------------------------
# Win32 structures / helpers (defined only on Windows)
# ---------------------------------------------------------------------------
if IS_WINDOWS:
    from ctypes import wintypes as _wt

    _WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, ctypes.c_void_p, ctypes.c_uint, ctypes.c_size_t, ctypes.c_ssize_t)
    _HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, ctypes.c_int, ctypes.c_size_t, ctypes.c_ssize_t)

    class _WNDCLASSW(ctypes.Structure):
        _fields_ = [("style", ctypes.c_uint), ("lpfnWndProc", _WNDPROC), ("cbClsExtra", ctypes.c_int),
                    ("cbWndExtra", ctypes.c_int), ("hInstance", ctypes.c_void_p), ("hIcon", ctypes.c_void_p),
                    ("hCursor", ctypes.c_void_p), ("hbrBackground", ctypes.c_void_p),
                    ("lpszMenuName", ctypes.c_wchar_p), ("lpszClassName", ctypes.c_wchar_p)]

    class _RAWINPUTDEVICE(ctypes.Structure):
        _fields_ = [("usUsagePage", ctypes.c_ushort), ("usUsage", ctypes.c_ushort),
                    ("dwFlags", ctypes.c_uint), ("hwndTarget", ctypes.c_void_p)]

    class _RAWINPUTHEADER(ctypes.Structure):
        _fields_ = [("dwType", ctypes.c_uint), ("dwSize", ctypes.c_uint),
                    ("hDevice", ctypes.c_void_p), ("wParam", ctypes.c_size_t)]

    class _RAWKEYBOARD(ctypes.Structure):
        _fields_ = [("MakeCode", ctypes.c_ushort), ("Flags", ctypes.c_ushort), ("Reserved", ctypes.c_ushort),
                    ("VKey", ctypes.c_ushort), ("Message", ctypes.c_uint), ("ExtraInformation", ctypes.c_ulong)]

    class _RAWINPUT(ctypes.Structure):
        _fields_ = [("header", _RAWINPUTHEADER), ("keyboard", _RAWKEYBOARD)]

    class _RAWINPUTDEVICELIST(ctypes.Structure):
        _fields_ = [("hDevice", ctypes.c_void_p), ("dwType", ctypes.c_uint)]

    class _KBDLLHOOKSTRUCT(ctypes.Structure):
        _fields_ = [("vkCode", ctypes.c_uint), ("scanCode", ctypes.c_uint), ("flags", ctypes.c_uint),
                    ("time", ctypes.c_uint), ("dwExtraInfo", ctypes.c_size_t)]

    _MSG = _wt.MSG
    _V, _UI, _SZ, _SSZ = ctypes.c_void_p, ctypes.c_uint, ctypes.c_size_t, ctypes.c_ssize_t

    # Private DLL handles so our argtypes never collide with other modules' use of user32.
    _u32 = ctypes.WinDLL("user32", use_last_error=True)
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.GetModuleHandleW.argtypes, _k32.GetModuleHandleW.restype = [ctypes.c_wchar_p], _V
    _u32.DefWindowProcW.argtypes, _u32.DefWindowProcW.restype = [_V, _UI, _SZ, _SSZ], _SSZ
    _u32.CreateWindowExW.argtypes = [_UI, ctypes.c_wchar_p, ctypes.c_wchar_p, _UI, ctypes.c_int, ctypes.c_int,
                                     ctypes.c_int, ctypes.c_int, _V, _V, _V, _V]
    _u32.CreateWindowExW.restype = _V
    _u32.RegisterClassW.argtypes = [ctypes.POINTER(_WNDCLASSW)]
    _u32.DestroyWindow.argtypes = [_V]
    _u32.PostMessageW.argtypes = [_V, _UI, _SZ, _SSZ]
    _u32.SetTimer.argtypes, _u32.SetTimer.restype = [_V, _SZ, _UI, _V], _SZ
    _u32.GetMessageW.argtypes = [ctypes.POINTER(_MSG), _V, _UI, _UI]
    _u32.TranslateMessage.argtypes = [ctypes.POINTER(_MSG)]
    _u32.DispatchMessageW.argtypes, _u32.DispatchMessageW.restype = [ctypes.POINTER(_MSG)], _SSZ
    _u32.RegisterRawInputDevices.argtypes = [ctypes.POINTER(_RAWINPUTDEVICE), _UI, _UI]
    _u32.GetRawInputData.argtypes, _u32.GetRawInputData.restype = [_V, _UI, _V, ctypes.POINTER(_UI), _UI], _UI
    _u32.GetRawInputDeviceInfoW.argtypes = [_V, _UI, _V, ctypes.POINTER(_UI)]
    _u32.GetRawInputDeviceInfoW.restype = _UI
    _u32.GetRawInputDeviceList.argtypes = [_V, ctypes.POINTER(_UI), _UI]
    _u32.GetRawInputDeviceList.restype = _UI
    _u32.SetWindowsHookExW.argtypes, _u32.SetWindowsHookExW.restype = [ctypes.c_int, _HOOKPROC, _V, _UI], _V
    _u32.UnhookWindowsHookEx.argtypes = [_V]
    _u32.CallNextHookEx.argtypes, _u32.CallNextHookEx.restype = [_V, ctypes.c_int, _SZ, _SSZ], _SSZ

    def _device_name(handle: int) -> str:
        n = ctypes.c_uint(0)
        _u32.GetRawInputDeviceInfoW(handle, 0x20000007, None, ctypes.byref(n))   # RIDI_DEVICENAME
        if not n.value:
            return ""
        buf = ctypes.create_unicode_buffer(n.value)
        if _u32.GetRawInputDeviceInfoW(handle, 0x20000007, buf, ctypes.byref(n)) == 0xFFFFFFFF:
            return ""
        return buf.value

    def _list_keyboards() -> list[int]:
        count = ctypes.c_uint(0)
        size = ctypes.sizeof(_RAWINPUTDEVICELIST)
        _u32.GetRawInputDeviceList(None, ctypes.byref(count), size)
        if not count.value:
            return []
        arr = (_RAWINPUTDEVICELIST * count.value)()
        got = _u32.GetRawInputDeviceList(arr, ctypes.byref(count), size)
        return [arr[i].hDevice for i in range(got) if arr[i].dwType == 1 and arr[i].hDevice]


# ---------------------------------------------------------------------------
# Persistent VID/PID lists (app_settings table)
# ---------------------------------------------------------------------------
_TRUSTED_KEY = config.HID_TRUSTED_SETTING_KEY
_BLOCKED_KEY = "hid_blocked_devices"


def _load_list(key: str) -> list[str]:
    import database
    try:
        value = json.loads(database.get_setting(key, "[]") or "[]")
        return [v for v in value if isinstance(v, str)]
    except (ValueError, TypeError):
        return []


def _save_list(key: str, values: list[str]) -> None:
    import database
    database.set_setting(key, json.dumps(values))
