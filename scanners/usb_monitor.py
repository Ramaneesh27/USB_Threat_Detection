"""
LEVEL 0 - Automatic USB detection.

Polls Windows removable drives with psutil/win32 APIs (falling back to
pure psutil where pywin32 isn't available) and fires a callback the
instant a new removable volume appears. No manual drive selection is
ever required - insertion alone triggers the callback chain that starts
a scan in app.py.
"""

from __future__ import annotations

import ctypes
import platform
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Optional

import psutil

import config
from utils.logger import get_logger

logger = get_logger(__name__)

_IS_WINDOWS = platform.system() == "Windows"

DRIVE_REMOVABLE = 2  # GetDriveType() return value for removable media


@dataclass
class USBDeviceInfo:
    drive_letter: str
    label: str
    capacity_bytes: int
    used_bytes: int
    file_system: str
    connected_time: str

    @property
    def capacity_human(self) -> str:
        return _human_bytes(self.capacity_bytes)

    @property
    def used_human(self) -> str:
        return _human_bytes(self.used_bytes)

    def to_dict(self) -> dict:
        return {
            "drive_letter": self.drive_letter,
            "label": self.label or "Removable Disk",
            "capacity_bytes": self.capacity_bytes,
            "capacity_human": self.capacity_human,
            "used_bytes": self.used_bytes,
            "used_human": self.used_human,
            "file_system": self.file_system,
            "connected_time": self.connected_time,
        }


def _human_bytes(n: int) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024.0:
            return f"{value:.2f} {unit}"
        value /= 1024.0
    return f"{value:.2f} PB"


def _get_volume_label(drive_letter: str) -> str:
    """Read the Windows volume label for a drive, e.g. 'D:\\' -> 'KINGSTON'."""
    if not _IS_WINDOWS:
        return ""
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        volume_name_buf = ctypes.create_unicode_buffer(261)
        fs_name_buf = ctypes.create_unicode_buffer(261)
        ok = kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(drive_letter), volume_name_buf, ctypes.sizeof(volume_name_buf),
            None, None, None, fs_name_buf, ctypes.sizeof(fs_name_buf),
        )
        if ok:
            return volume_name_buf.value
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not read volume label for %s: %s", drive_letter, exc)
    return ""


def _is_removable_drive(drive_letter: str) -> bool:
    """True only for actual removable media - internal drives are always ignored."""
    if not _IS_WINDOWS:
        return False
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        drive_type = kernel32.GetDriveTypeW(ctypes.c_wchar_p(drive_letter))
        return drive_type == DRIVE_REMOVABLE
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not determine drive type for %s: %s", drive_letter, exc)
        return False


def _enumerate_removable_drives() -> dict[str, USBDeviceInfo]:
    """Build a snapshot of every currently-connected removable drive."""
    drives: dict[str, USBDeviceInfo] = {}
    for part in psutil.disk_partitions(all=False):
        mountpoint = part.mountpoint
        if not mountpoint:
            continue
        if _IS_WINDOWS and not _is_removable_drive(mountpoint):
            continue
        if not _IS_WINDOWS and "removable" not in (part.opts or "").lower():
            # Non-Windows dev/test environments: best-effort filter only.
            continue
        try:
            usage = psutil.disk_usage(mountpoint)
        except (PermissionError, FileNotFoundError, OSError) as exc:
            logger.debug("Skipping unreadable drive %s: %s", mountpoint, exc)
            continue

        drives[mountpoint] = USBDeviceInfo(
            drive_letter=mountpoint,
            label=_get_volume_label(mountpoint),
            capacity_bytes=usage.total,
            used_bytes=usage.used,
            file_system=part.fstype or "unknown",
            connected_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
    return drives


class USBMonitor:
    """
    Background poller that watches for removable drives being plugged in
    or removed and invokes callbacks with zero manual interaction.
    """

    def __init__(
        self,
        on_connect: Callable[[USBDeviceInfo], None],
        on_disconnect: Optional[Callable[[str], None]] = None,
        poll_interval: float = config.USB_POLL_INTERVAL_SECONDS,
    ) -> None:
        self._on_connect = on_connect
        self._on_disconnect = on_disconnect
        self._poll_interval = poll_interval
        self._known: dict[str, USBDeviceInfo] = {}
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            logger.warning("USB monitor already running")
            return
        self._known = _enumerate_removable_drives()
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="USBMonitorThread", daemon=True)
        self._thread.start()
        logger.info("USB monitor started (baseline: %d removable drive(s))", len(self._known))

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("USB monitor stopped")

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                current = _enumerate_removable_drives()

                for drive_letter, info in current.items():
                    if drive_letter not in self._known:
                        logger.info("USB device connected: %s (%s)", drive_letter, info.label)
                        self._known[drive_letter] = info
                        self._on_connect(info)

                for drive_letter in list(self._known.keys()):
                    if drive_letter not in current:
                        logger.info("USB device disconnected: %s", drive_letter)
                        del self._known[drive_letter]
                        if self._on_disconnect:
                            self._on_disconnect(drive_letter)

            except Exception as exc:  # noqa: BLE001 - monitor must never crash silently
                logger.exception("USB monitor polling error: %s", exc)

            self._stop_event.wait(self._poll_interval)

    def current_devices(self) -> list[dict]:
        return [d.to_dict() for d in self._known.values()]
