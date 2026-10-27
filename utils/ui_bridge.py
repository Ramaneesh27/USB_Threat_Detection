"""
Tiny thread-safe event bridge between the backend (USB monitor, HID guard, settings API)
and whatever front end is running (desktop.py's native window + tray).

Backend code calls `emit("usb_inserted", device=...)`; desktop.py registers handlers with
`on(...)`. When nothing is registered (plain `python app.py`, tests) emit() is a no-op, so
the backend never depends on the GUI being there.

Events:
    usb_inserted            device: dict        a removable drive was plugged in (scan is starting)
    hid_alert               alert: dict         a rogue keyboard (BadUSB) was detected
    background_mode_changed enabled: bool       the Settings toggle was applied
"""

from __future__ import annotations

import threading
from typing import Callable

from utils.logger import get_logger

logger = get_logger(__name__)

_lock = threading.Lock()
_handlers: dict[str, list[Callable[..., None]]] = {}


def on(event: str, handler: Callable[..., None]) -> None:
    with _lock:
        _handlers.setdefault(event, []).append(handler)


def clear() -> None:
    with _lock:
        _handlers.clear()


def emit(event: str, **payload) -> None:
    with _lock:
        handlers = list(_handlers.get(event, ()))
    for handler in handlers:
        try:
            handler(**payload)
        except Exception:  # noqa: BLE001 - a UI failure must never break scanning or monitoring
            logger.exception("ui_bridge handler for %r failed", event)
