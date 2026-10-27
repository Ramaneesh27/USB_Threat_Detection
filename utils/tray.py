"""
System-tray icon (Windows notification area) for background mode.

Uses pystray + Pillow. A single left-click on the icon runs `on_open` (the menu's default
item), the right-click menu offers Open / Exit. start() returns False - instead of raising -
when pystray/Pillow are missing or the icon cannot be created, so callers can tell the user
why background mode is unavailable and leave the window in the taskbar.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional

import config
from utils.logger import get_logger

logger = get_logger(__name__)

try:
    import pystray
    from PIL import Image, ImageDraw
    TRAY_AVAILABLE = True
except ImportError:  # pragma: no cover
    TRAY_AVAILABLE = False


def _load_icon() -> "Image.Image":
    ico = Path(config.RESOURCE_DIR) / "assets" / "app.ico"
    try:
        return Image.open(ico).convert("RGBA").resize((64, 64))
    except Exception:  # noqa: BLE001 - missing/corrupt icon must not disable the tray
        img = Image.new("RGBA", (64, 64), (6, 11, 24, 255))
        ImageDraw.Draw(img).ellipse((12, 12, 52, 52), fill=(0, 200, 160, 255))
        return img


class TrayIcon:
    def __init__(self, on_open: Callable[[], None], on_exit: Callable[[], None],
                 title: str = "USB Threat Analyzer") -> None:
        self._on_open, self._on_exit, self._title = on_open, on_exit, title
        self._icon: Optional["pystray.Icon"] = None

    @property
    def running(self) -> bool:
        return self._icon is not None

    def start(self) -> bool:
        if not TRAY_AVAILABLE:
            logger.warning("pystray/Pillow not installed - system tray unavailable")
            return False
        if self._icon is not None:
            return True
        try:
            menu = pystray.Menu(
                pystray.MenuItem("Open USB Threat Analyzer", lambda icon, item: self._on_open(), default=True),
                pystray.MenuItem("Exit", lambda icon, item: self._on_exit()),
            )
            self._icon = pystray.Icon("USBThreatAnalyzer", _load_icon(), self._title, menu)
            self._icon.run_detached()          # runs its own thread; the window keeps the main one
            logger.info("System tray icon started")
            return True
        except Exception:  # noqa: BLE001
            logger.exception("Could not create the tray icon")
            self._icon = None
            return False

    def stop(self) -> None:
        icon, self._icon = self._icon, None
        if icon is not None:
            try:
                icon.stop()
            except Exception:  # noqa: BLE001
                logger.debug("Tray icon stop failed", exc_info=True)

    def notify(self, title: str, message: str) -> None:
        if self._icon is not None:
            try:
                self._icon.notify(message[:250], title[:60])
            except Exception:  # noqa: BLE001 - notifications are best-effort
                logger.debug("Tray notification failed", exc_info=True)
