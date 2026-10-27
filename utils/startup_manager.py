"""
Startup Manager - optional, user-controlled "Start with Windows" feature.

Scope and safety rules (do not relax these without updating this docstring
and the Settings UI copy together):

  - Only ever touches HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
  - Only ever creates/deletes ONE value, named exactly "USBThreatAnalyzer"
  - Never touches HKLM, the Startup shell folder, Scheduled Tasks, or services
  - Never requires or requests elevation (HKCU never needs admin rights)
  - Never enables itself automatically - persistence is only ever written in
    response to an explicit enable() call from the Settings UI
  - The registry value data is always the real, absolute path to this
    application's own executable/interpreter+script (plus, for the EXE, the
    single documented "--minimized" flag) - never disguised, renamed, or
    pointed at another product's name
  - No obfuscation, no hidden/system attributes on anything this module writes

This module is the ONLY place in the codebase allowed to touch this
registry key. Every other module must go through the functions below
rather than calling winreg directly.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from utils.logger import get_logger

logger = get_logger(__name__)

_RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
_VALUE_NAME = "USBThreatAnalyzer"

try:
    import winreg
    _WINREG_AVAILABLE = True
except ImportError:  # pragma: no cover - non-Windows dev environment
    _WINREG_AVAILABLE = False


class StartupManagerError(Exception):
    """Raised when a startup-registration operation cannot be completed."""


def get_executable_path() -> str:
    """
    Return the absolute path that should be launched at Windows startup.

    - When frozen by PyInstaller (single-file EXE), sys.frozen is True and
      sys.executable IS the application's own EXE - use it directly.
    - When running from source, sys.executable is the Python interpreter,
      so the value must be quoted interpreter-path + quoted script-path so
      Windows launches "python.exe" "app.py" correctly from any directory.
    """
    if getattr(sys, "frozen", False):
        exe_path = Path(sys.executable).resolve()
        if not exe_path.exists():
            raise StartupManagerError(f"Frozen executable path does not exist: {exe_path}")
        # --minimized: at login the app starts in the taskbar (USB monitoring runs
        # as usual) instead of throwing its window in the user's face.
        return f'"{exe_path}" --minimized'

    # Running from source: point at this project's app.py explicitly,
    # not at whatever __main__ happened to be, so the resulting command
    # is correct regardless of how startup_manager.py was imported.
    project_root = Path(__file__).resolve().parent.parent
    entry_script = project_root / "app.py"
    if not entry_script.exists():
        raise StartupManagerError(f"Could not locate app.py at expected path: {entry_script}")

    interpreter = Path(sys.executable).resolve()
    if not interpreter.exists():
        raise StartupManagerError(f"Python interpreter path does not exist: {interpreter}")

    return f'"{interpreter}" "{entry_script}"'


def is_enabled() -> bool:
    """
    Return True if the HKCU Run value for this application currently
    exists. Returns False (never raises) if the Run key or value is
    simply missing - that is the normal "disabled" state, not an error.
    """
    if not _WINREG_AVAILABLE:
        logger.debug("winreg unavailable (non-Windows environment); reporting startup as disabled.")
        return False

    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY_PATH, 0, winreg.KEY_READ)
    except FileNotFoundError:
        return False
    except OSError as exc:
        logger.warning("Could not open HKCU Run key to check startup status: %s", exc)
        return False

    try:
        winreg.QueryValueEx(key, _VALUE_NAME)
        return True
    except FileNotFoundError:
        return False
    except OSError as exc:
        logger.warning("Could not read %s value: %s", _VALUE_NAME, exc)
        return False
    finally:
        winreg.CloseKey(key)


def enable() -> dict:
    """
    Create the REG_SZ startup value pointing at this application's real
    executable/interpreter path. Called ONLY in direct response to the
    user checking the box and clicking Apply in Settings - never
    automatically.

    Returns a result dict: {"success": bool, "message": str, "path": str|None}.
    Never raises to the caller; all failures are reported in the dict so
    the UI can show them without crashing the app.
    """
    if not _WINREG_AVAILABLE:
        return {"success": False, "message": "Windows registry is not available on this platform.", "path": None}

    try:
        exe_path = get_executable_path()
    except StartupManagerError as exc:
        logger.error("Could not resolve executable path for startup registration: %s", exc)
        return {"success": False, "message": str(exc), "path": None}

    try:
        key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, _RUN_KEY_PATH, 0, winreg.KEY_WRITE)
    except PermissionError:
        msg = "Permission denied writing to HKCU Run key. No admin rights should be needed for HKCU - check your account's registry permissions."
        logger.error(msg)
        return {"success": False, "message": msg, "path": None}
    except OSError as exc:
        logger.error("Could not open/create HKCU Run key: %s", exc)
        return {"success": False, "message": f"Could not access the registry: {exc}", "path": None}

    try:
        winreg.SetValueEx(key, _VALUE_NAME, 0, winreg.REG_SZ, exe_path)
        logger.info("Startup enabled: HKCU\\%s\\%s = %s", _RUN_KEY_PATH, _VALUE_NAME, exe_path)
        return {"success": True, "message": "USB Threat Analyzer will now start when you log in to Windows.", "path": exe_path}
    except OSError as exc:
        logger.error("Could not write startup registry value: %s", exc)
        return {"success": False, "message": f"Could not write the registry value: {exc}", "path": None}
    finally:
        winreg.CloseKey(key)


def disable() -> dict:
    """
    Delete ONLY this application's own value from the HKCU Run key. Never
    touches any other value under that key. Treats "already absent" as
    success, since the end state the user wants (not present) is already
    true.
    """
    if not _WINREG_AVAILABLE:
        return {"success": False, "message": "Windows registry is not available on this platform."}

    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY_PATH, 0, winreg.KEY_WRITE)
    except FileNotFoundError:
        logger.info("Startup disable requested but Run key does not exist; nothing to do.")
        return {"success": True, "message": "Startup was already disabled."}
    except PermissionError:
        msg = "Permission denied accessing HKCU Run key."
        logger.error(msg)
        return {"success": False, "message": msg}
    except OSError as exc:
        logger.error("Could not open HKCU Run key for disable: %s", exc)
        return {"success": False, "message": f"Could not access the registry: {exc}"}

    try:
        winreg.DeleteValue(key, _VALUE_NAME)
        logger.info("Startup disabled: removed HKCU\\%s\\%s", _RUN_KEY_PATH, _VALUE_NAME)
        return {"success": True, "message": "USB Threat Analyzer will no longer start automatically with Windows."}
    except FileNotFoundError:
        logger.info("Startup value already absent; nothing to remove.")
        return {"success": True, "message": "Startup was already disabled."}
    except OSError as exc:
        logger.error("Could not delete startup registry value: %s", exc)
        return {"success": False, "message": f"Could not remove the registry value: {exc}"}
    finally:
        winreg.CloseKey(key)


def get_status() -> dict:
    """Convenience combined read used by the Settings page on load/refresh."""
    enabled = is_enabled()
    path: Optional[str] = None
    if enabled and _WINREG_AVAILABLE:
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY_PATH, 0, winreg.KEY_READ)
            path, _ = winreg.QueryValueEx(key, _VALUE_NAME)
            winreg.CloseKey(key)
        except OSError:
            path = None
    return {
        "enabled": enabled,
        "registered_path": path,
        "value_name": _VALUE_NAME,
        "key_path": f"HKCU\\{_RUN_KEY_PATH}",
        "platform_supported": _WINREG_AVAILABLE,
    }
