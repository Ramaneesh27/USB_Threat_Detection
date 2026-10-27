"""
USB Threat Analyzer - desktop entry point (the target of the standalone .exe).

Starts everything the dashboard needs and shows it in a native window, so the
user never has to start a server or open a browser:

  1. the Flask app is served by a private in-process HTTP server bound to
     127.0.0.1 on a free, randomly chosen port (no fixed port to collide with),
  2. a random per-launch token gates every request (see app.py), so other
     programs or web pages on the PC cannot drive the local API,
  3. the USB monitor starts,
  4. the dashboard opens in an embedded Microsoft Edge WebView2 window
     (pywebview). Closing the window exits the application - unless the user ticked
     "Run persistently in background" in Settings, in which case minimizing or closing
     hides the window and the app lives on as an icon in the system tray (click it to
     restore the window).
  5. whenever a USB drive is inserted the window pops up (from the tray, the taskbar or
     behind other windows), maximizes, and shows the scan progress.

Flags:
  --minimized   start in the taskbar, or straight into the tray when background mode is on
                (used by "Start with Windows")
  --selftest    verify the packaged build's dependencies, write
                history/selftest.log, exit 0 (ok) or 1 (problem). Used by build_exe.bat.

Run from source with `python desktop.py`; `python app.py` still runs the plain
web server for development.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import logging
import os
import secrets
import sys
import tempfile
import threading
import uuid
import zipfile
from pathlib import Path

import config
import database
from utils import tray as tray_mod
from utils import ui_bridge
from utils.logger import get_logger

logger = get_logger("desktop")

WINDOW_TITLE = "USB Threat Analyzer"
_MUTEX_NAME = "Local\\USBThreatAnalyzer.SingleInstance"
_WEBVIEW2_GUID = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
_WEBVIEW2_DOWNLOAD_URL = "https://go.microsoft.com/fwlink/p/?LinkId=2124703"

_MB_OK, _MB_YESNO, _MB_ICONERROR, _MB_ICONINFO, _IDYES = 0x0, 0x4, 0x10, 0x40, 6


def _message_box(text: str, *, yes_no: bool = False, error: bool = True) -> bool:
    """Native message box (a windowed EXE has no console). Returns True for 'Yes'."""
    if sys.platform != "win32":
        print(text)
        return False
    flags = (_MB_YESNO if yes_no else _MB_OK) | (_MB_ICONERROR if error else _MB_ICONINFO)
    return ctypes.windll.user32.MessageBoxW(0, text, WINDOW_TITLE, flags) == _IDYES


def _acquire_single_instance():
    """
    Only one copy may run: two would both react to the same USB insertion and
    fight over the database. Returns a handle to keep alive, or None if another
    instance is already running.
    """
    if sys.platform != "win32":
        return object()
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.CreateMutexW(None, False, _MUTEX_NAME)
    if kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
        return None
    return handle


def _webview2_installed() -> bool:
    """Microsoft's documented registry check for the Evergreen WebView2 Runtime."""
    if sys.platform != "win32":
        return False
    import winreg
    locations = (
        (winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{_WEBVIEW2_GUID}"),
        (winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\Microsoft\EdgeUpdate\Clients\{_WEBVIEW2_GUID}"),
        (winreg.HKEY_CURRENT_USER, rf"Software\Microsoft\EdgeUpdate\Clients\{_WEBVIEW2_GUID}"),
    )
    for hive, path in locations:
        try:
            with winreg.OpenKey(hive, path) as key:
                version, _ = winreg.QueryValueEx(key, "pv")
                if version and version != "0.0.0.0":
                    return True
        except OSError:
            continue
    return False


# ---------------------------------------------------------------------------
# Self-test (used by build_exe.bat to prove the packaged EXE has what it needs)
# ---------------------------------------------------------------------------
def _selftest() -> int:
    lines: list[str] = []
    ok = True

    def check(name: str, fn) -> None:
        nonlocal ok
        try:
            lines.append(f"PASS  {name}: {fn()}")
        except Exception as exc:  # noqa: BLE001
            ok = False
            lines.append(f"FAIL  {name}: {exc!r}")

    def resources() -> str:
        for rel in ("templates/index.html", "static/app.js", "static/style.css"):
            if not (config.RESOURCE_DIR / rel).is_file():
                raise FileNotFoundError(rel)
        return str(config.RESOURCE_DIR)

    def data_dir() -> str:
        probe = config.DATA_DIR / ".write_test"
        probe.write_text("ok")
        probe.unlink()
        return str(config.DATA_DIR)

    def libmagic() -> str:
        from utils import mime
        if not mime._MAGIC_AVAILABLE:
            raise RuntimeError("python-magic / libmagic did not load")
        detected = mime.detect_mime(config.RESOURCE_DIR / "templates" / "index.html")
        if not detected.startswith("text/"):
            raise RuntimeError(f"unexpected MIME result {detected!r} (magic.mgc missing?)")
        return detected

    def pe_parser() -> str:
        import pefile
        return f"pefile {getattr(pefile, '__version__', '?')}"

    def pdf() -> str:
        from reportlab.pdfgen import canvas
        out = Path(tempfile.mkdtemp()) / "t.pdf"
        c = canvas.Canvas(str(out))
        c.drawString(72, 720, "selftest")
        c.save()
        return f"{out.stat().st_size} bytes"

    def pipeline() -> str:
        import app as app_module
        database.init_db()
        work = Path(tempfile.mkdtemp())
        with zipfile.ZipFile(work / "t.zip", "w") as zf:
            zf.writestr("../evil.txt", "x")
        result = app_module._analyze_single_file("selftest", work / "t.zip")
        if not result["explanations"]:
            raise RuntimeError("no explanation produced for a Zip Slip archive")
        return f"score {result['risk_score']}, {len(result['explanations'])} explanation(s)"

    def signature_engine() -> str:
        from scanners import signature_verifier
        if not signature_verifier._CRYPTO_AVAILABLE:
            raise RuntimeError("'cryptography' did not load - signatures cannot be verified offline")
        windows, custom = signature_verifier.get_trust_store().snapshot()
        return f"{len(windows)} Windows root(s), {len(custom)} whitelisted cert(s)"

    def tray_support() -> str:
        if not tray_mod.TRAY_AVAILABLE:
            raise RuntimeError("pystray / Pillow did not load - background mode unavailable")
        return "pystray ok"

    def credential_api() -> str:
        from utils import credential_prompt
        if not credential_prompt.IS_WINDOWS:
            raise RuntimeError("not Windows")
        return "credui/secur32 bound"

    def webview2() -> str:
        import webview  # noqa: F401 - import errors are the thing being tested
        if not _webview2_installed():
            raise RuntimeError("Edge WebView2 Runtime not installed on this PC")
        return "installed"

    check("bundled resources", resources)
    check("writable data folder", data_dir)
    check("libmagic", libmagic)
    check("PE parser", pe_parser)
    check("PDF reports", pdf)
    check("scan pipeline", pipeline)
    check("signature verifier", signature_engine)
    check("system tray", tray_support)
    check("Windows credential prompt", credential_api)
    check("window (pywebview + WebView2)", webview2)

    log_path = config.HISTORY_DIR / "selftest.log"
    log_path.write_text("\n".join(lines) + f"\n\nRESULT: {'OK' if ok else 'FAILED'}\n", encoding="utf-8")
    if sys.stdout is not None:
        print("\n".join(lines))
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# Drag-and-drop scanning (files/folders dragged from File Explorer onto the window)
#
# A web page never sees real file paths - the browser hides them - so the page
# cannot be trusted (or even able) to say what to scan. Instead the NATIVE side
# receives the drop: pywebview hands us the real Windows paths straight from
# WebView2, we validate them here, run them through the same scan pipeline the
# USB monitor uses, and tell the page what happened via window.onNativeDrop().
# No HTTP endpoint is added, so the per-launch access token is unaffected.
# ---------------------------------------------------------------------------
DROP_AUTO_QUARANTINE = True   # scanned drops scoring >= config.AUTO_QUARANTINE_THRESHOLD are moved; False = never move them
_DROP_MAX_FILES = 5000        # per drop; a huge folder is truncated, not scanned forever
_ui: dict = {"window": None, "tray": None, "exiting": False}  # set in main() once the window exists
_FRONTEND_CALLBACKS = {"onNativeDrop", "onNativeEvent"}            # fixed names only, never user input


def _notify_frontend(payload: dict, callback: str = "onNativeDrop") -> None:
    """Send a status dict to app.js. json.dumps escapes everything, so file names are inert."""
    window = _ui["window"]
    if window is None or callback not in _FRONTEND_CALLBACKS:
        return
    try:
        window.evaluate_js(f"window.{callback} && window.{callback}({json.dumps(payload)})")
    except Exception:  # noqa: BLE001 - a UI hiccup must never break a scan
        logger.debug("Could not notify the page (%s)", callback, exc_info=True)


# ---------------------------------------------------------------------------
# Background mode: system tray, hide-on-minimize/close, auto-popup
# ---------------------------------------------------------------------------
def _background_enabled() -> bool:
    try:
        return database.get_bool_setting(config.BACKGROUND_MODE_SETTING_KEY, default=False)
    except Exception:  # noqa: BLE001
        return False


def _tray_active() -> bool:
    tray = _ui["tray"]
    return bool(tray and tray.running)


def _force_foreground() -> None:
    """
    Windows refuses to let a background process steal focus. Attaching our input queue to the
    current foreground thread for a moment, plus a brief topmost flash, is the standard way
    to make a legitimately-triggered popup (USB inserted) actually appear in front.
    """
    if sys.platform != "win32":
        return
    try:
        u = ctypes.WinDLL("user32", use_last_error=True)
        k = ctypes.WinDLL("kernel32")
        V, UL = ctypes.c_void_p, ctypes.c_ulong
        u.FindWindowW.argtypes, u.FindWindowW.restype = [ctypes.c_wchar_p, ctypes.c_wchar_p], V
        u.GetForegroundWindow.restype = V
        u.GetWindowThreadProcessId.argtypes, u.GetWindowThreadProcessId.restype = [V, ctypes.POINTER(UL)], UL
        u.AttachThreadInput.argtypes = [UL, UL, ctypes.c_int]
        u.SetForegroundWindow.argtypes = [V]
        u.BringWindowToTop.argtypes = [V]
        u.SetWindowPos.argtypes = [V, V, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_uint]
        hwnd = u.FindWindowW(None, WINDOW_TITLE)
        if not hwnd:
            return
        fg = u.GetForegroundWindow()
        fg_tid = u.GetWindowThreadProcessId(fg, None) if fg else 0
        my_tid = k.GetCurrentThreadId()
        attached = bool(fg_tid and fg_tid != my_tid and u.AttachThreadInput(my_tid, fg_tid, 1))
        try:
            flags = 0x0001 | 0x0002 | 0x0040          # SWP_NOSIZE | SWP_NOMOVE | SWP_SHOWWINDOW
            u.SetWindowPos(hwnd, V(-1), 0, 0, 0, 0, flags)   # HWND_TOPMOST
            u.SetWindowPos(hwnd, V(-2), 0, 0, 0, 0, flags)   # HWND_NOTOPMOST (flash only)
            u.BringWindowToTop(hwnd)
            u.SetForegroundWindow(hwnd)
        finally:
            if attached:
                u.AttachThreadInput(my_tid, fg_tid, 0)
    except Exception:  # noqa: BLE001 - focus is best-effort; the window is already shown
        logger.debug("Could not force the window to the foreground", exc_info=True)


def _show_window(maximize: bool = False) -> None:
    """Bring the main window back from hidden / minimized / behind other windows."""
    window = _ui["window"]
    if window is None:
        return
    try:
        window.show()
        window.restore()
        if maximize:
            window.maximize()
    except Exception:  # noqa: BLE001
        logger.exception("Could not show the main window")
    _force_foreground()


def _exit_app() -> None:
    """Real exit (tray menu -> Exit). Sets a flag so the close handler lets it through."""
    _ui["exiting"] = True
    tray = _ui["tray"]
    if tray:
        tray.stop()
    window = _ui["window"]
    if window is not None:
        try:
            window.destroy()
        except Exception:  # noqa: BLE001
            logger.exception("window.destroy() failed")


def _on_window_minimized() -> None:
    """Background mode: a minimized window leaves the taskbar and lives in the tray."""
    if _background_enabled() and _tray_active():
        try:
            _ui["window"].hide()
        except Exception:  # noqa: BLE001
            logger.exception("Could not hide the window to the tray")


def _on_window_closing():
    """Background mode: the X button hides to the tray instead of quitting. False cancels the close."""
    if _ui["exiting"] or not (_background_enabled() and _tray_active()):
        return True
    try:
        _ui["window"].hide()
    except Exception:  # noqa: BLE001
        logger.exception("Could not hide the window to the tray")
        return True
    return False


def _start_tray() -> bool:
    if _tray_active():
        return True
    tray = tray_mod.TrayIcon(on_open=_show_window, on_exit=_exit_app)
    if not tray.start():
        return False
    _ui["tray"] = tray
    return True


def _stop_tray() -> None:
    tray, _ui["tray"] = _ui["tray"], None
    if tray:
        tray.stop()
    _show_window()   # never leave the user with a hidden window and no tray icon to restore it


def _apply_background_mode(enabled: bool) -> None:
    """Runs when the Settings toggle is applied."""
    if enabled:
        if not _start_tray():
            database.set_bool_setting(config.BACKGROUND_MODE_SETTING_KEY, False)
            _notify_frontend({"event": "background_failed",
                              "message": "Could not create the system-tray icon; background mode stays off."},
                             "onNativeEvent")
    else:
        _stop_tray()


def _on_usb_inserted(device: dict) -> None:
    """Auto-popup: wake the window, maximize it and show the scanning progress screen."""
    if not config.AUTO_POPUP_ON_USB:
        return
    _show_window(maximize=True)
    _notify_frontend({"event": "usb_inserted", "device": device}, "onNativeEvent")


def _on_hid_alert(alert: dict) -> None:
    """A rogue keyboard was caught: make sure the user sees it, even from the tray."""
    _show_window()
    if _ui["tray"]:
        _ui["tray"].notify("Rogue keyboard detected", alert.get("message", ""))
    _notify_frontend({"event": "hid_alert", "alert": alert}, "onNativeEvent")


def _is_inside(path: Path, root: Path) -> bool:
    try:
        return path.resolve().is_relative_to(root)
    except (OSError, ValueError):
        return False


def _collect_drop_targets(raw_paths: list[str]) -> tuple[list[Path], int]:
    """
    Turn dropped paths into a de-duplicated list of real files to scan.
    Only absolute paths are accepted; folders are walked (symlinks/junctions are not
    followed); anything inside our own quarantine folder is ignored so a drop can
    never disturb an existing quarantine record. Returns (files, number_skipped).
    """
    quarantine_root = config.QUARANTINE_DIR.resolve()
    is_junction = getattr(os.path, "isjunction", lambda _p: False)
    files: list[Path] = []
    seen: set[str] = set()
    skipped = 0

    def add(path: Path) -> None:
        nonlocal skipped
        key = os.path.normcase(str(path))
        if key in seen:
            return
        seen.add(key)
        if len(files) >= _DROP_MAX_FILES or _is_inside(path, quarantine_root):
            skipped += 1
            return
        files.append(path)

    for raw in raw_paths:
        if not isinstance(raw, str) or "\x00" in raw or not Path(raw).is_absolute():
            skipped += 1
            continue
        path = Path(os.path.abspath(raw))
        try:
            if path.is_file():
                add(path)
            elif path.is_dir():
                for root, dirs, names in os.walk(path, followlinks=False):
                    dirs[:] = [d for d in dirs if not is_junction(os.path.join(root, d))]
                    for name in names:
                        add(Path(root) / name)
            else:
                skipped += 1
        except OSError as exc:
            logger.warning("Dropped path could not be read: %s (%s)", path, exc)
            skipped += 1
    return files, skipped


def _run_drop_scan(scan_id: str, files: list[Path], skipped: int) -> None:
    """Same steps as app._run_full_scan, for an explicit list of files."""
    import app as app_module

    live, lock = app_module._live_state, app_module._state_lock
    files_scanned = suspicious = quarantined = highest = 0
    sandbox_types: set[str] = set()
    try:
        for path in files:
            try:
                result = app_module._analyze_single_file(scan_id, path)
            except Exception as exc:  # noqa: BLE001 - one bad file must never abort the scan
                logger.warning("Skipping dropped file that could not be analyzed: %s (%s)", path, exc)
                skipped += 1
                continue

            files_scanned += 1
            with lock:
                live["scan_progress"][scan_id]["done"] = files_scanned
                live["scan_progress"][scan_id]["current_file"] = str(path)
                live["recent_findings"][scan_id].append(result)

            score = result["risk_score"]
            highest = max(highest, score)
            if score >= 30:
                suspicious += 1
            sandbox_type = app_module.auto_sandbox_if_needed(scan_id, path, result)
            if sandbox_type:
                sandbox_types.add(sandbox_type)
            if DROP_AUTO_QUARANTINE and app_module.auto_quarantine_if_needed(scan_id, path, result):
                quarantined += 1
            database.insert_file_result(scan_id, result)
    except Exception:  # noqa: BLE001
        logger.exception("Drop scan %s stopped early", scan_id)
    finally:
        database.finish_scan(scan_id, files_scanned, suspicious, highest,
                             sandbox_used=", ".join(sorted(sandbox_types)) or None, report_path=None)
        with lock:
            # A USB scan may have started meanwhile and owns the slot now - leave it alone.
            if live["active_scan"] == scan_id:
                live["active_scan"] = None

    if sandbox_types:
        try:
            report_path = app_module.generate_report(scan_id)
            scan = database.get_scan(scan_id)
            database.finish_scan(scan_id, scan["files_scanned"], scan["suspicious_files"],
                                 scan["highest_risk"], scan["sandbox_used"], report_path)
        except Exception:  # noqa: BLE001
            logger.exception("Could not generate automatic sandbox report for %s", scan_id)

    logger.info("Drop scan %s complete: %d files, %d suspicious, %d quarantined",
                scan_id, files_scanned, suspicious, quarantined)
    _notify_frontend({"event": "finished", "scan_id": scan_id, "files_scanned": files_scanned,
                      "suspicious": suspicious, "quarantined": quarantined,
                      "highest_risk": highest, "skipped": skipped})


def _start_drop_scan(raw_paths: list[str]) -> None:
    files, skipped = _collect_drop_targets(raw_paths)
    if not files:
        _notify_frontend({"event": "rejected",
                          "message": "Nothing scannable in that drop (no readable files)."})
        return

    import app as app_module

    scan_id = f"scan_{uuid.uuid4().hex[:10]}"
    live, lock = app_module._live_state, app_module._state_lock
    with lock:  # claim the single "active scan" slot atomically
        if live["active_scan"] is not None:
            claimed = False
        else:
            claimed = True
            live["active_scan"] = scan_id
            live["scan_progress"][scan_id] = {"total": len(files), "done": 0, "current_file": ""}
            live["recent_findings"][scan_id] = []
    if not claimed:
        _notify_frontend({"event": "rejected",
                          "message": "A scan is already running - drop your files again when it finishes."})
        return

    try:
        database.create_scan(scan_id, "Dropped files", "Drag & drop", 0, "")
    except Exception:  # noqa: BLE001
        logger.exception("Could not record drop scan %s", scan_id)
        with lock:
            live["active_scan"] = None
        _notify_frontend({"event": "error", "message": "Could not start the scan (see the log)."})
        return

    logger.info("Drop scan %s started: %d file(s), %d skipped", scan_id, len(files), skipped)
    _notify_frontend({"event": "started", "scan_id": scan_id, "total": len(files), "skipped": skipped})
    threading.Thread(target=_run_drop_scan, args=(scan_id, files, skipped),
                     daemon=True, name="DropScanThread").start()


def _active_view() -> str:
    """Which sidebar page is open; app.js keeps window.__activeView."""
    window = _ui["window"]
    try:
        value = window.evaluate_js("window.__activeView || ''") if window is not None else ""
    except Exception:  # noqa: BLE001
        return ""
    return value if isinstance(value, str) else ""


def _confirm_quarantine(files: list[Path]) -> bool:
    """Native Yes/No before dropped files are moved into quarantine (a stray drop must not move files)."""
    window = _ui["window"]
    if window is None:
        return False
    shown = "\n".join(f"  \u2022 {p.name}" for p in files[:6])
    more = f"\n  \u2026 and {len(files) - 6} more" if len(files) > 6 else ""
    try:
        return bool(window.create_confirmation_dialog(
            "Quarantine files",
            f"Move {len(files)} file{'s' if len(files) != 1 else ''} into quarantine?\n\n{shown}{more}\n\n"
            "They are moved out of their current folder. You can restore them later from the Quarantine page."))
    except Exception:  # noqa: BLE001 - no confirmation possible -> do NOT move anything
        logger.exception("Could not show the quarantine confirmation dialog")
        return False


def _run_drop_quarantine(files: list[Path], skipped: int) -> None:
    import app as app_module

    try:
        result = app_module.manual_quarantine([str(p) for p in files])
    except Exception:  # noqa: BLE001
        logger.exception("Manual quarantine from drop failed")
        _notify_frontend({"event": "quarantine_done", "quarantined": 0, "failed": len(files), "skipped": skipped,
                          "message": "Quarantine failed unexpectedly (see the log)."})
        return
    errors = [f"{Path(f['path']).name}: {f['error']}" for f in result["failed"][:3]]
    _notify_frontend({"event": "quarantine_done", "scan_id": result["scan_id"],
                      "quarantined": len(result["quarantined"]), "failed": len(result["failed"]),
                      "skipped": skipped, "errors": errors})


def _start_drop_quarantine(raw_paths: list[str]) -> None:
    """Files dropped while the Quarantine page is open are quarantined (folders are not accepted)."""
    files: list[Path] = []
    skipped = 0
    for raw in raw_paths:
        if isinstance(raw, str) and "\x00" not in raw and Path(raw).is_absolute() and Path(raw).is_file():
            files.append(Path(os.path.abspath(raw)))
        else:
            skipped += 1   # folders, missing paths, relative paths
    if not files:
        _notify_frontend({"event": "rejected", "message":
                          "Drop individual files to quarantine them. Folders are not accepted here - "
                          "open the file browser to choose files inside a folder."})
        return
    if not _confirm_quarantine(files):
        _notify_frontend({"event": "quarantine_cancelled", "message": "Nothing was quarantined."})
        return
    threading.Thread(target=_run_drop_quarantine, args=(files, skipped),
                     daemon=True, name="DropQuarantineThread").start()


def _on_files_dropped(event: dict) -> None:
    """pywebview 'drop' handler. Paths come from WebView2 itself (pywebviewFullPath)."""
    try:
        dropped = (event.get("dataTransfer") or {}).get("files") or []
        paths = [f.get("pywebviewFullPath") for f in dropped if isinstance(f, dict)]
        paths = [p for p in paths if isinstance(p, str) and p]
    except Exception:  # noqa: BLE001
        logger.exception("Unreadable drop event")
        paths = []
    if not paths:
        _notify_frontend({"event": "rejected",
                          "message": "Could not read a file path from that drop - drag files from File Explorer."})
        return
    active_view = _active_view()
    if active_view == "sandbox":
        files = [p for p in paths if Path(p).is_file()]
        if len(files) != 1 or len(paths) != 1:
            _notify_frontend({"event": "rejected",
                              "message": "Drop one file at a time for sandbox analysis."})
            return
        _notify_frontend({"event": "sandbox_file_dropped", "path": files[0]})
    elif active_view == "quarantine":
        _start_drop_quarantine(paths)
    else:
        _start_drop_scan(paths)


def _bind_drop_events(window) -> None:
    """Runs once the window exists (webview.start(func, window)). Failure only disables dropping."""
    try:
        from webview.dom import DOMEventHandler

        events = window.dom.document.events
        # dragenter/dragover must be cancelled or the drop is refused (or WebView2 would
        # navigate the window to the dropped file); drop reads the paths, then cancels too.
        events.dragenter += DOMEventHandler(lambda _e: None, True, False)
        events.dragover += DOMEventHandler(lambda _e: None, True, False, debounce=500)
        events.drop += DOMEventHandler(_on_files_dropped, True, False)
        logger.info("Drag-and-drop scanning enabled")
    except Exception:  # noqa: BLE001 - e.g. an old pywebview without window.dom
        logger.exception("Drag-and-drop scanning is unavailable; the rest of the app is unaffected")


# ---------------------------------------------------------------------------
# Normal launch
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=WINDOW_TITLE)
    parser.add_argument("--minimized", action="store_true", help="start minimized to the taskbar")
    parser.add_argument("--selftest", action="store_true", help="verify dependencies and exit")
    args = parser.parse_args(argv)

    if args.selftest:
        return _selftest()

    instance = _acquire_single_instance()
    if instance is None:
        _message_box("USB Threat Analyzer is already running.\n\nLook for it on the taskbar.",
                     error=False)
        return 0

    if sys.platform == "win32" and not _webview2_installed():
        if _message_box(
            "USB Threat Analyzer needs the Microsoft Edge WebView2 Runtime, which is not "
            "installed on this PC.\n\nOpen the Microsoft download page now?",
            yes_no=True,
        ):
            os.startfile(_WEBVIEW2_DOWNLOAD_URL)  # noqa: S606 - fixed Microsoft URL
        return 1

    # Imported here (not at the top) so --selftest and error paths stay lightweight.
    from werkzeug.serving import make_server

    from app import app, hid_guard, usb_monitor

    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    database.init_db()

    token = secrets.token_urlsafe(32)
    app.config["ACCESS_TOKEN"] = token
    server = make_server(config.FLASK_HOST, 0, app, threaded=True)  # port 0 = any free port
    port = server.server_port
    threading.Thread(target=server.serve_forever, name="HTTPServer", daemon=True).start()
    usb_monitor.start()
    hid_guard.start()
    ui_bridge.on("usb_inserted", _on_usb_inserted)
    ui_bridge.on("hid_alert", _on_hid_alert)
    ui_bridge.on("background_mode_changed", _apply_background_mode)
    if _background_enabled() and not _start_tray():
        logger.warning("Background mode is on but the tray icon could not start; using the taskbar")
    logger.info("Desktop app serving on 127.0.0.1:%d (private, token-protected)", port)

    exit_code = 0
    try:
        import webview

        webview.settings["ALLOW_DOWNLOADS"] = True  # PDF reports are downloadable
        window = webview.create_window(
            WINDOW_TITLE, f"http://{config.FLASK_HOST}:{port}/?t={token}",
            width=1280, height=820, min_size=(1000, 650),
            background_color="#060b18", minimized=args.minimized and not _tray_active(),
            hidden=args.minimized and _tray_active(),   # "Start with Windows" + background mode = tray only
        )
        _ui["window"] = window
        window.events.minimized += _on_window_minimized
        window.events.closing += _on_window_closing
        webview.start(_bind_drop_events, window, gui="edgechromium")  # blocks until the window is closed
    except Exception as exc:  # noqa: BLE001
        logger.exception("Could not open the application window")
        _message_box(f"USB Threat Analyzer could not open its window:\n\n{exc}\n\n"
                     f"Details are in {config.HISTORY_DIR / 'usb_threat_analyzer.log'}")
        exit_code = 1
    finally:
        if _ui["tray"]:
            _ui["tray"].stop()
        hid_guard.stop()
        usb_monitor.stop()
        server.shutdown()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
