"""
USB Threat Analyzer - main Flask application.

Wires together the USB monitor (Level 0), the Level 1-3 scanners, the
risk engine, quarantine system, Level 4 sandbox manager, SQLite
history, and the PDF report generator behind a single-page
Glassmorphism dashboard.

On startup, a background USB monitor begins watching for removable
drives. The instant one is inserted, a scan thread walks the drive
running every applicable level of analysis, scores each file, and
quarantines anything scoring config.AUTO_QUARANTINE_THRESHOLD (75) or more; files can also be
quarantined by hand from the Quarantine page. All of this
is exposed to the frontend over a small JSON API which the dashboard
polls / drives via fetch().
"""

from __future__ import annotations

import hmac
import os
import threading
import uuid
from datetime import datetime
from pathlib import Path

import psutil

from flask import Flask, abort, jsonify, make_response, render_template, request, send_file

import config
import database
from report_generator import generate_report
from sandbox import sandbox_manager
from scanners import level1_scanner, level2_zip_ast, level3_pe, quarantine, risk_engine
from scanners.hid_guard import HIDGuard
from scanners.usb_monitor import USBDeviceInfo, USBMonitor
from utils import startup_manager, tray, ui_bridge
from utils.logger import get_logger

logger = get_logger(__name__)

# templates/ and static/ are read from config.RESOURCE_DIR so the same code works
# from source and inside the PyInstaller one-file EXE (where they are unpacked
# to a temporary folder).
app = Flask(
    __name__,
    static_folder=str(config.RESOURCE_DIR / "static"),
    template_folder=str(config.RESOURCE_DIR / "templates"),
)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024

# Desktop mode (desktop.py) sets a random per-launch token here. When set, every
# request must carry it (as the cookie planted by the first page load), so a
# web page open in some other browser cannot drive this app's local API -
# which can restore or delete quarantined files. Unset when running
# `python app.py` for development, which behaves exactly as before.
_TOKEN_COOKIE = "uta_token"
app.config["ACCESS_TOKEN"] = None


@app.before_request
def _require_access_token():
    token = app.config.get("ACCESS_TOKEN")
    if not token:
        return None
    if request.path == "/" and hmac.compare_digest(request.args.get("t", ""), token):
        return None  # first load: index() converts this into the cookie
    if hmac.compare_digest(request.cookies.get(_TOKEN_COOKIE, ""), token):
        return None
    abort(403)

# In-memory live state the frontend polls; SQLite remains the source of
# truth for anything that must survive a restart.
_state_lock = threading.Lock()
_live_state = {
    "connected_devices": [],
    "active_scan": None,   # scan_id currently running, or None
    "scan_progress": {},   # scan_id -> {"total": int, "done": int, "current_file": str}
    "recent_findings": {}, # scan_id -> list[dict] (grows as the scan progresses)
}

# Files scoring at or above this are moved to quarantine automatically (config.py: 75).
_HIGH_RISK_QUARANTINE_THRESHOLD = config.AUTO_QUARANTINE_THRESHOLD

# Level 3 only has analyzers for these; other "executable" extensions (e.g. .com)
# fall through to the generic record instead of raising mid-scan.
_LEVEL3_EXTENSIONS = level3_pe.PE_EXTENSIONS | level3_pe.SCRIPT_EXECUTABLE_EXTENSIONS


# ---------------------------------------------------------------------------
# USB Monitor wiring (Level 0)
# ---------------------------------------------------------------------------
def _on_usb_connected(device: USBDeviceInfo) -> None:
    with _state_lock:
        _live_state["connected_devices"] = usb_monitor.current_devices()
    threading.Thread(target=_run_full_scan, args=(device,), daemon=True, name="ScanThread").start()
    # Wake the desktop window (restore from tray/taskbar, maximize, show scan progress).
    # No-op when running without the desktop shell (plain `python app.py`).
    ui_bridge.emit("usb_inserted", device=device.to_dict())


def _on_usb_disconnected(drive_letter: str) -> None:
    with _state_lock:
        _live_state["connected_devices"] = usb_monitor.current_devices()


usb_monitor = USBMonitor(on_connect=_on_usb_connected, on_disconnect=_on_usb_disconnected)

# BadUSB / keystroke-injection guard (Windows Raw Input; see scanners/hid_guard.py).
hid_guard = HIDGuard(on_alert=lambda alert: ui_bridge.emit("hid_alert", alert=alert))


# ---------------------------------------------------------------------------
# Core scan pipeline
# ---------------------------------------------------------------------------
def _run_full_scan(device: USBDeviceInfo) -> None:
    """Runs Levels 1-3 across an inserted drive, scores, and auto-quarantines."""
    scan_id = f"scan_{uuid.uuid4().hex[:10]}"
    root = Path(device.drive_letter)
    logger.info("Starting scan %s for device %s", scan_id, device.drive_letter)

    database.create_scan(scan_id, device.label or "Removable Disk", device.drive_letter,
                          device.capacity_bytes, device.file_system)

    with _state_lock:
        _live_state["active_scan"] = scan_id
        _live_state["scan_progress"][scan_id] = {"total": 0, "done": 0, "current_file": ""}
        _live_state["recent_findings"][scan_id] = []

    files_scanned = 0
    suspicious_count = 0
    highest_risk = 0
    sandbox_types: set[str] = set()

    try:
        all_paths = [p for p in root.rglob("*") if p.is_file()]
        with _state_lock:
            _live_state["scan_progress"][scan_id]["total"] = len(all_paths)

        for path in all_paths:
            try:
                result = _analyze_single_file(scan_id, path)
            except Exception as exc:  # noqa: BLE001 - one bad file must never abort the whole scan
                logger.warning("Skipping file that could not be analyzed during scan %s: %s (%s)",
                               scan_id, path, exc)
                continue

            files_scanned += 1
            with _state_lock:
                _live_state["scan_progress"][scan_id]["done"] = files_scanned
                _live_state["scan_progress"][scan_id]["current_file"] = str(path)
                _live_state["recent_findings"][scan_id].append(result)

            risk_score = result["risk_score"]
            highest_risk = max(highest_risk, risk_score)
            if risk_score >= 30:
                suspicious_count += 1

            sandbox_type = auto_sandbox_if_needed(scan_id, path, result)
            if sandbox_type:
                sandbox_types.add(sandbox_type)
            auto_quarantine_if_needed(scan_id, path, result)

            database.insert_file_result(scan_id, result)
    except Exception:  # noqa: BLE001 - e.g. the drive was pulled mid-scan
        logger.exception("Scan %s stopped early", scan_id)
    finally:
        database.finish_scan(scan_id, files_scanned, suspicious_count, highest_risk,
                              sandbox_used=", ".join(sorted(sandbox_types)) or None, report_path=None)
        with _state_lock:
            _live_state["active_scan"] = None

    if sandbox_types:
        try:
            report_path = generate_report(scan_id)
            scan = database.get_scan(scan_id)
            database.finish_scan(scan_id, scan["files_scanned"], scan["suspicious_files"],
                                 scan["highest_risk"], scan["sandbox_used"], report_path)
        except Exception:  # noqa: BLE001 - preserve scan results if report generation fails
            logger.exception("Could not generate automatic sandbox report for %s", scan_id)

    logger.info("Scan %s complete: %d files, %d suspicious, highest risk %d",
                scan_id, files_scanned, suspicious_count, highest_risk)


def auto_quarantine_if_needed(scan_id: str, path: Path, result: dict) -> bool:
    """
    The automatic rule: a file whose risk score is >= config.AUTO_QUARANTINE_THRESHOLD is moved
    to quarantine. `result` (the per-file dict that is saved and later printed in the PDF
    report) is updated in place: quarantined=True, quarantine_id, quarantine_mode="auto".
    If quarantining was required but impossible (protected folder, file locked...), the reason
    is appended to result["reasons"] so the report is honest about it. Returns True if moved.
    """
    score = int(result.get("risk_score") or 0)
    if score < config.AUTO_QUARANTINE_THRESHOLD:
        return False
    try:
        quarantine.ensure_quarantinable(path)
        q = quarantine.quarantine_file(scan_id, path, score, result.get("reasons", []),
                                       result.get("explanations"), source="auto")
    except (quarantine.QuarantineError, OSError) as exc:
        logger.warning("Could not auto-quarantine %s: %s", path, exc)
        result.setdefault("reasons", []).append(f"Auto-quarantine was not possible: {exc}")
        return False
    result["quarantined"] = True
    result["quarantine_id"] = q["id"]
    result["quarantine_mode"] = "auto"
    if not q["original_removed"]:
        result.setdefault("reasons", []).append(
            "A copy was quarantined but the original could not be removed (read-only media or file in use).")
    return True


def auto_sandbox_if_needed(scan_id: str, path: Path, result: dict) -> str | None:
    """Run dynamic analysis for threshold-risk files before quarantine can move them."""
    if int(result.get("risk_score") or 0) < config.AUTO_QUARANTINE_THRESHOLD:
        return None
    try:
        availability = sandbox_manager.detect_available_sandboxes()
        choice = None
        vm_name = None
        vmware_info = availability.get("vmware", {})
        saved_vm = database.get_setting("sandbox_vmware_vmx_path")
        if vmware_info.get("ready"):
            candidates = vmware_info.get("vms") or []
            configured_vm = candidates[0] if candidates else saved_vm
            if configured_vm and Path(configured_vm).is_file():
                choice, vm_name = "vmware", configured_vm
        if not choice:
            for candidate in ("windows_sandbox", "virtualbox", "vmware"):
                info = availability.get(candidate, {})
                if info.get("ready"):
                    choice = candidate
                    if candidate == "virtualbox" and info.get("vms"):
                        vm_name = info["vms"][0]
                    elif candidate == "vmware" and info.get("vms"):
                        vm_name = info["vms"][0]
                    break
        if not choice or (choice in ("vmware", "virtualbox") and not vm_name):
            result.setdefault("reasons", []).append(
                "Automatic sandbox analysis was skipped because no ready VM is configured.")
            return None
        analysis = sandbox_manager.run_analysis(path, scan_id, choice, vm_name)
        if analysis.get("status") == "completed":
            result["sandbox_status"] = "completed"
            return str(analysis.get("sandbox_type") or choice)
        result["sandbox_status"] = analysis.get("status", "error")
        result.setdefault("reasons", []).append(
            f"Automatic sandbox analysis did not complete: {analysis.get('message', 'see application log')}.")
    except Exception as exc:  # noqa: BLE001 - static scan and quarantine must still complete
        logger.exception("Automatic sandbox analysis failed for %s", path)
        result.setdefault("reasons", []).append(f"Automatic sandbox analysis failed: {exc}")
    return None


def manual_quarantine(paths: list) -> dict:
    """
    Quarantine files the user picked by hand (Quarantine page: file browser or drag & drop).

    Each file is validated (absolute, exists, regular file, not in a protected Windows folder),
    analysed with the normal pipeline so it gets a risk score and explanation, then moved into
    quarantine with source="manual". The whole batch is recorded as one "Manual quarantine"
    scan, so it shows up in Scan History and can produce a PDF report that lists the files.

    Returns {"scan_id": str | None, "quarantined": [...], "failed": [{"path", "error"}]}.
    """
    failed: list[dict] = []
    valid: list[Path] = []
    seen: set[str] = set()
    for raw in paths:
        if not isinstance(raw, str):
            failed.append({"path": str(raw), "error": "Invalid path."})
            continue
        key = os.path.normcase(raw)
        if key in seen:
            continue
        seen.add(key)
        if len(valid) >= config.QUARANTINE_MANUAL_MAX_FILES:
            failed.append({"path": raw, "error":
                           f"Too many files at once (limit {config.QUARANTINE_MANUAL_MAX_FILES})."})
            continue
        try:
            valid.append(quarantine.ensure_quarantinable(raw))
        except quarantine.QuarantineError as exc:
            failed.append({"path": raw, "error": str(exc)})

    if not valid:
        return {"scan_id": None, "quarantined": [], "failed": failed}

    scan_id = f"scan_{uuid.uuid4().hex[:10]}"
    database.create_scan(scan_id, "Manual quarantine", "Quarantine page", 0, "")
    done: list[dict] = []
    suspicious = highest = 0
    try:
        for path in valid:
            try:
                result = _analyze_single_file(scan_id, path)
            except Exception as exc:  # noqa: BLE001 - an unreadable file can still be quarantined
                logger.warning("Manual quarantine: could not analyze %s (%s)", path, exc)
                result = {
                    "file_name": path.name, "extension": path.suffix.lower(), "absolute_path": str(path),
                    "size_bytes": 0, "sha256": "", "mime_type": "", "created_date": "", "modified_date": "",
                    "level": 0, "risk_score": 0, "risk_level": "Low",
                    "reasons": [f"Could not be analyzed before quarantine: {exc}"], "explanations": [],
                    "quarantined": False,
                }
            result["reasons"] = ["Quarantined manually by the user."] + list(result.get("reasons") or [])
            score = int(result.get("risk_score") or 0)
            try:
                q = quarantine.quarantine_file(scan_id, path, score, result["reasons"],
                                               result.get("explanations"), source="manual")
            except (quarantine.QuarantineError, OSError) as exc:
                failed.append({"path": str(path), "error": str(exc)})
                continue
            result["quarantined"] = True
            result["quarantine_id"] = q["id"]
            result["quarantine_mode"] = "manual"
            database.insert_file_result(scan_id, result)
            highest = max(highest, score)
            if score >= 30:
                suspicious += 1
            done.append({"id": q["id"], "path": str(path), "quarantine_path": q["quarantine_path"],
                         "risk_score": score, "original_removed": q["original_removed"]})
    finally:
        database.finish_scan(scan_id, len(done), suspicious, highest, sandbox_used=None, report_path=None)
    logger.info("Manual quarantine %s: %d quarantined, %d failed", scan_id, len(done), len(failed))
    return {"scan_id": scan_id, "quarantined": done, "failed": failed}


def _analyze_single_file(scan_id: str, path: Path) -> dict:
    """Route a single file through the correct level(s) and compute its final risk score."""
    ext = path.suffix.lower()

    if ext in _LEVEL3_EXTENSIONS:
        # Level 3
        analysis = level3_pe.analyze_executable(path)
        data = analysis.to_dict()
        if isinstance(analysis, level3_pe.PEAnalysisResult):
            assessment = risk_engine.score_pe(data)
            level = 3
        else:
            assessment = risk_engine.score_script_executable(data)
            level = 3
        from utils.hash import sha256_of
        stat_result = path.stat()
        from datetime import datetime as _dt
        return {
            "file_name": path.name, "extension": ext, "absolute_path": str(path),
            "size_bytes": stat_result.st_size, "sha256": sha256_of(path),
            "mime_type": "", "created_date": _dt.fromtimestamp(stat_result.st_ctime).isoformat(),
            "modified_date": _dt.fromtimestamp(stat_result.st_mtime).isoformat(),
            "level": level, "risk_score": assessment.score, "risk_level": assessment.level,
            "reasons": assessment.reasons, "explanations": assessment.explanations,
            "quarantined": False, "detail": data,
        }

    if ext in config.ARCHIVE_EXTENSIONS:
        # Level 2 - zip
        zip_result = level2_zip_ast.analyze_zip(path)
        data = zip_result.to_dict()
        assessment = risk_engine.score_zip(data)
        from utils.hash import sha256_of
        stat_result = path.stat()
        from datetime import datetime as _dt
        return {
            "file_name": path.name, "extension": ext, "absolute_path": str(path),
            "size_bytes": stat_result.st_size, "sha256": sha256_of(path),
            "mime_type": "application/zip",
            "created_date": _dt.fromtimestamp(stat_result.st_ctime).isoformat(),
            "modified_date": _dt.fromtimestamp(stat_result.st_mtime).isoformat(),
            "level": 2, "risk_score": assessment.score, "risk_level": assessment.level,
            "reasons": assessment.reasons, "explanations": assessment.explanations,
            "quarantined": False, "detail": data,
        }

    if ext in config.SCRIPT_LANGUAGE_EXTENSIONS and ext not in config.EXECUTABLE_EXTENSIONS:
        # Level 2 - AST/script analysis
        script_result = level2_zip_ast.analyze_script(path)
        data = script_result.to_dict() if script_result else {}
        assessment = risk_engine.score_script(data)
        from utils.hash import sha256_of
        stat_result = path.stat()
        from datetime import datetime as _dt
        return {
            "file_name": path.name, "extension": ext, "absolute_path": str(path),
            "size_bytes": stat_result.st_size, "sha256": sha256_of(path),
            "mime_type": "text/plain",
            "created_date": _dt.fromtimestamp(stat_result.st_ctime).isoformat(),
            "modified_date": _dt.fromtimestamp(stat_result.st_mtime).isoformat(),
            "level": 2, "risk_score": assessment.score, "risk_level": assessment.level,
            "reasons": assessment.reasons, "explanations": assessment.explanations,
            "quarantined": False, "detail": data,
        }

    if ext in config.NON_EXECUTABLE_EXTENSIONS:
        # Level 1
        finding = level1_scanner.scan_file(path)
        assessment = risk_engine.score_level1(finding.flags, finding.details)
        result = finding.to_dict()
        result["risk_score"] = assessment.score
        result["risk_level"] = assessment.level
        result["reasons"] = assessment.reasons or finding.reasons
        result["explanations"] = assessment.explanations
        result["quarantined"] = False
        return result

    # Unrecognized extension - record minimally at Low risk rather than skipping silently.
    from utils.hash import sha256_of
    stat_result = path.stat()
    from datetime import datetime as _dt
    return {
        "file_name": path.name, "extension": ext, "absolute_path": str(path),
        "size_bytes": stat_result.st_size, "sha256": sha256_of(path),
        "mime_type": "unknown/unknown",
        "created_date": _dt.fromtimestamp(stat_result.st_ctime).isoformat(),
        "modified_date": _dt.fromtimestamp(stat_result.st_mtime).isoformat(),
        "level": 0, "risk_score": 0, "risk_level": "Low",
        "reasons": ["Unrecognized file type - not covered by current scan levels."],
        "explanations": [], "quarantined": False,
    }


# ---------------------------------------------------------------------------
# Routes - pages
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    response = make_response(render_template(
        "index.html", auto_quarantine_threshold=config.AUTO_QUARANTINE_THRESHOLD))
    token = app.config.get("ACCESS_TOKEN")
    if token:
        response.set_cookie(_TOKEN_COOKIE, token, httponly=True, samesite="Strict")
    return response


# ---------------------------------------------------------------------------
# Routes - API: USB / scan status
# ---------------------------------------------------------------------------
@app.route("/api/status")
def api_status():
    with _state_lock:
        active_scan = _live_state["active_scan"]
        progress = _live_state["scan_progress"].get(active_scan, {}) if active_scan else {}
        devices = _live_state["connected_devices"]
    return jsonify({
        "connected_devices": devices,
        "active_scan": active_scan,
        "progress": progress,
    })


@app.route("/api/scan/<scan_id>/findings")
def api_scan_findings(scan_id: str):
    with _state_lock:
        live = _live_state["recent_findings"].get(scan_id)
    if live is not None:
        return jsonify({"source": "live", "findings": live})
    return jsonify({"source": "database", "findings": database.list_files_for_scan(scan_id)})


@app.route("/api/scan/<scan_id>")
def api_scan_detail(scan_id: str):
    scan = database.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "scan not found"}), 404
    return jsonify(scan)


# ---------------------------------------------------------------------------
# Routes - API: history
# ---------------------------------------------------------------------------
@app.route("/api/history")
def api_history():
    return jsonify(database.list_scans())


# ---------------------------------------------------------------------------
# Routes - API: quarantine
# ---------------------------------------------------------------------------
@app.route("/api/quarantine")
def api_quarantine_list():
    return jsonify(database.list_quarantine())


@app.route("/api/quarantine/<int:item_id>/restore", methods=["POST"])
def api_quarantine_restore(item_id: int):
    try:
        path = quarantine.restore_file(item_id)
        return jsonify({"status": "restored", "path": path})
    except quarantine.QuarantineAuthError as exc:
        return jsonify({"error": str(exc), "auth_outcome": exc.outcome}), 403
    except quarantine.QuarantineError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/quarantine/<int:item_id>/delete", methods=["POST"])
def api_quarantine_delete(item_id: int):
    try:
        quarantine.delete_permanently(item_id)
        return jsonify({"status": "deleted"})
    except quarantine.QuarantineAuthError as exc:
        return jsonify({"error": str(exc), "auth_outcome": exc.outcome}), 403
    except quarantine.QuarantineError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/quarantine/<int:item_id>/export", methods=["POST"])
def api_quarantine_export(item_id: int):
    try:
        export_dir = config.REPORTS_DIR / "exported_samples"
        path = quarantine.export_sample(item_id, export_dir)
        return jsonify({"status": "exported", "path": path})
    except quarantine.QuarantineAuthError as exc:
        return jsonify({"error": str(exc), "auth_outcome": exc.outcome}), 403
    except quarantine.QuarantineError as exc:
        return jsonify({"error": str(exc)}), 400


def _require_app_request() -> None:
    """
    State-changing endpoints that touch arbitrary files must be called by this app's own JS,
    which sends a custom header. A custom header forces a CORS preflight for any other web
    page, and this server never answers preflights - so no other site can trigger them.
    """
    if request.headers.get("X-UTA-Request") != "1":
        abort(403)


@app.route("/api/quarantine/add", methods=["POST"])
def api_quarantine_add():
    """Manual quarantine: body {"paths": ["C:\\...\\file.exe", ...]} (absolute file paths)."""
    _require_app_request()
    payload = request.get_json(force=True, silent=True) or {}
    paths = payload.get("paths")
    if not isinstance(paths, list) or not paths:
        return jsonify({"error": "No files were selected."}), 400
    result = manual_quarantine(paths)
    if not result["quarantined"]:
        first = result["failed"][0]["error"] if result["failed"] else "Nothing was quarantined."
        return jsonify({"error": first, **result}), 400
    return jsonify(result)


# ---------------------------------------------------------------------------
# Routes - API: file browser for the Quarantine page (pick files on a USB drive or the PC)
# ---------------------------------------------------------------------------
_FS_LIST_LIMIT = 2000


@app.route("/api/fs/roots")
def api_fs_roots():
    """Starting points for the file browser: connected USB drives first, then other drives and folders."""
    with _state_lock:
        usb_devices = list(_live_state["connected_devices"])
    usb_keys = {os.path.normcase(os.path.abspath(d.get("drive_letter", ""))) for d in usb_devices}

    roots: list[dict] = []
    for d in usb_devices:
        roots.append({"name": f"USB: {d.get('label') or 'Removable Disk'} ({d.get('drive_letter')})",
                      "path": d.get("drive_letter"), "kind": "usb"})
    try:
        for part in psutil.disk_partitions(all=False):
            mount = part.mountpoint
            if os.path.normcase(os.path.abspath(mount)) in usb_keys:
                continue
            roots.append({"name": f"Drive {mount}", "path": mount, "kind": "drive"})
    except Exception:  # noqa: BLE001 - listing drives is a convenience, never fatal
        logger.debug("Could not list drives", exc_info=True)
    home = Path.home()
    for label in ("Desktop", "Documents", "Downloads"):
        folder = home / label
        if folder.is_dir():
            roots.append({"name": label, "path": str(folder), "kind": "folder"})
    return jsonify(roots)


@app.route("/api/fs/list")
def api_fs_list():
    """List one folder (read-only). Hidden and system files are included on purpose."""
    raw = request.args.get("path", "")
    folder = Path(raw)
    if not raw or "\x00" in raw or not folder.is_absolute():
        return jsonify({"error": "Enter a full folder path, e.g. E:\\"}), 400
    try:
        if not folder.is_dir():
            return jsonify({"error": f"Not a folder: {raw}"}), 400
        entries: list[dict] = []
        truncated = False
        with os.scandir(folder) as it:
            for entry in it:
                if len(entries) >= _FS_LIST_LIMIT:
                    truncated = True
                    break
                try:
                    is_dir = entry.is_dir(follow_symlinks=False)
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                entries.append({
                    "name": entry.name, "path": entry.path, "is_dir": is_dir,
                    "size_bytes": 0 if is_dir else st.st_size,
                    "modified": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"),
                })
    except PermissionError:
        return jsonify({"error": "Access denied to that folder."}), 403
    except OSError as exc:
        return jsonify({"error": f"Cannot open that folder: {exc}"}), 400
    entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
    parent = folder.parent
    return jsonify({
        "path": str(folder), "parent": str(parent) if parent != folder else None,
        "entries": entries, "truncated": truncated,
    })


# ---------------------------------------------------------------------------
# Routes - API: Level 4 sandbox
# ---------------------------------------------------------------------------
@app.route("/api/sandbox/available")
def api_sandbox_available():
    return jsonify(sandbox_manager.detect_available_sandboxes())


@app.route("/api/sandbox/snapshots/<scan_id>")
def api_sandbox_snapshots(scan_id: str):
    """Return persisted BEFORE/AFTER guest snapshots and their diff for the viewer."""
    runs = database.list_sandbox_runs_for_scan(scan_id)
    if not runs:
        return jsonify({"error": "No sandbox snapshot data found for this scan."}), 404
    run = runs[-1]
    before = run.get("before_snapshot", {}) or {}
    after = run.get("after_snapshot", {}) or {}
    return jsonify({
        "scan_id": scan_id,
        "sandbox_type": run.get("sandbox_type"),
        "started_at": run.get("started_at"),
        "finished_at": run.get("finished_at"),
        "baseline_snapshot_name": before.get("baseline_snapshot_name") or "",
        "before_snapshot_name": before.get("vmware_snapshot_name") or "",
        "after_snapshot_name": after.get("vmware_snapshot_name") or "",
        "vmx_path": before.get("vmx_path") or after.get("vmx_path") or "",
        "before_snapshot": before,
        "after_snapshot": after,
        "diff": run.get("diff", {}),
        "verdict_notes": run.get("verdict_notes", ""),
    })


@app.route("/api/quarantine/<int:item_id>/sandbox", methods=["POST"])
def api_quarantine_sandbox(item_id: int):
    payload = request.get_json(force=True, silent=True) or {}
    sandbox_choice = payload.get("sandbox_type", "vmware")
    vm_name = payload.get("vm_name")
    guest_password = payload.get("guest_password") or None

    item = database.get_quarantine_item(item_id)
    if not item:
        return jsonify({"error": "quarantine item not found"}), 404

    try:
        file_path = quarantine.get_sandbox_candidate_path(item_id)
    except quarantine.QuarantineError as exc:
        return jsonify({"error": str(exc)}), 400

    result = sandbox_manager.run_analysis(
        file_path=file_path, scan_id=item["scan_id"],
        sandbox_choice=sandbox_choice, vm_name=vm_name, guest_password=guest_password,
    )
    return jsonify(result)


@app.route("/api/sandbox/analyze", methods=["POST"])
def api_sandbox_analyze():
    """Manually analyze one selected file, then create a downloadable forensic PDF."""
    _require_app_request()
    payload = request.get_json(silent=True) or {}
    sandbox_choice = request.form.get("sandbox_type") or payload.get("sandbox_type") or "vmware"
    vm_name = request.form.get("vm_name") or payload.get("vm_name") or None
    guest_password = request.form.get("guest_password") or payload.get("guest_password") or None
    upload = request.files.get("file")
    raw_path = request.form.get("path") or payload.get("path")

    if upload and upload.filename:
        from werkzeug.utils import secure_filename

        filename = secure_filename(Path(upload.filename).name)
        if not filename:
            return jsonify({"error": "Choose a file with a valid name."}), 400
        scan_id = f"scan_{uuid.uuid4().hex[:10]}"
        source_dir = config.SANDBOX_STAGING_DIR / scan_id / "manual_source"
        source_dir.mkdir(parents=True, exist_ok=True)
        file_path = source_dir / filename
        upload.save(file_path)
    elif isinstance(raw_path, str) and raw_path and "\x00" not in raw_path:
        file_path = Path(raw_path)
        if not file_path.is_absolute() or not file_path.is_file():
            return jsonify({"error": "Select an existing file using an absolute path."}), 400
        scan_id = f"scan_{uuid.uuid4().hex[:10]}"
    else:
        return jsonify({"error": "Choose a file to analyze."}), 400

    try:
        result = _analyze_single_file(scan_id, file_path)
        database.create_scan(scan_id, "Manual sandbox analysis", str(file_path),
                             file_path.stat().st_size, "")
        database.insert_file_result(scan_id, result)
        analysis = sandbox_manager.run_analysis(file_path, scan_id, sandbox_choice, vm_name, guest_password=guest_password)
        if sandbox_choice == "vmware" and vm_name and Path(vm_name).is_file():
            database.set_setting("sandbox_vmware_vmx_path", str(Path(vm_name)))
        if analysis.get("status") != "completed":
            database.finish_scan(scan_id, 1, int(result["risk_score"] >= 30),
                                 result["risk_score"], analysis.get("sandbox_type"), None)
            return jsonify({"error": analysis.get("message", "Sandbox analysis did not complete."),
                            "status": analysis.get("status"), "scan_id": scan_id}), 400
        database.finish_scan(scan_id, 1, int(result["risk_score"] >= 30), result["risk_score"],
                             analysis.get("sandbox_type"), None)
        report_path = generate_report(scan_id)
        database.finish_scan(scan_id, 1, int(result["risk_score"] >= 30), result["risk_score"],
                             analysis.get("sandbox_type"), report_path)
        return jsonify({**analysis, "scan_id": scan_id,
                        "report_url": f"/api/report/{scan_id}/download"})
    except Exception as exc:  # noqa: BLE001 - return a useful error and preserve logs
        logger.exception("Manual sandbox analysis failed for %s", file_path)
        return jsonify({"error": f"Sandbox analysis failed: {exc}"}), 500


# ---------------------------------------------------------------------------
# Routes - API: Settings / Start with Windows
# ---------------------------------------------------------------------------
@app.route("/api/settings/startup")
def api_startup_status():
    """
    Read-only status check used to sync the Settings checkbox on page load.
    Reports the real current registry state - never assumes or caches it.
    """
    return jsonify(startup_manager.get_status())


@app.route("/api/settings/startup", methods=["POST"])
def api_startup_apply():
    """
    Apply the user's chosen startup preference. This is the ONLY code path
    that ever writes or deletes the HKCU Run value, and it only runs in
    direct response to this explicit request from the Settings page's
    Apply Changes button - never automatically and never on app launch.
    """
    payload = request.get_json(force=True, silent=True) or {}
    enabled = bool(payload.get("enabled", False))

    try:
        result = startup_manager.enable() if enabled else startup_manager.disable()
    except Exception as exc:  # noqa: BLE001 - this endpoint must never crash the app
        logger.exception("Unexpected error applying startup setting: %s", exc)
        return jsonify({"success": False, "message": f"Unexpected error: {exc}"}), 500

    status_code = 200 if result.get("success") else 400
    response = {**result, "status": startup_manager.get_status()}
    return jsonify(response), status_code


@app.route("/api/settings/background")
def api_background_get():
    """Current 'run in background / system tray' choice plus whether the tray can work at all."""
    return jsonify({
        "enabled": database.get_bool_setting(config.BACKGROUND_MODE_SETTING_KEY, default=False),
        "tray_available": tray.TRAY_AVAILABLE,
    })


@app.route("/api/settings/background", methods=["POST"])
def api_background_apply():
    """
    Persist the user's explicit choice. Background mode is OFF until the user ticks the box and
    applies it (permission), and the desktop shell reacts through ui_bridge.
    """
    payload = request.get_json(force=True, silent=True) or {}
    enabled = bool(payload.get("enabled", False))
    if enabled and not tray.TRAY_AVAILABLE:
        return jsonify({"success": False, "enabled": False,
                        "message": "System tray support (pystray + Pillow) is not installed."}), 400
    database.set_bool_setting(config.BACKGROUND_MODE_SETTING_KEY, enabled)
    ui_bridge.emit("background_mode_changed", enabled=enabled)
    return jsonify({
        "success": True, "enabled": enabled,
        "message": ("Running in the background. Closing or minimizing the window keeps the app in the "
                    "system tray." if enabled else "Background mode turned off."),
    })


@app.route("/api/hid/status")
def api_hid_status():
    return jsonify(hid_guard.status())


@app.route("/api/hid/alerts")
def api_hid_alerts():
    return jsonify(hid_guard.alerts())


@app.route("/api/hid/trust", methods=["POST"])
def api_hid_trust():
    """'This is my own keyboard': trust its VID/PID and re-enable it."""
    payload = request.get_json(force=True, silent=True) or {}
    result = hid_guard.trust_device(str(payload.get("alert_id", "")))
    return jsonify(result), (200 if result.get("success") else 400)


_AUTO_DOWNLOAD_SETTING_KEY = "auto_download_report"


@app.route("/api/settings/preferences")
def api_preferences_get():
    """Read-only status check used to sync the Auto-Download toggle on page load."""
    return jsonify({
        "auto_download_report": database.get_bool_setting(_AUTO_DOWNLOAD_SETTING_KEY, default=False),
    })


@app.route("/api/settings/preferences", methods=["POST"])
def api_preferences_apply():
    """Persist simple user preferences (currently just Auto-Download Report)."""
    payload = request.get_json(force=True, silent=True) or {}
    if "auto_download_report" in payload:
        database.set_bool_setting(_AUTO_DOWNLOAD_SETTING_KEY, bool(payload["auto_download_report"]))
    return jsonify({
        "success": True,
        "auto_download_report": database.get_bool_setting(_AUTO_DOWNLOAD_SETTING_KEY, default=False),
    })


# ---------------------------------------------------------------------------
# Routes - API: PDF report
# ---------------------------------------------------------------------------
@app.route("/api/scan/<scan_id>/report", methods=["POST"])
def api_generate_report(scan_id: str):
    try:
        path = generate_report(scan_id)
        scan = database.get_scan(scan_id)
        database.finish_scan(
            scan_id, scan["files_scanned"], scan["suspicious_files"],
            scan["highest_risk"], scan["sandbox_used"], path,
        )
        return jsonify({"status": "generated", "path": path})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404


@app.route("/api/report/<scan_id>/download")
def api_download_report(scan_id: str):
    scan = database.get_scan(scan_id)
    if not scan or not scan.get("report_path"):
        return jsonify({"error": "report not generated yet"}), 404
    return send_file(scan["report_path"], as_attachment=True)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    database.init_db()
    usb_monitor.start()
    hid_guard.start()
    logger.info("USB Threat Analyzer starting on http://%s:%d", config.FLASK_HOST, config.FLASK_PORT)
    try:
        app.run(host=config.FLASK_HOST, port=config.FLASK_PORT, debug=config.FLASK_DEBUG,
                 use_reloader=False, threaded=True)
    finally:
        hid_guard.stop()
        usb_monitor.stop()


if __name__ == "__main__":
    main()
