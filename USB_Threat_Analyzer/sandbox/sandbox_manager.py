"""
Sandbox Manager - the single entry point Level 4 orchestration goes
through. Detects which sandbox environments are installed, lets the
caller choose when more than one is available, and runs the full
launch -> before-snapshot -> execute -> monitor -> after-snapshot ->
compare workflow, persisting the result to the database.

The host application process never executes a suspicious file
directly; every execution happens inside whichever isolated sandbox
was selected.
"""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import database
from sandbox import virtualbox, vmware, windows_sandbox
from sandbox.runtime_monitor import RuntimeEvent, RuntimeMonitor
from utils.hash import sha256_of
from utils.logger import get_logger

logger = get_logger(__name__)


def detect_available_sandboxes() -> dict[str, dict]:
    """
    Detect every sandbox environment installed on this machine.
    Returns a dict keyed by sandbox type with readiness info, so the UI
    can show "Windows Sandbox Ready / VirtualBox Installed / VMware
    Installed" and let the user choose when more than one exists.
    """
    availability = {
        "windows_sandbox": {
            "name": "Windows Sandbox",
            "ready": windows_sandbox.is_available(),
        },
        "vmware": {
            "name": "VMware",
            "ready": vmware.is_available(),
            "vms": vmware.list_registered_vms() if vmware.is_available() else [],
            "vmrun_path": vmware.get_vmrun_path(),
        },
        "virtualbox": {
            "name": "VirtualBox",
            "ready": virtualbox.is_available(),
            "vms": virtualbox.list_vms() if virtualbox.is_available() else [],
        },
    }
    logger.info("Sandbox detection: %s", {k: v["ready"] for k, v in availability.items()})
    return availability


def run_analysis(
    file_path: str | Path,
    scan_id: str,
    sandbox_choice: str,
    vm_name: Optional[str] = None,
    guest_password: Optional[str] = None,
    on_runtime_event: Optional[callable] = None,
) -> dict:
    """
    Run the full Level 4 dynamic analysis workflow for one file.

    Args:
        file_path: Path to the suspicious (typically quarantined) file.
        scan_id: The parent scan this run belongs to, for DB linkage.
        sandbox_choice: One of "windows_sandbox", "vmware", "virtualbox".
        vm_name: Required for vmware/virtualbox - VMX path or VM name.
        on_runtime_event: Optional callback invoked with each live
            RuntimeEvent for streaming to the UI during the run.

    Returns:
        Dict with sandbox_type, status, snapshots, and diff - the same
        shape persisted to the sandbox_runs table.
    """
    file_path = Path(file_path)
    file_hash = sha256_of(file_path)
    started_at = datetime.utcnow().isoformat()

    events: list[RuntimeEvent] = []

    def _capture_event(evt: RuntimeEvent) -> None:
        events.append(evt)
        if on_runtime_event:
            on_runtime_event(evt)

    monitor: Optional[RuntimeMonitor] = None
    result: dict = {}
    try:
        import config
        staging_dir = config.SANDBOX_STAGING_DIR / scan_id
        monitor = RuntimeMonitor(staging_dir, _capture_event)
        monitor.start()

        if sandbox_choice == "windows_sandbox":
            result = windows_sandbox.run_in_sandbox(file_path, scan_id)
        elif sandbox_choice == "vmware":
            if not vm_name:
                raise ValueError("vm_name (VMX path) is required for VMware analysis")
            result = vmware.run_in_sandbox(file_path, vm_name, scan_id, guest_password=guest_password or "analysis")
        elif sandbox_choice == "virtualbox":
            if not vm_name:
                raise ValueError("vm_name is required for VirtualBox analysis")
            result = virtualbox.run_in_sandbox(file_path, vm_name, scan_id, guest_password=guest_password or "analysis")
        else:
            raise ValueError(f"Unknown sandbox choice: {sandbox_choice}")
    except Exception as exc:  # noqa: BLE001 - preserve a truthful failure result
        logger.exception("Sandbox analysis failed for %s", file_path)
        result = {"sandbox_type": sandbox_choice, "status": "error", "message": str(exc)}

    finally:
        if monitor:
            monitor.stop()

    finished_at = datetime.utcnow().isoformat()
    result["live_events"] = [
        {"timestamp": e.timestamp, "category": e.category, "description": e.description}
        for e in events
    ]

    before_snapshot = result.get("before_snapshot", {})
    after_snapshot = result.get("after_snapshot", {})
    diff = result.get("diff", {})

    verdict_notes = _build_verdict_notes(result, events)

    database.insert_sandbox_run(
        scan_id=scan_id, file_sha256=file_hash, sandbox_type=result.get("sandbox_type", sandbox_choice),
        started_at=started_at, finished_at=finished_at,
        before_snapshot=before_snapshot, after_snapshot=after_snapshot,
        diff=diff, verdict_notes=verdict_notes,
    )

    result["verdict_notes"] = verdict_notes
    logger.info("Sandbox analysis complete for %s via %s: %s",
                file_path.name, sandbox_choice, result.get("status"))
    return result


def _build_verdict_notes(result: dict, events: list[RuntimeEvent]) -> str:
    """
    Summarize behavior indicators observed during the run, phrased as
    indicators rather than a definitive malware verdict.
    """
    if result.get("status") != "completed":
        return result.get("message", "Sandbox run did not complete.")

    diff = result.get("diff", {})
    summary = diff.get("summary", {})
    notes = []
    if summary.get("registry", 0) > 0:
        notes.append(f"Registry changes: {summary['registry']}")
    if summary.get("files", 0) > 0:
        notes.append(f"File changes: {summary['files']}")
    if summary.get("network", 0) > 0:
        notes.append(f"New network connections: {summary['network']}")
    if summary.get("startup", 0) > 0:
        notes.append(f"New startup persistence entries: {summary['startup']}")
    if summary.get("services", 0) > 0:
        notes.append(f"New services created: {summary['services']}")
    if summary.get("scheduled_tasks", 0) > 0:
        notes.append(f"New scheduled tasks: {summary['scheduled_tasks']}")
    if summary.get("collection_failures", 0) > 0:
        notes.append(f"Guest-state collection failures: {summary['collection_failures']} (unavailable data is not inferred).")

    rapid_flags = [e.description for e in events if "ransomware" in e.description.lower()]
    if rapid_flags:
        notes.append("Rapid file-change pattern consistent with ransomware-style behavior observed.")

    if not notes:
        return "No significant system changes observed during the monitored execution window."
    return "Behavior indicators observed - " + "; ".join(notes) + "."
