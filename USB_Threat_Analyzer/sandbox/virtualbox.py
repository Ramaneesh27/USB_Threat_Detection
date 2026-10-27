"""
VirtualBox integration via VBoxManage (Oracle VirtualBox's official CLI).
Supports real VM snapshot restore/take and guest control execution
using VBoxManage's `snapshot`, `guestcontrol copyto`, and
`guestcontrol run` commands.

Requires:
  - VirtualBox installed with VBoxManage on PATH.
  - A pre-built analysis VM with Guest Additions installed and a clean
    baseline snapshot named "clean_baseline".
"""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

import config
from sandbox.guest_state import GUEST_STAGING_PATH, GUEST_SNAPSHOT_SCRIPT, diff_guest_snapshots
from utils.logger import get_logger

logger = get_logger(__name__)

_BASELINE_SNAPSHOT = "clean_baseline"


def is_available() -> bool:
    """Detect whether VirtualBox's VBoxManage CLI is installed."""
    return shutil.which("VBoxManage") is not None


def _run_vboxmanage(args: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    cmd = ["VBoxManage"] + args
    logger.debug("Running: %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def list_vms() -> list[str]:
    """List registered VirtualBox VM names."""
    if not is_available():
        return []
    try:
        result = _run_vboxmanage(["list", "vms"])
        return [line.split('"')[1] for line in result.stdout.splitlines() if '"' in line]
    except (subprocess.SubprocessError, OSError, IndexError) as exc:
        logger.warning("Could not list VirtualBox VMs: %s", exc)
        return []



def _require_success(result: subprocess.CompletedProcess, operation: str) -> subprocess.CompletedProcess:
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "unknown VBoxManage error").strip()
        raise RuntimeError(f"VirtualBox {operation} failed: {detail}")
    return result


def _capture_guest_snapshot(vm_name: str, scan_id: str, label: str, guest_user: str, guest_password: str) -> dict:
    import json
    staging_dir = config.SANDBOX_STAGING_DIR / scan_id
    staging_dir.mkdir(parents=True, exist_ok=True)
    script_path = staging_dir / "guest_snapshot.ps1"
    host_result = staging_dir / f"{label}_guest_snapshot.json"
    guest_script = rf"{GUEST_STAGING_PATH}\guest_snapshot.ps1"
    guest_result = rf"{GUEST_STAGING_PATH}\{label}_guest_snapshot.json"
    script_path.write_text(GUEST_SNAPSHOT_SCRIPT, encoding="utf-8")
    _require_success(_run_vboxmanage(["guestcontrol", vm_name, "copyto", str(script_path), guest_script,
                                      "--username", guest_user, "--password", guest_password]),
                     "guest collector upload")
    _require_success(_run_vboxmanage([
        "guestcontrol", vm_name, "run", "--exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "--username", guest_user, "--password", guest_password, "--wait-stdout", "--wait-stderr", "--",
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", guest_script, "-OutputPath", guest_result
    ], timeout=120), f"{label} guest collection")
    _require_success(_run_vboxmanage(["guestcontrol", vm_name, "copyfrom", guest_result, str(host_result),
                                      "--username", guest_user, "--password", guest_password]),
                     f"{label} guest result download")
    try:
        snapshot = json.loads(host_result.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"Could not read {label} guest-state result: {exc}") from exc
    snapshot.setdefault("collection_errors", [])
    snapshot.setdefault("open_ports", [])
    return snapshot

def run_in_sandbox(file_path: str | Path, vm_name: str, scan_id: str,
                    guest_user: str = "analyst", guest_password: str = "analysis") -> dict:
    """
    Restore the analysis VM to its clean baseline snapshot, start it
    headless, copy the suspicious file into the guest via Guest
    Additions, execute it, take an after-snapshot, and report the
    snapshot names. The suspicious file only ever runs inside the
    isolated VM guest, never on the host.
    """
    file_path = Path(file_path)

    if not is_available():
        return {"sandbox_type": "VirtualBox", "status": "unavailable",
                "message": "VBoxManage CLI not found; VirtualBox is not installed or not on PATH."}

    if vm_name not in list_vms():
        return {"sandbox_type": "VirtualBox", "status": "error",
                "message": f"VM '{vm_name}' is not registered in VirtualBox."}

    started_at = time.time()
    before_snapshot_name = f"before_{scan_id}"
    after_snapshot_name = f"after_{scan_id}"

    vm_started = False
    try:
        logger.info("Restoring VirtualBox VM %s to baseline snapshot", vm_name)
        _require_success(_run_vboxmanage(["snapshot", vm_name, "restore", _BASELINE_SNAPSHOT]), "baseline restore")
        _require_success(_run_vboxmanage(["startvm", vm_name, "--type", "headless"]), "VM start")
        vm_started = True
        time.sleep(20)  # allow guest OS + Guest Additions to come up

        _require_success(_run_vboxmanage(["snapshot", vm_name, "take", before_snapshot_name]), "BEFORE snapshot")
        before_snapshot = _capture_guest_snapshot(vm_name, scan_id, "before", guest_user, guest_password)

        guest_target = f"{GUEST_STAGING_PATH}\\{file_path.name}"
        _require_success(_run_vboxmanage([
            "guestcontrol", vm_name, "copyto", str(file_path), guest_target,
            "--username", guest_user, "--password", guest_password,
        ]), "sample upload")

        logger.info("Executing sample inside VirtualBox guest: %s", guest_target)
        execution_timed_out = False
        try:
            _require_success(_run_vboxmanage([
                "guestcontrol", vm_name, "run", "--exe", guest_target,
                "--username", guest_user, "--password", guest_password,
            ], timeout=config.SANDBOX_RUN_TIMEOUT_SECONDS), "sample execution")
        except subprocess.TimeoutExpired:
            execution_timed_out = True
            logger.info("VirtualBox guest execution reached timeout for %s", file_path.name)

        time.sleep(5)
        after_snapshot = _capture_guest_snapshot(vm_name, scan_id, "after", guest_user, guest_password)
        diff = diff_guest_snapshots(before_snapshot, after_snapshot)
        _require_success(_run_vboxmanage(["snapshot", vm_name, "take", after_snapshot_name]), "AFTER snapshot")

    except (subprocess.SubprocessError, OSError, RuntimeError) as exc:
        logger.exception("VirtualBox sandbox run failed: %s", exc)
        return {"sandbox_type": "VirtualBox", "status": "error", "message": str(exc)}
    finally:
        if vm_started:
            _run_vboxmanage(["controlvm", vm_name, "poweroff"])

    finished_at = time.time()

    return {
        "sandbox_type": "VirtualBox",
        "status": "completed",
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": round(finished_at - started_at, 1),
        "before_snapshot_name": before_snapshot_name,
        "after_snapshot_name": after_snapshot_name,
        "before_snapshot": before_snapshot,
        "after_snapshot": after_snapshot,
        "diff": diff,
        "execution_timed_out": execution_timed_out,
    }
