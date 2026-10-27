"""
VMware integration via vmrun (VMware Workstation/Player's official CLI
automation tool). Supports real VM snapshot revert/create/compare
around a guest execution using vmrun's `snapshot`, `revertToSnapshot`,
`runProgramInGuest`, and `copyFileFromHostToGuest` commands.

Requires:
  - VMware Workstation/Player installed (vmrun.exe does NOT need to be on
    PATH - see _locate_vmrun() below, which also checks the standard
    install directories and the registry).
  - A pre-built analysis VM registered with a clean baseline snapshot
    named "clean_baseline" and VMware Tools installed in the guest.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

import config
from sandbox.guest_state import GUEST_STAGING_PATH, GUEST_SNAPSHOT_SCRIPT, diff_guest_snapshots
from utils.logger import get_logger

logger = get_logger(__name__)

_BASELINE_SNAPSHOT = "clean_baseline"
# VMware Workstation/Player installers do NOT reliably add vmrun.exe to
# the system PATH, so PATH-only detection (shutil.which) produces false
# negatives on machines where VMware is genuinely installed. These are
# the standard install locations across VMware product/version history.
_COMMON_INSTALL_DIRS = (
    r"C:\Program Files (x86)\VMware\VMware Workstation",
    r"C:\Program Files\VMware\VMware Workstation",
    r"C:\Program Files\VMware\VMware Workstation Pro",
    r"C:\Program Files (x86)\VMware\VMware Workstation Pro",
    r"C:\Program Files (x86)\VMware\VMware Player",
    r"C:\Program Files\VMware\VMware Player",
    r"C:\Program Files (x86)\VMware\VMware VIX",
    r"C:\Program Files\VMware\VMware VIX",
)

# Registry locations that store VMware's actual install directory,
# checked when vmrun.exe isn't found on PATH or in the common paths above.
_REGISTRY_LOOKUPS = (
    (r"SOFTWARE\WOW6432Node\VMware, Inc.\VMware Workstation", "InstallPath"),
    (r"SOFTWARE\VMware, Inc.\VMware Workstation", "InstallPath"),
    (r"SOFTWARE\WOW6432Node\VMware, Inc.\VMware Player", "InstallPath"),
    (r"SOFTWARE\VMware, Inc.\VMware Player", "InstallPath"),
)

_resolved_vmrun_path: Optional[str] = None  # cached after first successful lookup


def _registry_install_dirs() -> list[str]:
    """Read VMware's install directory from HKLM, if the registry keys exist."""
    dirs: list[str] = []
    try:
        import winreg
    except ImportError:
        return dirs

    views = [winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY] if hasattr(winreg, "KEY_WOW64_64KEY") else [0]
    for key_path, value_name in _REGISTRY_LOOKUPS:
        for view in views:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ | view)
                install_path, _ = winreg.QueryValueEx(key, value_name)
                winreg.CloseKey(key)
                if install_path:
                    dirs.append(install_path)
            except OSError:
                continue
    return dirs


def _locate_vmrun() -> Optional[str]:
    """
    Resolve the full path to vmrun.exe using, in order:
      1. PATH (shutil.which) - fastest, works if the user added it manually.
      2. Standard VMware install directories.
      3. The install directory recorded in the Windows registry by the
         VMware installer itself - the most reliable source, since it
         reflects wherever VMware was actually installed even if it's a
         non-default location, as long as it matches one of the known
         product registry keys.
    Result is cached in-process after the first successful lookup.
    """
    global _resolved_vmrun_path
    if _resolved_vmrun_path and Path(_resolved_vmrun_path).exists():
        return _resolved_vmrun_path

    exe_name = "vmrun.exe" if os.name == "nt" else "vmrun"

    configured = os.environ.get("VMRUN_PATH", "").strip().strip('"')
    if configured:
        candidate = Path(configured)
        if candidate.is_file():
            _resolved_vmrun_path = str(candidate)
            return _resolved_vmrun_path

    on_path = shutil.which("vmrun")
    if on_path:
        _resolved_vmrun_path = on_path
        return on_path

    for directory in _COMMON_INSTALL_DIRS:
        candidate = Path(directory) / exe_name
        if candidate.exists():
            _resolved_vmrun_path = str(candidate)
            return _resolved_vmrun_path

    for directory in _registry_install_dirs():
        base = Path(directory)
        for candidate in (base / exe_name, base / "vmrun.exe", base / "bin" / exe_name):
            if candidate.exists() and candidate.is_file():
                _resolved_vmrun_path = str(candidate)
                return _resolved_vmrun_path

    # Last-resort bounded search in the standard VMware roots. This handles
    # newer VMware installers that use a product-specific subdirectory.
    for root in (Path(r"C:\Program Files\VMware"), Path(r"C:\Program Files (x86)\VMware")):
        if root.exists():
            try:
                for candidate in root.glob("**/vmrun.exe"):
                    if candidate.is_file():
                        _resolved_vmrun_path = str(candidate)
                        return _resolved_vmrun_path
            except OSError:
                pass

    return None


def is_available() -> bool:
    """
    Detect whether VMware's vmrun CLI is installed. Checks PATH, the
    standard VMware install directories, and the registry install path -
    not PATH alone, since VMware does not always register itself there.
    """
    return _locate_vmrun() is not None


def get_vmrun_path() -> Optional[str]:
    """Public accessor for the resolved vmrun.exe path, mainly for diagnostics/UI display."""
    return _locate_vmrun()


def _run_vmrun(args: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    vmrun_path = _locate_vmrun()
    if not vmrun_path:
        raise RuntimeError(
            "VMware vmrun.exe was not found. Install VMware Workstation/Player, "
            "or set the VMRUN_PATH environment variable to the full path of vmrun.exe."
        )
    cmd = [vmrun_path] + args
    logger.debug("Running: %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _require_vmrun(result: subprocess.CompletedProcess, operation: str) -> subprocess.CompletedProcess:
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "unknown vmrun error").strip()
        raise RuntimeError(f"VMware {operation} failed: {detail}")
    return result


def _capture_guest_snapshot(vmx_path: str, scan_id: str, label: str,
                            guest_user: str, guest_password: str) -> dict:
    """Run the collector inside the guest and return only data actually collected."""
    import json

    staging_dir = config.SANDBOX_STAGING_DIR / scan_id
    staging_dir.mkdir(parents=True, exist_ok=True)
    script_path = staging_dir / "guest_snapshot.ps1"
    host_result = staging_dir / f"{label}_guest_snapshot.json"
    guest_script = rf"{GUEST_STAGING_PATH}\guest_snapshot.ps1"
    guest_result = rf"{GUEST_STAGING_PATH}\{label}_guest_snapshot.json"
    script_path.write_text(GUEST_SNAPSHOT_SCRIPT, encoding="utf-8")

    _require_vmrun(_run_vmrun(["-gu", guest_user, "-gp", guest_password,
                               "copyFileFromHostToGuest", vmx_path, str(script_path), guest_script]),
                   "guest collector upload")
    _require_vmrun(_run_vmrun(["-gu", guest_user, "-gp", guest_password,
                               "runProgramInGuest", vmx_path,
                               r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                               "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", guest_script,
                               "-OutputPath", guest_result], timeout=120),
                   f"{label} guest collection")
    _require_vmrun(_run_vmrun(["-gu", guest_user, "-gp", guest_password,
                               "copyFileFromGuestToHost", vmx_path, guest_result, str(host_result)]),
                   f"{label} guest result download")
    try:
        with host_result.open("r", encoding="utf-8-sig") as snapshot_file:
            snapshot = json.load(snapshot_file)
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"Could not read {label} guest-state result: {exc}") from exc
    snapshot.setdefault("collection_errors", [])
    snapshot.setdefault("open_ports", [])
    return snapshot


def _diff_guest_snapshots(before: dict, after: dict) -> dict:
    return diff_guest_snapshots(before, after)



def list_snapshots(vmx_path: str) -> list[str]:
    """Return the actual snapshot names reported by VMware for this VM."""
    if not Path(vmx_path).exists():
        raise RuntimeError(f"VMX file not found: {vmx_path}")
    result = _require_vmrun(_run_vmrun(["listSnapshots", vmx_path]), "list snapshots")
    snapshots: list[str] = []
    for raw in (result.stdout or "").splitlines():
        name = raw.strip()
        if not name or name.lower().startswith("total snapshots:"):
            continue
        # vmrun can prefix nested snapshot names with indentation/tree markers.
        name = name.lstrip("|+- \t")
        if name and name not in snapshots:
            snapshots.append(name)
    return snapshots


def ensure_baseline_snapshot(vmx_path: str) -> tuple[str, bool]:
    """Ensure a real VMware baseline snapshot exists and verify it afterwards.

    Returns (snapshot_name, created_now). If clean_baseline is absent, it is
    created from the VM's current state and immediately verified through
    listSnapshots. This avoids assuming a database/UI label means VMware has
    actually created the snapshot.
    """
    snapshots = list_snapshots(vmx_path)
    if _BASELINE_SNAPSHOT in snapshots:
        return _BASELINE_SNAPSHOT, False

    logger.warning(
        "VMware baseline snapshot '%s' does not exist for %s; creating it from the VM's current state.",
        _BASELINE_SNAPSHOT, vmx_path,
    )
    _create_verified_snapshot(vmx_path, _BASELINE_SNAPSHOT, timeout=300)
    snapshots_after = list_snapshots(vmx_path)
    if _BASELINE_SNAPSHOT not in snapshots_after:
        raise RuntimeError(
            f"VMware reported successful baseline creation, but '{_BASELINE_SNAPSHOT}' "
            f"is not present in the VM snapshot list. Available snapshots: "
            f"{', '.join(snapshots_after) if snapshots_after else '(none)'}"
        )
    return _BASELINE_SNAPSHOT, True



def _create_verified_snapshot(vmx_path: str, snapshot_name: str, timeout: int = 300) -> None:
    """Create a VMware snapshot and verify it exists even if vmrun takes a long time.

    Snapshot creation can legitimately take more than 60 seconds on large VMs.
    If vmrun times out, we check VMware's snapshot list before reporting failure,
    because the snapshot may have completed while the CLI process was waiting.
    """
    try:
        _require_vmrun(
            _run_vmrun(["snapshot", vmx_path, snapshot_name], timeout=timeout),
            f"{snapshot_name} snapshot creation",
        )
    except subprocess.TimeoutExpired as exc:
        try:
            existing = list_snapshots(vmx_path)
        except Exception as check_exc:
            raise RuntimeError(
                f"VMware snapshot '{snapshot_name}' exceeded the {timeout}-second wait, "
                f"and its final state could not be verified: {check_exc}"
            ) from exc
        if snapshot_name not in existing:
            raise RuntimeError(
                f"VMware snapshot '{snapshot_name}' did not finish within {timeout} seconds. "
                f"Available snapshots: {', '.join(existing) if existing else '(none)'}"
            ) from exc
        logger.warning("vmrun timed out waiting for '%s', but VMware reports the snapshot exists; continuing.", snapshot_name)

    actual = list_snapshots(vmx_path)
    if snapshot_name not in actual:
        raise RuntimeError(
            f"VMware did not create snapshot '{snapshot_name}'. "
            f"Available snapshots: {', '.join(actual) if actual else '(none)'}"
        )


def list_registered_vms() -> list[str]:
    """List VMs currently registered/running under vmrun (best-effort)."""
    if not is_available():
        return []
    try:
        result = _run_vmrun(["list"])
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip().endswith(".vmx")]
        return lines
    except (subprocess.SubprocessError, OSError) as exc:
        logger.warning("Could not list VMware VMs: %s", exc)
        return []


def run_in_sandbox(file_path: str | Path, vmx_path: str, scan_id: str,
                    guest_user: str = "analyst", guest_password: str = "analysis") -> dict:
    """
    Revert the analysis VM to its clean baseline snapshot, copy the
    suspicious file into the guest, execute it, take a fresh snapshot,
    and report the two snapshot names for comparison. The host process
    only ever calls vmrun; the target file itself runs solely inside
    the isolated VM guest.
    """
    file_path = Path(file_path)

    if not is_available():
        return {"sandbox_type": "VMware", "status": "unavailable",
                "message": "vmrun CLI not found; VMware Workstation/Player is not installed or not on PATH."}

    if not Path(vmx_path).exists():
        return {"sandbox_type": "VMware", "status": "error",
                "message": f"VMX file not found: {vmx_path}"}

    started_at = time.time()
    before_snapshot_name = f"before_{scan_id}"
    after_snapshot_name = f"after_{scan_id}"

    vm_started = False
    try:
        baseline_snapshot_name, baseline_created = ensure_baseline_snapshot(vmx_path)
        logger.info("Reverting VMware VM %s to verified baseline snapshot '%s'", vmx_path, baseline_snapshot_name)
        _require_vmrun(_run_vmrun(["revertToSnapshot", vmx_path, baseline_snapshot_name]), "baseline restore")
        _require_vmrun(_run_vmrun(["start", vmx_path, "nogui"]), "VM start")
        vm_started = True
        time.sleep(15)  # allow guest OS to finish booting

        _create_verified_snapshot(vmx_path, before_snapshot_name, timeout=300)
        before_snapshot = _capture_guest_snapshot(
            vmx_path, scan_id, "before", guest_user, guest_password)
        before_snapshot.update({
            "vmware_snapshot_name": before_snapshot_name,
            "vmx_path": str(Path(vmx_path).resolve()),
            "baseline_snapshot_name": baseline_snapshot_name,
            "baseline_created_now": baseline_created,
        })

        guest_target = f"{GUEST_STAGING_PATH}\\{file_path.name}"
        _require_vmrun(_run_vmrun([
            "-gu", guest_user, "-gp", guest_password,
            "copyFileFromHostToGuest", vmx_path, str(file_path), guest_target,
        ]), "sample upload")

        logger.info("Executing sample inside VMware guest: %s", guest_target)
        execution_timed_out = False
        try:
            _require_vmrun(_run_vmrun([
                "-gu", guest_user, "-gp", guest_password,
                "runProgramInGuest", vmx_path, guest_target,
            ], timeout=config.SANDBOX_RUN_TIMEOUT_SECONDS), "sample execution")
        except subprocess.TimeoutExpired:
            execution_timed_out = True
            logger.info("VMware guest execution reached timeout for %s", file_path.name)

        time.sleep(5)
        after_snapshot = _capture_guest_snapshot(
            vmx_path, scan_id, "after", guest_user, guest_password)
        diff = _diff_guest_snapshots(before_snapshot, after_snapshot)
        _create_verified_snapshot(vmx_path, after_snapshot_name, timeout=300)
        after_snapshot.update({
            "vmware_snapshot_name": after_snapshot_name,
            "vmx_path": str(Path(vmx_path).resolve()),
            "baseline_snapshot_name": baseline_snapshot_name,
            "baseline_created_now": baseline_created,
        })

    except (subprocess.SubprocessError, OSError, RuntimeError) as exc:
        logger.exception("VMware sandbox run failed: %s", exc)
        return {"sandbox_type": "VMware", "status": "error", "message": str(exc)}
    finally:
        if vm_started:
            _run_vmrun(["stop", vmx_path, "hard"])

    finished_at = time.time()

    return {
        "sandbox_type": "VMware",
        "status": "completed",
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": round(finished_at - started_at, 1),
        "before_snapshot_name": before_snapshot_name,
        "after_snapshot_name": after_snapshot_name,
        "baseline_snapshot_name": baseline_snapshot_name,
        "baseline_created_now": baseline_created,
        "before_snapshot": before_snapshot,
        "after_snapshot": after_snapshot,
        "diff": diff,
        "execution_timed_out": execution_timed_out,
    }
