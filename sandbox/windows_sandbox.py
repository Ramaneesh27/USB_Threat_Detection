"""
Windows Sandbox integration.

Windows Sandbox is a disposable, lightweight desktop environment built
into Windows 10/11 Pro+/Enterprise. Each run gets a fresh, isolated
instance with no persisted state, launched via a generated .wsb
configuration file. Because there is no external VM snapshot API for
Windows Sandbox, this module implements the "logical" before/after
comparison described in the spec: a snapshot of the HOST's shared
staging folder and process table is taken immediately before launch
and again after the sandboxed process finishes/times out, and the
suspicious file itself only ever runs inside the disposable guest.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

import config
from sandbox.snapshot import capture_snapshot, diff_snapshots
from utils.logger import get_logger

logger = get_logger(__name__)

_WSB_TEMPLATE = """<Configuration>
  <VGpu>Disable</VGpu>
  <Networking>Enable</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{host_folder}</HostFolder>
      <SandboxFolder>C:\\Sandbox</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>cmd /c start C:\\Sandbox\\{filename}</Command>
  </LogonCommand>
</Configuration>
"""


def is_available() -> bool:
    """
    Detect whether Windows Sandbox is installed and enabled. Windows
    Sandbox ships as the WindowsSandbox.exe launcher once the optional
    feature "Containers-DisposableClientVM" is enabled.
    """
    exe = shutil.which("WindowsSandbox.exe") or shutil.which("WindowsSandbox")
    if exe:
        return True
    default_path = Path(r"C:\Windows\System32\WindowsSandbox.exe")
    return default_path.exists()


def _write_wsb_config(staging_dir: Path, target_filename: str) -> Path:
    wsb_path = staging_dir / "run.wsb"
    wsb_path.write_text(
        _WSB_TEMPLATE.format(host_folder=str(staging_dir), filename=target_filename),
        encoding="utf-8",
    )
    return wsb_path


def run_in_sandbox(file_path: str | Path, scan_id: str) -> dict:
    """
    Copy the suspicious file into an isolated staging folder, generate a
    .wsb config that maps ONLY that staging folder into a disposable
    Windows Sandbox instance, launch it, and capture a logical
    before/after comparison of the host staging area and process table.

    The host itself never executes the file - only the disposable guest does.
    """
    file_path = Path(file_path)
    staging_dir = config.SANDBOX_STAGING_DIR / scan_id
    staging_dir.mkdir(parents=True, exist_ok=True)

    staged_target = staging_dir / file_path.name
    shutil.copy2(str(file_path), str(staged_target))

    if not is_available():
        logger.warning("Windows Sandbox not available on this system")
        return {
            "sandbox_type": "Windows Sandbox",
            "status": "unavailable",
            "message": "Windows Sandbox is not installed/enabled on this system.",
        }

    before = capture_snapshot(watch_dirs=[staging_dir])

    wsb_config = _write_wsb_config(staging_dir, file_path.name)
    started_at = time.time()
    try:
        process = subprocess.Popen(["WindowsSandbox.exe", str(wsb_config)])
        logger.info("Launched Windows Sandbox for %s (pid=%s)", file_path.name, process.pid)

        deadline = started_at + config.SANDBOX_RUN_TIMEOUT_SECONDS
        while time.time() < deadline and process.poll() is None:
            time.sleep(2)

        timed_out = process.poll() is None
        if timed_out:
            logger.info("Sandbox run for %s reached timeout; capturing state and terminating.", file_path.name)
            process.terminate()

    except (OSError, subprocess.SubprocessError) as exc:
        logger.exception("Failed to launch Windows Sandbox: %s", exc)
        return {
            "sandbox_type": "Windows Sandbox",
            "status": "error",
            "message": f"Could not launch Windows Sandbox: {exc}",
        }

    finished_at = time.time()
    after = capture_snapshot(watch_dirs=[staging_dir])
    diff = diff_snapshots(before, after)

    return {
        "sandbox_type": "Windows Sandbox",
        "status": "completed",
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": round(finished_at - started_at, 1),
        "before_snapshot": before.to_dict(),
        "after_snapshot": after.to_dict(),
        "diff": diff,
    }
