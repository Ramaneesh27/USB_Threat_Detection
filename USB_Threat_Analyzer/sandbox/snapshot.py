"""
System snapshot capture used for BEFORE/AFTER comparison around a
sandboxed execution. Snapshots are real, live-queried state - never
fabricated - covering files, registry run-keys, startup entries,
running processes, services, scheduled tasks, and active network
connections. Works against the local sandbox execution context (used
for both the "logical" Windows Sandbox comparison and the pre/post
state captured against a VM's guest before it is snapshotted by
VMware/VirtualBox).
"""

from __future__ import annotations

import platform
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

import psutil

from utils.logger import get_logger

logger = get_logger(__name__)

_IS_WINDOWS = platform.system() == "Windows"


@dataclass
class SystemSnapshot:
    taken_at: str
    files: list[str] = field(default_factory=list)
    registry_run_keys: dict[str, str] = field(default_factory=dict)
    startup_entries: list[str] = field(default_factory=list)
    processes: list[dict] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    scheduled_tasks: list[str] = field(default_factory=list)
    network_connections: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _list_directory(path: Path) -> list[str]:
    if not path.exists():
        return []
    try:
        return [str(p) for p in path.rglob("*") if p.is_file()]
    except (OSError, PermissionError) as exc:
        logger.debug("Could not list %s: %s", path, exc)
        return []


def _read_registry_run_keys() -> dict[str, str]:
    """Read HKCU/HKLM Run keys - the classic persistence location."""
    if not _IS_WINDOWS:
        return {}
    entries: dict[str, str] = {}
    try:
        import winreg
        for hive, hive_name in ((winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
            try:
                key = winreg.OpenKey(hive, r"Software\Microsoft\Windows\CurrentVersion\Run")
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        entries[f"{hive_name}\\{name}"] = str(value)
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except FileNotFoundError:
                continue
    except ImportError:
        logger.debug("winreg unavailable (non-Windows environment)")
    return entries


def _read_startup_folder() -> list[str]:
    if not _IS_WINDOWS:
        return []
    import os
    appdata = os.environ.get("APPDATA", "")
    programdata = os.environ.get("PROGRAMDATA", "")
    paths = [
        Path(appdata) / "Microsoft/Windows/Start Menu/Programs/Startup",
        Path(programdata) / "Microsoft/Windows/Start Menu/Programs/Startup",
    ]
    entries: list[str] = []
    for p in paths:
        entries.extend(_list_directory(p))
    return entries


def _list_processes() -> list[dict]:
    procs = []
    for p in psutil.process_iter(attrs=["pid", "name", "exe", "ppid"]):
        try:
            procs.append(p.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return procs


def _list_services() -> list[str]:
    if not _IS_WINDOWS:
        return []
    try:
        out = subprocess.run(
            ["sc", "query", "state=", "all"], capture_output=True, text=True, timeout=15
        )
        return [line.strip() for line in out.stdout.splitlines() if line.strip().startswith("SERVICE_NAME")]
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("Could not query services: %s", exc)
        return []


def _list_scheduled_tasks() -> list[str]:
    if not _IS_WINDOWS:
        return []
    try:
        out = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV", "/nh"], capture_output=True, text=True, timeout=15
        )
        return [line.split(",")[0].strip('"') for line in out.stdout.splitlines() if line.strip()]
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("Could not query scheduled tasks: %s", exc)
        return []


def _list_network_connections() -> list[dict]:
    conns = []
    try:
        for c in psutil.net_connections(kind="inet"):
            conns.append({
                "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                "status": c.status,
                "pid": c.pid,
            })
    except (psutil.AccessDenied, PermissionError) as exc:
        logger.debug("Could not enumerate network connections: %s", exc)
    return conns


def capture_snapshot(watch_dirs: list[Path] | None = None) -> SystemSnapshot:
    """
    Capture a live snapshot of the current system/sandbox-guest state.
    `watch_dirs` should include the sandbox's user profile / temp / desktop
    so newly dropped files are visible in the diff.
    """
    watch_dirs = watch_dirs or []
    files: list[str] = []
    for d in watch_dirs:
        files.extend(_list_directory(d))

    snapshot = SystemSnapshot(
        taken_at=datetime.utcnow().isoformat(),
        files=files,
        registry_run_keys=_read_registry_run_keys(),
        startup_entries=_read_startup_folder(),
        processes=_list_processes(),
        services=_list_services(),
        scheduled_tasks=_list_scheduled_tasks(),
        network_connections=_list_network_connections(),
    )
    logger.info(
        "Snapshot captured: %d files, %d processes, %d services, %d scheduled tasks",
        len(snapshot.files), len(snapshot.processes), len(snapshot.services), len(snapshot.scheduled_tasks),
    )
    return snapshot


def diff_snapshots(before: SystemSnapshot, after: SystemSnapshot) -> dict:
    """Compute the BEFORE -> AFTER difference across every tracked category."""
    before_files, after_files = set(before.files), set(after.files)
    before_procs = {(p.get("pid"), p.get("name")) for p in before.processes}
    after_procs = {(p.get("pid"), p.get("name")) for p in after.processes}
    before_services, after_services = set(before.services), set(after.services)
    before_tasks, after_tasks = set(before.scheduled_tasks), set(after.scheduled_tasks)
    before_startup, after_startup = set(before.startup_entries), set(after.startup_entries)
    before_reg, after_reg = set(before.registry_run_keys.items()), set(after.registry_run_keys.items())
    before_net = {(c["raddr"], c["status"]) for c in before.network_connections if c["raddr"]}
    after_net = {(c["raddr"], c["status"]) for c in after.network_connections if c["raddr"]}

    diff = {
        "new_files": sorted(after_files - before_files),
        "deleted_files": sorted(before_files - after_files),
        "new_processes": sorted(str(p) for p in (after_procs - before_procs)),
        "registry_changes": sorted(f"{k}={v}" for k, v in (after_reg - before_reg)),
        "startup_persistence_new": sorted(after_startup - before_startup),
        "new_services": sorted(after_services - before_services),
        "new_scheduled_tasks": sorted(after_tasks - before_tasks),
        "new_network_connections": sorted(f"{addr} ({status})" for addr, status in (after_net - before_net)),
        "summary": {},
    }
    diff["summary"] = {
        "files": len(diff["new_files"]) + len(diff["deleted_files"]),
        "registry": len(diff["registry_changes"]),
        "network": len(diff["new_network_connections"]),
        "startup": len(diff["startup_persistence_new"]),
        "services": len(diff["new_services"]),
        "scheduled_tasks": len(diff["new_scheduled_tasks"]),
        "new_processes": len(diff["new_processes"]),
    }
    return diff
