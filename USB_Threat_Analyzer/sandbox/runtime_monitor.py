"""
Real-time runtime behavior monitor.

Watches the sandbox staging directory and host-visible process/network
tables *while* a sandboxed sample is running (not just before/after),
using `watchdog` for filesystem events and `psutil` for process/network
polling. This powers the live activity feed in the UI during a Level 4
run and specifically looks for rapid mass file changes consistent with
ransomware-style encryption behavior.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

import psutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from utils.logger import get_logger

logger = get_logger(__name__)

# If more than this many file modify/create events occur within the
# rolling window below, flag rapid file-encryption-like behavior.
_RAPID_CHANGE_EVENT_THRESHOLD = 20
_RAPID_CHANGE_WINDOW_SECONDS = 5.0


@dataclass
class RuntimeEvent:
    timestamp: float
    category: str  # "file" | "process" | "network"
    description: str


class _StagingDirHandler(FileSystemEventHandler):
    def __init__(self, on_event: Callable[[RuntimeEvent], None]) -> None:
        self._on_event = on_event
        self._recent_timestamps: list[float] = []
        self._rapid_flagged = False

    def _record(self, category: str, description: str) -> None:
        now = time.time()
        self._on_event(RuntimeEvent(timestamp=now, category=category, description=description))

        self._recent_timestamps.append(now)
        cutoff = now - _RAPID_CHANGE_WINDOW_SECONDS
        self._recent_timestamps = [t for t in self._recent_timestamps if t >= cutoff]

        if len(self._recent_timestamps) >= _RAPID_CHANGE_EVENT_THRESHOLD and not self._rapid_flagged:
            self._rapid_flagged = True
            self._on_event(RuntimeEvent(
                timestamp=now, category="file",
                description=(
                    f"Rapid file change behavior detected: {len(self._recent_timestamps)} "
                    f"file events within {_RAPID_CHANGE_WINDOW_SECONDS:.0f}s - "
                    f"consistent with mass file encryption/ransomware behavior."
                ),
            ))

    def on_created(self, event):
        if not event.is_directory:
            self._record("file", f"New file: {event.src_path}")

    def on_modified(self, event):
        if not event.is_directory:
            self._record("file", f"Modified: {event.src_path}")

    def on_deleted(self, event):
        if not event.is_directory:
            self._record("file", f"Deleted: {event.src_path}")


class RuntimeMonitor:
    """
    Watches a staging directory plus host process/network state for the
    duration of a sandbox run, emitting RuntimeEvent objects as they
    happen so the UI can show a live activity feed.
    """

    def __init__(self, watch_dir: Path, on_event: Callable[[RuntimeEvent], None]) -> None:
        self._watch_dir = watch_dir
        self._on_event = on_event
        self._observer: Optional[Observer] = None
        self._poll_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._baseline_pids: set[int] = set()
        self._baseline_conns: set[tuple] = set()

    def start(self) -> None:
        self._watch_dir.mkdir(parents=True, exist_ok=True)
        handler = _StagingDirHandler(self._on_event)
        self._observer = Observer()
        self._observer.schedule(handler, str(self._watch_dir), recursive=True)
        self._observer.start()

        self._baseline_pids = {p.pid for p in psutil.process_iter()}
        try:
            self._baseline_conns = {
                (c.raddr.ip, c.raddr.port) for c in psutil.net_connections(kind="inet") if c.raddr
            }
        except (psutil.AccessDenied, PermissionError):
            self._baseline_conns = set()

        self._stop_event.clear()
        self._poll_thread = threading.Thread(target=self._poll_loop, name="RuntimeMonitorPoll", daemon=True)
        self._poll_thread.start()
        logger.info("Runtime monitor started for %s", self._watch_dir)

    def stop(self) -> None:
        self._stop_event.set()
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
        if self._poll_thread:
            self._poll_thread.join(timeout=5)
        logger.info("Runtime monitor stopped")

    def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                current_pids = {p.pid for p in psutil.process_iter()}
                new_pids = current_pids - self._baseline_pids
                for pid in new_pids:
                    try:
                        name = psutil.Process(pid).name()
                        self._on_event(RuntimeEvent(
                            timestamp=time.time(), category="process",
                            description=f"New process spawned: {name} (pid={pid})",
                        ))
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                self._baseline_pids = current_pids

                try:
                    current_conns = {
                        (c.raddr.ip, c.raddr.port) for c in psutil.net_connections(kind="inet") if c.raddr
                    }
                    for ip, port in (current_conns - self._baseline_conns):
                        self._on_event(RuntimeEvent(
                            timestamp=time.time(), category="network",
                            description=f"Outbound connection: {ip}:{port}",
                        ))
                    self._baseline_conns = current_conns
                except (psutil.AccessDenied, PermissionError):
                    pass

            except Exception as exc:  # noqa: BLE001
                logger.debug("Runtime monitor poll error: %s", exc)

            self._stop_event.wait(1.0)
