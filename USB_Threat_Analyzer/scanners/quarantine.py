"""
Quarantine System.

Files are MOVED (never automatically deleted) into quarantine/scan_<id>/ with full
provenance recorded in SQLite. Two things put a file here:
  * AUTO   - a scan gave it a risk score >= config.AUTO_QUARANTINE_THRESHOLD (75), or
  * MANUAL - the user chose it in the sidebar's Quarantine page (file browser or drag & drop).
Both are recorded (quarantine.source) and both are listed in the PDF report. Supports
restore-to-original-location, permanent deletion (explicit user action
only), sample export (hashed copy for external analysis), and handing
a file off to the sandbox for dynamic analysis.

RELEASE PROTECTION: anything that lets a quarantined file leave quarantine
(restore, permanent delete, export) first challenges the signed-in user with the
native Windows Security prompt and only proceeds once the OS has verified their
account password or PIN (see utils/credential_prompt.py). Nothing is changed on
disk or in the database before that check passes.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Optional

import config
import database
from utils import credential_prompt
from utils.hash import sha256_of
from utils.logger import get_logger

logger = get_logger(__name__)


class QuarantineError(Exception):
    """Raised for quarantine operations that cannot be completed safely."""


class QuarantineAuthError(QuarantineError):
    """The user did not (or could not) prove who they are; the file was NOT released."""

    def __init__(self, message: str, outcome: str = credential_prompt.FAILED) -> None:
        super().__init__(message)
        self.outcome = outcome


_ACTION_TEXT = {
    "restore": ("Restore quarantined file", "restore this file from quarantine"),
    "delete": ("Permanently delete quarantined file", "permanently delete this quarantined file"),
    "export": ("Export quarantined sample", "export a copy of this quarantined file"),
}


def _require_user_authentication(action: str, item: dict) -> None:
    """Block until the Windows account password/PIN is verified, or raise QuarantineAuthError."""
    if not config.QUARANTINE_REQUIRE_OS_AUTH:
        logger.warning("Quarantine release protection is DISABLED in config (%s of item %s).",
                       action, item.get("id"))
        return
    title, verb = _ACTION_TEXT[action]
    name = Path(item["quarantine_path"]).name
    result = credential_prompt.verify_current_user(
        title, f"USB Threat Analyzer needs to confirm it is you before you {verb}:\n\n{name}\n\n"
               f"Enter your Windows password or PIN.",
        parent_window_title="USB Threat Analyzer")
    if not result.verified:
        logger.warning("Quarantine %s of item %s DENIED (%s)", action, item.get("id"), result.outcome)
        raise QuarantineAuthError(result.message or "Verification failed.", result.outcome)
    logger.info("Quarantine %s of item %s authorized by Windows account verification",
                action, item.get("id"))


def ensure_quarantinable(path: str | Path) -> Path:
    """
    Validate a path BEFORE anything is moved. Returns the absolute path or raises
    QuarantineError with a message that is safe to show the user. Refuses: relative paths,
    missing files, folders, and anything inside a protected location (the Windows
    directory, or the quarantine folder itself - see config.quarantine_protected_roots()).
    """
    raw = str(path)
    if not raw or "\x00" in raw:
        raise QuarantineError("Invalid file path.")
    candidate = Path(raw)
    if not candidate.is_absolute():
        raise QuarantineError(f"Not an absolute path: {raw}")
    if not candidate.exists():
        raise QuarantineError(f"File not found: {raw}")
    if candidate.is_dir():
        raise QuarantineError(f"{candidate.name} is a folder - choose the files inside it.")
    if not candidate.is_file():
        raise QuarantineError(f"Not a regular file: {raw}")
    try:
        resolved = candidate.resolve()
    except OSError as exc:
        raise QuarantineError(f"Cannot read {raw}: {exc}") from exc
    for root in config.quarantine_protected_roots():
        if resolved == root or root in resolved.parents:
            if root == config.QUARANTINE_DIR.resolve():
                raise QuarantineError(f"{candidate.name} is already inside quarantine.")
            raise QuarantineError(
                f"{candidate.name} is in a protected Windows system folder ({root}); moving it "
                f"could stop Windows from working, so it was not quarantined.")
    return candidate


def quarantine_file(scan_id: str, source_path: str | Path, risk_score: int,
                     reasons: list[str], explanations: Optional[list[dict]] = None,
                     source: str = "auto") -> dict:
    """
    Move a file out of its original location and into an isolated quarantine folder,
    recording full provenance. `source` is "auto" (risk score reached the threshold) or
    "manual" (the user chose it). The original file is never left executable/reachable
    from its original path: if the move fails (e.g. read-only media) the sample is copied
    and a removal of the original is attempted; the result's `original_removed` says
    whether the original is really gone.
    """
    source = "manual" if source == "manual" else "auto"
    source_path = Path(source_path)
    if not source_path.exists():
        raise QuarantineError(f"Source file no longer exists: {source_path}")

    scan_quarantine_dir = config.QUARANTINE_DIR / scan_id
    scan_quarantine_dir.mkdir(parents=True, exist_ok=True)

    sha256 = sha256_of(source_path)
    dest_name = f"{sha256[:16]}_{source_path.name}"
    dest_path = scan_quarantine_dir / dest_name

    try:
        shutil.move(str(source_path), str(dest_path))
    except (OSError, PermissionError) as exc:
        # If we cannot move it off the USB (e.g. read-only media), copy the
        # sample for analysis instead of silently doing nothing, and log it.
        logger.warning("Could not move %s off source media (%s); copying instead.", source_path, exc)
        try:
            shutil.copy2(str(source_path), str(dest_path))
        except OSError as copy_exc:
            raise QuarantineError(f"Could not move or copy {source_path.name}: {copy_exc}") from copy_exc
        try:
            source_path.unlink()
        except OSError:
            pass   # read-only media / file in use: reported through original_removed below

    original_removed = not source_path.exists()
    record_id = database.insert_quarantine_record(
        scan_id=scan_id, original_path=str(source_path), quarantine_path=str(dest_path),
        sha256=sha256, risk_score=risk_score, reasons=reasons, explanations=explanations,
        source=source,
    )
    logger.info("Quarantined (%s) %s -> %s (risk=%d, original_removed=%s)",
                source, source_path, dest_path, risk_score, original_removed)

    return {
        "id": record_id, "original_path": str(source_path), "quarantine_path": str(dest_path),
        "sha256": sha256, "risk_score": risk_score, "reasons": reasons,
        "explanations": explanations or [], "source": source,
        "original_removed": original_removed,
    }


def restore_file(item_id: int, destination: Optional[str] = None) -> str:
    """Restore a quarantined file back to its original location (or a chosen destination)."""
    item = database.get_quarantine_item(item_id)
    if not item:
        raise QuarantineError(f"No quarantine record with id {item_id}")

    quarantine_path = Path(item["quarantine_path"])
    if not quarantine_path.exists():
        raise QuarantineError(f"Quarantined file missing from disk: {quarantine_path}")

    _require_user_authentication("restore", item)

    target = Path(destination) if destination else Path(item["original_path"])
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(quarantine_path), str(target))

    database.update_quarantine_status(item_id, "restored")
    logger.info("Restored quarantine item %d to %s", item_id, target)
    return str(target)


def delete_permanently(item_id: int) -> None:
    """Permanently delete a quarantined file. Requires an explicit user action - never automatic."""
    item = database.get_quarantine_item(item_id)
    if not item:
        raise QuarantineError(f"No quarantine record with id {item_id}")

    _require_user_authentication("delete", item)

    quarantine_path = Path(item["quarantine_path"])
    if quarantine_path.exists():
        quarantine_path.unlink()

    database.update_quarantine_status(item_id, "deleted")
    logger.info("Permanently deleted quarantine item %d (%s)", item_id, quarantine_path)


def export_sample(item_id: int, export_dir: str | Path) -> str:
    """Export a hashed copy of a quarantined file for external analysis/sharing."""
    item = database.get_quarantine_item(item_id)
    if not item:
        raise QuarantineError(f"No quarantine record with id {item_id}")

    quarantine_path = Path(item["quarantine_path"])
    if not quarantine_path.exists():
        raise QuarantineError(f"Quarantined file missing from disk: {quarantine_path}")

    _require_user_authentication("export", item)

    export_dir = Path(export_dir)
    export_dir.mkdir(parents=True, exist_ok=True)
    export_path = export_dir / f"SAMPLE_{item['sha256'][:16]}_{quarantine_path.name}"
    shutil.copy2(str(quarantine_path), str(export_path))

    logger.info("Exported sample for quarantine item %d to %s", item_id, export_path)
    return str(export_path)


def get_sandbox_candidate_path(item_id: int) -> str:
    """Resolve the on-disk path of a quarantined file for hand-off to the sandbox."""
    item = database.get_quarantine_item(item_id)
    if not item:
        raise QuarantineError(f"No quarantine record with id {item_id}")
    path = Path(item["quarantine_path"])
    if not path.exists():
        raise QuarantineError(f"Quarantined file missing from disk: {path}")
    return str(path)
