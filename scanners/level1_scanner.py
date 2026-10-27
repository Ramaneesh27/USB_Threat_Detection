"""
LEVEL 1 - File Security Scanner.

Scans every non-executable file (images, documents, PDF, text, office,
audio, video) and runs the six Level 1 checks: double extension, hidden
attributes, MIME verification, abnormal size, entropy analysis, and
appended-payload (trailing data after a format's real EOF marker).

This module only *collects evidence and flags* - it never claims a file
is malware. Verdicts belong to the risk engine.
"""

from __future__ import annotations

import platform
import stat
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import config
from utils.entropy import classify_entropy, entropy_of_file
from utils.hash import hash_file
from utils.logger import get_logger
from utils.mime import check_extension_mismatch, detect_mime

logger = get_logger(__name__)

_IS_WINDOWS = platform.system() == "Windows"

# Known EOF / trailer markers used for appended-payload detection.
_EOF_MARKERS = {
    ".jpg": b"\xff\xd9",
    ".jpeg": b"\xff\xd9",
    ".png": b"\x49\x45\x4e\x44\xae\x42\x60\x82",  # IEND chunk + CRC
    ".pdf": b"%%EOF",
}
_ZIP_EOCD_SIGNATURE = b"\x50\x4b\x05\x06"  # End Of Central Directory


@dataclass
class FileFinding:
    file_name: str
    extension: str
    absolute_path: str
    size_bytes: int
    sha256: str
    mime_type: str
    created_date: str
    modified_date: str
    level: int = 1
    reasons: list[str] = field(default_factory=list)
    flags: dict = field(default_factory=dict)  # machine-readable flag -> True/value
    details: dict = field(default_factory=dict)  # flag -> file-specific explanation sentence

    def add_reason(self, flag_key: str, human_text: str, value=True) -> None:
        self.flags[flag_key] = value
        self.details[flag_key] = human_text
        self.reasons.append(human_text)

    def to_dict(self) -> dict:
        d = {
            "file_name": self.file_name,
            "extension": self.extension,
            "absolute_path": self.absolute_path,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "mime_type": self.mime_type,
            "created_date": self.created_date,
            "modified_date": self.modified_date,
            "level": self.level,
            "reasons": self.reasons,
            "flags": self.flags,
        }
        return d


def _get_windows_attributes(path: Path) -> dict:
    """Read FILE_ATTRIBUTE_* flags on Windows; degrade gracefully elsewhere."""
    attrs = {"Hidden": False, "System": False, "Read Only": False, "Archive": False}
    if not _IS_WINDOWS:
        return attrs
    try:
        import ctypes
        FILE_ATTRIBUTE_READONLY = 0x1
        FILE_ATTRIBUTE_HIDDEN = 0x2
        FILE_ATTRIBUTE_SYSTEM = 0x4
        FILE_ATTRIBUTE_ARCHIVE = 0x20

        value = ctypes.windll.kernel32.GetFileAttributesW(str(path))  # type: ignore[attr-defined]
        if value == -1:
            return attrs
        attrs["Read Only"] = bool(value & FILE_ATTRIBUTE_READONLY)
        attrs["Hidden"] = bool(value & FILE_ATTRIBUTE_HIDDEN)
        attrs["System"] = bool(value & FILE_ATTRIBUTE_SYSTEM)
        attrs["Archive"] = bool(value & FILE_ATTRIBUTE_ARCHIVE)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not read Windows attributes for %s: %s", path, exc)
    return attrs


def _check_double_extension(path: Path, finding: FileFinding) -> None:
    """
    Detect disguised executables such as invoice.pdf.exe or photo.jpg.scr:
    a final extension is executable while an earlier extension makes the
    file look benign.
    """
    suffixes = [s.lower() for s in path.suffixes]
    if len(suffixes) < 2:
        return
    final_ext = suffixes[-1]
    preceding_ext = suffixes[-2]
    if final_ext in config.EXECUTABLE_EXTENSIONS and preceding_ext in (
        config.NON_EXECUTABLE_EXTENSIONS | config.ARCHIVE_EXTENSIONS
    ):
        finding.add_reason(
            "double_extension",
            f"Disguised executable: filename ends in '{preceding_ext}{final_ext}' - "
            f"appears to be a '{preceding_ext}' file but actually executes as '{final_ext}'.",
        )


def _check_hidden_attributes(path: Path, finding: FileFinding) -> None:
    """
    Flag Hidden/System/Read-Only/Archive attributes. These are legitimate
    on many OS files but are a common technique for concealing dropped
    payloads on a USB drive from a casual folder browse.
    """
    attrs = _get_windows_attributes(path)
    active = [name for name, is_set in attrs.items() if is_set]
    if attrs.get("Hidden") or attrs.get("System"):
        finding.add_reason(
            "hidden_system_file",
            "File has Hidden and/or System attributes set - these attributes "
            "hide a file from normal Explorer views and are frequently used "
            "to conceal malicious payloads dropped onto removable media.",
            value=active,
        )
    elif active:
        # Read-only/Archive alone is common and low-signal; record but don't score.
        finding.flags["attributes"] = active


def _check_mime_mismatch(path: Path, finding: FileFinding) -> None:
    mismatch = check_extension_mismatch(path)
    if mismatch is None:
        return
    if mismatch["disguised_executable"]:
        finding.add_reason(
            "disguised_executable",
            f"Content signature indicates executable code (MIME "
            f"'{mismatch['detected_mime']}') despite a non-executable "
            f"extension ('{mismatch['extension']}') - classic renamed-executable trick.",
        )
    else:
        finding.add_reason(
            "mime_mismatch",
            f"File extension '{mismatch['extension']}' does not match detected "
            f"content type '{mismatch['detected_mime']}'.",
        )


def _check_abnormal_size(path: Path, finding: FileFinding) -> None:
    ext = path.suffix.lower()
    max_expected = config.EXPECTED_MAX_SIZE.get(ext)
    if max_expected and finding.size_bytes > max_expected:
        finding.add_reason(
            "abnormal_size",
            f"Unusually large '{ext}' file: {finding.size_bytes / (1024*1024):.1f} MB "
            f"exceeds the expected ceiling of {max_expected / (1024*1024):.0f} MB for this type.",
        )


def _check_entropy(path: Path, finding: FileFinding) -> None:
    value = entropy_of_file(path)
    label = classify_entropy(value)
    finding.flags["entropy_value"] = value
    finding.flags["entropy_label"] = label
    if label in ("Packed", "Encrypted Indicator"):
        finding.add_reason(
            "high_entropy",
            f"Shannon entropy {value:.2f}/8.0 classifies as '{label}'. This is a "
            f"statistical indicator only - it is also normal for legitimately "
            f"compressed or encrypted content and is never proof of malware alone.",
            value=value,
        )


def _check_appended_payload(path: Path, finding: FileFinding) -> None:
    """
    Detect data appended after a format's real end-of-file marker, a
    technique used to smuggle a second payload inside an image/PDF/zip
    that still opens normally in its native viewer.
    """
    ext = path.suffix.lower()
    marker = _EOF_MARKERS.get(ext)
    try:
        data = path.read_bytes()
    except (OSError, PermissionError) as exc:
        logger.debug("Could not read %s for appended-payload check: %s", path, exc)
        return

    trailing = 0
    if marker and ext != ".pdf":
        idx = data.rfind(marker)
        if idx != -1:
            trailing = len(data) - (idx + len(marker))
    elif ext == ".pdf":
        idx = data.rfind(marker)
        if idx != -1:
            trailing = len(data) - (idx + len(marker))
    elif ext == ".zip":
        idx = data.rfind(_ZIP_EOCD_SIGNATURE)
        if idx != -1:
            # EOCD record is at least 22 bytes; anything meaningfully beyond that is suspect.
            trailing = len(data) - (idx + 22)

    if trailing > 16:  # small trailing padding is common and not worth flagging
        finding.add_reason(
            "appended_payload",
            f"{trailing} bytes of data found appended after the file's expected "
            f"end-of-file marker - may indicate a hidden secondary payload.",
            value=trailing,
        )


def scan_file(path: str | Path) -> FileFinding:
    """
    Run the complete Level 1 check suite on a single file and return the
    populated FileFinding (evidence + human-readable reasons, no verdict).
    """
    path = Path(path)
    stat_result = path.stat()
    hashes = hash_file(path, ("sha256",))

    finding = FileFinding(
        file_name=path.name,
        extension=path.suffix.lower(),
        absolute_path=str(path),
        size_bytes=stat_result.st_size,
        sha256=hashes["sha256"],
        mime_type=detect_mime(path),
        created_date=datetime.fromtimestamp(stat_result.st_ctime).isoformat(),
        modified_date=datetime.fromtimestamp(stat_result.st_mtime).isoformat(),
    )

    _check_double_extension(path, finding)
    _check_hidden_attributes(path, finding)
    _check_mime_mismatch(path, finding)
    _check_abnormal_size(path, finding)
    _check_entropy(path, finding)
    _check_appended_payload(path, finding)

    return finding


def is_level1_target(path: Path) -> bool:
    """True if this file belongs to the Level 1 (non-executable) file set."""
    return path.suffix.lower() in config.NON_EXECUTABLE_EXTENSIONS


def walk_and_scan(root: str | Path) -> list[FileFinding]:
    """Recursively scan every Level 1 target file under a directory tree."""
    root = Path(root)
    results: list[FileFinding] = []
    for entry in root.rglob("*"):
        if entry.is_file() and is_level1_target(entry):
            try:
                results.append(scan_file(entry))
            except (OSError, PermissionError) as exc:
                logger.warning("Skipping unreadable file %s: %s", entry, exc)
    logger.info("Level 1 scan complete: %d file(s) analyzed under %s", len(results), root)
    return results
