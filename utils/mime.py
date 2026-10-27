"""
MIME type detection and extension/content mismatch checking.

Uses python-magic (libmagic bindings) to read actual file content
signatures rather than trusting the file extension, which is the
core defense against renamed-executable tricks like cat.jpg actually
being application/x-msdownload.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

try:
    import magic  # python-magic
    _MAGIC_AVAILABLE = True
except ImportError:  # pragma: no cover - environment without libmagic
    _MAGIC_AVAILABLE = False

from utils.logger import get_logger

logger = get_logger(__name__)

# Extensions that legitimately correspond to executable/script MIME types.
_EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".msi", ".ps1", ".vbs", ".com", ".sys",
}

# MIME substrings that indicate executable/script content regardless of extension.
_EXECUTABLE_MIME_MARKERS = (
    "x-msdownload",
    "x-dosexec",
    "x-executable",
    "x-sharedlib",
    "x-elf",
    "application/x-msdos-program",
)

# A conservative map of extension -> plausible MIME prefixes/values.
_EXPECTED_MIME = {
    ".jpg": ("image/jpeg",), ".jpeg": ("image/jpeg",), ".png": ("image/png",),
    ".gif": ("image/gif",), ".bmp": ("image/bmp", "image/x-ms-bmp"),
    ".pdf": ("application/pdf",), ".txt": ("text/plain",),
    ".csv": ("text/plain", "text/csv"), ".doc": ("application/msword",),
    ".docx": ("application/zip", "application/vnd.openxmlformats"),
    ".xls": ("application/vnd.ms-excel",),
    ".xlsx": ("application/zip", "application/vnd.openxmlformats"),
    ".ppt": ("application/vnd.ms-powerpoint",),
    ".pptx": ("application/zip", "application/vnd.openxmlformats"),
    ".mp3": ("audio/mpeg",), ".wav": ("audio/x-wav", "audio/wav"),
    ".mp4": ("video/mp4",), ".avi": ("video/x-msvideo",),
    ".zip": ("application/zip",), ".rar": ("application/x-rar",),
    ".7z": ("application/x-7z-compressed",),
}


def detect_mime(path: str | Path) -> str:
    """Return the detected MIME type of a file, or 'unknown/unknown' on failure."""
    path = Path(path)
    if not _MAGIC_AVAILABLE:
        logger.debug("python-magic/libmagic unavailable; MIME detection degraded for %s", path)
        return "unknown/unknown"
    try:
        return magic.from_file(str(path), mime=True)
    except Exception as exc:  # noqa: BLE001 - libmagic can raise many error types
        logger.warning("MIME detection failed for %s: %s", path, exc)
        return "unknown/unknown"


def is_executable_mime(mime_type: str) -> bool:
    """True if the detected MIME type indicates executable/binary program content."""
    mime_type = (mime_type or "").lower()
    return any(marker in mime_type for marker in _EXECUTABLE_MIME_MARKERS)


def check_extension_mismatch(path: str | Path) -> Optional[dict]:
    """
    Compare a file's extension against its real MIME type.

    Returns:
        None if no mismatch is detected (or extension is unrecognized/unmapped).
        Otherwise a dict describing the mismatch, including whether the
        content resolves to an executable disguised under a non-executable
        extension (the highest-severity case).
    """
    path = Path(path)
    ext = path.suffix.lower()
    mime_type = detect_mime(path)

    if mime_type == "unknown/unknown":
        return None

    disguised_executable = is_executable_mime(mime_type) and ext not in _EXECUTABLE_EXTENSIONS

    expected = _EXPECTED_MIME.get(ext)
    mismatch = False
    if expected is not None:
        mismatch = not any(mime_type.startswith(prefix) for prefix in expected)

    if not mismatch and not disguised_executable:
        return None

    return {
        "extension": ext,
        "detected_mime": mime_type,
        "expected_mime": expected,
        "disguised_executable": disguised_executable,
    }
