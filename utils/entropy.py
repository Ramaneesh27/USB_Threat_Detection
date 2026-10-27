"""
Shannon entropy calculation and classification.

Entropy is a *signal*, never proof of malware by itself. High entropy
is normal for legitimately compressed/encrypted files (zip, jpg, mp4,
encrypted archives). This module only measures and labels; the risk
engine decides how much weight to give the label, and callers must
never phrase entropy findings as a malware verdict.
"""

from __future__ import annotations

import math
from collections import Counter
from pathlib import Path

from utils.logger import get_logger

logger = get_logger(__name__)

_CHUNK_SIZE = 1024 * 1024
_MAX_BYTES_SAMPLED = 8 * 1024 * 1024  # cap sampling for very large files


def shannon_entropy(data: bytes) -> float:
    """Return the Shannon entropy (bits/byte, 0.0-8.0) of a byte string."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def entropy_of_file(path: str | Path) -> float:
    """
    Compute entropy for a file, sampling up to _MAX_BYTES_SAMPLED bytes
    (evenly across the file) so very large media files don't stall a scan.
    """
    path = Path(path)
    try:
        size = path.stat().st_size
        with open(path, "rb") as fh:
            if size <= _MAX_BYTES_SAMPLED:
                data = fh.read()
            else:
                # Sample the start, middle, and end of the file.
                third = _MAX_BYTES_SAMPLED // 3
                data = bytearray()
                fh.seek(0)
                data += fh.read(third)
                fh.seek(size // 2)
                data += fh.read(third)
                fh.seek(max(0, size - third))
                data += fh.read(third)
        return round(shannon_entropy(bytes(data)), 4)
    except (OSError, PermissionError) as exc:
        logger.warning("Could not read %s for entropy analysis: %s", path, exc)
        return 0.0


def classify_entropy(value: float) -> str:
    """
    Classify an entropy value into a human-readable bucket.

    Thresholds are heuristic industry rules of thumb, not certainties:
      < 5.0   : Normal      (plain text, uncompressed structured data)
      5.0-6.5 : Compressed  (typical for jpg/png/office/zip containers)
      6.5-7.5 : Packed      (consistent with packed/obfuscated executables)
      >= 7.5  : Encrypted Indicator (consistent with encryption or strong packing)
    """
    if value < 5.0:
        return "Normal"
    if value < 6.5:
        return "Compressed"
    if value < 7.5:
        return "Packed"
    return "Encrypted Indicator"
