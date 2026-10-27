"""
File hashing utilities.

Provides streaming SHA-256 (and optional MD5/SHA-1 for cross-referencing
against third-party threat intel) so large files on a USB drive never
have to be fully loaded into memory at once.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict

from utils.logger import get_logger

logger = get_logger(__name__)

_CHUNK_SIZE = 1024 * 1024  # 1 MB


def hash_file(path: str | Path, algorithms: tuple[str, ...] = ("sha256",)) -> Dict[str, str]:
    """
    Compute one or more hex digests for a file in a single streaming pass.

    Args:
        path: Path to the file on disk.
        algorithms: Any subset of hashlib's supported algorithm names,
            e.g. ("sha256", "md5", "sha1").

    Returns:
        Dict mapping algorithm name -> hex digest string.
        On read failure, every requested algorithm maps to "" and the
        error is logged (callers treat this as "hash unavailable" rather
        than raising, so a single unreadable file never crashes a scan).
    """
    path = Path(path)
    hashers = {alg: hashlib.new(alg) for alg in algorithms}

    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(_CHUNK_SIZE)
                if not chunk:
                    break
                for hasher in hashers.values():
                    hasher.update(chunk)
    except (OSError, PermissionError) as exc:
        logger.warning("Could not hash file %s: %s", path, exc)
        return {alg: "" for alg in algorithms}

    return {alg: hasher.hexdigest() for alg, hasher in hashers.items()}


def sha256_of(path: str | Path) -> str:
    """Convenience wrapper returning only the SHA-256 hex digest."""
    return hash_file(path, ("sha256",))["sha256"]
