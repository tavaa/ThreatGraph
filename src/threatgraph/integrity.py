"""Fixity helpers: SHA-256 of files and bytes.

Fixity = proof that a bit-stream did not change (OAIS Preservation Description
Information; course L23). SHA-256 is used because it is collision-resistant
and available in the standard library.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

CHUNK = 1024 * 1024  # 1 MiB


class IntegrityError(RuntimeError):
    """Raised when a file does not match the expected size or hash."""


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
