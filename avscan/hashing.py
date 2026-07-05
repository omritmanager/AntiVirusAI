"""
hashing.py — Pure-stdlib SHA-256 helpers.

Deliberately dependency-free (no numpy / ember). The quarantine and hash-lookup
layers depend only on this, so file RESTORE works even if the ML stack (numpy,
lightgbm, ember) is broken or missing. Recovery must never require the very
libraries a bad scan might have disturbed.
"""
from __future__ import annotations

import hashlib


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path) -> str:
    """Streaming SHA-256 of a file (lowercase hex)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
