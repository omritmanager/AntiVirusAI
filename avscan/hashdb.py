"""
hashdb.py — Read-only SHA-256 baseline lookup (spec §3.5.4).

This is the SIGNATURE-based half of the academic comparison. It is completely
independent of the ML model: a lookup only answers "is this exact SHA-256 already
in our local baseline DB?" — it never influences the ML verdict.

Key behaviors:
  * Opens the SQLite DB read-only during scans (no writes, safe to share).
  * Degrades gracefully if the DB file is absent: `available` is False and every
    lookup returns the "not found" answer. The scanner NEVER crashes because the
    hash DB is missing — it simply runs ML-only.
  * Normalizes hashes to lowercase hex before querying.

No network calls, ever (spec §14). The baseline is a local SQLite file.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

# hash_verdict constants
KNOWN_MALWARE = "KNOWN_MALWARE"
NOT_IN_DB = "NOT_IN_DB"


class HashDB:
    """Read-only lookups against the local baseline SQLite DB."""

    def __init__(self, sqlite_path):
        self.path = Path(sqlite_path) if sqlite_path else None
        self._conn: sqlite3.Connection | None = None
        if self.path and self.path.exists():
            try:
                uri = self.path.resolve().as_uri() + "?mode=ro"
                # check_same_thread=False: the GUI runs scans on a worker thread.
                self._conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
            except Exception:
                self._conn = None

    @property
    def available(self) -> bool:
        return self._conn is not None

    @staticmethod
    def _norm(sha256_hex: str) -> str:
        return (sha256_hex or "").strip().lower()

    def contains(self, sha256_hex: str) -> bool:
        """True iff the (normalized) hash is in the baseline DB."""
        if not self._conn:
            return False
        try:
            cur = self._conn.execute(
                "SELECT 1 FROM known_malware WHERE sha256 = ? LIMIT 1",
                (self._norm(sha256_hex),),
            )
            return cur.fetchone() is not None
        except Exception:
            return False

    def lookup(self, sha256_hex: str) -> dict | None:
        """Return the row as a dict, or None if absent / DB unavailable."""
        if not self._conn:
            return None
        try:
            cur = self._conn.execute(
                "SELECT sha256, family, first_seen, added_at "
                "FROM known_malware WHERE sha256 = ? LIMIT 1",
                (self._norm(sha256_hex),),
            )
            row = cur.fetchone()
        except Exception:
            return None
        if row is None:
            return None
        return {"sha256": row[0], "family": row[1],
                "first_seen": row[2], "added_at": row[3]}

    def verdict(self, sha256_hex: str) -> str:
        """KNOWN_MALWARE or NOT_IN_DB (the hash_verdict used in reports)."""
        return KNOWN_MALWARE if self.contains(sha256_hex) else NOT_IN_DB

    def count(self) -> int:
        """Number of known hashes (0 if DB unavailable)."""
        if not self._conn:
            return 0
        try:
            return int(self._conn.execute("SELECT COUNT(*) FROM known_malware").fetchone()[0])
        except Exception:
            return 0

    def close(self) -> None:
        if self._conn:
            try:
                self._conn.close()
            finally:
                self._conn = None

    def __enter__(self) -> "HashDB":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
