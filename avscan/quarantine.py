"""
quarantine.py — Move, neutralize, and restore detected malware (spec §6).

Policy:
  * Only MALWARE is auto-quarantined. POTENTIAL_ZERODAY is reported, never moved
    automatically (it needs human review).
  * Neutralize the stored copy so it cannot execute from quarantine:
      - store it with a `.quarantine` suffix, AND
      - optionally XOR every byte with a fixed key (default 0x55) so the stored
        file is not a live executable. Whether it was XOR'd is recorded so
        restore is exact.
  * Safe ordering (atomic-ish): write the quarantine copy -> VERIFY it reverses to
    the original SHA-256 -> only THEN remove the original. The original is never
    deleted before the quarantined copy is verified.
  * A manifest (quarantine/manifest.json) records every entry so files can be
    restored and the action is auditable.
  * Permission/IO errors are surfaced as QuarantineError (the orchestrator
    catches them and continues) — quarantine never crashes a scan.

XOR uses bytes.translate with a 256-byte table (C-fast, symmetric).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from . import config
from .hashing import sha256_bytes, sha256_file


class QuarantineError(RuntimeError):
    pass


def _xor_table(key: int) -> bytes:
    return bytes(b ^ (key & 0xFF) for b in range(256))


def xor_bytes(data: bytes, key: int) -> bytes:
    """Symmetric single-byte XOR via translate table (fast, reversible)."""
    return data.translate(_xor_table(key))


class Quarantine:
    def __init__(self, quarantine_dir=None, manifest_path=None,
                 use_xor: bool = True, xor_key: int = config.XOR_KEY_DEFAULT):
        self.dir = Path(quarantine_dir) if quarantine_dir else config.QUARANTINE_DIR
        self.manifest_path = Path(manifest_path) if manifest_path else config.QUARANTINE_MANIFEST
        self.use_xor = use_xor
        self.xor_key = xor_key
        self.dir.mkdir(parents=True, exist_ok=True)
        self._entries: list[dict] = self._load_manifest()

    # ── manifest ─────────────────────────────────────────────────────────────
    def _load_manifest(self) -> list[dict]:
        if not self.manifest_path.exists():
            return []
        try:
            with open(self.manifest_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else data.get("entries", [])
        except Exception:
            return []

    def _save_manifest(self) -> None:
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.manifest_path, "w", encoding="utf-8") as f:
            json.dump(self._entries, f, indent=2)

    def entries(self) -> list[dict]:
        return list(self._entries)

    # ── quarantine ───────────────────────────────────────────────────────────
    def _dest_path(self, sha256: str, original_name: str) -> Path:
        # sha-prefixed so distinct files never collide; identical content is idempotent.
        return self.dir / f"{sha256[:16]}__{original_name}.quarantine"

    def quarantine_file(self, original_path, sha256: str | None = None,
                        lgbm_prob: float | None = None) -> dict:
        """Quarantine one file. Returns the manifest entry. Raises QuarantineError."""
        src = Path(original_path)
        if not src.exists():
            raise QuarantineError(f"original not found: {src}")

        try:
            data = src.read_bytes()
        except Exception as e:
            raise QuarantineError(f"cannot read {src}: {e}") from e

        original_sha = sha256 or sha256_bytes(data)
        if sha256 and sha256_bytes(data) != sha256.lower():
            # bytes changed since the scan read them — refuse to act on stale info
            raise QuarantineError(f"hash mismatch for {src} (file changed since scan)")

        dest = self._dest_path(original_sha, src.name)
        stored = xor_bytes(data, self.xor_key) if self.use_xor else data

        # 1) write the quarantine copy
        try:
            dest.write_bytes(stored)
        except Exception as e:
            raise QuarantineError(f"cannot write quarantine copy {dest}: {e}") from e

        # 2) VERIFY the copy reverses to the original SHA-256 (before deleting!)
        try:
            check = dest.read_bytes()
            if self.use_xor:
                check = xor_bytes(check, self.xor_key)
            if sha256_bytes(check) != original_sha:
                dest.unlink(missing_ok=True)
                raise QuarantineError(f"verification failed for {src}; original kept")
        except QuarantineError:
            raise
        except Exception as e:
            dest.unlink(missing_ok=True)
            raise QuarantineError(f"verification error for {src}: {e}") from e

        # 3) only now remove the original
        try:
            src.unlink()
        except Exception as e:
            dest.unlink(missing_ok=True)  # roll back the copy; original stays
            raise QuarantineError(f"cannot remove original {src}: {e}") from e

        entry = {
            "sha256": original_sha,
            "original_path": str(src.resolve() if src.parent.exists() else src),
            "original_name": src.name,
            "quarantine_path": str(dest),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "lgbm_prob": lgbm_prob,
            "xored": self.use_xor,
            "xor_key": self.xor_key if self.use_xor else None,
        }
        # replace any prior entry for the same quarantine_path
        self._entries = [e for e in self._entries if e.get("quarantine_path") != str(dest)]
        self._entries.append(entry)
        self._save_manifest()
        return entry

    def quarantine_for_result(self, file_result) -> tuple[bool, str | None]:
        """Adapter for orchestrator.on_malware. Never raises; returns (ok, path)."""
        try:
            entry = self.quarantine_file(
                file_result.path, sha256=file_result.sha256,
                lgbm_prob=file_result.lgbm_prob,
            )
            return True, entry["quarantine_path"]
        except QuarantineError:
            return False, None

    # ── restore ──────────────────────────────────────────────────────────────
    def _restore_entry(self, entry: dict, dest_override: str | None = None) -> str:
        qpath = Path(entry["quarantine_path"])
        if not qpath.exists():
            raise QuarantineError(f"quarantine file missing: {qpath}")
        data = qpath.read_bytes()
        if entry.get("xored"):
            data = xor_bytes(data, int(entry.get("xor_key", config.XOR_KEY_DEFAULT)))
        if sha256_bytes(data) != entry["sha256"]:
            raise QuarantineError(f"restored content hash mismatch for {qpath}")

        target = Path(dest_override) if dest_override else Path(entry["original_path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

        # verify on-disk, then drop the quarantine copy + manifest entry
        if sha256_file(target) != entry["sha256"]:
            raise QuarantineError(f"on-disk verification failed for {target}")
        qpath.unlink(missing_ok=True)
        self._entries = [e for e in self._entries
                         if e.get("quarantine_path") != entry["quarantine_path"]]
        self._save_manifest()
        return str(target)

    def restore(self, sha256_or_all: str, dest_override: str | None = None) -> list[str]:
        """Restore by SHA-256 (all matching entries) or 'all'. Returns restored paths."""
        if sha256_or_all.lower() == "all":
            targets = list(self._entries)
        else:
            key = sha256_or_all.strip().lower()
            targets = [e for e in self._entries if e.get("sha256", "").lower() == key]
        if not targets:
            raise QuarantineError(f"no quarantine entry matches: {sha256_or_all}")

        restored: list[str] = []
        errors: list[str] = []
        for entry in targets:
            try:
                restored.append(self._restore_entry(entry, dest_override))
            except QuarantineError as e:
                errors.append(str(e))
        if errors and not restored:
            raise QuarantineError("; ".join(errors))
        return restored
