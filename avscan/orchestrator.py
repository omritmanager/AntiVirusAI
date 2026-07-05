"""
orchestrator.py — Folder walk, whitelist, per-file ML + hash, aggregation (spec §4).

Responsibilities:
  * Recursively walk a folder, keeping only files whose suffix is in VALID_EXT.
  * Apply the system-file whitelist (skip System32/SysWOW64/WinSxS), toggleable.
    Whitelisted files are tallied as SKIPPED_SYSTEM and NEVER sent to the engine.
  * For each scanned file, run the ML engine AND the SHA-256 hash lookup
    INDEPENDENTLY, then derive the comparison_tag (spec §3.5.5).
  * Aggregate counts + a hash_comparison block (spec §3.5.6).
  * Sequential, deterministic processing. Per-file errors are caught and tallied;
    one bad file never aborts the scan.

UI-agnostic: callers pass optional callbacks for progress and flagged-file events,
so the CLI (tqdm/plain) and GUI (worker thread) share this exact logic.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from . import config
from .engine import Engine, get_engine, MALWARE, POTENTIAL_ZERODAY, SAFE, ERROR
from .hashdb import HashDB, KNOWN_MALWARE, NOT_IN_DB

# comparison_tag constants (spec §3.5.5)
BOTH_CAUGHT = "BOTH_CAUGHT"
ML_ONLY_CATCH = "ML_ONLY_CATCH"
HASH_ONLY_CATCH = "HASH_ONLY_CATCH"
BOTH_CLEAR = "BOTH_CLEAR"

SKIPPED_SYSTEM = "SKIPPED_SYSTEM"


@dataclass
class FileResult:
    path: str
    name: str
    sha256: str | None
    size: int
    ml_verdict: str                  # MALWARE | POTENTIAL_ZERODAY | SAFE | ERROR
    lgbm_prob: float | None = None
    if_score: float | None = None
    hash_verdict: str | None = None  # KNOWN_MALWARE | NOT_IN_DB | None(=not checked)
    comparison_tag: str | None = None
    error: str | None = None
    quarantined: bool = False
    quarantine_path: str | None = None

    @property
    def ml_flagged(self) -> bool:
        return self.ml_verdict in (MALWARE, POTENTIAL_ZERODAY)


@dataclass
class ScanSummary:
    total_files_seen: int = 0
    scanned: int = 0            # files sent to the engine (includes errors)
    skipped_system: int = 0
    errors: int = 0
    malware: int = 0
    potential_zeroday: int = 0
    safe: int = 0
    flagged_pct: float = 0.0


@dataclass
class ScanResult:
    folder: str
    scan_id: str
    started_at: str
    finished_at: str
    duration_seconds: float
    summary: ScanSummary
    results: list[FileResult] = field(default_factory=list)
    hash_comparison: dict | None = None
    options: dict = field(default_factory=dict)


# ── whitelist (spec §5) ──────────────────────────────────────────────────────
def _normalize_prefixes(prefixes: Iterable[str]) -> list[str]:
    out = []
    for p in prefixes:
        n = os.path.normcase(os.path.normpath(p)).rstrip("\\/")
        if n:
            out.append(n)
    return out


def is_whitelisted(path: str, normalized_prefixes: list[str]) -> bool:
    """True if `path` is at or under any whitelist prefix (case-insensitive)."""
    ap = os.path.normcase(os.path.normpath(os.path.abspath(path)))
    for pref in normalized_prefixes:
        if ap == pref or ap.startswith(pref + os.sep):
            return True
    return False


# ── robust file discovery ────────────────────────────────────────────────────
def iter_candidate_files(folder: Path, on_walk_error: Callable | None = None):
    """Yield files under `folder` whose suffix is in VALID_EXT.

    Uses os.walk with an error handler so unreadable directories (permission
    denied, etc.) are skipped rather than aborting the whole walk.
    """
    def _onerror(err):
        if on_walk_error:
            on_walk_error(err)

    for dirpath, _dirnames, filenames in os.walk(folder, onerror=_onerror):
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() in config.VALID_EXT:
                yield Path(dirpath) / fn


# ── comparison tag (spec §3.5.5) ─────────────────────────────────────────────
def comparison_tag(ml_verdict: str, hash_verdict: str | None) -> str | None:
    """Combine the two INDEPENDENT verdicts into a reporting tag.

    Returns None when the hash layer didn't run, or the file errored in ML.
    POTENTIAL_ZERODAY counts as an ML catch (spec table: 'MALWARE / ZERODAY').
    """
    if hash_verdict is None or ml_verdict == ERROR:
        return None
    ml_flagged = ml_verdict in (MALWARE, POTENTIAL_ZERODAY)
    known = hash_verdict == KNOWN_MALWARE
    if ml_flagged and known:
        return BOTH_CAUGHT
    if ml_flagged and not known:
        return ML_ONLY_CATCH
    if not ml_flagged and known:
        return HASH_ONLY_CATCH
    return BOTH_CLEAR


# ── main scan ────────────────────────────────────────────────────────────────
def scan_folder(
    folder,
    *,
    engine: Engine | None = None,
    use_if: bool = False,
    whitelist_enabled: bool = True,
    whitelist_prefixes: list[str] | None = None,
    hash_db: HashDB | None = None,
    hash_compare: bool = True,
    zeroday_hashes: set[str] | None = None,
    progress_cb: Callable[[int, int, Path], None] | None = None,
    flagged_cb: Callable[[FileResult], None] | None = None,
    error_cb: Callable[[str], None] | None = None,
    on_malware: Callable[[FileResult], tuple[bool, str | None]] | None = None,
) -> ScanResult:
    """Scan `folder` and return a ScanResult.

    engine          : reuse a loaded Engine (else a shared one is created).
    use_if          : consult the Isolation Forest second layer.
    hash_db         : a HashDB; if None and hash_compare, the default DB is opened.
    zeroday_hashes  : if given, the headline block is computed over these hashes.
    on_malware      : optional callback to quarantine MALWARE files; returns
                      (quarantined, quarantine_path).
    """
    folder = Path(folder)
    scan_id = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    started_at = datetime.now(timezone.utc).isoformat()
    t0 = time.time()

    if engine is None:
        engine = get_engine(load_if=True)

    # Hash layer setup (independent of ML).
    owns_db = False
    if hash_compare and hash_db is None:
        hash_db = HashDB(config.BASELINE_SQLITE)
        owns_db = True
    hash_active = bool(hash_compare and hash_db is not None and hash_db.available)

    prefixes = _normalize_prefixes(
        whitelist_prefixes if whitelist_prefixes is not None else config.load_whitelist()
    )

    summary = ScanSummary()
    results: list[FileResult] = []
    tag_counts = {BOTH_CAUGHT: 0, ML_ONLY_CATCH: 0, HASH_ONLY_CATCH: 0, BOTH_CLEAR: 0}

    if not folder.exists():
        finished_at = datetime.now(timezone.utc).isoformat()
        if owns_db and hash_db:
            hash_db.close()
        return ScanResult(str(folder), scan_id, started_at, finished_at,
                          round(time.time() - t0, 3), summary, results, None,
                          {"error": f"folder not found: {folder}"})

    candidates = list(iter_candidate_files(folder, on_walk_error=error_cb))
    summary.total_files_seen = len(candidates)
    total = len(candidates)

    for i, fp in enumerate(candidates, 1):
        if progress_cb:
            progress_cb(i, total, fp)

        # Whitelist filtering (never sent to the engine).
        if whitelist_enabled and is_whitelisted(str(fp), prefixes):
            summary.skipped_system += 1
            continue

        summary.scanned += 1

        # ML layer (independent) — classify_file reads the bytes once and hashes.
        ml, sha, size = engine.classify_file(fp, use_if=use_if)

        # Hash layer (independent) — never feeds back into the ML verdict.
        hv = hash_db.verdict(sha) if (hash_active and sha) else None

        fr = FileResult(
            path=str(fp), name=fp.name, sha256=sha, size=size,
            ml_verdict=ml.ml_verdict, lgbm_prob=ml.lgbm_prob, if_score=ml.if_score,
            hash_verdict=hv, comparison_tag=comparison_tag(ml.ml_verdict, hv),
            error=ml.error,
        )

        # Tally.
        if fr.ml_verdict == MALWARE:
            summary.malware += 1
        elif fr.ml_verdict == POTENTIAL_ZERODAY:
            summary.potential_zeroday += 1
        elif fr.ml_verdict == SAFE:
            summary.safe += 1
        else:  # ERROR
            summary.errors += 1
        if fr.comparison_tag in tag_counts:
            tag_counts[fr.comparison_tag] += 1

        # Action: quarantine MALWARE only (POTENTIAL_ZERODAY is reported, not moved).
        if fr.ml_verdict == MALWARE and on_malware is not None:
            try:
                quarantined, qpath = on_malware(fr)
                fr.quarantined, fr.quarantine_path = quarantined, qpath
            except Exception as e:  # quarantine failure must not abort the scan
                if error_cb:
                    error_cb(f"quarantine failed for {fr.path}: {e}")

        if fr.ml_flagged and flagged_cb:
            flagged_cb(fr)

        results.append(fr)

    classified = summary.malware + summary.potential_zeroday + summary.safe
    flagged = summary.malware + summary.potential_zeroday
    summary.flagged_pct = round(100.0 * flagged / classified, 2) if classified else 0.0

    # hash_comparison block (spec §3.5.6).
    hash_comparison = None
    if hash_compare:
        hash_comparison = {
            "db_path": str(getattr(hash_db, "path", config.BASELINE_SQLITE)),
            "db_available": hash_active,
            "known_hashes_in_db": hash_db.count() if hash_active else 0,
            "files": dict(tag_counts),
        }
        if zeroday_hashes is not None:
            hash_comparison["headline"] = _headline(results, zeroday_hashes)

    finished_at = datetime.now(timezone.utc).isoformat()
    duration = round(time.time() - t0, 3)
    if owns_db and hash_db:
        hash_db.close()

    options = {
        "use_if": use_if,
        "whitelist_enabled": whitelist_enabled,
        "hash_compare": hash_compare,
        "hash_active": hash_active,
    }
    return ScanResult(str(folder), scan_id, started_at, finished_at, duration,
                      summary, results, hash_comparison, options)


def _headline(results: list[FileResult], zeroday_hashes: set[str]) -> dict:
    """Headline metric over the known simulated-zero-day samples (spec §3.5.6).

    For files whose SHA-256 is in the withheld zero-day set: how many did the
    hash lookup catch (0 by construction) vs how many did ML flag.
    """
    zd = {h.lower() for h in zeroday_hashes}
    scanned_zd = [r for r in results if r.sha256 and r.sha256.lower() in zd]
    caught_hash = sum(1 for r in scanned_zd if r.hash_verdict == KNOWN_MALWARE)
    caught_ml = sum(1 for r in scanned_zd if r.ml_flagged)
    n = len(scanned_zd)
    return {
        "simulated_zeroday_scanned": n,
        "caught_by_hash": caught_hash,
        "caught_by_ml": caught_ml,
        "ml_zeroday_detection_rate": round(caught_ml / n, 4) if n else 0.0,
        "hash_zeroday_detection_rate": round(caught_hash / n, 4) if n else 0.0,
    }
