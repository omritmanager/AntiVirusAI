"""
build_hash_db.py — One-time builder for the SHA-256 baseline DB (spec §3.5.2).

NOT part of the runtime scanner. Constructs the signature baseline used by the
academic comparison, performing the deliberate 80/20 "simulated zero-day" split:

  * 80% of the malware SHA-256 hashes  -> inserted into baseline.sqlite
    (these simulate malware already published to global signature feeds)
  * 20% withheld                       -> written to simulated_zeroday_hashes.txt
    (these simulate brand-new malware not yet in any signature feed)

The split is DETERMINISTIC (seed=42): hashes are de-duplicated, sorted to a
canonical order, then shuffled with a seeded RNG, so the result is reproducible
and independent of the order they appear in the source file.

Source: data/datasets/modern_malware_features.json (per-sample sha256 + first_seen).
We stream it with a regex so the giant per-sample `features` arrays are skipped
(full 1 GB scan in ~2s) — no need to load 48k x 2381 floats into memory.

Outputs (into data/hashdb/):
  baseline.sqlite                 (table known_malware, 80%)
  known_hashes.txt                (the 80% that were inserted)
  simulated_zeroday_hashes.txt    (the withheld 20%)
  split_manifest.json             (counts, seed, split ratio, timestamps, source)

Usage:
  python build_hash_db.py                       # default source + 80/20 + seed 42
  python build_hash_db.py --rebuild             # overwrite an existing DB
  python build_hash_db.py --hash-list hashes.txt  # build from a plain SHA-256 list
  python build_hash_db.py --split 0.8 --seed 42
"""
from __future__ import annotations

import argparse
import json
import random
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from avscan import config

# ── Streaming extraction (regex; skips the huge features arrays) ─────────────
_SHA_RE = re.compile(rb'"sha256"\s*:\s*"([0-9a-fA-F]{64})"')
_FS_RE = re.compile(rb'"first_seen"\s*:\s*"([^"]{0,64})"')
_WINDOW = 400          # first_seen always sits within a few hundred bytes of sha256
_CHUNK = 8 * 1024 * 1024


def stream_sha_firstseen(path: Path):
    """Yield (sha256_lower, first_seen_or_None) for every sample in the JSON."""
    buf = b""
    with open(path, "rb") as f:
        while True:
            chunk = f.read(_CHUNK)
            eof = not chunk
            buf += chunk
            pos = 0
            for m in _SHA_RE.finditer(buf):
                end = m.end()
                # Defer matches whose first_seen window may be cut off by the chunk edge.
                if not eof and end + _WINDOW > len(buf):
                    break
                sha = m.group(1).decode("ascii").lower()
                fsm = _FS_RE.search(buf, end, min(end + _WINDOW, len(buf)))
                fs = fsm.group(1).decode("ascii") if fsm else None
                yield sha, fs
                pos = end
            buf = buf[pos:] if pos else buf
            if eof:
                break


_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


def read_hash_list(path: Path):
    """Yield (sha256_lower, None) for each valid SHA-256 line in a text file."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            tok = line.strip().split()[0] if line.strip() else ""
            if _HEX64.match(tok):
                yield tok.lower(), None


# ── Collection + split ───────────────────────────────────────────────────────
def collect_hashes(source: Path | None, hash_list: Path | None):
    """Return (sha->first_seen dict, source_label, source_path). first_seen may be None."""
    sha_to_fs: dict[str, str | None] = {}
    if hash_list:
        label, src = "hash_list", hash_list
        for sha, fs in read_hash_list(hash_list):
            sha_to_fs.setdefault(sha, fs)
    else:
        label, src = "features_json", source
        for sha, fs in stream_sha_firstseen(source):
            # keep first non-null first_seen seen for a sha
            if sha not in sha_to_fs or (sha_to_fs[sha] is None and fs is not None):
                sha_to_fs[sha] = fs
    return sha_to_fs, label, src


def deterministic_split(shas: list[str], split: float, seed: int):
    """Sort to canonical order, seeded-shuffle, split into (known, zeroday)."""
    ordered = sorted(set(shas))                 # canonical, order-independent
    rng = random.Random(seed)
    rng.shuffle(ordered)
    n_known = int(len(ordered) * split)
    return ordered[:n_known], ordered[n_known:]


# ── SQLite writing ───────────────────────────────────────────────────────────
SCHEMA = """
CREATE TABLE known_malware (
    sha256      TEXT PRIMARY KEY,
    family      TEXT,
    first_seen  TEXT,
    added_at    TEXT
);
CREATE INDEX idx_sha ON known_malware(sha256);
"""


def write_sqlite(db_path: Path, known: list[str], sha_to_fs: dict, added_at: str):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(SCHEMA)
        conn.executemany(
            "INSERT OR IGNORE INTO known_malware (sha256, family, first_seen, added_at) "
            "VALUES (?, ?, ?, ?)",
            [(sha, "unknown", sha_to_fs.get(sha), added_at) for sha in known],
        )
        conn.commit()
    finally:
        conn.close()


def write_lines(path: Path, items: list[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(items))
        if items:
            f.write("\n")


# ── Main ─────────────────────────────────────────────────────────────────────
def main() -> int:
    ap = argparse.ArgumentParser(description="Build the SHA-256 baseline DB (80/20 split).")
    ap.add_argument("--source", type=Path, default=config.MALWARE_FEATURES_JSON,
                    help="malware features JSON with per-sample sha256 + first_seen")
    ap.add_argument("--hash-list", type=Path, default=None,
                    help="plain text file of SHA-256 hashes (overrides --source)")
    ap.add_argument("--out-dir", type=Path, default=config.HASHDB_DIR)
    ap.add_argument("--split", type=float, default=0.8, help="fraction inserted (known)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--rebuild", action="store_true", help="overwrite an existing DB")
    args = ap.parse_args()

    out_dir = args.out_dir
    db_path = out_dir / "baseline.sqlite"
    known_txt = out_dir / "known_hashes.txt"
    zeroday_txt = out_dir / "simulated_zeroday_hashes.txt"
    manifest_json = out_dir / "split_manifest.json"

    print("=" * 64)
    print("AntivirusAI V7 - hash baseline builder (spec 3.5.2)")
    print("=" * 64)

    if db_path.exists() and not args.rebuild:
        print(f"[STOP] {db_path} already exists. Use --rebuild to overwrite.")
        return 1

    # Validate source availability.
    if args.hash_list:
        if not args.hash_list.exists():
            print(f"[STOP] hash list not found: {args.hash_list}")
            return 1
        print(f"Source: hash list  {args.hash_list}")
    else:
        if not args.source.exists():
            print(f"[STOP] source JSON not found: {args.source}\n"
                  f"       Provide --source <path> or --hash-list <path>.")
            return 1
        print(f"Source: features JSON  {args.source}")

    print("Collecting hashes (streaming) ...")
    sha_to_fs, label, src = collect_hashes(args.source, args.hash_list)
    total = len(sha_to_fs)
    if total == 0:
        print("[STOP] no SHA-256 hashes found in the source.")
        return 1
    with_fs = sum(1 for v in sha_to_fs.values() if v)
    print(f"  unique hashes: {total}  (with first_seen: {with_fs}) via {label}")

    known, zeroday = deterministic_split(list(sha_to_fs.keys()), args.split, args.seed)
    added_at = datetime.now(timezone.utc).isoformat()

    print(f"Splitting {args.split:.0%}/{1-args.split:.0%} (seed={args.seed}) ...")
    print(f"  known (-> DB):            {len(known)}")
    print(f"  simulated zero-day (held): {len(zeroday)}")

    print("Writing SQLite + text + manifest ...")
    write_sqlite(db_path, known, sha_to_fs, added_at)
    write_lines(known_txt, known)
    write_lines(zeroday_txt, zeroday)

    manifest = {
        "created_at": added_at,
        "source_type": label,
        "source_path": str(src),
        "seed": args.seed,
        "split_fraction_known": args.split,
        "counts": {
            "total_unique": total,
            "known_in_db": len(known),
            "simulated_zeroday_withheld": len(zeroday),
            "with_first_seen": with_fs,
        },
        "outputs": {
            "baseline_sqlite": str(db_path),
            "known_hashes_txt": str(known_txt),
            "simulated_zeroday_hashes_txt": str(zeroday_txt),
        },
        "note": ("Deterministic: hashes de-duplicated, sorted canonically, then "
                 "shuffled with a seeded RNG. 20% withheld simulate zero-day malware "
                 "invisible to SHA-256 signature matching but still detectable by ML."),
    }
    with open(manifest_json, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    # Verify DB row count matches.
    conn = sqlite3.connect(str(db_path))
    try:
        n_rows = conn.execute("SELECT COUNT(*) FROM known_malware").fetchone()[0]
    finally:
        conn.close()

    print("-" * 64)
    print(f"  DB rows inserted: {n_rows}  (expected {len(known)})")
    print(f"  baseline.sqlite:  {db_path}")
    print(f"  known_hashes.txt: {known_txt}")
    print(f"  zeroday_hashes:   {zeroday_txt}")
    print(f"  manifest:         {manifest_json}")
    print("[DONE]" if n_rows == len(known) else "[WARN] row count mismatch")
    return 0 if n_rows == len(known) else 2


if __name__ == "__main__":
    sys.exit(main())
