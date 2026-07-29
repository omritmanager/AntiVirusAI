"""
extract_new_benign.py — Stage 1 of the benign-corpus augmentation pipeline.

Walks a folder of candidate benign .exe files, and for each one that survives
reads once, extracts:
  * sha256                          (avscan.hashing.sha256_bytes)
  * features                        (Engine.processed_vector — the EXACT
                                      2381-dim inference-time vector, temporal
                                      indices already zeroed: guarantees
                                      train/serve parity for free)
  * ml_verdict / lgbm_prob          (Engine.classify_bytes — the CURRENT
                                      production model's opinion, needed by
                                      Stage 2's anti-poisoning tiering)
  * signature_status / signer       (avscan.signature.verify — needed by
                                      Stage 2's tiering)

Never aborts on one bad file (corrupt / non-PE despite .exe extension) — logs
and continues, matching the scanner's own "never crash on one bad file" rule.

Checkpointed: appends one JSON object per line to the output file as each file
finishes, flushed immediately. A rerun with the same --output skips paths
already present in that file, so an interrupted multi-hour run resumes for
free.

Processes size-ascending so the bulk of the file count (small files) finishes
first and gives an early, checkpoint-recoverable signal, rather than a huge
installer stalling all visible progress.

Usage:
  python src/augmentation/extract_new_benign.py --input-dir "D:\\safe exe" \\
      --output data/augmentation/extracted_dry_run.jsonl --limit 300
  python src/augmentation/extract_new_benign.py --input-dir "D:\\safe exe" \\
      --output data/augmentation/extracted_full.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from avscan import signature  # noqa: E402
from avscan.compat import apply_compat_shims  # noqa: E402
from avscan.engine import Engine, sha256_bytes  # noqa: E402

apply_compat_shims()          # must run before `import lief` (spec §2)
import lief                   # noqa: E402


def compute_imphash(data: bytes) -> str | None:
    """Import hash, used by Stage 3 as a group-key fallback when a file has no
    trusted signer. None on any parse failure — never raises, matches the
    scanner's own per-file failure tolerance."""
    try:
        binary = lief.PE.parse(data)
        if binary is None:
            return None
        return lief.PE.get_imphash(binary)
    except Exception:
        return None


def stratified_sample(paths: list[Path], limit: int) -> list[Path]:
    """Evenly-spaced sample across the size-sorted list (paths already sorted).

    A random or size-ascending-truncated sample would either miss the tail of
    the size distribution entirely or be dominated by it; an even stride over
    the sorted list exercises small/medium/large files proportionally within
    the sample budget, without any single file dominating a dry run's runtime.
    """
    n = len(paths)
    if n <= limit:
        return paths
    step = n / limit
    return [paths[int(i * step)] for i in range(limit)]


def already_done(output_path: Path) -> set[str]:
    done = set()
    if not output_path.exists():
        return done
    with open(output_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                if "path" in rec:
                    done.add(rec["path"])
            except json.JSONDecodeError:
                continue
    return done


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input-dir", type=Path, default=Path(r"D:\safe exe"))
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--limit", type=int, default=None,
                    help="size-stratified sample size (omit for the full corpus)")
    ap.add_argument("--progress-every", type=int, default=50)
    args = ap.parse_args()

    if not args.input_dir.is_dir():
        print(f"[STOP] input dir not found: {args.input_dir}")
        return 1

    print("=" * 70)
    print("STAGE 1: EXTRACT NEW BENIGN FEATURES")
    print("=" * 70)
    print(f"Input:  {args.input_dir}")
    print(f"Output: {args.output}")

    print("\n[1] Listing candidate .exe files...")
    all_files = [p for p in args.input_dir.iterdir()
                if p.is_file() and p.suffix.lower() == ".exe"]
    all_files.sort(key=lambda p: p.stat().st_size)
    total_bytes_all = sum(p.stat().st_size for p in all_files)
    print(f"  Found {len(all_files):,} .exe files, {total_bytes_all/1e9:.1f} GB total")

    targets = stratified_sample(all_files, args.limit) if args.limit else all_files
    if args.limit:
        print(f"  Dry-run sample: {len(targets):,} files (size-stratified)")
        big = [p for p in targets if p.stat().st_size > 100 * 1024 * 1024]
        print(f"  Sample includes {len(big)} file(s) >100MB "
              f"{'(large-file path exercised)' if big else '(NOTE: no large file in this sample)'}")

    print(f"\n[2] Checking for a previous checkpoint at {args.output}...")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    done_paths = already_done(args.output)
    if done_paths:
        print(f"  Resuming: {len(done_paths):,} file(s) already extracted, skipping them")
    remaining = [p for p in targets if str(p) not in done_paths]
    print(f"  {len(remaining):,} file(s) left to process")

    if not remaining:
        print("\nNothing to do — output already complete for this target set.")
        return 0

    print("\n[3] Loading Engine (models load once, reused for every file)...")
    engine = Engine(load_if=True)
    print("  Engine ready.")

    print(f"\n[4] Extracting ({len(remaining):,} files)...")
    t0 = time.time()
    bytes_done = 0
    ok = fail = skipped_small = 0
    fail_log = []

    with open(args.output, "a", encoding="utf-8") as out_f:
        for i, path in enumerate(remaining, 1):
            try:
                with open(path, "rb") as f:
                    data = f.read()
            except Exception as e:
                fail += 1
                fail_log.append((str(path), f"read failed: {e}"))
                continue

            bytes_done += len(data)
            sha = sha256_bytes(data)
            vec = engine.processed_vector(data)
            if vec is None:
                fail += 1
                fail_log.append((str(path), "processed_vector returned None "
                                            "(corrupt / non-PE / bad dim / NaN-Inf)"))
                continue

            ml = engine.classify_bytes(data, use_if=True)
            sig = signature.verify(str(path))
            imphash = compute_imphash(data)

            rec = {
                "path": str(path),
                "sha256": sha,
                "size": len(data),
                "features": vec.tolist(),
                "ml_verdict": ml.ml_verdict,
                "lgbm_prob": ml.lgbm_prob,
                "if_score": ml.if_score,
                "signature_status": sig.status,
                "signature_signer": sig.signer,
                "imphash": imphash,
            }
            out_f.write(json.dumps(rec) + "\n")
            out_f.flush()
            ok += 1

            if i % args.progress_every == 0 or i == len(remaining):
                elapsed = time.time() - t0
                rate_files = i / elapsed if elapsed > 0 else 0
                rate_mb = (bytes_done / 1e6) / elapsed if elapsed > 0 else 0
                remaining_bytes = sum(p.stat().st_size for p in remaining[i:])
                eta = remaining_bytes / (bytes_done / elapsed) if bytes_done and elapsed else 0
                print(f"  [{i:>6,}/{len(remaining):,}]  ok={ok:,} fail={fail:,}  "
                      f"{rate_files:.2f} files/s  {rate_mb:.1f} MB/s  "
                      f"ETA {eta/60:.1f} min")

    elapsed = time.time() - t0
    print(f"\n{'='*70}")
    print("STAGE 1 COMPLETE")
    print(f"{'='*70}")
    print(f"  Processed:  {ok + fail:,} file(s) in {elapsed/60:.1f} min "
          f"({elapsed/(ok+fail):.3f} s/file avg)" if (ok + fail) else "")
    print(f"  Succeeded:  {ok:,}")
    print(f"  Failed:     {fail:,}")
    print(f"  Output:     {args.output}")

    if fail_log:
        fail_path = args.output.with_suffix(".failures.txt")
        with open(fail_path, "w", encoding="utf-8") as f:
            for path, reason in fail_log:
                f.write(f"{path}\t{reason}\n")
        print(f"  Failure log: {fail_path} ({len(fail_log)} entries)")

    print(f"\nNext: Stage 2 - anti-poisoning filter")
    print(f"      python src\\augmentation\\anti_poison_filter.py --input {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
