"""
cluster_and_dedup.py — Stage 3 of the benign-corpus augmentation pipeline.

Takes Stage 2's accepted.jsonl and:

1. Drops exact SHA-256 duplicates within the new batch (e.g. the same
   installer downloaded multiple times under different names).

2. Assigns a GROUP KEY to every surviving sample, priority order:
     (a) Authenticode signer identity, if TRUSTED — the strongest available
         "same publisher" signal.
     (b) import hash (imphash), if the signer isn't usable — catches
         same-toolchain/same-packer near-duplicates that a different
         filename or a minor version bump wouldn't change.
     (c) rounded-feature signature (first 100 EMBER features, 2dp) as a last
         resort — this is deep_shortcut_audit.py's existing technique,
         reused rather than reinvented.
   This group key is what Stage 4's split uses instead of the SHA-256 alone,
   so near-duplicate installer builds can never end up split across
   train/val/holdout — a plain i.i.d. split would let that happen silently
   and inflate holdout metrics in exactly the way that hides memorization.

3. Downsamples any group wildly overrepresented (many builds of the same
   installer) so training isn't dominated by one template. Truncation is
   deterministic (sorted by SHA-256), not random, for reproducibility.

4. Runs deep_shortcut_audit.py's within-class-diversity check (originally
   malware-only) against this new benign batch, as a diagnostic — not a gate,
   just visibility into how repetitive the corpus is before it goes into
   training.

Usage:
  python src/augmentation/cluster_and_dedup.py \\
      --input data/augmentation/extracted_dry_run.accepted.jsonl \\
      --max-per-group 20
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def normalize_signer(name: str | None) -> str:
    return (name or "").strip().lower()


def feature_signature(features: list[float], n: int = 100) -> str:
    """Deterministic fallback group key: round the first N features, hash them.

    Same technique deep_shortcut_audit.py uses to detect near-duplicate
    samples ("distinct 'signatures' among rounded first-100-features").
    """
    rounded = tuple(round(x, 2) for x in features[:n])
    return hashlib.sha256(repr(rounded).encode()).hexdigest()[:16]


def assign_group_key(rec: dict) -> str:
    signer = normalize_signer(rec.get("signature_signer"))
    if rec.get("signature_status") == "TRUSTED" and signer:
        return f"signer:{signer}"
    imphash = rec.get("imphash")
    if imphash:
        return f"imphash:{imphash}"
    return f"featsig:{feature_signature(rec['features'])}"


def read_jsonl(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def diversity_check(records: list[dict], n: int = 100) -> dict:
    """Reproduces deep_shortcut_audit.py's within-class diversity check on
    this new benign batch (that script only ran it on malware)."""
    if not records:
        return {"sampled": 0, "distinct": 0, "ratio": 1.0}
    feats = np.array([r["features"][:n] for r in records], dtype=np.float32)
    quant = np.round(feats, decimals=2)
    distinct = len({tuple(row) for row in quant})
    ratio = distinct / len(records)
    return {"sampled": len(records), "distinct": distinct, "ratio": ratio}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", type=Path, required=True,
                    help="Stage 2 accepted.jsonl")
    ap.add_argument("--out-dir", type=Path, default=None,
                    help="defaults to --input's parent directory")
    ap.add_argument("--max-per-group", type=int, default=20,
                    help="cap on samples kept per group key after downsampling")
    args = ap.parse_args()

    if not args.input.exists():
        print(f"[STOP] input not found: {args.input}")
        return 1
    out_dir = args.out_dir or args.input.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("STAGE 3: DEDUP + GROUP-KEY ASSIGNMENT")
    print("=" * 70)

    print(f"\n[1] Loading {args.input.name}...")
    records = list(read_jsonl(args.input))
    print(f"  {len(records):,} records loaded")

    print(f"\n[2] Exact SHA-256 dedup...")
    seen_sha = set()
    deduped = []
    n_exact_dupes = 0
    for rec in records:
        sha = rec["sha256"]
        if sha in seen_sha:
            n_exact_dupes += 1
            continue
        seen_sha.add(sha)
        deduped.append(rec)
    print(f"  Exact duplicates removed: {n_exact_dupes:,}")
    print(f"  Remaining: {len(deduped):,}")

    print(f"\n[3] Assigning group keys...")
    key_kind_counts = defaultdict(int)
    groups: dict[str, list[dict]] = defaultdict(list)
    for rec in deduped:
        key = assign_group_key(rec)
        rec["group_key"] = key
        groups[key].append(rec)
        key_kind_counts[key.split(":", 1)[0]] += 1
    print(f"  Distinct groups: {len(groups):,}")
    for kind, count in sorted(key_kind_counts.items(), key=lambda kv: -kv[1]):
        print(f"    {kind:<10} {count:,} samples")

    group_sizes = sorted(((k, len(v)) for k, v in groups.items()), key=lambda kv: -kv[1])
    print(f"\n  Largest groups:")
    for key, size in group_sizes[:10]:
        flag = "  <-- will downsample" if size > args.max_per_group else ""
        print(f"    {size:>5}  {key}{flag}")

    print(f"\n[4] Downsampling groups over {args.max_per_group}...")
    final_records = []
    n_downsampled_away = 0
    n_groups_capped = 0
    for key, members in groups.items():
        if len(members) > args.max_per_group:
            n_groups_capped += 1
            members = sorted(members, key=lambda r: r["sha256"])[:args.max_per_group]
            n_downsampled_away += len(groups[key]) - len(members)
        final_records.extend(members)
    print(f"  Groups capped: {n_groups_capped}")
    print(f"  Samples removed by downsampling: {n_downsampled_away:,}")
    print(f"  Final sample count: {len(final_records):,}")

    print(f"\n[5] Within-class diversity check (deep_shortcut_audit.py technique)...")
    diversity = diversity_check(final_records)
    print(f"  Sampled:  {diversity['sampled']:,}")
    print(f"  Distinct: {diversity['distinct']:,}")
    print(f"  Ratio:    {diversity['ratio']*100:.1f}%")
    if diversity["ratio"] < 0.20:
        print(f"  WARNING: diversity ratio <20% — this batch may still be "
              f"dominated by a few templates even after downsampling.")
    else:
        print(f"  Healthy diversity.")

    out_path = out_dir / (args.input.stem.replace(".accepted", "") + ".deduped.jsonl")
    with open(out_path, "w", encoding="utf-8") as f:
        for rec in final_records:
            f.write(json.dumps(rec) + "\n")

    summary = {
        "input_records": len(records),
        "exact_duplicates_removed": n_exact_dupes,
        "distinct_groups": len(groups),
        "group_key_kind_counts": dict(key_kind_counts),
        "groups_capped": n_groups_capped,
        "samples_removed_by_downsampling": n_downsampled_away,
        "final_sample_count": len(final_records),
        "diversity": diversity,
        "max_per_group": args.max_per_group,
    }
    summary_path = out_dir / (args.input.stem.replace(".accepted", "") + ".group_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"\n{'='*70}")
    print("STAGE 3 COMPLETE")
    print(f"{'='*70}")
    print(f"  Output:  {out_path}")
    print(f"  Summary: {summary_path}")
    print(f"\nNext: Stage 4 - group-aware split")
    print(f"      python src\\augmentation\\split_new_benign.py --input {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
