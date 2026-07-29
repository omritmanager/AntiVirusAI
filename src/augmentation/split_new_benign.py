"""
split_new_benign.py — Stage 4 of the benign-corpus augmentation pipeline.

Takes Stage 3's deduped+grouped JSONL and:

1. Carves out a VENDOR-HOLDOUT set: picks a deterministic subset of
   signer-identified vendor groups (>=5 samples each) and excludes them 100%
   from train+val. This is the honest generalization signal — these vendors'
   installer/toolchain patterns contribute ZERO training examples, so good
   performance here can't be explained by memorizing anything about them.
   (A same-corpus holdout, by contrast, is still closer to train than truly
   unrelated software, because the whole corpus was harvested the same way —
   see the writeup caveat in Stage 6/7.)

2. GROUP-AWARE 70/15/15 split of everything else (sklearn's GroupShuffleSplit
   on `group_key`, seed=42, matching phase6_split_dataset.py's ratio
   convention). Every sample sharing a group key lands entirely in train,
   entirely in new-val, or entirely in new-holdout — never split across. A
   plain i.i.d. split would let near-duplicate installer builds leak across
   the boundary, inflating holdout metrics in exactly the way that hides the
   memorization failure this whole pipeline is trying to guard against.

3. Appends new-train/new-val to the EXISTING data/splits_clean X_train/X_val
   arrays — but writes the result to NEW *_augmented.npy files. The original
   X_train.npy/X_val.npy and the official X_test_balanced.npy/
   X_test_imbalanced.npy are never modified; Stage 5 explicitly loads the
   augmented files, keeping every stage's input recoverable and inspectable.

4. Saves new-holdout and vendor-holdout as their own new files, plus a
   groupinfo sidecar recording each holdout row's group_key and whether that
   group_key also appears in the augmented train set ("singleton" if not) —
   Stage 6 uses this for the clustered-vs-singleton FPR gap check.

Usage:
  python src/augmentation/split_new_benign.py \\
      --input data/augmentation/extracted_dry_run.deduped.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
from sklearn.model_selection import GroupShuffleSplit

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from avscan import config  # noqa: E402

SEED = 42
MIN_VENDOR_GROUP_SIZE = 5
MAX_VENDOR_GROUPS_HELD_OUT = 10


def read_jsonl(path: Path) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def carve_vendor_holdout(records: list[dict]) -> tuple[list[dict], list[dict]]:
    """Return (remaining, vendor_holdout). Deterministic: sorts eligible
    signer group keys alphabetically and takes an evenly-spaced subset,
    rather than picking by sample count (which would bias toward whichever
    vendor happens to be best-represented in this particular corpus)."""
    by_group = defaultdict(list)
    for r in records:
        by_group[r["group_key"]].append(r)

    eligible = sorted(
        k for k, v in by_group.items()
        if k.startswith("signer:") and len(v) >= MIN_VENDOR_GROUP_SIZE
    )
    if not eligible:
        return records, []

    n_hold = min(MAX_VENDOR_GROUPS_HELD_OUT, max(1, len(eligible) // 5))
    step = len(eligible) / n_hold
    chosen = {eligible[int(i * step)] for i in range(n_hold)}

    vendor_holdout, remaining = [], []
    for r in records:
        (vendor_holdout if r["group_key"] in chosen else remaining).append(r)
    return remaining, vendor_holdout


def group_split(records: list[dict], test_size: float, seed: int) -> tuple[list[dict], list[dict]]:
    if not records:
        return [], []
    groups = [r["group_key"] for r in records]
    n_groups = len(set(groups))
    if n_groups < 2:
        # Not enough distinct groups to split meaningfully — everything stays
        # in the first bucket rather than crashing GroupShuffleSplit.
        return records, []
    gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    idx_a, idx_b = next(gss.split(records, groups=groups))
    return [records[i] for i in idx_a], [records[i] for i in idx_b]


def to_arrays(records: list[dict]) -> tuple[np.ndarray, np.ndarray]:
    if not records:
        return np.zeros((0, config.EXPECTED_DIM), dtype=np.float32), np.zeros((0,), dtype=np.int8)
    X = np.array([r["features"] for r in records], dtype=np.float32)
    y = np.zeros(len(records), dtype=np.int8)     # every record here is benign
    return X, y


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", type=Path, required=True,
                    help="Stage 3 deduped.jsonl")
    ap.add_argument("--splits-dir", type=Path, default=config.SPLITS_CLEAN_DIR)
    ap.add_argument("--suffix", default="augmented",
                    help="suffix for the new *_<suffix>.npy files (never overwrites originals)")
    args = ap.parse_args()

    if not args.input.exists():
        print(f"[STOP] input not found: {args.input}")
        return 1

    print("=" * 70)
    print("STAGE 4: GROUP-AWARE SPLIT + VENDOR HOLDOUT")
    print("=" * 70)

    print(f"\n[1] Loading {args.input.name}...")
    records = read_jsonl(args.input)
    print(f"  {len(records):,} records, {len(set(r['group_key'] for r in records)):,} groups")

    print(f"\n[2] Carving vendor-holdout (>= {MIN_VENDOR_GROUP_SIZE} samples/vendor)...")
    remaining, vendor_holdout = carve_vendor_holdout(records)
    if vendor_holdout:
        vendors = sorted(set(r["group_key"] for r in vendor_holdout))
        print(f"  Vendor groups held out: {len(vendors)}  ({len(vendor_holdout):,} samples)")
        for v in vendors:
            print(f"    {v}")
    else:
        print(f"  No eligible vendor groups (need >= {MIN_VENDOR_GROUP_SIZE} samples/signer) "
              f"— skipping vendor-holdout for this run.")
    print(f"  Remaining for train/val/holdout split: {len(remaining):,}")

    print(f"\n[3] Group-aware 70/15/15 split (seed={SEED})...")
    train_val, new_holdout = group_split(remaining, test_size=0.15, seed=SEED)
    new_train, new_val = group_split(train_val, test_size=0.15 / 0.85, seed=SEED)
    print(f"  New train:   {len(new_train):,}")
    print(f"  New val:     {len(new_val):,}")
    print(f"  New holdout: {len(new_holdout):,}")

    # Sanity: no group key should appear in more than one of these buckets.
    def group_set(recs):
        return set(r["group_key"] for r in recs)
    overlaps = (
        (group_set(new_train) & group_set(new_val)) |
        (group_set(new_train) & group_set(new_holdout)) |
        (group_set(new_val) & group_set(new_holdout)) |
        (group_set(new_train) & group_set(vendor_holdout)) |
        (group_set(new_val) & group_set(vendor_holdout)) |
        (group_set(new_holdout) & group_set(vendor_holdout))
    )
    if overlaps:
        print(f"  [BUG] group key(s) leaked across split boundaries: {overlaps}")
        return 2
    print(f"  Group-boundary check: OK (no group appears in two buckets)")

    print(f"\n[4] Loading existing splits from {args.splits_dir}...")
    X_train = np.load(args.splits_dir / "X_train.npy")
    y_train = np.load(args.splits_dir / "y_train.npy")
    X_val = np.load(args.splits_dir / "X_val.npy")
    y_val = np.load(args.splits_dir / "y_val.npy")
    print(f"  X_train: {X_train.shape}   X_val: {X_val.shape}")

    print(f"\n[5] Appending new benign samples...")
    Xnt, ynt = to_arrays(new_train)
    Xnv, ynv = to_arrays(new_val)
    X_train_aug = np.vstack([X_train, Xnt]) if len(Xnt) else X_train
    y_train_aug = np.concatenate([y_train, ynt]) if len(ynt) else y_train
    X_val_aug = np.vstack([X_val, Xnv]) if len(Xnv) else X_val
    y_val_aug = np.concatenate([y_val, ynv]) if len(ynv) else y_val
    print(f"  X_train: {X_train.shape} -> {X_train_aug.shape}")
    print(f"  X_val:   {X_val.shape} -> {X_val_aug.shape}")

    print(f"\n[6] Saving augmented splits (suffix='{args.suffix}')...")
    np.save(args.splits_dir / f"X_train_{args.suffix}.npy", X_train_aug)
    np.save(args.splits_dir / f"y_train_{args.suffix}.npy", y_train_aug)
    np.save(args.splits_dir / f"X_val_{args.suffix}.npy", X_val_aug)
    np.save(args.splits_dir / f"y_val_{args.suffix}.npy", y_val_aug)
    print(f"  Saved X_train_{args.suffix}.npy / y_train_{args.suffix}.npy")
    print(f"  Saved X_val_{args.suffix}.npy / y_val_{args.suffix}.npy")
    print(f"  (X_train.npy / X_val.npy / X_test_balanced.npy / X_test_imbalanced.npy untouched)")

    print(f"\n[7] Saving new-holdout + vendor-holdout test sets...")
    train_group_keys = group_set(new_train)

    def save_holdout(recs, name):
        if not recs:
            print(f"  {name}: skipped (empty)")
            return
        X, y = to_arrays(recs)
        np.save(args.splits_dir / f"X_{name}.npy", X)
        np.save(args.splits_dir / f"y_{name}.npy", y)
        groupinfo = [
            {"sha256": r["sha256"], "path": r["path"], "group_key": r["group_key"],
             "singleton": r["group_key"] not in train_group_keys}
            for r in recs
        ]
        with open(args.splits_dir / f"X_{name}.groupinfo.json", "w", encoding="utf-8") as f:
            json.dump(groupinfo, f, indent=2)
        n_singleton = sum(1 for g in groupinfo if g["singleton"])
        print(f"  {name}: {X.shape}  ({n_singleton}/{len(recs)} singleton vs train)")

    save_holdout(new_holdout, "test_new_benign_holdout")
    save_holdout(vendor_holdout, "test_unseen_vendor")

    print(f"\n{'='*70}")
    print("STAGE 4 COMPLETE")
    print(f"{'='*70}")
    print(f"\nNext: Stage 5 - retrain candidate")
    print(f"      python src\\training\\v7\\phase8c_retrain_augmented.py --suffix {args.suffix}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
