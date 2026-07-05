"""
Phase 6: Create train/validation/test splits from modern dataset.
Uses modern_benign_merged.json + modern_malware_features.json.

Split strategy:
  70% train | 15% validation | 15% test (balanced)
  + separate imbalanced test (1:50)

All splits are stratified by label.
Random seed = 42 everywhere for reproducibility.
"""

import json
import numpy as np
import pickle
from pathlib import Path
from datetime import datetime
from collections import Counter
import gc

ROOT    = Path(r"C:\Users\omri9\Desktop\School\Final Project")
DATASETS = ROOT / "data" / "datasets"
SPLITS   = ROOT / "data" / "splits"
SPLITS.mkdir(parents=True, exist_ok=True)

BENIGN_FILE  = DATASETS / "modern_benign_merged.json"
MALWARE_FILE = DATASETS / "modern_malware_features.json"

SEED = 42
rng  = np.random.default_rng(SEED)

print("=" * 70)
print("PHASE 6: DATASET SPLIT")
print("=" * 70)
print(f"Seed: {SEED}")
print(f"Time: {datetime.now()}")

# ── Load ──────────────────────────────────────────────────────
print("\n[1] Loading datasets...")
with open(BENIGN_FILE) as f:
    benign = json.load(f)
with open(MALWARE_FILE) as f:
    malware = json.load(f)

b_samples = benign["samples"]
m_samples = malware["samples"]

print(f"  Benign:  {len(b_samples):,}")
print(f"  Malware: {len(m_samples):,}")

# ── Shuffle each class independently ─────────────────────────
print("\n[2] Shuffling (seed=42)...")
b_idx = rng.permutation(len(b_samples))
m_idx = rng.permutation(len(m_samples))

b_shuffled = [b_samples[i] for i in b_idx]
m_shuffled = [m_samples[i] for i in m_idx]

# ── Split each class 70/15/15 ─────────────────────────────────
print("\n[3] Splitting 70/15/15...")

def split_indices(n, train=0.70, val=0.15):
    t = int(n * train)
    v = int(n * val)
    return t, v, n - t - v

b_t, b_v, b_te = split_indices(len(b_shuffled))
m_t, m_v, m_te = split_indices(len(m_shuffled))

b_train = b_shuffled[:b_t]
b_val   = b_shuffled[b_t:b_t+b_v]
b_test  = b_shuffled[b_t+b_v:]

m_train = m_shuffled[:m_t]
m_val   = m_shuffled[m_t:m_t+m_v]
m_test  = m_shuffled[m_t+m_v:]

print(f"\n  {'Split':<12} {'Benign':>10} {'Malware':>10} {'Total':>10} {'Ratio':>10}")
print(f"  {'-'*52}")
for name, bn, mn in [("Train", b_train, m_train),
                      ("Validation", b_val, m_val),
                      ("Test (bal.)", b_test, m_test)]:
    total = len(bn) + len(mn)
    ratio = len(mn) / max(len(bn), 1)
    print(f"  {name:<12} {len(bn):>10,} {len(mn):>10,} {total:>10,} {ratio:>9.2f}:1")

# ── Build splits ──────────────────────────────────────────────
print("\n[4] Building feature matrices...")

def build_XY(benign_list, malware_list, label=""):
    samples = benign_list + malware_list
    X = np.array([s["features"] for s in samples], dtype=np.float32)
    y = np.array([0]*len(benign_list) + [1]*len(malware_list), dtype=np.int8)
    # Shuffle combined
    perm = rng.permutation(len(samples))
    return X[perm], y[perm]

X_train, y_train = build_XY(b_train, m_train, "train")
X_val,   y_val   = build_XY(b_val,   m_val,   "val")
X_test,  y_test  = build_XY(b_test,  m_test,  "test")

print(f"  Train:      {X_train.shape}  labels: {dict(zip(*np.unique(y_train, return_counts=True)))}")
print(f"  Validation: {X_val.shape}  labels: {dict(zip(*np.unique(y_val, return_counts=True)))}")
print(f"  Test (bal): {X_test.shape}  labels: {dict(zip(*np.unique(y_test, return_counts=True)))}")

# ── Imbalanced test (1:50) ────────────────────────────────────
print("\n[5] Building imbalanced test (1:50)...")
# Use test malware + 50x more benign from val set
n_mal  = len(m_test)
n_ben_needed = min(n_mal * 50, len(b_val))
b_imbalanced = rng.choice(len(b_val), size=n_ben_needed, replace=False)
b_imb_list   = [b_val[i] for i in b_imbalanced]

X_imb = np.array(
    [s["features"] for s in b_imb_list] +
    [s["features"] for s in m_test],
    dtype=np.float32
)
y_imb = np.array(
    [0]*len(b_imb_list) + [1]*len(m_test),
    dtype=np.int8
)
perm = rng.permutation(len(y_imb))
X_imb, y_imb = X_imb[perm], y_imb[perm]

actual_ratio = (y_imb == 0).sum() / max((y_imb == 1).sum(), 1)
print(f"  Shape:      {X_imb.shape}")
print(f"  Benign:     {(y_imb==0).sum():,}")
print(f"  Malware:    {(y_imb==1).sum():,}")
print(f"  Actual ratio: {actual_ratio:.0f}:1 benign:malware")

# ── Memory summary ─────────────────────────────────────────────
print("\n[6] Memory usage:")
for name, X in [("train", X_train), ("val", X_val),
                 ("test_bal", X_test), ("test_imb", X_imb)]:
    print(f"  {name:<12} {X.nbytes / (1024**2):>8.1f} MB")

# ── Save as numpy ──────────────────────────────────────────────
print("\n[7] Saving splits...")

def save_split(X, y, name):
    np.save(SPLITS / f"X_{name}.npy", X)
    np.save(SPLITS / f"y_{name}.npy", y)
    print(f"  Saved: X_{name}.npy + y_{name}.npy  ({X.nbytes/(1024**2):.1f} MB)")

save_split(X_train, y_train, "train")
save_split(X_val,   y_val,   "val")
save_split(X_test,  y_test,  "test_balanced")
save_split(X_imb,   y_imb,   "test_imbalanced")

# ── Save metadata ──────────────────────────────────────────────
meta = {
    "created_at": datetime.now().isoformat(),
    "seed": SEED,
    "lief_version": benign["lief_version"],
    "feature_dim": 2381,
    "splits": {
        "train":           {"benign": len(b_train), "malware": len(m_train), "total": len(y_train)},
        "val":             {"benign": len(b_val),   "malware": len(m_val),   "total": len(y_val)},
        "test_balanced":   {"benign": len(b_test),  "malware": len(m_test),  "total": len(y_test)},
        "test_imbalanced": {"benign": len(b_imb_list), "malware": len(m_test), "total": len(y_imb)},
    },
    "sources": {
        "benign_file":  BENIGN_FILE.name,
        "malware_file": MALWARE_FILE.name,
    }
}

with open(SPLITS / "split_metadata.json", "w") as f:
    json.dump(meta, f, indent=2)

print(f"\n  Saved: split_metadata.json")
print(f"  Location: {SPLITS}")

# ── Final summary ──────────────────────────────────────────────
print(f"\n{'='*70}")
print("PHASE 6 COMPLETE")
print(f"{'='*70}")
print(f"\n  Total samples:     {len(y_train)+len(y_val)+len(y_test):,}")
print(f"  Train:             {len(y_train):,}")
print(f"  Validation:        {len(y_val):,}")
print(f"  Test (balanced):   {len(y_test):,}")
print(f"  Test (imbalanced): {len(y_imb):,} (1:{actual_ratio:.0f})")
print(f"\n  Files saved to: {SPLITS}")
print(f"\nNext: Phase 7 - Remove temporal features")
print(f"      python src\\training\\v7\\phase7_remove_temporal.py")