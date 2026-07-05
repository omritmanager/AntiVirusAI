"""
Phase 7: Remove temporal features + fix imbalanced test set.

Temporal features removed (V6's killer):
  These features encode WHEN a file was compiled/linked,
  not WHAT it does. The model must not learn 'modern = malware'.

Feature indices (EMBER v2 layout):
  GeneralFileInfo group (1536-1597):
    1542: has_debug
    1543: imports_count  <- NOT temporal, keep
    1544: exports_count  <- NOT temporal, keep
    1548: has_relocations
    1549: has_resources  <- NOT temporal, keep
    1552: has_signature  <- useful signal, keep
    1557: major_linker_version   <-- REMOVE (temporal)
    1558: minor_linker_version   <-- REMOVE (temporal)

  HeaderFileInfo group (1598-1666):
    1599: machine_type bits       <-- REMOVE (DLL/EXE flag = shortcut)
    1602: timestamp               <-- REMOVE (compilation time)
    1609: major_image_version     <-- REMOVE (temporal)
    1610: minor_image_version     <-- REMOVE (temporal)
    1612: major_os_version        <-- REMOVE (temporal)
    1613: minor_os_version        <-- REMOVE (temporal)
    1616: major_subsystem_version <-- REMOVE (temporal)
    1617: minor_subsystem_version <-- REMOVE (temporal)

Note: We zero these features rather than remove them (keeps vector size=2381,
compatible with any future EMBER usage).
"""

import numpy as np
import json
from pathlib import Path
from datetime import datetime

ROOT   = Path(r"C:\Users\omri9\Desktop\School\Final Project")
SPLITS = ROOT / "data" / "splits"

SEED = 42
rng  = np.random.default_rng(SEED)

print("=" * 70)
print("PHASE 7: REMOVE TEMPORAL FEATURES + FIX IMBALANCED TEST")
print("=" * 70)

# ── Feature indices to zero out ───────────────────────────────
TEMPORAL_INDICES = [
    1557,  # major_linker_version
    1558,  # minor_linker_version
    1599,  # machine_type (DLL/EXE flag — structural shortcut)
    1602,  # timestamp
    1609,  # major_image_version
    1610,  # minor_image_version
    1612,  # major_os_version
    1613,  # minor_os_version
    1616,  # major_subsystem_version
    1617,  # minor_subsystem_version
]

print(f"\n[1] Features to zero out: {len(TEMPORAL_INDICES)}")
feature_names = {
    1557: "major_linker_version",
    1558: "minor_linker_version",
    1599: "machine_type (DLL/EXE flag)",
    1602: "timestamp",
    1609: "major_image_version",
    1610: "minor_image_version",
    1612: "major_os_version",
    1613: "minor_os_version",
    1616: "major_subsystem_version",
    1617: "minor_subsystem_version",
}
for idx in TEMPORAL_INDICES:
    print(f"  idx {idx}: {feature_names[idx]}")

# ── Load and clean all splits ─────────────────────────────────
print("\n[2] Loading and cleaning splits...")

splits_to_clean = ["train", "val", "test_balanced"]
cleaned = {}

for split_name in splits_to_clean:
    X = np.load(SPLITS / f"X_{split_name}.npy")
    y = np.load(SPLITS / f"y_{split_name}.npy")
    
    # Zero out temporal features
    before_mean = X[:, TEMPORAL_INDICES].mean()
    X[:, TEMPORAL_INDICES] = 0.0
    after_mean  = X[:, TEMPORAL_INDICES].mean()
    
    cleaned[split_name] = (X, y)
    print(f"  {split_name:<20} shape={X.shape}  "
          f"temporal mean before={before_mean:.3f} after={after_mean:.3f}")

# ── Build PROPER imbalanced test (1:5 ratio) ──────────────────
# We don't have enough benign for 1:50, so use 1:5 which is still
# more realistic than 1:1, and document this limitation.
print("\n[3] Building proper imbalanced test set (1:5 ratio)...")

X_train, y_train = cleaned["train"]
X_val,   y_val   = cleaned["val"]
X_test,  y_test  = cleaned["test_balanced"]

# Pool all benign from val + test for imbalanced test
X_val_benign   = X_val[y_val == 0]
X_test_benign  = X_test[y_test == 0]
X_test_malware = X_test[y_test == 1]

X_all_benign = np.vstack([X_val_benign, X_test_benign])
n_malware    = len(X_test_malware)
n_benign_needed = min(n_malware * 5, len(X_all_benign))

# Pick benign randomly
benign_idx   = rng.choice(len(X_all_benign), size=n_benign_needed, replace=False)
X_benign_imb = X_all_benign[benign_idx]

X_imb = np.vstack([X_benign_imb, X_test_malware])
y_imb = np.array([0]*len(X_benign_imb) + [1]*len(X_test_malware), dtype=np.int8)
perm  = rng.permutation(len(y_imb))
X_imb, y_imb = X_imb[perm], y_imb[perm]

actual_ratio = (y_imb == 0).sum() / max((y_imb == 1).sum(), 1)
print(f"  Benign:  {(y_imb==0).sum():,}")
print(f"  Malware: {(y_imb==1).sum():,}")
print(f"  Ratio:   1:{actual_ratio:.1f}")

cleaned["test_imbalanced"] = (X_imb, y_imb)

# ── Verify temporal features are zeroed ──────────────────────
print("\n[4] Verifying temporal features are gone...")
for split_name, (X, y) in cleaned.items():
    temporal_sum = np.abs(X[:, TEMPORAL_INDICES]).sum()
    print(f"  {split_name:<22} temporal feature sum = {temporal_sum:.4f}  "
          + ("OK" if temporal_sum == 0 else "ERROR - not zeroed!"))

# ── Save cleaned splits ───────────────────────────────────────
print("\n[5] Saving cleaned splits...")
CLEANED = ROOT / "data" / "splits_clean"
CLEANED.mkdir(parents=True, exist_ok=True)

for split_name, (X, y) in cleaned.items():
    np.save(CLEANED / f"X_{split_name}.npy", X)
    np.save(CLEANED / f"y_{split_name}.npy", y)
    mb = X.nbytes / (1024**2)
    print(f"  X_{split_name}.npy  {X.shape}  {mb:.0f} MB")

# ── Save metadata ─────────────────────────────────────────────
meta = {
    "created_at":        datetime.now().isoformat(),
    "seed":              SEED,
    "feature_dim":       2381,
    "temporal_indices_zeroed": TEMPORAL_INDICES,
    "temporal_feature_names":  feature_names,
    "splits": {
        name: {
            "shape": list(X.shape),
            "n_benign":  int((y==0).sum()),
            "n_malware": int((y==1).sum()),
        }
        for name, (X, y) in cleaned.items()
    },
    "note": (
        "Temporal features zeroed (not removed) to maintain 2381-dim compatibility. "
        "test_imbalanced uses 1:5 ratio (benign:malware) due to dataset size constraints. "
        "DLL/EXE flag (idx 1599) removed to prevent structural shortcut learning."
    )
}

with open(CLEANED / "split_metadata_clean.json", "w") as f:
    json.dump(meta, f, indent=2)

# ── Final report ──────────────────────────────────────────────
print(f"\n{'='*70}")
print("PHASE 7 COMPLETE")
print(f"{'='*70}")
print(f"\n  Temporal features zeroed: {len(TEMPORAL_INDICES)}")
print(f"  {'Split':<22} {'Shape':>18} {'Benign':>9} {'Malware':>9}")
print(f"  {'-'*60}")
for name, (X, y) in cleaned.items():
    print(f"  {name:<22} {str(X.shape):>18} "
          f"{(y==0).sum():>9,} {(y==1).sum():>9,}")
print(f"\n  Output: {CLEANED}")
print(f"\nNext: Phase 8 - Train LightGBM")
print(f"      python src\\training\\v7\\phase8_train_lgbm.py")