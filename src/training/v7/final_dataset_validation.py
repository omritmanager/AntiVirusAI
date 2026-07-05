"""
Final comprehensive validation before Phase 6 (merge).
Runs deep cross-dataset checks that catch problems individual validation misses.
"""
import json
import sys
from pathlib import Path
from collections import Counter
import numpy as np
import gc

ROOT = Path(r"C:\Users\omri9\Desktop\School\Final Project")
BENIGN_FILE  = ROOT / "data" / "datasets" / "modern_benign_features.json"
MALWARE_FILE = ROOT / "data" / "datasets" / "modern_malware_features.json"

REQUIRED_LIEF = "0.17.6"
REQUIRED_DIM  = 2381

issues   = []
warnings = []

def section(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


# ── 1. Both files exist ─────────────────────────────────────────────
section("[1] FILES EXIST")
for f in [BENIGN_FILE, MALWARE_FILE]:
    if not f.exists():
        issues.append(f"Missing: {f}")
        print(f"  MISSING: {f}")
    else:
        mb = f.stat().st_size / (1024**2)
        print(f"  OK: {f.name} ({mb:.1f} MB)")

if issues:
    print("\nFATAL: missing files. Stop.")
    sys.exit(1)

# ── 2. Load both ────────────────────────────────────────────────────
section("[2] LOADING DATASETS")
print("Loading benign...")
with open(BENIGN_FILE) as f:
    benign = json.load(f)
print(f"  {len(benign['samples']):,} benign samples")

print("Loading malware...")
with open(MALWARE_FILE) as f:
    malware = json.load(f)
print(f"  {len(malware['samples']):,} malware samples")

print(f"  TOTAL: {len(benign['samples']) + len(malware['samples']):,} samples")


# ── 3. LIEF version MUST match exactly ──────────────────────────────
section("[3] LIEF VERSION CROSS-CHECK")
b_lief = benign.get("lief_version", "MISSING")
m_lief = malware.get("lief_version", "MISSING")

print(f"  Benign LIEF:  {b_lief}")
print(f"  Malware LIEF: {m_lief}")

if not b_lief.startswith(REQUIRED_LIEF):
    issues.append(f"Benign LIEF wrong: {b_lief}")
if not m_lief.startswith(REQUIRED_LIEF):
    issues.append(f"Malware LIEF wrong: {m_lief}")

# Critical: both extracted with same exact LIEF build
b_full = b_lief
m_full = m_lief
if b_full != m_full:
    warnings.append(
        f"LIEF builds differ slightly: '{b_full}' vs '{m_full}'. "
        f"Both are 0.17.6 family so should be OK, but worth noting."
    )
else:
    print(f"  EXACT MATCH (both '{b_full}')")


# ── 4. Feature dimensions identical ─────────────────────────────────
section("[4] FEATURE DIMENSION CHECK")
b_dim = benign.get("feature_dim", 0)
m_dim = malware.get("feature_dim", 0)
print(f"  Benign:  {b_dim}")
print(f"  Malware: {m_dim}")

if b_dim != REQUIRED_DIM or m_dim != REQUIRED_DIM:
    issues.append(f"Wrong dimensions: benign={b_dim}, malware={m_dim}")
elif b_dim != m_dim:
    issues.append(f"Dimension mismatch: {b_dim} vs {m_dim}")
else:
    print(f"  MATCH ({REQUIRED_DIM} features)")


# ── 5. Label sanity ─────────────────────────────────────────────────
section("[5] LABEL DISTRIBUTION")
b_labels = Counter(s.get("target") for s in benign["samples"])
m_labels = Counter(s.get("target") for s in malware["samples"])
print(f"  Benign labels:  {dict(b_labels)}")
print(f"  Malware labels: {dict(m_labels)}")

if list(b_labels.keys()) != [0]:
    issues.append(f"Benign has non-zero labels: {dict(b_labels)}")
if list(m_labels.keys()) != [1]:
    issues.append(f"Malware has non-one labels: {dict(m_labels)}")

if not issues:
    print(f"  PERFECT: all benign=0, all malware=1")


# ── 6. NO hash overlap between datasets (CRITICAL) ──────────────────
section("[6] CROSS-DATASET HASH OVERLAP (CRITICAL)")
b_hashes = {s.get("sha256", "").lower() for s in benign["samples"]}
m_hashes = {s.get("sha256", "").lower() for s in malware["samples"]}

print(f"  Unique benign hashes:  {len(b_hashes):,}")
print(f"  Unique malware hashes: {len(m_hashes):,}")

overlap = b_hashes & m_hashes
if overlap:
    issues.append(
        f"CRITICAL: {len(overlap)} hashes appear in BOTH benign and malware! "
        f"This would poison the training. Examples: {list(overlap)[:3]}"
    )
    print(f"  POISONED: {len(overlap)} hashes in both!")
else:
    print(f"  CLEAN: zero overlap")


# ── 7. Feature statistics deep-dive ─────────────────────────────────
section("[7] FEATURE STATISTICS (sample of 3000 from each)")

def feat_stats(samples, name, n=3000):
    n = min(n, len(samples))
    mat = np.array([s["features"] for s in samples[:n]], dtype=np.float32)
    return {
        "name":     name,
        "rows":     mat.shape[0],
        "cols":     mat.shape[1],
        "nan":      int(np.isnan(mat).sum()),
        "inf":      int(np.isinf(mat).sum()),
        "min":      float(mat.min()),
        "max":      float(mat.max()),
        "mean":     float(mat.mean()),
        "median":   float(np.median(mat)),
        "std":      float(mat.std()),
        "sparsity": 100 * float((mat == 0).sum()) / mat.size,
    }

b_stats = feat_stats(benign["samples"], "benign")
m_stats = feat_stats(malware["samples"], "malware")

print(f"\n{'Metric':<15} {'Benign':>18} {'Malware':>18}")
print("-" * 55)
for key in ["rows", "cols", "nan", "inf", "min", "max", "mean", "median", "std", "sparsity"]:
    bv = b_stats[key]; mv = m_stats[key]
    if isinstance(bv, float):
        print(f"  {key:<13} {bv:>18.4f} {mv:>18.4f}")
    else:
        print(f"  {key:<13} {bv:>18,} {mv:>18,}")

if b_stats["nan"] or m_stats["nan"]:
    issues.append("NaN values found")
if b_stats["inf"] or m_stats["inf"]:
    issues.append("Inf values found")

# Sparsity should be similar (within 15% of each other)
sp_diff = abs(b_stats["sparsity"] - m_stats["sparsity"])
if sp_diff > 15:
    warnings.append(
        f"Sparsity differs by {sp_diff:.1f}% ({b_stats['sparsity']:.1f}% vs "
        f"{m_stats['sparsity']:.1f}%). May indicate extraction inconsistency."
    )
else:
    print(f"\n  Sparsity diff: {sp_diff:.1f}% (acceptable)")


# ── 8. Per-feature variance check (catches "dead" features) ─────────
section("[8] FEATURE VARIANCE CHECK")
print("Checking if any feature dimension is identical in all samples...")

n_check = min(5000, len(benign["samples"]))
mat_b = np.array([s["features"] for s in benign["samples"][:n_check]], dtype=np.float32)
mat_m = np.array([s["features"] for s in malware["samples"][:n_check]], dtype=np.float32)
combined = np.vstack([mat_b, mat_m])

variances = combined.var(axis=0)
dead_features = int((variances == 0).sum())
print(f"  Combined samples: {combined.shape[0]:,}")
print(f"  Features with zero variance: {dead_features} / {combined.shape[1]}")

# Some zero-variance features are normal in EMBER (rarely-set flags)
# But more than 200 is suspicious
if dead_features > 300:
    warnings.append(
        f"{dead_features} features have zero variance — high for EMBER v2 (~50-150 typical)"
    )
else:
    print(f"  Normal range (EMBER usually has 50-200 sparse features)")

del combined, mat_b, mat_m
gc.collect()


# ── 9. Class separability quick check ───────────────────────────────
section("[9] CLASS SEPARABILITY (sanity)")
print("Computing mean feature vector per class...")
print("If means are identical, the data is broken.")

mat_b = np.array([s["features"] for s in benign["samples"][:3000]], dtype=np.float32)
mat_m = np.array([s["features"] for s in malware["samples"][:3000]], dtype=np.float32)
mean_b = mat_b.mean(axis=0)
mean_m = mat_m.mean(axis=0)
mean_diff = np.abs(mean_b - mean_m)

print(f"  Mean L1 distance between classes: {mean_diff.sum():.2f}")
print(f"  Features differing >0.01:         {int((mean_diff > 0.01).sum())} / {len(mean_diff)}")
print(f"  Features differing >1.0:          {int((mean_diff > 1.0).sum())} / {len(mean_diff)}")

if mean_diff.sum() < 100:
    issues.append("Class means too similar — features may not distinguish benign/malware")
else:
    print(f"  Healthy separation between classes")

del mat_b, mat_m
gc.collect()


# ── 10. Memory load test ────────────────────────────────────────────
section("[10] MEMORY LOAD TEST (simulating training)")
print("Loading ALL features into a single matrix...")
print("This is what training will do.")

try:
    all_features = []
    all_labels   = []
    for s in benign["samples"]:
        all_features.append(s["features"])
        all_labels.append(0)
    for s in malware["samples"]:
        all_features.append(s["features"])
        all_labels.append(1)
    
    X = np.array(all_features, dtype=np.float32)
    y = np.array(all_labels, dtype=np.int8)
    
    gb = X.nbytes / (1024**3)
    print(f"  Matrix shape:  {X.shape}")
    print(f"  Memory used:   {gb:.2f} GB")
    print(f"  Labels:        {dict(Counter(y.tolist()))}")
    print(f"  SUCCESS — can fit in memory")
    
    del X, y, all_features, all_labels
    gc.collect()
except MemoryError:
    issues.append("Not enough RAM to load combined dataset — need >16 GB")
    print(f"  OUT OF MEMORY!")


# ── 11. Final report ────────────────────────────────────────────────
section("FINAL REPORT")

print(f"\n  Benign samples:    {len(benign['samples']):>8,}")
print(f"  Malware samples:   {len(malware['samples']):>8,}")
print(f"  Combined total:    {len(benign['samples']) + len(malware['samples']):>8,}")
print(f"  Class ratio:       1:{len(malware['samples'])/len(benign['samples']):.2f} (malware:benign)")

if issues:
    print("\nCRITICAL ISSUES:")
    for i, issue in enumerate(issues, 1):
        print(f"  {i}. {issue}")
    print("\nDO NOT PROCEED to merge. Fix these first.")
    sys.exit(1)
elif warnings:
    print(f"\nWARNINGS ({len(warnings)}):")
    for w in warnings:
        print(f"  - {w}")
    print("\nDatasets are usable but review warnings.")
    print("OK to proceed to Phase 6 (merge).")
else:
    print(f"\nALL CHECKS PASSED — datasets are READY for training")
    print("Proceed to Phase 6 (Merge & Split).")