"""
Merge modern_benign_features.json + exe_only_features.json
Then validate the combined dataset.
"""
import json
import numpy as np
from pathlib import Path
from collections import Counter

ROOT = Path(r"C:\Users\omri9\Desktop\School\Final Project\data\datasets")
BENIGN_FILE  = ROOT / "modern_benign_features.json"
EXE_FILE     = ROOT / "exe_only_features.json"
MERGED_FILE  = ROOT / "modern_benign_merged.json"
MALWARE_FILE = ROOT / "modern_malware_features.json"

print("=" * 70)
print("MERGE + VALIDATE BENIGN DATASETS")
print("=" * 70)

# Load both
print("\n[1] Loading...")
with open(BENIGN_FILE) as f: benign = json.load(f)
with open(EXE_FILE) as f:    exe    = json.load(f)

b_samples = benign["samples"]
e_samples = exe["samples"]

print(f"  Benign (V1):  {len(b_samples):,}")
print(f"  EXE-only:     {len(e_samples):,}")

# Verify LIEF versions match
b_lief = benign.get("lief_version", "")
e_lief = exe.get("lief_version", "")
print(f"\n[2] LIEF version check:")
print(f"  Benign: {b_lief}")
print(f"  EXE:    {e_lief}")
if b_lief != e_lief:
    print("  FATAL: LIEF versions differ! Cannot merge.")
    exit(1)
print(f"  MATCH")

# Check for SHA-256 overlap before merging
print(f"\n[3] Hash overlap check...")
b_hashes = {s["sha256"] for s in b_samples}
e_hashes = {s["sha256"] for s in e_samples}
overlap = b_hashes & e_hashes
print(f"  Benign hashes:   {len(b_hashes):,}")
print(f"  EXE hashes:      {len(e_hashes):,}")
print(f"  Overlap:         {len(overlap)}")
if overlap:
    print(f"  Removing {len(overlap)} duplicates from EXE set...")
    e_samples = [s for s in e_samples if s["sha256"] not in b_hashes]
    print(f"  EXE after dedup: {len(e_samples):,}")

# Also check against malware hashes
print(f"\n[4] Cross-check with malware dataset...")
with open(MALWARE_FILE) as f: malware = json.load(f)
m_hashes = {s["sha256"] for s in malware["samples"]}

b_poison = {s["sha256"] for s in b_samples} & m_hashes
e_poison = {s["sha256"] for s in e_samples} & m_hashes
print(f"  Benign-malware overlap: {len(b_poison)}")
print(f"  EXE-malware overlap:    {len(e_poison)}")
if e_poison:
    print(f"  Removing {len(e_poison)} poisoned EXE samples...")
    e_samples = [s for s in e_samples if s["sha256"] not in m_hashes]

# Merge
print(f"\n[5] Merging...")
merged = b_samples + e_samples
print(f"  Combined: {len(merged):,}")

# Extension distribution
print(f"\n[6] Extension distribution after merge:")
ext_count = Counter()
for s in merged:
    fname = (s.get("file_name") or "").lower()
    if s.get("extension"):
        ext_count[s["extension"]] += 1
    elif fname.endswith(".dll"):  ext_count[".dll"] += 1
    elif fname.endswith(".exe"):  ext_count[".exe"] += 1
    elif fname.endswith(".sys"):  ext_count[".sys"] += 1
    else:                         ext_count["other"] += 1

for ext, c in ext_count.most_common():
    pct = 100 * c / len(merged)
    bar = "#" * int(pct / 2)
    print(f"  {ext:<8} {c:>6,} ({pct:>5.1f}%) {bar}")

exe_pct = 100 * ext_count.get(".exe", 0) / len(merged)
print(f"\n  EXE percentage: {exe_pct:.1f}%", end="")
if exe_pct >= 18:
    print(" (GOOD - shortcut significantly reduced)")
elif exe_pct >= 13:
    print(" (ACCEPTABLE - some improvement)")
else:
    print(" (STILL LOW)")

# Feature quality
print(f"\n[7] Feature quality (first 2000)...")
mat = np.array([s["features"] for s in merged[:2000]], dtype=np.float32)
print(f"  Shape:    {mat.shape}")
print(f"  NaN:      {int(np.isnan(mat).sum())}")
print(f"  Inf:      {int(np.isinf(mat).sum())}")
print(f"  Sparsity: {100*(mat==0).sum()/mat.size:.1f}%")
print(f"  Min:      {mat.min():.2f}")
print(f"  Max:      {mat.max():.2f}")

# Save
print(f"\n[8] Saving merged file...")
from datetime import datetime
output = {
    "created_at":    datetime.now().isoformat(),
    "lief_version":  b_lief,
    "feature_version": 2,
    "feature_dim":   2381,
    "total_samples": len(merged),
    "label_meaning": "0 = benign",
    "sources": {
        "original_benign": len(b_samples),
        "exe_only_added":  len(e_samples),
    },
    "samples": merged,
}

with open(MERGED_FILE, "w") as f:
    json.dump(output, f)

size_mb = MERGED_FILE.stat().st_size / (1024**2)
print(f"  Saved: {MERGED_FILE.name} ({size_mb:.1f} MB)")

print(f"\n{'='*70}")
print(f"SUMMARY")
print(f"{'='*70}")
print(f"  Benign original: {len(b_samples):,}")
print(f"  EXE added:       {len(e_samples):,}")
print(f"  TOTAL benign:    {len(merged):,}")
print(f"  EXE percentage:  {exe_pct:.1f}%")
print(f"  Malware total:   {len(malware['samples']):,}")
print(f"  Grand total:     {len(merged) + len(malware['samples']):,}")