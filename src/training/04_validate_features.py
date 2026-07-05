"""
Validate modern_malware_features.json before transferring to main PC.
"""
import json
import numpy as np
from pathlib import Path

MALWARE_FILE = Path(r"C:\Users\omri9\Downloads\modern_benign_features_dedup(3).json")

def main():
    print("=" * 70)
    print("MALWARE DATASET VALIDATION")
    print("=" * 70)
    
    if not MALWARE_FILE.exists():
        print(f"FATAL: {MALWARE_FILE} not found")
        return
    
    size_mb = MALWARE_FILE.stat().st_size / (1024**2)
    print(f"\nFile: {MALWARE_FILE.name}")
    print(f"Size: {size_mb:.1f} MB")
    
    print("\nLoading...")
    with open(MALWARE_FILE) as f:
        data = json.load(f)
    
    lief_ver = data.get("lief_version", "MISSING")
    feat_dim = data.get("feature_dim", 0)
    samples  = data.get("samples", [])
    
    print(f"\nMetadata:")
    print(f"  LIEF:     {lief_ver}")
    print(f"  Feat dim: {feat_dim}")
    print(f"  Samples:  {len(samples):,}")
    
    if not lief_ver.startswith("0.17.6"):
        print(f"\n  ERROR: LIEF mismatch (need 0.17.6)")
        return
    
    if feat_dim != 2381:
        print(f"\n  ERROR: Feature dim should be 2381")
        return
    
    # Check labels
    labels = [s.get("target") for s in samples]
    if not all(l == 1 for l in labels):
        print(f"\n  ERROR: Not all labels are 1 (malware)")
        return
    
    # Check dimensions
    wrong = sum(1 for s in samples if len(s.get("features", [])) != 2381)
    if wrong > 0:
        print(f"\n  ERROR: {wrong} samples with wrong dimension")
        return
    
    # Check quality
    print(f"\nQuality check (first 2000 samples)...")
    check_n = min(2000, len(samples))
    matrix = np.array([s["features"] for s in samples[:check_n]], dtype=np.float32)
    
    nan_count = int(np.isnan(matrix).sum())
    inf_count = int(np.isinf(matrix).sum())
    sparsity  = 100 * (matrix == 0).sum() / matrix.size
    
    print(f"  NaN:      {nan_count}")
    print(f"  Inf:      {inf_count}")
    print(f"  Sparsity: {sparsity:.1f}%")
    
    if nan_count > 0 or inf_count > 0:
        print(f"\n  ERROR: Found NaN/Inf values")
        return
    
    # Check duplicates
    hashes = [s.get("sha256", "") for s in samples]
    unique = len(set(hashes))
    dupes  = len(samples) - unique
    
    print(f"\nUnique samples: {unique:,}")
    if dupes > 0:
        print(f"  Duplicates: {dupes} (will be removed at merge)")
    
    print("\n" + "=" * 70)
    print("VALIDATION PASSED")
    print("=" * 70)
    print(f"\nReady to transfer:")
    print(f"  File:    {MALWARE_FILE.name}")
    print(f"  Size:    {size_mb:.1f} MB")
    print(f"  Samples: {len(samples):,}")
    print(f"\nDo NOT transfer the raw EXE files — only this JSON.")

if __name__ == "__main__":
    main()