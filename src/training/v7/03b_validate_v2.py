"""
Validate the V2 feature file before sending to Omri.
"""

import os
import sys
import json
from pathlib import Path
from collections import Counter
import numpy as np

USERNAME = os.environ.get("USERNAME")
PROJECT_ROOT = Path(rf"C:\Users\{USERNAME}\Desktop\Final Project")
FEATURES_PATH = PROJECT_ROOT / "modern_benign_collected" / "features" / "modern_benign_features_v2.json"


def main():
    print("=" * 70)
    print("V2 DATASET VALIDATION")
    print("=" * 70)
    
    if not FEATURES_PATH.exists():
        print(f"FATAL: {FEATURES_PATH} not found")
        return
    
    print(f"Loading {FEATURES_PATH.name}...")
    with open(FEATURES_PATH, encoding="utf-8") as f:
        data = json.load(f)
    
    size_mb = FEATURES_PATH.stat().st_size / (1024**2)
    print(f"\nFile size:      {size_mb:.1f} MB")
    print(f"LIEF version:   {data.get('lief_version')}")
    print(f"Feature dim:    {data.get('feature_dim')}")
    print(f"Total samples:  {data.get('total_samples'):,}")
    
    samples = data["samples"]
    issues = []
    
    # 1. LIEF version
    if not data["lief_version"].startswith("0.17.6"):
        issues.append(f"Wrong LIEF: {data['lief_version']}")
    
    # 2. Dimensions
    if data["feature_dim"] != 2381:
        issues.append(f"Wrong dim: {data['feature_dim']}")
    
    # 3. Labels
    targets = Counter(s.get("target") for s in samples)
    print(f"\nLabels: {dict(targets)}")
    if list(targets.keys()) != [0]:
        issues.append(f"Bad labels: {dict(targets)}")
    
    # 4. Uniqueness
    hashes = set(s.get("sha256", "") for s in samples)
    print(f"Unique SHA-256: {len(hashes):,}")
    if len(hashes) != len(samples):
        issues.append(f"Duplicates: {len(samples) - len(hashes)}")
    
    # 5. Feature dim consistency
    wrong_dim = sum(1 for s in samples if len(s.get("features", [])) != 2381)
    if wrong_dim:
        issues.append(f"{wrong_dim} have wrong feature dim")
    
    # 6. NaN/Inf check
    print(f"\nFeature quality (first 2000):")
    sample_n = min(2000, len(samples))
    mat = np.array([s["features"] for s in samples[:sample_n]], dtype=np.float32)
    nan_count = int(np.isnan(mat).sum())
    inf_count = int(np.isinf(mat).sum())
    sparsity = 100 * (mat == 0).sum() / mat.size
    print(f"  NaN:      {nan_count}")
    print(f"  Inf:      {inf_count}")
    print(f"  Sparsity: {sparsity:.1f}%")
    if nan_count: issues.append("NaN values")
    if inf_count: issues.append("Inf values")
    
    # 7. Extension distribution (CRITICAL — must have more EXE now)
    print(f"\n--- Extension distribution ---")
    ext_counter = Counter(s.get("extension", "?") for s in samples)
    exe_count = ext_counter.get(".exe", 0)
    dll_count = ext_counter.get(".dll", 0)
    exe_pct = 100 * exe_count / len(samples)
    dll_pct = 100 * dll_count / len(samples)
    
    for ext, c in ext_counter.most_common():
        pct = 100 * c / len(samples)
        print(f"  {ext:<8} {c:>6,} ({pct:>5.1f}%)")
    
    print(f"\nEXE percentage: {exe_pct:.1f}%")
    if exe_pct < 15:
        issues.append(f"EXE only {exe_pct:.1f}% — still imbalanced (need >15%)")
    
    # 8. Category diversity (CRITICAL)
    print(f"\n--- Source category distribution ---")
    cat_counter = Counter(s.get("category", "Unknown") for s in samples)
    
    microsoft_categories = ["Windows System", "Microsoft Product", "Windows Other"]
    ms_count = sum(c for cat, c in cat_counter.items() if cat in microsoft_categories)
    ms_pct = 100 * ms_count / len(samples)
    
    for cat, c in cat_counter.most_common():
        pct = 100 * c / len(samples)
        bar = "#" * int(pct / 2)
        flag = " (Microsoft)" if cat in microsoft_categories else ""
        print(f"  {cat:<25} {c:>6,} ({pct:>5.1f}%) {bar}{flag}")
    
    print(f"\nMicrosoft total: {ms_pct:.1f}%")
    if ms_pct > 80:
        issues.append(f"Microsoft still {ms_pct:.1f}% — need more non-MS software")
    
    # Final summary
    print("\n" + "=" * 70)
    if issues:
        print("VALIDATION FAILED:")
        for i, issue in enumerate(issues, 1):
            print(f"  {i}. {issue}")
        print("\nDo not send to Omri yet.")
    else:
        print("ALL CHECKS PASSED")
        print(f"\nReady to send to Omri:")
        print(f"  File: {FEATURES_PATH}")
        print(f"  Size: {size_mb:.1f} MB")
        print(f"  Samples: {len(samples):,}")
        print(f"  EXE: {exe_pct:.1f}%  |  DLL: {dll_pct:.1f}%")
        print(f"  Non-Microsoft: {100-ms_pct:.1f}%")


if __name__ == "__main__":
    main()