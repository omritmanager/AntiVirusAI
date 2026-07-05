"""
Validate modern_benign_features.json received from teammate.
Checks versions, data quality, and compatibility with our pipeline.
"""

import json
import sys
import numpy as np
from pathlib import Path
from collections import Counter
sys.stdout.reconfigure(encoding='utf-8') # <--- הוסף את השורה הזו
BENIGN_FILE = Path(r"C:\Users\omri9\Desktop\School\Final Project\data\datasets\modern_benign_features.json")

REQUIRED = {
    "lief_version":    "0.17.6",
    "feature_dim":     2381,
    "label":           0,        # all benign
}

def main():
    print("=" * 70)
    print("TEAMMATE BENIGN DATASET VALIDATION")
    print("=" * 70)

    issues   = []
    warnings = []

    # ── 1. File exists ──────────────────────────────────────────────────
    print("\n[1] File check...")
    if not BENIGN_FILE.exists():
        print(f"    FATAL: file not found at {BENIGN_FILE}")
        sys.exit(1)
    size_mb = BENIGN_FILE.stat().st_size / (1024**2)
    print(f"    Path: {BENIGN_FILE}")
    print(f"    Size: {size_mb:.1f} MB")
    print(f"    OK")

    # ── 2. Load ──────────────────────────────────────────────────────────
    print("\n[2] Loading JSON...")
    with open(BENIGN_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    print(f"    OK")

    # ── 3. Metadata ──────────────────────────────────────────────────────
    print("\n[3] Metadata check...")
    lief_ver    = data.get("lief_version", "MISSING")
    feature_dim = data.get("feature_dim",  0)
    total       = data.get("total_samples", 0)

    print(f"    LIEF version:   {lief_ver}")
    print(f"    Feature dim:    {feature_dim}")
    print(f"    Total samples:  {total:,}")

    if not lief_ver.startswith(REQUIRED["lief_version"]):
        issues.append(
            f"LIEF version mismatch: got '{lief_ver}', need '{REQUIRED['lief_version']}'\n"
            f"    This is CRITICAL — features extracted with a different LIEF version\n"
            f"    are incompatible with our model. The teammate must re-extract."
        )
    else:
        print(f"    LIEF version: MATCH (0.17.6)")

    if feature_dim != REQUIRED["feature_dim"]:
        issues.append(f"Feature dim mismatch: got {feature_dim}, need {REQUIRED['feature_dim']}")
    else:
        print(f"    Feature dim: MATCH (2381)")

    # ── 4. Samples ───────────────────────────────────────────────────────
    print("\n[4] Sample-level checks...")
    samples = data.get("samples", [])
    if not samples:
        print("    FATAL: no samples in file")
        sys.exit(1)
    print(f"    Sample count: {len(samples):,}")

    # All target = 0?
    targets = Counter(s.get("target") for s in samples)
    print(f"    Labels: {dict(targets)}")
    if any(t != 0 for t in targets):
        issues.append(f"Non-benign labels found: {dict(targets)} — should be all 0")

    # Unique SHA-256
    hashes = [s.get("sha256", s.get("file_name", "")) for s in samples]
    unique = len(set(hashes))
    print(f"    Unique samples: {unique:,}")
    if unique != len(samples):
        warnings.append(f"{len(samples) - unique} duplicates found (will be removed at merge)")

    # Correct feature vector length
    wrong_dim = sum(1 for s in samples if len(s.get("features", [])) != 2381)
    print(f"    Wrong-dim vectors: {wrong_dim}")
    if wrong_dim > 0:
        issues.append(f"{wrong_dim} samples have wrong feature vector length")

    # ── 5. Feature quality ───────────────────────────────────────────────
    print("\n[5] Feature quality (first 2000 samples)...")
    check_n = min(2000, len(samples))
    matrix  = np.array([s["features"] for s in samples[:check_n]], dtype=np.float32)

    nan_count = int(np.isnan(matrix).sum())
    inf_count = int(np.isinf(matrix).sum())
    sparsity  = 100 * (matrix == 0).sum() / matrix.size
    val_min   = float(matrix.min())
    val_max   = float(matrix.max())
    val_mean  = float(matrix.mean())

    print(f"    NaN count:  {nan_count}")
    print(f"    Inf count:  {inf_count}")
    print(f"    Min value:  {val_min:.2f}")
    print(f"    Max value:  {val_max:.2f}")
    print(f"    Mean value: {val_mean:.4f}")
    print(f"    Sparsity:   {sparsity:.1f}%")

    if nan_count > 0:
        issues.append(f"{nan_count} NaN values in features")
    if inf_count > 0:
        issues.append(f"{inf_count} Inf values in features")
    if sparsity < 30 or sparsity > 95:
        warnings.append(f"Unusual sparsity: {sparsity:.1f}% (expected 50-80%)")

    # ── 6. Cross-check with our existing data ────────────────────────────
    print("\n[6] Cross-check: compare first sample to our extraction...")
    print("    Extracting features from notepad.exe with our LIEF 0.17.6...")

    import lief as lief_lib
    for attr in ['bad_format','bad_file','pe_error','parser_error',
                 'read_out_of_bound','not_found']:
        if not hasattr(lief_lib, attr):
            setattr(lief_lib, attr, type(attr, (Exception,), {}))

    if not hasattr(np, 'int'):    np.int = int
    if not hasattr(np, 'bool'):   np.bool = bool
    if not hasattr(np, 'float'):  np.float = float
    if not hasattr(np, 'object'): np.object = object

    from ember import PEFeatureExtractor
    extractor = PEFeatureExtractor(feature_version=2)

    import os
    test_paths = [
        r"C:\Windows\System32\notepad.exe",
        r"C:\Windows\notepad.exe",
    ]
    test_file = next((p for p in test_paths if os.path.exists(p)), None)

    if test_file:
        with open(test_file, "rb") as f:
            raw = f.read()
        our_features = extractor.feature_vector(raw)
        print(f"    Our first 5 values:      {our_features[:5]}")

        # Find a sample in the benign file that might match notepad
        # (won't match exactly — different files — but sparsity should be similar)
        their_sample = np.array(samples[0]["features"], dtype=np.float32)
        our_sparsity  = 100 * (our_features == 0).sum() / len(our_features)
        their_sparsity = 100 * (their_sample == 0).sum() / len(their_sample)
        print(f"    Their first sample name: {samples[0].get('file_name', 'unknown')}")
        print(f"    Their first 5 values:    {their_sample[:5]}")
        print(f"    Our sparsity:   {our_sparsity:.1f}%")
        print(f"    Their sparsity: {their_sparsity:.1f}%")

        if abs(our_sparsity - their_sparsity) > 25:
            warnings.append(
                f"Large sparsity difference: ours={our_sparsity:.1f}%, "
                f"theirs={their_sparsity:.1f}%. "
                f"May indicate LIEF version mismatch despite same version string."
            )
        else:
            print(f"    Sparsity difference: {abs(our_sparsity - their_sparsity):.1f}% — OK")
    else:
        print(f"    SKIPPED — notepad.exe not found")

    # ── 7. Source diversity ──────────────────────────────────────────────
    print("\n[7] Source diversity check...")
    source_dirs = Counter()
    for s in samples:
        fname = s.get("file_name", "")
        # Guess category by filename patterns
        fname_lower = fname.lower()
        if any(x in fname_lower for x in ["chrome", "firefox", "edge", "brave", "opera"]):
            source_dirs["Browser"] += 1
        elif any(x in fname_lower for x in ["discord", "slack", "teams", "zoom", "whatsapp"]):
            source_dirs["Communication"] += 1
        elif any(x in fname_lower for x in ["python", "node", "git", "docker", "rust", "golang"]):
            source_dirs["Dev Tools"] += 1
        elif any(x in fname_lower for x in ["steam", "unity", "unreal", "nvidia"]):
            source_dirs["Gaming"] += 1
        elif any(x in fname_lower for x in ["adobe", "obs", "blender", "vlc", "audacity"]):
            source_dirs["Creative"] += 1
        elif any(x in fname_lower for x in ["notepad", "7zip", "winrar", "putty", "filezilla"]):
            source_dirs["Utilities"] += 1
        else:
            source_dirs["System/Other"] += 1

    for src, count in source_dirs.most_common():
        pct = 100 * count / len(samples)
        bar = "█" * int(pct / 2)
        print(f"    {src:<20} {count:>6,} ({pct:>4.1f}%) {bar}")

    if source_dirs.get("System/Other", 0) / len(samples) > 0.90:
        warnings.append(
            "Over 90% of samples are System/Other — "
            "possible lack of diversity (only system files collected)"
        )

    # ── 8. Summary ───────────────────────────────────────────────────────
    print("\n" + "=" * 70)

    if issues:
        print("VALIDATION FAILED")
        print("=" * 70)
        print(f"\n{len(issues)} CRITICAL ISSUE(S):")
        for i, issue in enumerate(issues, 1):
            print(f"\n  {i}. {issue}")
        print("\nDo NOT use this file for training until issues are fixed.")
        print("Contact teammate with the specific errors above.")

    elif warnings:
        print("VALIDATION PASSED WITH WARNINGS")
        print("=" * 70)
        print(f"\n{len(warnings)} WARNING(S):")
        for w in warnings:
            print(f"  - {w}")
        print("\nThe file is usable but review the warnings.")
        print(f"Ready to merge: {BENIGN_FILE.name} ({size_mb:.1f} MB, {len(samples):,} samples)")

    else:
        print("ALL CHECKS PASSED")
        print("=" * 70)
        print(f"\n  File:     {BENIGN_FILE.name}")
        print(f"  Size:     {size_mb:.1f} MB")
        print(f"  Samples:  {len(samples):,}")
        print(f"  LIEF:     {lief_ver}")
        print(f"  Dim:      {feature_dim}")
        print(f"  NaN/Inf:  0")
        print(f"\nReady for Phase 6: Merge Dataset")


if __name__ == "__main__":
    main()