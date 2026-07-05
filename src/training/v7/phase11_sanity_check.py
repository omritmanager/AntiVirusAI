"""
Phase 11: Sanity check on real system files.
Tests the model on files it has NEVER seen in training.
These are files from the live system — the ultimate real-world test.

V6 failed catastrophically here (90%+ FPR on System32).
V7 should pass with <1% FPR.
"""

import os
import sys
import pickle
import json
import numpy as np
from pathlib import Path
from datetime import datetime
from collections import Counter

# Version gate
import lief
for a in ['bad_format','bad_file','pe_error','parser_error',
          'read_out_of_bound','not_found']:
    if not hasattr(lief, a):
        setattr(lief, a, type(a, (Exception,), {}))

if not hasattr(np, 'int'):    np.int = int
if not hasattr(np, 'bool'):   np.bool = bool
if not hasattr(np, 'float'):  np.float = float
if not hasattr(np, 'object'): np.object = object

from ember import PEFeatureExtractor

ROOT   = Path(r"C:\Users\omri9\Desktop\School\Final Project")
MODELS = ROOT / "models" / "v7"
EVAL   = ROOT / "evaluation"
EVAL.mkdir(parents=True, exist_ok=True)

SEED = 42
print("=" * 70)
print("PHASE 11: SANITY CHECK ON REAL SYSTEM FILES")
print("=" * 70)
print(f"LIEF: {lief.__version__}")

# Load model + config
with open(MODELS / "lgbm_v7_correct.pkl", "rb") as f:
    model = pickle.load(f)
with open(MODELS / "thresholds.json") as f:
    thresholds = json.load(f)

THRESHOLD = thresholds["recommended"]
print(f"Model: lgbm_v7_correct.pkl")
print(f"Threshold: {THRESHOLD}")

# Temporal features to zero (same as Phase 7)
TEMPORAL_INDICES = [
    1557, 1558, 1599, 1602,
    1609, 1610, 1612, 1613, 1616, 1617
]

extractor = PEFeatureExtractor(feature_version=2)

def extract_and_predict(filepath):
    """Extract features and return prediction for one file."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        if len(data) < 100:
            return None, None, None
        vec = extractor.feature_vector(data)
        if vec is None or len(vec) != 2381:
            return None, None, None
        if np.isnan(vec).any() or np.isinf(vec).any():
            return None, None, None
        # Apply Phase 7 zeroing
        vec[TEMPORAL_INDICES] = 0.0
        prob = model.predict_proba(vec.reshape(1, -1))[0, 1]
        pred = int(prob >= THRESHOLD)
        return prob, pred, vec
    except Exception:
        return None, None, None

def scan_directory(dir_path, label, max_files=1000, extensions=None):
    """Scan directory and return results."""
    if extensions is None:
        extensions = {".exe", ".dll", ".sys"}
    
    dir_path = Path(dir_path)
    if not dir_path.exists():
        print(f"  SKIP (not found): {dir_path}")
        return {}
    
    results = {"total": 0, "extracted": 0, "flagged": 0, "safe": 0,
               "flagged_files": [], "probs": []}
    count = 0
    
    for filepath in dir_path.rglob("*"):
        if count >= max_files:
            break
        try:
            if not filepath.is_file():
                continue
            if filepath.suffix.lower() not in extensions:
                continue
            
            prob, pred, _ = extract_and_predict(filepath)
            results["total"] += 1
            
            if prob is None:
                continue
            
            results["extracted"] += 1
            results["probs"].append(float(prob))
            
            if pred == 1:
                results["flagged"] += 1
                results["flagged_files"].append({
                    "path": str(filepath),
                    "prob": float(prob)
                })
            else:
                results["safe"] += 1
            
            count += 1
        except Exception:
            continue
    
    fpr = results["flagged"] / max(results["extracted"], 1) * 100
    print(f"\n  {label}")
    print(f"    Files scanned:   {results['extracted']:,}")
    print(f"    Flagged:         {results['flagged']:,} ({fpr:.2f}%)")
    print(f"    Safe:            {results['safe']:,}")
    
    if results["flagged_files"]:
        print(f"    Flagged files (top 5):")
        for f in sorted(results["flagged_files"],
                        key=lambda x: x["prob"], reverse=True)[:5]:
            fname = Path(f["path"]).name
            print(f"      {fname:<50} prob={f['prob']:.3f}")
    
    if results["probs"]:
        probs = np.array(results["probs"])
        print(f"    Probability stats: "
              f"mean={probs.mean():.3f}  "
              f"p95={np.percentile(probs,95):.3f}  "
              f"max={probs.max():.3f}")
    
    results["fpr_pct"] = fpr
    return results

# ── Scan directories ──────────────────────────────────────────
print("\n" + "=" * 70)
print("[1] KNOWN BENIGN DIRECTORIES")
print("    V6 failed here. V7 should show <1% FPR.")
print("=" * 70)

all_results = {}

# Critical directories
scan_targets = [
    (r"C:\Windows\System32",    "Windows System32",  2000),
    (r"C:\Windows\SysWOW64",    "Windows SysWOW64",  1000),
]

# Optional: installed apps
optional_dirs = [
    (r"C:\Program Files\Git",           "Git"),
    (r"C:\Program Files\7-Zip",         "7-Zip"),
    (r"C:\Program Files\Mozilla Firefox","Firefox"),
    (r"C:\Program Files\Google\Chrome", "Google Chrome"),
    (r"C:\Program Files (x86)\Steam",   "Steam"),
]
for path, name, *_ in optional_dirs:
    if Path(path).exists():
        scan_targets.append((path, name, 500))

for dir_path, label, max_f in scan_targets:
    r = scan_directory(dir_path, label, max_files=max_f)
    all_results[label] = r

# Overall FPR across all benign dirs
print("\n" + "=" * 70)
print("[2] AGGREGATE RESULTS ON BENIGN DIRECTORIES")
print("=" * 70)

total_extracted = sum(r.get("extracted", 0) for r in all_results.values())
total_flagged   = sum(r.get("flagged", 0) for r in all_results.values())
overall_fpr = 100 * total_flagged / max(total_extracted, 1)

print(f"\n  Total files scanned: {total_extracted:,}")
print(f"  Total flagged:       {total_flagged:,}")
print(f"  Overall FPR:         {overall_fpr:.2f}%")

print(f"\n  {'Directory':<30} {'Scanned':>9} {'Flagged':>9} {'FPR':>8}")
print(f"  {'-'*60}")
for label, r in all_results.items():
    if r.get("extracted", 0) > 0:
        fpr = r["fpr_pct"]
        flag = ""
        if fpr > 5:   flag = "  *** HIGH ***"
        elif fpr > 1: flag = "  * elevated"
        print(f"  {label:<30} {r['extracted']:>9,} "
              f"{r['flagged']:>9,} {fpr:>7.2f}%{flag}")

# Verdict
print(f"\n{'='*70}")
print("VERDICT")
print(f"{'='*70}")
if overall_fpr < 0.5:
    print(f"\n  EXCELLENT: {overall_fpr:.2f}% FPR on system files.")
    print(f"  V7 completely avoids V6's catastrophic false positive problem.")
elif overall_fpr < 1.0:
    print(f"\n  GOOD: {overall_fpr:.2f}% FPR on system files.")
    print(f"  Well within acceptable range for static antivirus.")
elif overall_fpr < 3.0:
    print(f"\n  ACCEPTABLE: {overall_fpr:.2f}% FPR.")
    print(f"  Better than V6 (>90%) but some false positives exist.")
else:
    print(f"\n  CONCERN: {overall_fpr:.2f}% FPR.")
    print(f"  Investigate the flagged files.")

# Save results
report = {
    "created_at":    datetime.now().isoformat(),
    "threshold":     THRESHOLD,
    "total_scanned": total_extracted,
    "total_flagged": total_flagged,
    "overall_fpr":   overall_fpr,
    "by_directory":  {k: {
        "scanned": v.get("extracted", 0),
        "flagged": v.get("flagged", 0),
        "fpr_pct": v.get("fpr_pct", 0),
        "flagged_files": v.get("flagged_files", [])[:10],
    } for k, v in all_results.items()},
}
with open(EVAL / "phase11_sanity_check.json", "w") as f:
    json.dump(report, f, indent=2)

print(f"\n  Saved: evaluation/phase11_sanity_check.json")
print(f"\nNext: Phase 12 - Zero-day test")
print(f"      python src\\training\\v7\\phase12_zeroday_test.py")