"""
scan_folder_v7.py — Standalone folder scanner using the V7 model.

Uses the EXACT validated inference pipeline:
  - LIEF 0.17.6 + patched EMBER (FeatureHasher double-bracket)
  - Temporal feature zeroing (10 indices)
  - LightGBM threshold = 0.40
  - Isolation Forest as second-opinion (POTENTIAL_ZERODAY tier)

Usage:
  python scan_folder_v7.py "C:\\path\\to\\folder"
"""
import sys
import os
import pickle
import json
import numpy as np
from pathlib import Path
from collections import Counter

# ── Compatibility shims (same as training) ──────────────────────
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

# ── Config ───────────────────────────────────────────────────────
ROOT   = Path(r"C:\Users\me\Desktop\school\Final Project")
MODELS = ROOT / "models" / "v7"

LGBM_PATH = MODELS / "lgbm_v7_correct.pkl"
IF_PATH   = MODELS / "isolation_forest.pkl"

# Same temporal indices zeroed in Phase 7
TEMPORAL_INDICES = [1557, 1558, 1599, 1602, 1609, 1610, 1612, 1613, 1616, 1617]

# Load thresholds from disk if available, else defaults
LGBM_THRESHOLD = 0.40
IF_THRESHOLD   = 0.3694358641837102
try:
    with open(MODELS / "thresholds.json") as f:
        t = json.load(f)
        LGBM_THRESHOLD = t.get("recommended", LGBM_THRESHOLD)
    with open(MODELS / "if_config.json") as f:
        IF_THRESHOLD = json.load(f).get("anomaly_threshold", IF_THRESHOLD)
except Exception:
    pass

VALID_EXT = {".exe", ".dll", ".sys", ".scr", ".com", ".ocx", ".cpl", ".drv"}

# ── Load models ──────────────────────────────────────────────────
print("=" * 60)
print("V7 FOLDER SCANNER")
print("=" * 60)
print(f"LIEF: {lief.__version__}")

with open(LGBM_PATH, "rb") as f:
    lgbm = pickle.load(f)
print(f"Loaded: {LGBM_PATH.name}")

iso = None
if IF_PATH.exists():
    with open(IF_PATH, "rb") as f:
        iso = pickle.load(f)
    print(f"Loaded: {IF_PATH.name}")

print(f"LightGBM threshold: {LGBM_THRESHOLD}")
print(f"IF threshold:       {IF_THRESHOLD}")

extractor = PEFeatureExtractor(feature_version=2)

# ── Scan logic ───────────────────────────────────────────────────
def classify_file(filepath):
    """
    Returns: (verdict, lgbm_prob, if_flag)
    verdict in {MALWARE, POTENTIAL_ZERODAY, SAFE, ERROR}
    """
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        if len(data) < 100:
            return "ERROR", None, None

        vec = extractor.feature_vector(data)
        vec = np.array(vec, dtype=np.float32)
        if len(vec) != 2381 or np.isnan(vec).any() or np.isinf(vec).any():
            return "ERROR", None, None

        # Apply the SAME temporal zeroing as training
        vec[TEMPORAL_INDICES] = 0.0
        vec = vec.reshape(1, -1)

        # Layer 1: LightGBM
        lgbm_prob = float(lgbm.predict_proba(vec)[0, 1])
        if lgbm_prob >= LGBM_THRESHOLD:
            return "MALWARE", lgbm_prob, None

        # Layer 2: Isolation Forest (only on files LightGBM cleared)
        if iso is not None:
            if_score = float(-iso.score_samples(vec)[0])
            if if_score >= IF_THRESHOLD:
                return "POTENTIAL_ZERODAY", lgbm_prob, if_score

        return "SAFE", lgbm_prob, None

    except Exception as e:
        return "ERROR", None, None


def scan_folder(folder):
    folder = Path(folder)
    if not folder.exists():
        print(f"\nERROR: Folder not found: {folder}")
        return

    results = {"MALWARE": [], "POTENTIAL_ZERODAY": [], "SAFE": [], "ERROR": []}

    files = [f for f in folder.rglob("*")
             if f.is_file() and f.suffix.lower() in VALID_EXT]

    print(f"\nScanning {len(files)} files in {folder} ...\n")

    for i, fp in enumerate(files, 1):
        verdict, prob, if_flag = classify_file(fp)
        results[verdict].append({
            "file": fp.name,
            "path": str(fp),
            "lgbm_prob": prob,
            "if_score": if_flag,
        })
        # Live progress for flagged files
        if verdict == "MALWARE":
            print(f"  [{i:>4}] MALWARE          {fp.name:<45} p={prob:.3f}")
        elif verdict == "POTENTIAL_ZERODAY":
            print(f"  [{i:>4}] POTENTIAL_ZERODAY {fp.name:<45} if={if_flag:.3f}")

    # ── Summary ──────────────────────────────────────────────────
    valid = (len(results["MALWARE"]) + len(results["POTENTIAL_ZERODAY"])
             + len(results["SAFE"]))
    print("\n" + "=" * 60)
    print("SCAN RESULTS")
    print("=" * 60)
    print(f"Total valid PE files scanned: {valid}")
    print(f"  Known Malware (LightGBM):  {len(results['MALWARE'])}")
    print(f"  Potential Zero-Day (IF):   {len(results['POTENTIAL_ZERODAY'])}")
    print(f"  Safe / Clean:              {len(results['SAFE'])}")
    print(f"  Errors / unparseable:      {len(results['ERROR'])}")

    if valid > 0:
        flagged = len(results["MALWARE"]) + len(results["POTENTIAL_ZERODAY"])
        print(f"\n  Total flagged:  {100*flagged/valid:.2f}%")
        print(f"  Total safe:     {100*len(results['SAFE'])/valid:.2f}%")

    # Show probability distribution of SAFE files (diagnostic)
    if results["SAFE"]:
        safe_probs = [r["lgbm_prob"] for r in results["SAFE"]
                      if r["lgbm_prob"] is not None]
        if safe_probs:
            sp = np.array(safe_probs)
            print(f"\n  SAFE files LightGBM prob distribution:")
            print(f"    mean={sp.mean():.4f}  median={np.median(sp):.4f}")
            print(f"    p90={np.percentile(sp,90):.4f}  "
                  f"max={sp.max():.4f}")
            # How many are NEAR the threshold (borderline misses)?
            near = (sp >= 0.20).sum()
            print(f"    Files with prob in [0.20, {LGBM_THRESHOLD}): {near} "
                  f"(borderline — would flag at lower threshold)")

    # Save full results
    out = ROOT / "evaluation" / "folder_scan_results.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  Saved: {out}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scan_folder_v7.py \"C:\\path\\to\\folder\"")
        sys.exit(1)
    scan_folder(sys.argv[1])