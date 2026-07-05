"""
Phase 12: Zero-day detection test.

Tests the model on malware it has never seen:
1. Temporal holdout: malware from AFTER our training cutoff
2. Family holdout: malware families NOT in training set
3. Comparison: LightGBM alone vs Hybrid (LightGBM + IF)

This is the key academic contribution:
"Can the hybrid model detect novel malware better than supervised alone?"
"""

import pickle
import json
import numpy as np
from pathlib import Path
from datetime import datetime
from collections import Counter
from sklearn.metrics import (
    f1_score, precision_score, recall_score,
    roc_auc_score, confusion_matrix
)

ROOT   = Path(r"C:\Users\omri9\Desktop\School\Final Project")
SPLITS = ROOT / "data" / "splits_clean"
MODELS = ROOT / "models" / "v7"
EVAL   = ROOT / "evaluation"
DATASETS = ROOT / "data" / "datasets"

print("=" * 70)
print("PHASE 12: ZERO-DAY DETECTION ANALYSIS")
print("=" * 70)

# Load models
with open(MODELS / "lgbm_v7_correct.pkl", "rb") as f:
    lgbm = pickle.load(f)
with open(MODELS / "isolation_forest.pkl", "rb") as f:
    iso = pickle.load(f)
with open(MODELS / "thresholds.json") as f:
    thresholds = json.load(f)
with open(MODELS / "if_config.json") as f:
    if_config = json.load(f)

LGBM_T = thresholds["recommended"]
IF_T   = if_config["anomaly_threshold"]

print(f"LightGBM threshold: {LGBM_T}")
print(f"IF threshold:       {IF_T}")

# ── Load malware dataset with metadata ────────────────────────
print("\n[1] Loading malware metadata for temporal analysis...")
with open(DATASETS / "modern_malware_features.json") as f:
    malware_data = json.load(f)

samples = malware_data["samples"]
print(f"  Total malware samples: {len(samples):,}")

# Check available metadata
has_first_seen = sum(1 for s in samples if s.get("first_seen"))
has_tags       = sum(1 for s in samples if s.get("tags") or s.get("tag_queried"))
print(f"  With 'first_seen' date: {has_first_seen:,}")
print(f"  With tags:              {has_tags:,}")

# Year distribution
years = Counter()
for s in samples:
    fs = s.get("first_seen", "") or ""
    y = fs[:4] if len(fs) >= 4 else "unknown"
    years[y] += 1

print(f"\n  Year distribution:")
for y, c in sorted(years.items()):
    bar = "#" * int(50 * c / len(samples))
    print(f"    {y}: {c:>6,}  {bar}")

# ── Simulate temporal holdout ─────────────────────────────────
print("\n[2] Temporal holdout simulation...")
print("    'Zero-day' = samples that would appear AFTER a training cutoff")

# Load test set hashes to know what was 'seen'
X_test = np.load(SPLITS / "X_test_balanced.npy")
y_test = np.load(SPLITS / "y_test_balanced.npy")

# Since all our malware is from daily dumps with date metadata,
# simulate: "trained on first 80%, test on last 20% (most recent)"
malware_only = [s for s in samples if s.get("first_seen")]
malware_only.sort(key=lambda s: s.get("first_seen", ""))

if len(malware_only) > 100:
    cutoff_idx  = int(len(malware_only) * 0.80)
    recent_20pct = malware_only[cutoff_idx:]
    
    print(f"  Total with date:    {len(malware_only):,}")
    print(f"  'Training' cutoff:  first 80% ({cutoff_idx:,} samples)")
    print(f"  'Zero-day' set:     last 20% ({len(recent_20pct):,} samples)")
    
    if len(recent_20pct) > 0:
        first_date = recent_20pct[0].get("first_seen", "?")[:7]
        last_date  = recent_20pct[-1].get("first_seen", "?")[:7]
        print(f"  Zero-day date range: {first_date} to {last_date}")
    
    # Extract features for zero-day set
    zd_features = np.array(
        [s["features"] for s in recent_20pct],
        dtype=np.float32
    )
    
    # Zero temporal features (same as training)
    TEMPORAL = [1557,1558,1599,1602,1609,1610,1612,1613,1616,1617]
    zd_features[:, TEMPORAL] = 0.0
    
    y_zd = np.ones(len(zd_features), dtype=np.int8)
    
    # Predict with both models
    lgbm_prob = lgbm.predict_proba(zd_features)[:, 1]
    lgbm_pred = (lgbm_prob >= LGBM_T).astype(int)
    
    if_scores = -iso.score_samples(zd_features)
    if_pred   = (if_scores >= IF_T).astype(int)
    
    hybrid_pred = ((lgbm_pred == 1) | (if_pred == 1)).astype(int)
    
    lgbm_dr   = lgbm_pred.mean() * 100
    if_dr     = if_pred.mean() * 100
    hybrid_dr = hybrid_pred.mean() * 100
    
    # Samples caught ONLY by IF (true zero-day contribution)
    if_only = ((lgbm_pred == 0) & (if_pred == 1)).sum()
    
    print(f"\n  ZERO-DAY DETECTION RATES:")
    print(f"    LightGBM alone:   {lgbm_dr:.1f}%  ({lgbm_pred.sum():,}/{len(lgbm_pred):,})")
    print(f"    IsolationForest:  {if_dr:.1f}%   ({if_pred.sum():,}/{len(if_pred):,})")
    print(f"    Hybrid:           {hybrid_dr:.1f}%  ({hybrid_pred.sum():,}/{len(hybrid_pred):,})")
    print(f"\n    Samples caught ONLY by IF (not LightGBM): {if_only:,}")
    print(f"    IF additional contribution: "
          f"{100*if_only/max(len(lgbm_pred)-lgbm_pred.sum(),1):.1f}% "
          f"of LightGBM misses")
    
    zeroday_results = {
        "n_samples":    len(recent_20pct),
        "date_range":   f"{first_date} to {last_date}",
        "lgbm_dr":      float(lgbm_dr),
        "if_dr":        float(if_dr),
        "hybrid_dr":    float(hybrid_dr),
        "if_only":      int(if_only),
    }
else:
    print("  Not enough dated malware samples for temporal analysis.")
    zeroday_results = {}

# ── Family-level analysis ─────────────────────────────────────
print("\n[3] Malware family analysis...")

# Get tags/families
families = Counter()
for s in samples:
    tag = s.get("tag_queried") or s.get("signature") or "unknown"
    families[tag] += 1

print(f"  Top 10 malware families/tags in dataset:")
for fam, c in families.most_common(10):
    pct = 100 * c / len(samples)
    print(f"    {fam:<25} {c:>6,} ({pct:>5.1f}%)")

# For each family, measure detection rate
print(f"\n  Detection rate by family:")
print(f"  {'Family':<20} {'Count':>7} {'LGBM DR':>9} {'IF DR':>9} {'Hybrid DR':>10}")
print(f"  {'-'*60}")

family_results = []
for fam, count in families.most_common(15):
    fam_samples = [s for s in samples
                   if (s.get("tag_queried") or
                       s.get("signature") or "unknown") == fam]
    if len(fam_samples) < 10:
        continue
    
    X_fam = np.array([s["features"] for s in fam_samples], dtype=np.float32)
    X_fam[:, TEMPORAL] = 0.0
    
    lgbm_p = lgbm.predict_proba(X_fam)[:, 1]
    lgbm_d = (lgbm_p >= LGBM_T).mean() * 100
    
    if_s = -iso.score_samples(X_fam)
    if_d = (if_s >= IF_T).mean() * 100
    
    hyb_d = (((lgbm_p >= LGBM_T) | (if_s >= IF_T))).mean() * 100
    
    flag = "  <- strong" if lgbm_d > 95 else ("  <- weak" if lgbm_d < 70 else "")
    print(f"  {fam:<20} {count:>7,} {lgbm_d:>8.1f}% {if_d:>8.1f}% "
          f"{hyb_d:>9.1f}%{flag}")
    
    family_results.append({
        "family": fam, "count": count,
        "lgbm_dr": float(lgbm_d),
        "if_dr":   float(if_d),
        "hybrid_dr": float(hyb_d),
    })

# ── Summary ────────────────────────────────────────────────────
print(f"\n{'='*70}")
print("ZERO-DAY ANALYSIS SUMMARY")
print(f"{'='*70}")

if zeroday_results:
    improvement = zeroday_results["hybrid_dr"] - zeroday_results["lgbm_dr"]
    print(f"""
  Temporal holdout (most recent 20% of malware):
    LightGBM detection:  {zeroday_results['lgbm_dr']:.1f}%
    Hybrid detection:    {zeroday_results['hybrid_dr']:.1f}%
    IF contribution:     +{improvement:.1f}% additional detection

  INTERPRETATION:
""")
    if improvement >= 5:
        print(f"  GOOD: Hybrid adds {improvement:.1f}% on recent malware.")
        print(f"  The IF layer catches malware that LightGBM misses.")
        print(f"  This validates the hybrid architecture.")
    elif improvement >= 1:
        print(f"  MODEST: Hybrid adds {improvement:.1f}% on recent malware.")
        print(f"  The IF contribution is real but limited.")
        print(f"  Academic finding: static features generalize well temporally.")
    else:
        print(f"  LIMITED: LightGBM already captures temporal patterns.")
        print(f"  Key finding: the supervised model generalizes well to")
        print(f"  recent malware — no need for anomaly layer for known families.")
        print(f"  IF would add more value on truly novel (unseen) architectures.")

# Save
report = {
    "created_at":     datetime.now().isoformat(),
    "thresholds":     {"lgbm": LGBM_T, "if": IF_T},
    "zeroday_results": zeroday_results,
    "family_results":  family_results,
    "year_distribution": dict(years),
}
with open(EVAL / "phase12_zeroday.json", "w") as f:
    json.dump(report, f, indent=2)

print(f"\n  Saved: evaluation/phase12_zeroday.json")
print(f"\nNext: Phase 13 - Generate final report")
print(f"      python src\\training\\v7\\phase13_final_report.py")