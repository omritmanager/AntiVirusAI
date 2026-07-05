"""
Phase 10: Full hybrid model evaluation.

Combines LightGBM (supervised) + Isolation Forest (anomaly detection).
Tests on ALL test sets and produces the academic comparison table.
"""

import numpy as np
import pickle
import json
from pathlib import Path
from datetime import datetime
from sklearn.metrics import (
    f1_score, precision_score, recall_score,
    roc_auc_score, average_precision_score,
    confusion_matrix
)

ROOT   = Path(r"C:\Users\omri9\Desktop\School\Final Project")
SPLITS = ROOT / "data" / "splits_clean"
MODELS = ROOT / "models" / "v7"
EVAL   = ROOT / "evaluation"
EVAL.mkdir(parents=True, exist_ok=True)

SEED = 42
print("=" * 70)
print("PHASE 10: HYBRID MODEL EVALUATION")
print("=" * 70)
print(f"Time: {datetime.now()}")

# â”€â”€ Load models â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
print("\n[1] Loading models...")
with open(MODELS / "lgbm_v7.pkl", "rb") as f:
    lgbm = pickle.load(f)
with open(MODELS / "isolation_forest.pkl", "rb") as f:
    iso_forest = pickle.load(f)
with open(MODELS / "if_config.json") as f:
    if_config = json.load(f)
with open(MODELS / "thresholds.json") as f:
    thresholds = json.load(f)

lgbm_threshold = thresholds.get("low_fpr", 0.5)
if_threshold   = if_config["anomaly_threshold"]

print(f"  LightGBM threshold: {lgbm_threshold}")
print(f"  IF threshold:       {if_threshold}")

# â”€â”€ Load test sets â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
print("\n[2] Loading test sets...")
test_sets = {}
for name, fname in [
    ("test_balanced",   "X_test_balanced.npy"),
    ("test_imbalanced", "X_test_imbalanced.npy"),
]:
    X = np.load(SPLITS / fname)
    y = np.load(SPLITS / fname.replace("X_", "y_"))
    test_sets[name] = (X, y)
    print(f"  {name:<22}: {X.shape} "
          f"benign={(y==0).sum():,} malware={(y==1).sum():,}")

# â”€â”€ Decision functions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def predict_lgbm(X, threshold):
    prob = lgbm.predict_proba(X)[:, 1]
    return prob, (prob >= threshold).astype(int)

def predict_if(X, threshold):
    scores = -iso_forest.score_samples(X)   # higher = more anomalous
    return scores, (scores >= threshold).astype(int)

def predict_hybrid(X, lgbm_thresh, if_thresh):
    lgbm_prob, lgbm_pred = predict_lgbm(X, lgbm_thresh)
    if_scores, if_pred   = predict_if(X, if_thresh)
    
    # Tier logic:
    # MALWARE:           supervised says malware  (high confidence)
    # POTENTIAL_ZERODAY: supervised says benign BUT anomaly detector flags it
    # SAFE:              both say benign
    # SUSPICIOUS:        mixed signals at boundary
    
    tier = np.where(
        lgbm_pred == 1,           "MALWARE",
        np.where(
            if_pred == 1,         "POTENTIAL_ZERODAY",
                                  "SAFE"
        )
    )
    
    # For metrics: MALWARE + POTENTIAL_ZERODAY both count as "detected"
    hybrid_pred = ((lgbm_pred == 1) | (if_pred == 1)).astype(int)
    
    return hybrid_pred, tier, lgbm_prob, if_scores

# â”€â”€ Evaluation function â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def full_eval(X, y, model_name, y_pred, y_prob=None):
    cm = confusion_matrix(y, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    
    metrics = {
        "model":     model_name,
        "f1":        float(f1_score(y, y_pred, zero_division=0)),
        "precision": float(precision_score(y, y_pred, zero_division=0)),
        "recall":    float(recall_score(y, y_pred, zero_division=0)),
        "fpr":       float(fpr),
        "fnr":       float(fnr),
        "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
    }
    if y_prob is not None:
        try:
            metrics["roc_auc"] = float(roc_auc_score(y, y_prob))
            metrics["pr_auc"]  = float(average_precision_score(y, y_prob))
        except Exception:
            pass
    return metrics

# â”€â”€ Run evaluation on all test sets â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
print("\n[3] Evaluating all models on all test sets...")
all_results = {}

for test_name, (X, y) in test_sets.items():
    print(f"\n  {'='*60}")
    print(f"  Test set: {test_name}")
    print(f"  {'='*60}")
    
    results = []
    
    # LightGBM alone
    lgbm_prob, lgbm_pred = predict_lgbm(X, lgbm_threshold)
    m = full_eval(X, y, "LightGBM", lgbm_pred, lgbm_prob)
    results.append(m)
    print(f"\n  LightGBM (threshold={lgbm_threshold}):")
    print(f"    F1={m['f1']:.4f}  Precision={m['precision']:.4f}  "
          f"Recall={m['recall']:.4f}")
    print(f"    FPR={m['fpr']*100:.2f}%  FNR={m['fnr']*100:.2f}%")
    print(f"    TP={m['tp']:,} FP={m['fp']:,} FN={m['fn']:,} TN={m['tn']:,}")
    
    # Isolation Forest alone
    if_scores, if_pred = predict_if(X, if_threshold)
    m_if = full_eval(X, y, "IsolationForest", if_pred, if_scores)
    results.append(m_if)
    print(f"\n  Isolation Forest alone:")
    print(f"    F1={m_if['f1']:.4f}  Precision={m_if['precision']:.4f}  "
          f"Recall={m_if['recall']:.4f}")
    print(f"    FPR={m_if['fpr']*100:.2f}%  FNR={m_if['fnr']*100:.2f}%")
    print(f"    TP={m_if['tp']:,} FP={m_if['fp']:,} "
          f"FN={m_if['fn']:,} TN={m_if['tn']:,}")
    
    # Hybrid
    hybrid_pred, tiers, lgbm_prob2, if_scores2 = predict_hybrid(
        X, lgbm_threshold, if_threshold)
    m_hyb = full_eval(X, y, "Hybrid", hybrid_pred, lgbm_prob2)
    results.append(m_hyb)
    print(f"\n  Hybrid (LightGBM + IF):")
    print(f"    F1={m_hyb['f1']:.4f}  Precision={m_hyb['precision']:.4f}  "
          f"Recall={m_hyb['recall']:.4f}")
    print(f"    FPR={m_hyb['fpr']*100:.2f}%  FNR={m_hyb['fnr']*100:.2f}%")
    print(f"    TP={m_hyb['tp']:,} FP={m_hyb['fp']:,} "
          f"FN={m_hyb['fn']:,} TN={m_hyb['tn']:,}")
    
    # Tier distribution
    tier_counts = {}
    for t in tiers:
        tier_counts[t] = tier_counts.get(t, 0) + 1
    print(f"\n  Tier breakdown:")
    for tier, count in sorted(tier_counts.items()):
        pct = 100 * count / len(tiers)
        print(f"    {tier:<22}: {count:>6,} ({pct:>5.1f}%)")
    
    # Zero-day proxy: malware caught ONLY by IF (not by LightGBM)
    lgbm_missed = (lgbm_pred == 0) & (y == 1)
    if_caught_zeroday = (lgbm_missed) & (if_pred == 1)
    zd_additional = if_caught_zeroday.sum()
    zd_total = lgbm_missed.sum()
    print(f"\n  Zero-day proxy:")
    print(f"    Malware missed by LightGBM:     {zd_total:,}")
    print(f"    Of those, caught by IF:          {zd_additional:,}")
    if zd_total > 0:
        print(f"    IF zero-day recovery rate:       "
              f"{100*zd_additional/zd_total:.1f}%")
    
    all_results[test_name] = results

# â”€â”€ Summary table â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
print(f"\n\n{'='*70}")
print("FINAL COMPARISON TABLE")
print(f"{'='*70}")

for test_name, results in all_results.items():
    print(f"\n  {test_name.upper()}")
    print(f"  {'Model':<22} {'F1':>8} {'Prec':>8} {'Recall':>8} "
          f"{'FPR':>8} {'FNR':>8}")
    print(f"  {'-'*65}")
    for m in results:
        roc = f"{m.get('roc_auc', 0):.4f}" if 'roc_auc' in m else "  N/A  "
        print(f"  {m['model']:<22} {m['f1']:>8.4f} {m['precision']:>8.4f} "
              f"{m['recall']:>8.4f} {m['fpr']*100:>7.2f}% {m['fnr']*100:>7.2f}%")

# â”€â”€ Save results â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
report = {
    "created_at":    datetime.now().isoformat(),
    "lgbm_threshold": lgbm_threshold,
    "if_threshold":   if_threshold,
    "results":        {k: v for k, v in all_results.items()},
}
with open(EVAL / "phase10_results.json", "w") as f:
    json.dump(report, f, indent=2)
print(f"\n  Saved: evaluation/phase10_results.json")
print(f"\nNext: Phase 11 - Sanity check on real system files")
print(f"      python src\\training\\v7\\phase11_sanity_check.py")
