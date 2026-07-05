"""
Phase 10b: Find the optimal LightGBM threshold properly.
Then re-evaluate hybrid with corrected threshold.
"""

import numpy as np
import pickle
import json
from pathlib import Path
from datetime import datetime
from sklearn.metrics import (
    f1_score, precision_score, recall_score,
    roc_auc_score, average_precision_score,
    confusion_matrix, roc_curve, precision_recall_curve
)

ROOT   = Path(r"C:\Users\omri9\Desktop\School\Final Project")
SPLITS = ROOT / "data" / "splits_clean"
MODELS = ROOT / "models" / "v7"
EVAL   = ROOT / "evaluation"

print("=" * 70)
print("PHASE 10b: THRESHOLD ANALYSIS + FINAL EVALUATION")
print("=" * 70)

# Load
with open(MODELS / "lgbm_v7.pkl", "rb") as f:
    lgbm = pickle.load(f)
with open(MODELS / "isolation_forest.pkl", "rb") as f:
    iso = pickle.load(f)
with open(MODELS / "if_config.json") as f:
    if_config = json.load(f)

X_val  = np.load(SPLITS / "X_val.npy")
y_val  = np.load(SPLITS / "y_val.npy")
X_test = np.load(SPLITS / "X_test_balanced.npy")
y_test = np.load(SPLITS / "y_test_balanced.npy")
X_imb  = np.load(SPLITS / "X_test_imbalanced.npy")
y_imb  = np.load(SPLITS / "y_test_imbalanced.npy")

# ── 1. Proper threshold selection on VAL set ──────────────────
print("\n[1] Threshold analysis on VALIDATION set")
print("    Goal: maximize F1 while keeping FPR < 1%")

y_prob_val = lgbm.predict_proba(X_val)[:, 1]

print(f"\n  {'Threshold':>10} {'F1':>8} {'Prec':>8} {'Recall':>8} "
      f"{'FPR':>8} {'FNR':>8}")
print(f"  {'-'*55}")

best_f1_threshold = 0.5
best_f1_score     = 0.0
best_lowfpr_threshold = 0.5
best_lowfpr_f1        = 0.0

threshold_results = []
for t in np.arange(0.05, 0.96, 0.05):
    pred = (y_prob_val >= t).astype(int)
    cm   = confusion_matrix(y_val, pred)
    tn, fp, fn, tp = cm.ravel()
    f1   = f1_score(y_val, pred, zero_division=0)
    prec = precision_score(y_val, pred, zero_division=0)
    rec  = recall_score(y_val, pred, zero_division=0)
    fpr  = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr  = fn / (fn + tp) if (fn + tp) > 0 else 0
    
    threshold_results.append({
        "threshold": float(t),
        "f1": float(f1), "precision": float(prec),
        "recall": float(rec), "fpr": float(fpr), "fnr": float(fnr)
    })
    
    flag = ""
    if f1 > best_f1_score:
        best_f1_score = f1
        best_f1_threshold = t
    if fpr < 0.01 and f1 > best_lowfpr_f1:
        best_lowfpr_f1 = f1
        best_lowfpr_threshold = t
        flag = " <- best (FPR<1%)"
    
    print(f"  {t:>10.2f} {f1:>8.4f} {prec:>8.4f} {rec:>8.4f} "
          f"{fpr*100:>7.2f}% {fnr*100:>7.2f}%{flag}")

print(f"\n  Best F1 threshold:       {best_f1_threshold:.2f} "
      f"(F1={best_f1_score:.4f})")
print(f"  Best FPR<1% threshold:   {best_lowfpr_threshold:.2f} "
      f"(F1={best_lowfpr_f1:.4f})")

# ── 2. Evaluate with correct thresholds on test sets ─────────
print(f"\n[2] Final evaluation with corrected thresholds")

def evaluate_model(X, y, lgbm_t, if_t, test_name):
    lgbm_prob = lgbm.predict_proba(X)[:, 1]
    lgbm_pred = (lgbm_prob >= lgbm_t).astype(int)
    
    if_scores = -iso.score_samples(X)
    if_pred   = (if_scores >= if_t).astype(int)
    
    hybrid_pred = ((lgbm_pred == 1) | (if_pred == 1)).astype(int)
    
    def metrics(y_true, y_pred, prob=None):
        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = cm.ravel()
        fpr = fp/(fp+tn) if (fp+tn)>0 else 0
        fnr = fn/(fn+tp) if (fn+tp)>0 else 0
        m = {
            "f1":        float(f1_score(y_true, y_pred, zero_division=0)),
            "precision": float(precision_score(y_true, y_pred, zero_division=0)),
            "recall":    float(recall_score(y_true, y_pred, zero_division=0)),
            "fpr":       float(fpr), "fnr": float(fnr),
            "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
        }
        if prob is not None:
            try:
                m["roc_auc"] = float(roc_auc_score(y_true, prob))
                m["pr_auc"]  = float(average_precision_score(y_true, prob))
            except Exception:
                pass
        return m
    
    m_lgbm   = metrics(y, lgbm_pred,   lgbm_prob)
    m_if     = metrics(y, if_pred,     if_scores)
    m_hybrid = metrics(y, hybrid_pred, lgbm_prob)
    
    # What does IF add?
    lgbm_missed        = (lgbm_pred == 0) & (y == 1)
    if_rescued         = lgbm_missed & (if_pred == 1)
    zeroday_rescue_pct = 100 * if_rescued.sum() / max(lgbm_missed.sum(), 1)
    
    print(f"\n  {'─'*60}")
    print(f"  {test_name}")
    print(f"  {'─'*60}")
    print(f"  {'Model':<20} {'F1':>7} {'Prec':>7} {'Rec':>7} "
          f"{'FPR':>7} {'FNR':>7} {'ROC':>7}")
    
    for mname, m in [("LightGBM", m_lgbm),
                      ("IsolationForest", m_if),
                      ("Hybrid", m_hybrid)]:
        roc = f"{m.get('roc_auc',0):.4f}" if 'roc_auc' in m else "  ---  "
        print(f"  {mname:<20} {m['f1']:>7.4f} {m['precision']:>7.4f} "
              f"{m['recall']:>7.4f} {m['fpr']*100:>6.2f}% "
              f"{m['fnr']*100:>6.2f}% {roc:>7}")
    
    print(f"\n  Malware missed by LightGBM: {lgbm_missed.sum():,}")
    print(f"  Rescued by IF:              {if_rescued.sum():,} "
          f"({zeroday_rescue_pct:.1f}% of missed)")
    print(f"  FP cost of adding IF:       "
          f"+{m_hybrid['fp'] - m_lgbm['fp']:,} extra false positives")
    
    return m_lgbm, m_if, m_hybrid


r_bal  = evaluate_model(X_test, y_test, best_lowfpr_threshold,
                         if_config["anomaly_threshold"], "TEST BALANCED")
r_imb  = evaluate_model(X_imb,  y_imb,  best_lowfpr_threshold,
                         if_config["anomaly_threshold"], "TEST IMBALANCED")

# ── 3. ROC curve data ─────────────────────────────────────────
print(f"\n[3] ROC curve data (for plotting later)...")
y_prob_test = lgbm.predict_proba(X_test)[:, 1]
fpr_roc, tpr_roc, thresh_roc = roc_curve(y_test, y_prob_test)
roc_auc = roc_auc_score(y_test, y_prob_test)
print(f"  LightGBM ROC AUC: {roc_auc:.4f}")

np.save(EVAL / "roc_fpr.npy",    fpr_roc)
np.save(EVAL / "roc_tpr.npy",    tpr_roc)
np.save(EVAL / "roc_thresh.npy", thresh_roc)
print(f"  Saved ROC curve data")

# ── 4. Update thresholds file ─────────────────────────────────
updated_thresholds = {
    "lgbm_best_f1":   float(best_f1_threshold),
    "lgbm_low_fpr":   float(best_lowfpr_threshold),
    "if_threshold":   if_config["anomaly_threshold"],
    "recommended":    float(best_lowfpr_threshold),
    "description": {
        "lgbm_best_f1": f"Maximizes F1 (F1={best_f1_score:.4f})",
        "lgbm_low_fpr": f"Best F1 while FPR<1% (F1={best_lowfpr_f1:.4f})",
        "recommended":  "Use this in production — minimizes false positives",
    }
}
with open(MODELS / "thresholds.json", "w") as f:
    json.dump(updated_thresholds, f, indent=2)
print(f"\n  Updated: thresholds.json")
print(f"  Recommended LightGBM threshold: {best_lowfpr_threshold:.2f}")

# ── Final academic summary ────────────────────────────────────
print(f"\n{'='*70}")
print("ACADEMIC RESULTS SUMMARY")
print(f"{'='*70}")

m_lgbm, m_if, m_hybrid = r_bal
print(f"""
  Model Architecture: LightGBM (supervised) + Isolation Forest (anomaly)
  Dataset: 81,011 modern PE files (2022-2026)
  Test set: 12,153 samples (4,850 benign / 7,303 malware)

  PRIMARY MODEL — LightGBM:
    F1:        {m_lgbm['f1']:.4f}
    Precision: {m_lgbm['precision']:.4f}
    Recall:    {m_lgbm['recall']:.4f}  ({m_lgbm['recall']*100:.1f}% malware detected)
    ROC AUC:   {m_lgbm.get('roc_auc', 0):.4f}
    FPR:       {m_lgbm['fpr']*100:.2f}%  ({m_lgbm['fp']:,} false positives)
    FNR:       {m_lgbm['fnr']*100:.2f}%  ({m_lgbm['fn']:,} missed malware)

  ANOMALY LAYER — Isolation Forest:
    Detection on IF alone: {m_if['recall']*100:.1f}%
    FPR on IF alone:       {m_if['fpr']*100:.2f}%
    Note: IF adds limited value as standalone detector on this dataset.
          Best used as a second opinion for borderline cases.

  KEY FINDING:
    For this dataset, LightGBM alone achieves near-optimal performance.
    The hybrid approach does not significantly improve detection.
    This is a valid research finding — not all hybrid systems outperform
    their components. The anomaly detector may add more value on
    truly novel zero-day samples not present in this test set.
""")

print(f"Next: Phase 11 - Sanity check on real system files")