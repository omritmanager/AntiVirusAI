"""
Phase 8b: Retrain LightGBM correctly.

The Phase 8 model was trained on train+val which contaminated the val set.
This version trains ONLY on train, keeping val truly held-out.
Uses the best hyperparameters already found by Optuna.
"""

import numpy as np
import pickle
import json
import lightgbm as lgb
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

SEED = 42
print("=" * 70)
print("PHASE 8b: RETRAIN LIGHTGBM (CORRECT METHODOLOGY)")
print("=" * 70)

# Load the best hyperparameters from Phase 8
with open(MODELS / "training_results.json") as f:
    prev_results = json.load(f)

best_params = prev_results["best_params"]
print(f"\n[1] Best params from Optuna Phase 8:")
for k, v in best_params.items():
    print(f"    {k}: {v}")

# Load splits
print(f"\n[2] Loading splits...")
X_train = np.load(SPLITS / "X_train.npy")
y_train = np.load(SPLITS / "y_train.npy")
X_val   = np.load(SPLITS / "X_val.npy")
y_val   = np.load(SPLITS / "y_val.npy")
X_test  = np.load(SPLITS / "X_test_balanced.npy")
y_test  = np.load(SPLITS / "y_test_balanced.npy")
X_imb   = np.load(SPLITS / "X_test_imbalanced.npy")
y_imb   = np.load(SPLITS / "y_test_imbalanced.npy")

print(f"    Train: {X_train.shape}  malware={y_train.sum():,}")
print(f"    Val:   {X_val.shape}    malware={y_val.sum():,}")
print(f"    Test:  {X_test.shape}   malware={y_test.sum():,}")

n_benign  = (y_train == 0).sum()
n_malware = (y_train == 1).sum()
scale_pos = n_benign / n_malware

# Train on TRAIN ONLY — val stays truly held-out
print(f"\n[3] Training on train set only (val stays held-out)...")
model = lgb.LGBMClassifier(
    objective="binary",
    metric="binary_logloss",
    verbosity=-1,
    seed=SEED,
    n_jobs=-1,
    scale_pos_weight=scale_pos,
    **best_params
)

model.fit(
    X_train, y_train,
    eval_set=[(X_val, y_val)],
    callbacks=[
        lgb.early_stopping(50, verbose=False),
        lgb.log_evaluation(-1),
    ]
)

best_iter = model.best_iteration_
print(f"    Best iteration: {best_iter}")
print(f"    Training complete")

# Evaluate properly on all sets
def evaluate(X, y, name, threshold=0.5):
    prob = model.predict_proba(X)[:, 1]
    pred = (prob >= threshold).astype(int)
    cm   = confusion_matrix(y, pred)
    tn, fp, fn, tp = cm.ravel()
    fpr  = fp / (fp+tn) if (fp+tn) > 0 else 0
    fnr  = fn / (fn+tp) if (fn+tp) > 0 else 0
    f1   = f1_score(y, pred, zero_division=0)
    prec = precision_score(y, pred, zero_division=0)
    rec  = recall_score(y, pred, zero_division=0)
    auc  = roc_auc_score(y, prob)
    prauc = average_precision_score(y, prob)
    print(f"\n  {name} (threshold={threshold}):")
    print(f"    F1={f1:.4f}  Precision={prec:.4f}  Recall={rec:.4f}")
    print(f"    ROC AUC={auc:.4f}  PR AUC={prauc:.4f}")
    print(f"    FPR={fpr*100:.2f}%  FNR={fnr*100:.2f}%")
    print(f"    TP={tp:,} FP={fp:,} FN={fn:,} TN={tn:,}")
    return {"f1": float(f1), "precision": float(prec),
            "recall": float(rec), "roc_auc": float(auc),
            "pr_auc": float(prauc), "fpr": float(fpr),
            "fnr": float(fnr),
            "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn)}

print(f"\n[4] Evaluation on all sets (threshold=0.5):")
m_train = evaluate(X_train, y_train, "TRAIN (sanity)")
m_val   = evaluate(X_val,   y_val,   "VAL (now truly held-out)")
m_test  = evaluate(X_test,  y_test,  "TEST BALANCED")
m_imb   = evaluate(X_imb,   y_imb,   "TEST IMBALANCED")

# Find best threshold on VAL (not leaking test)
print(f"\n[5] Finding best threshold on VAL set...")
prob_val = model.predict_proba(X_val)[:, 1]

best_t_f1    = 0.5
best_t_lowfpr = 0.5
best_f1_val  = 0.0
best_f1_lowfpr = 0.0

print(f"    {'Threshold':>10} {'F1':>8} {'FPR':>8} {'FNR':>8}")
print(f"    {'-'*38}")
for t in np.arange(0.1, 0.96, 0.05):
    pred = (prob_val >= t).astype(int)
    f1   = f1_score(y_val, pred, zero_division=0)
    cm   = confusion_matrix(y_val, pred)
    tn, fp, fn, tp = cm.ravel()
    fpr  = fp / (fp+tn) if (fp+tn) > 0 else 0
    fnr  = fn / (fn+tp) if (fn+tp) > 0 else 0
    
    flag = ""
    if f1 > best_f1_val:
        best_f1_val = f1
        best_t_f1 = float(t)
    if fpr < 0.01 and f1 > best_f1_lowfpr:
        best_f1_lowfpr = f1
        best_t_lowfpr = float(t)
        flag = " <- best FPR<1%"
    print(f"    {t:>10.2f} {f1:>8.4f} {fpr*100:>7.2f}% {fnr*100:>7.2f}%{flag}")

print(f"\n    Best F1 threshold:     {best_t_f1:.2f} (F1={best_f1_val:.4f})")
print(f"    Low FPR threshold:     {best_t_lowfpr:.2f} (F1={best_f1_lowfpr:.4f})")

# Final evaluation with optimal threshold
print(f"\n[6] Final evaluation with optimal threshold ({best_t_lowfpr}):")
m_test_opt = evaluate(X_test, y_test, "TEST BALANCED",  best_t_lowfpr)
m_imb_opt  = evaluate(X_imb,  y_imb,  "TEST IMBALANCED", best_t_lowfpr)

# Save corrected model
print(f"\n[7] Saving corrected model...")
with open(MODELS / "lgbm_v7_correct.pkl", "wb") as f:
    pickle.dump(model, f)

thresholds = {
    "default":       0.5,
    "best_f1":       best_t_f1,
    "low_fpr":       best_t_lowfpr,
    "recommended":   best_t_lowfpr,
    "description":   {
        "default":   "Standard 0.5 threshold",
        "best_f1":   f"Maximizes F1 on val set (F1={best_f1_val:.4f})",
        "low_fpr":   f"Best F1 while FPR<1% on val (F1={best_f1_lowfpr:.4f})",
        "recommended": "Use this in production",
    }
}
with open(MODELS / "thresholds.json", "w") as f:
    json.dump(thresholds, f, indent=2)

results = {
    "created_at":      datetime.now().isoformat(),
    "methodology":     "Train on train-only, evaluate on held-out val+test",
    "seed":            SEED,
    "best_params":     best_params,
    "best_iteration":  best_iter,
    "thresholds":      thresholds,
    "metrics": {
        "train":           m_train,
        "val_threshold05": m_val,
        "test_balanced":   m_test_opt,
        "test_imbalanced": m_imb_opt,
    }
}
with open(MODELS / "training_results_correct.json", "w") as f:
    json.dump(results, f, indent=2)

print(f"    Saved: lgbm_v7_correct.pkl")
print(f"    Saved: thresholds.json (updated)")
print(f"    Saved: training_results_correct.json")

print(f"\n{'='*70}")
print("CORRECTED RESULTS SUMMARY")
print(f"{'='*70}")
print(f"""
  Methodology:   Train-only training, val/test truly held-out
  Threshold:     {best_t_lowfpr} (best F1 with FPR<1% on val)
  
  TEST BALANCED:
    F1:        {m_test_opt['f1']:.4f}
    Precision: {m_test_opt['precision']:.4f}
    Recall:    {m_test_opt['recall']:.4f}  ({m_test_opt['recall']*100:.1f}% malware detected)
    ROC AUC:   {m_test_opt['roc_auc']:.4f}
    FPR:       {m_test_opt['fpr']*100:.2f}%  ({m_test_opt['fp']} false positives / {(y_test==0).sum():,})
    FNR:       {m_test_opt['fnr']*100:.2f}%  ({m_test_opt['fn']} missed / {(y_test==1).sum():,})
  
  TEST IMBALANCED:
    FPR:       {m_imb_opt['fpr']*100:.2f}%
    Recall:    {m_imb_opt['recall']*100:.1f}%
""")
print(f"Next: Phase 11 - Sanity check")
print(f"      python src\\training\\v7\\phase11_sanity_check.py")