"""
Phase 8: Train LightGBM classifier with Optuna hyperparameter tuning.

Strategy:
- 30 Optuna trials on validation set
- Objective: maximize F1 (balances precision/recall)
- Final model trained on train+val after best params found
- All randomness seeded at 42
"""

import numpy as np
import json
import pickle
import lightgbm as lgb
import optuna
from pathlib import Path
from datetime import datetime
from sklearn.metrics import (
    f1_score, precision_score, recall_score,
    roc_auc_score, average_precision_score,
    confusion_matrix
)

optuna.logging.set_verbosity(optuna.logging.WARNING)

ROOT    = Path(r"C:\Users\omri9\Desktop\School\Final Project")
SPLITS  = ROOT / "data" / "splits_clean"
MODELS  = ROOT / "models" / "v7"
MODELS.mkdir(parents=True, exist_ok=True)

SEED        = 42
N_TRIALS    = 30
N_JOBS_LGB  = -1   # use all CPU cores

print("=" * 70)
print("PHASE 8: TRAIN LIGHTGBM")
print("=" * 70)
print(f"Seed:    {SEED}")
print(f"Trials:  {N_TRIALS}")
print(f"Time:    {datetime.now()}")

# ── Load splits ───────────────────────────────────────────────
print("\n[1] Loading splits...")
X_train = np.load(SPLITS / "X_train.npy")
y_train = np.load(SPLITS / "y_train.npy")
X_val   = np.load(SPLITS / "X_val.npy")
y_val   = np.load(SPLITS / "y_val.npy")

print(f"  Train: {X_train.shape}  malware={y_train.sum():,}  benign={(y_train==0).sum():,}")
print(f"  Val:   {X_val.shape}    malware={y_val.sum():,}    benign={(y_val==0).sum():,}")

# Class weight for imbalance
n_benign  = (y_train == 0).sum()
n_malware = (y_train == 1).sum()
scale_pos_weight = n_benign / n_malware
print(f"\n  scale_pos_weight (auto): {scale_pos_weight:.3f}")

# ── Optuna objective ──────────────────────────────────────────
def objective(trial):
    params = {
        "objective":        "binary",
        "metric":           "binary_logloss",
        "verbosity":        -1,
        "seed":             SEED,
        "n_jobs":           N_JOBS_LGB,
        "scale_pos_weight": scale_pos_weight,
        # Tuned by Optuna
        "n_estimators":     trial.suggest_int("n_estimators", 200, 1000),
        "learning_rate":    trial.suggest_float("learning_rate", 0.01, 0.2, log=True),
        "num_leaves":       trial.suggest_int("num_leaves", 31, 255),
        "max_depth":        trial.suggest_int("max_depth", 4, 12),
        "min_child_samples":trial.suggest_int("min_child_samples", 10, 100),
        "subsample":        trial.suggest_float("subsample", 0.5, 1.0),
        "colsample_bytree": trial.suggest_float("colsample_bytree", 0.5, 1.0),
        "reg_alpha":        trial.suggest_float("reg_alpha", 1e-8, 10.0, log=True),
        "reg_lambda":       trial.suggest_float("reg_lambda", 1e-8, 10.0, log=True),
    }
    
    model = lgb.LGBMClassifier(**params)
    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        callbacks=[lgb.early_stopping(50, verbose=False),
                   lgb.log_evaluation(-1)]
    )
    
    y_pred = model.predict(X_val)
    return f1_score(y_val, y_pred)


# ── Run Optuna ────────────────────────────────────────────────
print(f"\n[2] Optuna hyperparameter search ({N_TRIALS} trials)...")
print("    (This takes 30-60 minutes)")

study = optuna.create_study(
    direction="maximize",
    sampler=optuna.samplers.TPESampler(seed=SEED),
    study_name="lgbm_v7"
)

study.optimize(objective, n_trials=N_TRIALS, show_progress_bar=True)

best_params = study.best_params
best_f1     = study.best_value
print(f"\n  Best F1 on validation: {best_f1:.4f}")
print(f"  Best params:")
for k, v in best_params.items():
    print(f"    {k}: {v}")


# ── Train final model on train+val ────────────────────────────
print(f"\n[3] Training final model on train+val combined...")
X_trainval = np.vstack([X_train, X_val])
y_trainval = np.concatenate([y_train, y_val])
print(f"  Combined: {X_trainval.shape}  malware={y_trainval.sum():,}")

final_params = {
    "objective":        "binary",
    "metric":           "binary_logloss",
    "verbosity":        -1,
    "seed":             SEED,
    "n_jobs":           N_JOBS_LGB,
    "scale_pos_weight": scale_pos_weight,
    **best_params
}

final_model = lgb.LGBMClassifier(**final_params)
final_model.fit(X_trainval, y_trainval)
print("  Training complete")


# ── Evaluate on validation (to verify, not for tuning) ────────
print(f"\n[4] Evaluating on validation set...")

def evaluate(model, X, y, name, threshold=0.5):
    y_prob = model.predict_proba(X)[:, 1]
    y_pred = (y_prob >= threshold).astype(int)
    
    cm = confusion_matrix(y, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    metrics = {
        "f1":        float(f1_score(y, y_pred)),
        "precision": float(precision_score(y, y_pred)),
        "recall":    float(recall_score(y, y_pred)),
        "roc_auc":   float(roc_auc_score(y, y_prob)),
        "pr_auc":    float(average_precision_score(y, y_prob)),
        "fpr":       float(fp / (fp + tn)) if (fp + tn) > 0 else 0,
        "fnr":       float(fn / (fn + tp)) if (fn + tp) > 0 else 0,
        "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
    }
    
    print(f"\n  === {name} ===")
    print(f"  F1:        {metrics['f1']:.4f}")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall:    {metrics['recall']:.4f}")
    print(f"  ROC AUC:   {metrics['roc_auc']:.4f}")
    print(f"  PR AUC:    {metrics['pr_auc']:.4f}")
    print(f"  FPR:       {metrics['fpr']:.4f}  ({metrics['fpr']*100:.2f}%)")
    print(f"  FNR:       {metrics['fnr']:.4f}  ({metrics['fnr']*100:.2f}%)")
    print(f"  Confusion: TP={tp:,} FP={fp:,} FN={fn:,} TN={tn:,}")
    
    return metrics

val_metrics = evaluate(final_model, X_val, y_val, "VALIDATION SET")


# ── Find optimal threshold ────────────────────────────────────
print(f"\n[5] Finding optimal threshold (target FPR < 1%)...")
y_prob_val = final_model.predict_proba(X_val)[:, 1]

best_threshold = 0.5
best_threshold_f1 = 0.0
results_by_threshold = []

for thresh in np.arange(0.1, 0.95, 0.05):
    y_pred_t = (y_prob_val >= thresh).astype(int)
    f1  = f1_score(y_val, y_pred_t)
    cm  = confusion_matrix(y_val, y_pred_t)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    results_by_threshold.append((thresh, f1, fpr))

print(f"\n  {'Thresh':>8} {'F1':>8} {'FPR':>8}")
print(f"  {'-'*28}")
for thresh, f1, fpr in results_by_threshold:
    flag = " <-- recommended" if fpr < 0.01 and f1 > best_threshold_f1 else ""
    print(f"  {thresh:>8.2f} {f1:>8.4f} {fpr:>8.4f}{flag}")
    if fpr < 0.01 and f1 > best_threshold_f1:
        best_threshold_f1 = f1
        best_threshold = thresh

print(f"\n  Selected threshold: {best_threshold:.2f}")
print(f"  F1 at threshold:    {best_threshold_f1:.4f}")


# ── Save model + metadata ─────────────────────────────────────
print(f"\n[6] Saving model...")
model_path = MODELS / "lgbm_v7.pkl"
with open(model_path, "wb") as f:
    pickle.dump(final_model, f)
print(f"  Saved: {model_path}")

# Save thresholds
thresholds = {
    "default":     0.5,
    "low_fpr":     float(best_threshold),
    "description": {
        "default":  "Standard threshold, balanced precision/recall",
        "low_fpr":  f"FPR<1% threshold — use in production to minimize false positives",
    }
}
with open(MODELS / "thresholds.json", "w") as f:
    json.dump(thresholds, f, indent=2)

# Save full results
results = {
    "created_at":     datetime.now().isoformat(),
    "seed":           SEED,
    "n_optuna_trials": N_TRIALS,
    "best_val_f1":    best_f1,
    "best_params":    best_params,
    "final_params":   final_params,
    "thresholds":     thresholds,
    "val_metrics":    val_metrics,
}
with open(MODELS / "training_results.json", "w") as f:
    json.dump(results, f, indent=2)

# ── Final summary ─────────────────────────────────────────────
print(f"\n{'='*70}")
print("PHASE 8 COMPLETE")
print(f"{'='*70}")
print(f"\n  Model saved:       {model_path.name}")
print(f"  Optuna best F1:    {best_f1:.4f}")
print(f"  Val F1:            {val_metrics['f1']:.4f}")
print(f"  Val ROC AUC:       {val_metrics['roc_auc']:.4f}")
print(f"  Val FPR:           {val_metrics['fpr']*100:.2f}%")
print(f"  Optimal threshold: {best_threshold:.2f} (FPR<1%)")
print(f"\nNext: Phase 9 - Train Isolation Forest")
print(f"      python src\\training\\v7\\phase9_train_isolation_forest.py")