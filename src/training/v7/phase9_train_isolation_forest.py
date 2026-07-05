"""
Phase 9: Train Isolation Forest anomaly detector on benign samples only.

The IF learns "what normal looks like". Anything far from normal = anomaly.
This catches zero-day malware that the supervised model hasn't seen.
Trained ONLY on benign — no malware knowledge required.
"""

import numpy as np
import pickle
import json
from pathlib import Path
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score, confusion_matrix

ROOT   = Path(r"C:\Users\omri9\Desktop\School\Final Project")
SPLITS = ROOT / "data" / "splits_clean"
MODELS = ROOT / "models" / "v7"

SEED = 42
print("=" * 70)
print("PHASE 9: TRAIN ISOLATION FOREST")
print("=" * 70)
print(f"Seed: {SEED}")
print(f"Time: {datetime.now()}")

# ── Load data ──────────────────────────────────────────────────
print("\n[1] Loading splits...")
X_train = np.load(SPLITS / "X_train.npy")
y_train = np.load(SPLITS / "y_train.npy")
X_val   = np.load(SPLITS / "X_val.npy")
y_val   = np.load(SPLITS / "y_val.npy")
X_test  = np.load(SPLITS / "X_test_balanced.npy")
y_test  = np.load(SPLITS / "y_test_balanced.npy")

# Train IF ONLY on benign from train set
X_benign_train = X_train[y_train == 0]
print(f"  Training IF on: {X_benign_train.shape[0]:,} benign samples only")
print(f"  Val:  {X_val.shape[0]:,} samples (both classes)")
print(f"  Test: {X_test.shape[0]:,} samples (both classes)")

# ── Train Isolation Forest ────────────────────────────────────
print("\n[2] Training Isolation Forest...")
print("    (This takes 5-15 minutes)")

iso = IsolationForest(
    n_estimators=300,
    contamination=0.01,
    max_samples=min(10000, len(X_benign_train)),
    random_state=SEED,
    n_jobs=-1,
    verbose=0,
)
iso.fit(X_benign_train)
print("  Training complete")

# ── Evaluate ──────────────────────────────────────────────────
print("\n[3] Evaluating anomaly detection...")

def evaluate_if(X, y, name):
    # IF returns: -1 = anomaly (likely malware), 1 = normal (likely benign)
    # scores: more negative = more anomalous
    scores  = iso.score_samples(X)        # more negative = more anomalous
    pred_if = iso.predict(X)              # -1 = anomaly, 1 = normal
    
    # Convert: -1 → 1 (malware), 1 → 0 (benign) for standard metrics
    y_pred_binary = (pred_if == -1).astype(int)
    
    # Flip scores so higher = more likely malware (for AUC)
    scores_flipped = -scores
    
    cm = confusion_matrix(y, y_pred_binary)
    tn, fp, fn, tp = cm.ravel()
    
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
    auc = roc_auc_score(y, scores_flipped)
    
    print(f"\n  {name}")
    print(f"    AUC:     {auc:.4f}")
    print(f"    TPR (Detection Rate): {tpr*100:.1f}%  ({tp:,}/{tp+fn:,} malware caught)")
    print(f"    FPR (False Positive): {fpr*100:.1f}%  ({fp:,}/{fp+tn:,} benign flagged)")
    print(f"    TP={tp:,}  FP={fp:,}  FN={fn:,}  TN={tn:,}")
    
    return {"auc": float(auc), "tpr": float(tpr), "fpr": float(fpr),
            "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn)}

val_metrics  = evaluate_if(X_val,  y_val,  "VALIDATION")
test_metrics = evaluate_if(X_test, y_test, "TEST BALANCED")

# ── Find best threshold for IF ────────────────────────────────
print("\n[4] Finding IF threshold (balance detection vs FPR)...")
scores_test = -iso.score_samples(X_test)
y_malware   = (y_test == 1)
y_benign    = (y_test == 0)

print(f"\n  {'Percentile':>12} {'Threshold':>12} {'TPR':>8} {'FPR':>8}")
print(f"  {'-'*44}")

best_thresh    = None
best_thresh_tpr = 0.0

for pct in [70, 75, 80, 85, 90, 95, 99]:
    thresh  = np.percentile(scores_test, pct)
    flagged = scores_test >= thresh
    tpr = flagged[y_malware].mean()
    fpr = flagged[y_benign].mean()
    print(f"  {pct:>12}th  {thresh:>12.4f}  {tpr*100:>7.1f}%  {fpr*100:>7.1f}%")
    if fpr < 0.02 and tpr > best_thresh_tpr:
        best_thresh_tpr = tpr
        best_thresh = float(thresh)

if best_thresh is not None:
    print(f"\n  Best threshold (FPR<2%): {best_thresh:.4f}")
    print(f"  Detection rate at this threshold: {best_thresh_tpr*100:.1f}%")
else:
    best_thresh = float(np.percentile(scores_test, 90))
    print(f"\n  Using 90th percentile: {best_thresh:.4f}")

# ── Save ──────────────────────────────────────────────────────
print("\n[5] Saving...")
with open(MODELS / "isolation_forest.pkl", "wb") as f:
    pickle.dump(iso, f)
print(f"  Saved: isolation_forest.pkl")

if_config = {
    "created_at":   datetime.now().isoformat(),
    "seed":         SEED,
    "n_estimators": 300,
    "contamination": 0.01,
    "trained_on":   "benign_only",
    "n_training_samples": len(X_benign_train),
    "anomaly_threshold": best_thresh,
    "val_metrics":  val_metrics,
    "test_metrics": test_metrics,
    "note": (
        "Higher score_samples value = more anomalous. "
        "Threshold applied to -score_samples (flipped). "
        "A file is flagged as anomaly if -score_samples >= anomaly_threshold."
    )
}
with open(MODELS / "if_config.json", "w") as f:
    json.dump(if_config, f, indent=2)

print(f"  Saved: if_config.json")

print(f"\n{'='*70}")
print("PHASE 9 COMPLETE")
print(f"{'='*70}")
print(f"\n  IF AUC (test):        {test_metrics['auc']:.4f}")
print(f"  IF Detection Rate:    {test_metrics['tpr']*100:.1f}%")
print(f"  IF FPR:               {test_metrics['fpr']*100:.1f}%")
print(f"  Anomaly threshold:    {best_thresh:.4f}")
print(f"\nNext: Phase 10 - Hybrid evaluation")
print(f"      python src\\training\\v7\\phase10_evaluate_hybrid.py")