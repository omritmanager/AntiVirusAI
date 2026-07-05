"""
Quick check: is the 100% accuracy real or leakage?
Test on held-out test set that was NEVER seen during training.
"""
import numpy as np
import pickle
from pathlib import Path
from sklearn.metrics import (
    f1_score, precision_score, recall_score,
    roc_auc_score, confusion_matrix
)

ROOT   = Path(r"C:\Users\omri9\Desktop\School\Final Project")
SPLITS = ROOT / "data" / "splits_clean"
MODELS = ROOT / "models" / "v7"

print("Loading model and test sets...")
with open(MODELS / "lgbm_v7.pkl", "rb") as f:
    model = pickle.load(f)

X_val   = np.load(SPLITS / "X_val.npy")
y_val   = np.load(SPLITS / "y_val.npy")
X_test  = np.load(SPLITS / "X_test_balanced.npy")
y_test  = np.load(SPLITS / "y_test_balanced.npy")
X_train = np.load(SPLITS / "X_train.npy")
y_train = np.load(SPLITS / "y_train.npy")

def evaluate(X, y, name):
    y_prob = model.predict_proba(X)[:, 1]
    y_pred = model.predict(X)
    cm = confusion_matrix(y, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    print(f"\n  {name}")
    print(f"    F1={f1_score(y,y_pred):.4f}  "
          f"Precision={precision_score(y,y_pred):.4f}  "
          f"Recall={recall_score(y,y_pred):.4f}")
    print(f"    ROC AUC={roc_auc_score(y,y_prob):.4f}  "
          f"FPR={fpr*100:.2f}%")
    print(f"    TP={tp:,} FP={fp:,} FN={fn:,} TN={tn:,}")
    return fpr

print("=" * 60)
print("LEAKAGE DIAGNOSIS")
print("=" * 60)

print("\n--- Sanity check: Train set (SHOULD be ~100%) ---")
fpr_train = evaluate(X_train, y_train, "TRAIN (seen in training)")

print("\n--- Key test: Val set ---")
fpr_val = evaluate(X_val, y_val, "VAL (used in final model training!)")

print("\n--- Real test: Test set (NEVER seen) ---")
fpr_test = evaluate(X_test, y_test, "TEST BALANCED (held-out)")

print("\n" + "=" * 60)
print("DIAGNOSIS")
print("=" * 60)

if fpr_val < 0.001 and fpr_test < 0.001:
    print("\n  Both val and test have near-zero FPR.")
    print("  The model genuinely learned well OR there is")
    print("  a structural shortcut (DLL/EXE or source feature).")
    print("  Need to check what features drive the predictions.")
elif fpr_val < 0.001 and fpr_test > 0.02:
    print("\n  VAL: perfect  |  TEST: worse")
    print("  This is LEAKAGE. Final model was trained on val,")
    print("  so val results are meaningless.")
    print("  The test set results are the real performance.")
else:
    print(f"\n  VAL FPR: {fpr_val*100:.2f}%  TEST FPR: {fpr_test*100:.2f}%")
    print("  Investigate further.")