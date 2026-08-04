"""
Phase 8c: Retrain LightGBM on the benign-augmented dataset (candidate only).

Mirrors phase8b_retrain_correct.py EXACTLY — same Optuna-tuned hyperparameters
(from training_results_correct.json), same train-only methodology (val stays
genuinely held out, matching the leakage fix phase8b already applied), same
scale_pos_weight recomputation. The ONLY difference is the input data: the
augmented X_train/y_val produced by src/augmentation/split_new_benign.py
(new benign samples appended, official test sets untouched).

Hyperparameters are reused rather than re-tuned so this experiment answers
one question — "did more/better benign data help?" — without also changing
the hyperparameters, which would confound the comparison.

Saves ONLY to models/v7/lgbm_v7_correct_candidate.pkl. The production
lgbm_v7_correct.pkl is never touched by this script — a swap is a separate,
explicit, human-approved action after src/validation/validate_candidate_v7.py
passes every gate.
"""

import numpy as np
import pickle
import json
import argparse
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


def evaluate(model, X, y, name, threshold=0.5):
    prob = model.predict_proba(X)[:, 1]
    pred = (prob >= threshold).astype(int)
    cm   = confusion_matrix(y, pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr  = fp / (fp+tn) if (fp+tn) > 0 else 0
    fnr  = fn / (fn+tp) if (fn+tp) > 0 else 0
    f1   = f1_score(y, pred, zero_division=0)
    prec = precision_score(y, pred, zero_division=0)
    rec  = recall_score(y, pred, zero_division=0)
    try:
        auc = roc_auc_score(y, prob)
        prauc = average_precision_score(y, prob)
    except ValueError:
        auc = prauc = float("nan")   # single-class eval set (e.g. all-benign holdout)
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


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--suffix", default="augmented",
                    help="matches the --suffix used by split_new_benign.py")
    args = ap.parse_args()

    print("=" * 70)
    print("PHASE 8c: RETRAIN ON AUGMENTED BENIGN DATA (CANDIDATE)")
    print("=" * 70)

    with open(MODELS / "training_results_correct.json") as f:
        prev_results = json.load(f)
    best_params = prev_results["best_params"]
    print(f"\n[1] Reusing hyperparameters from phase8b (training_results_correct.json):")
    for k, v in best_params.items():
        print(f"    {k}: {v}")

    print(f"\n[2] Loading augmented splits (suffix='{args.suffix}')...")
    X_train = np.load(SPLITS / f"X_train_{args.suffix}.npy")
    y_train = np.load(SPLITS / f"y_train_{args.suffix}.npy")
    X_val   = np.load(SPLITS / f"X_val_{args.suffix}.npy")
    y_val   = np.load(SPLITS / f"y_val_{args.suffix}.npy")
    # Official, untouched test sets — read-only reference points, never regenerated here.
    X_test  = np.load(SPLITS / "X_test_balanced.npy")
    y_test  = np.load(SPLITS / "y_test_balanced.npy")
    X_imb   = np.load(SPLITS / "X_test_imbalanced.npy")
    y_imb   = np.load(SPLITS / "y_test_imbalanced.npy")

    print(f"    Train (augmented): {X_train.shape}  malware={y_train.sum():,}  benign={(y_train==0).sum():,}")
    print(f"    Val   (augmented): {X_val.shape}    malware={y_val.sum():,}    benign={(y_val==0).sum():,}")
    print(f"    Test (official, unchanged):  {X_test.shape}")

    n_benign  = (y_train == 0).sum()
    n_malware = (y_train == 1).sum()
    scale_pos = n_benign / n_malware
    print(f"\n    scale_pos_weight (recomputed for augmented ratio): {scale_pos:.3f}")

    print(f"\n[3] Training on augmented train set only (val stays held-out)...")
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

    print(f"\n[4] Evaluation on all sets (threshold=0.5):")
    m_train = evaluate(model, X_train, y_train, "TRAIN (augmented, sanity)")
    m_val   = evaluate(model, X_val,   y_val,   "VAL (augmented, held-out)")
    m_test  = evaluate(model, X_test,  y_test,  "TEST BALANCED (official, unchanged)")
    m_imb   = evaluate(model, X_imb,   y_imb,   "TEST IMBALANCED (official, unchanged)")

    print(f"\n[5] Finding best threshold on augmented VAL set...")
    prob_val = model.predict_proba(X_val)[:, 1]
    best_t_lowfpr, best_f1_lowfpr = 0.5, 0.0
    for t in np.arange(0.1, 0.96, 0.05):
        pred = (prob_val >= t).astype(int)
        f1 = f1_score(y_val, pred, zero_division=0)
        cm = confusion_matrix(y_val, pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp+tn) if (fp+tn) > 0 else 0
        if fpr < 0.01 and f1 > best_f1_lowfpr:
            best_f1_lowfpr = f1
            best_t_lowfpr = float(t)
    print(f"    Low-FPR threshold: {best_t_lowfpr:.2f} (F1={best_f1_lowfpr:.4f})")

    print(f"\n[6] Final evaluation with optimal threshold ({best_t_lowfpr}):")
    m_test_opt = evaluate(model, X_test, y_test, "TEST BALANCED", best_t_lowfpr)
    m_imb_opt  = evaluate(model, X_imb,  y_imb,  "TEST IMBALANCED", best_t_lowfpr)

    print(f"\n[7] Saving CANDIDATE model (production file untouched)...")
    candidate_path = MODELS / "lgbm_v7_correct_candidate.pkl"
    with open(candidate_path, "wb") as f:
        pickle.dump(model, f)
    print(f"    Saved: {candidate_path}")

    results = {
        "created_at":     datetime.now().isoformat(),
        "methodology":    "phase8b recipe replayed on benign-augmented train/val; "
                          "official test sets untouched",
        "seed":           SEED,
        "suffix":         args.suffix,
        "best_params":    best_params,
        "best_iteration": best_iter,
        "threshold_low_fpr": best_t_lowfpr,
        "metrics": {
            "train":           m_train,
            "val":             m_val,
            "test_balanced_default":   m_test,
            "test_imbalanced_default": m_imb,
            "test_balanced_opt":       m_test_opt,
            "test_imbalanced_opt":     m_imb_opt,
        },
        "compare_to": {
            "production_model": "lgbm_v7_correct.pkl",
            "production_test_balanced_f1": prev_results["metrics"]["test_balanced"]["f1"],
            "production_test_balanced_recall": prev_results["metrics"]["test_balanced"]["recall"],
            "production_test_imbalanced_fpr": prev_results["metrics"]["test_imbalanced"]["fpr"],
        },
    }
    results_path = MODELS / f"training_results_candidate_{args.suffix}.json"
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"    Saved: {results_path}")

    print(f"\n{'='*70}")
    print("PHASE 8c COMPLETE — CANDIDATE ONLY, PRODUCTION FILE UNTOUCHED")
    print(f"{'='*70}")
    print(f"""
  Official TEST BALANCED (unchanged file, apples-to-apples comparison):
    Candidate F1:        {m_test_opt['f1']:.4f}   (production: {prev_results['metrics']['test_balanced']['f1']:.4f})
    Candidate Recall:    {m_test_opt['recall']:.4f}   (production: {prev_results['metrics']['test_balanced']['recall']:.4f})
    Candidate FPR:       {m_test_opt['fpr']*100:.2f}%   (production: {prev_results['metrics']['test_balanced']['fpr']*100:.2f}%)

  Next: Stage 6 - validation gates
        python src\\validation\\validate_candidate_v7.py --suffix {args.suffix}
""")


if __name__ == "__main__":
    main()
