"""
validate_candidate_v7.py — Stage 6 of the benign-corpus augmentation pipeline.

Runs every gate the candidate model (models/v7/lgbm_v7_correct_candidate.pkl,
from phase8c) must pass before a production swap could even be considered.
Nothing here modifies models/v7/lgbm_v7_correct.pkl — this script only reads
and reports.

Gates (all against the CURRENT production model as the baseline):
  1. F1 on the official, unchanged X_test_balanced >= REGRESSION_F1_MIN (0.98)
     — this is the same gate avscan/selfcheck.py enforces at every app
     startup; a candidate that fails it can never ship.
  2. FPR on the official, unchanged X_test_imbalanced not worse than current.
  3. Malware recall on both official test sets, reported on its own line —
     adding only benign data could trade FN for FP without moving F1 much,
     and a hidden recall regression is worse for an AV product than the FP
     problem this whole effort exists to fix.
  4. FPR on the new benign holdout (Stage 4) — reported, but explicitly
     labeled a WEAKER signal: this corpus is homogeneous (harvested the same
     way, same era, same mainstream installer frameworks), so even a
     group-aware holdout sits closer to train than genuinely unrelated
     software.
  5. FPR on the vendor-holdout (Stage 4, if it exists) — the real
     generalization signal, because those vendors contributed ZERO training
     examples of their own toolchain/installer pattern.
  6. Clustered-vs-singleton FPR gap on the new holdout — samples whose group
     key also appears in train ("clustered") vs samples whose group key is
     unique to holdout ("singleton"). A much worse singleton FPR is a direct,
     quantified memorization signal.
  7. Feature-importance-group diff: buckets each model's own top-20
     gain-importance features into EMBER's structural groups (ByteHistogram /
     ByteEntropy / Strings / GeneralFileInfo / HeaderInfo / SectionInfo /
     ImportsInfo / ExportsInfo / DataDirectories — same buckets
     check_pe_type_shortcut.py and deep_shortcut_audit.py already use) and
     compares production vs candidate. If HeaderInfo/structural features
     become MORE dominant in the candidate, an FPR "fix" is a worse shortcut,
     not a real one, even if the aggregate numbers look good.
  8. Scoped shortcut re-check on the NEW batch specifically (full metadata
     for the pre-existing training samples no longer exists on disk, so this
     is not a full deep_shortcut_audit.py re-run — that scoping limit is
     reported explicitly, not silently overclaimed): temporal-zeroing still
     holds in the augmented arrays, plus the new batch's own within-class
     diversity ratio (already computed by Stage 3, re-reported here for
     visibility alongside the other gates).
  9. Leakage sanity: val F1 should not be suspiciously close to 1.0 (that
     would mean the augmented val set is contaminated), matching
     check_leakage.py's own diagnostic framing.
  10. Known-FP canary (reported only, never gates the decision, n=1): re-run
      the DigiCert-signed Go-binary case that motivated this whole effort.

Usage:
  python src/validation/validate_candidate_v7.py --suffix augmented
"""
from __future__ import annotations

import argparse
import json
import pickle
import sys
from pathlib import Path

import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, recall_score

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from avscan import config  # noqa: E402

KNOWN_FP_CANARY = Path(r"C:\Users\omri9\Downloads\Claude Setup.exe")

# Same EMBER v2 layout used by check_pe_type_shortcut.py / deep_shortcut_audit.py.
_FEATURE_GROUPS = [
    (0, 256, "ByteHistogram"),
    (256, 512, "ByteEntropy"),
    (512, 1536, "Strings"),
    (1536, 1598, "GeneralFileInfo"),
    (1598, 1667, "HeaderInfo (timestamp/version!)"),
    (1667, 1923, "SectionInfo"),
    (1923, 2179, "ImportsInfo"),
    (2179, 2307, "ExportsInfo"),
    (2307, 2381, "DataDirectories"),
]


def feat_group(idx: int) -> str:
    for lo, hi, name in _FEATURE_GROUPS:
        if lo <= idx < hi:
            return name
    return "Unknown"


def load_model(path: Path):
    with open(path, "rb") as f:
        return pickle.load(f)


def metrics_at(model, X, y, threshold) -> dict:
    prob = model.predict_proba(X)[:, 1]
    pred = (prob >= threshold).astype(int)
    cm = confusion_matrix(y, pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    return {
        "f1": float(f1_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "fpr": float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0,
        "fnr": float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0,
        "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
        "n": len(y),
    }


def top_feature_groups(model, top_n: int = 20) -> dict:
    importances = model.booster_.feature_importance(importance_type="gain")
    top_idx = np.argsort(importances)[::-1][:top_n]
    groups = {}
    for idx in top_idx:
        g = feat_group(int(idx))
        groups[g] = groups.get(g, 0) + 1
    return groups


def gate(label: str, passed: bool, detail: str, gates: list):
    gates.append({"gate": label, "passed": passed, "detail": detail})
    mark = "PASS" if passed else "FAIL"
    print(f"  [{mark}] {label}: {detail}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--suffix", default="augmented")
    args = ap.parse_args()
    splits = config.SPLITS_CLEAN_DIR
    models_dir = config.MODELS_DIR

    print("=" * 70)
    print("STAGE 6: VALIDATION GATE SUITE")
    print("=" * 70)

    print("\n[1] Loading models...")
    prod_path = config.LGBM_PATH
    cand_path = models_dir / "lgbm_v7_correct_candidate.pkl"
    if not cand_path.exists():
        print(f"[STOP] candidate model not found: {cand_path} — run Stage 5 first.")
        return 1
    prod = load_model(prod_path)
    cand = load_model(cand_path)
    print(f"  Production: {prod_path}")
    print(f"  Candidate:  {cand_path}")

    print("\n[2] Loading official (unchanged) test sets...")
    X_bal = np.load(splits / "X_test_balanced.npy")
    y_bal = np.load(splits / "y_test_balanced.npy")
    X_imb = np.load(splits / "X_test_imbalanced.npy")
    y_imb = np.load(splits / "y_test_imbalanced.npy")

    gates = []

    print("\n[3] Gate 1-3: official test sets (production vs candidate)...")
    prod_bal = metrics_at(prod, X_bal, y_bal, config.LGBM_THRESHOLD)
    cand_bal = metrics_at(cand, X_bal, y_bal, config.LGBM_THRESHOLD)
    prod_imb = metrics_at(prod, X_imb, y_imb, config.LGBM_THRESHOLD)
    cand_imb = metrics_at(cand, X_imb, y_imb, config.LGBM_THRESHOLD)

    print(f"    production  test_balanced   F1={prod_bal['f1']:.4f} recall={prod_bal['recall']:.4f} fpr={prod_bal['fpr']*100:.2f}%")
    print(f"    candidate   test_balanced   F1={cand_bal['f1']:.4f} recall={cand_bal['recall']:.4f} fpr={cand_bal['fpr']*100:.2f}%")
    print(f"    production  test_imbalanced F1={prod_imb['f1']:.4f} recall={prod_imb['recall']:.4f} fpr={prod_imb['fpr']*100:.2f}%")
    print(f"    candidate   test_imbalanced F1={cand_imb['f1']:.4f} recall={cand_imb['recall']:.4f} fpr={cand_imb['fpr']*100:.2f}%")

    gate("F1 floor on official test_balanced", cand_bal["f1"] >= config.REGRESSION_F1_MIN,
         f"candidate F1={cand_bal['f1']:.6f} (min {config.REGRESSION_F1_MIN}, "
         f"production={prod_bal['f1']:.6f}, expected~{config.REGRESSION_F1_EXPECTED:.6f})", gates)
    gate("FPR not worse on official test_imbalanced", cand_imb["fpr"] <= prod_imb["fpr"] + 1e-9,
         f"candidate={cand_imb['fpr']*100:.2f}%  production={prod_imb['fpr']*100:.2f}%", gates)
    gate("Malware recall not worse (test_balanced)", cand_bal["recall"] >= prod_bal["recall"] - 1e-9,
         f"candidate={cand_bal['recall']:.4f}  production={prod_bal['recall']:.4f}", gates)
    gate("Malware recall not worse (test_imbalanced)", cand_imb["recall"] >= prod_imb["recall"] - 1e-9,
         f"candidate={cand_imb['recall']:.4f}  production={prod_imb['recall']:.4f}", gates)

    print("\n[4] Gate 4-6: new benign holdout + vendor holdout...")
    holdout_path = splits / "X_test_new_benign_holdout.npy"
    if holdout_path.exists():
        X_hold = np.load(holdout_path)
        y_hold = np.load(splits / "y_test_new_benign_holdout.npy")
        with open(splits / "X_test_new_benign_holdout.groupinfo.json") as f:
            groupinfo = json.load(f)

        prod_hold = metrics_at(prod, X_hold, y_hold, config.LGBM_THRESHOLD)
        cand_hold = metrics_at(cand, X_hold, y_hold, config.LGBM_THRESHOLD)
        print(f"    [weaker signal — homogeneous corpus] new-holdout FPR: "
              f"production={prod_hold['fpr']*100:.2f}%  candidate={cand_hold['fpr']*100:.2f}%  (n={cand_hold['n']})")

        # Clustered vs singleton FPR gap (memorization signal).
        singleton_idx = [i for i, g in enumerate(groupinfo) if g["singleton"]]
        clustered_idx = [i for i, g in enumerate(groupinfo) if not g["singleton"]]
        if singleton_idx and clustered_idx:
            cand_single = metrics_at(cand, X_hold[singleton_idx], y_hold[singleton_idx], config.LGBM_THRESHOLD)
            cand_clust = metrics_at(cand, X_hold[clustered_idx], y_hold[clustered_idx], config.LGBM_THRESHOLD)
            gap = cand_single["fpr"] - cand_clust["fpr"]
            gate("Clustered-vs-singleton FPR gap (memorization signal)", gap <= 0.10,
                 f"singleton FPR={cand_single['fpr']*100:.2f}% (n={cand_single['n']})  "
                 f"clustered FPR={cand_clust['fpr']*100:.2f}% (n={cand_clust['n']})  gap={gap*100:.2f}pp", gates)
        else:
            print(f"    (not enough singleton/clustered samples in holdout to compute the gap)")
    else:
        print(f"    (no new-holdout file found at {holdout_path} — Stage 4 skipped or not yet run)")

    vendor_path = splits / "X_test_unseen_vendor.npy"
    if vendor_path.exists():
        X_ven = np.load(vendor_path)
        y_ven = np.load(splits / "y_test_unseen_vendor.npy")
        prod_ven = metrics_at(prod, X_ven, y_ven, config.LGBM_THRESHOLD)
        cand_ven = metrics_at(cand, X_ven, y_ven, config.LGBM_THRESHOLD)
        print(f"    [REAL generalization signal] vendor-holdout FPR: "
              f"production={prod_ven['fpr']*100:.2f}%  candidate={cand_ven['fpr']*100:.2f}%  (n={cand_ven['n']})")
        gate("Vendor-holdout FPR improves or holds vs production", cand_ven["fpr"] <= prod_ven["fpr"] + 1e-9,
             f"candidate={cand_ven['fpr']*100:.2f}%  production={prod_ven['fpr']*100:.2f}%", gates)
    else:
        print(f"    (no vendor-holdout file — not enough distinct vendor groups in this run)")

    print("\n[5] Gate 7: feature-importance-group diff (shortcut check)...")
    prod_groups = top_feature_groups(prod)
    cand_groups = top_feature_groups(cand)
    print(f"    {'Group':<32} {'Production':>12} {'Candidate':>12}")
    all_groups = sorted(set(prod_groups) | set(cand_groups))
    for g in all_groups:
        print(f"    {g:<32} {prod_groups.get(g, 0):>12} {cand_groups.get(g, 0):>12}")
    header_prod = prod_groups.get("HeaderInfo (timestamp/version!)", 0)
    header_cand = cand_groups.get("HeaderInfo (timestamp/version!)", 0)
    gate("HeaderInfo/structural share did not increase in candidate's top-20",
         header_cand <= header_prod,
         f"production={header_prod}/20  candidate={header_cand}/20 "
         f"(these are the zeroed temporal features plus other header fields — "
         f"an increase means the FPR fix leans harder on structure, not behavior)", gates)

    print("\n[6] Gate 8: scoped shortcut re-check on the new batch...")
    aug_path = splits / f"X_train_{args.suffix}.npy"
    if aug_path.exists():
        X_aug = np.load(aug_path)
        temporal_sum = float(np.abs(X_aug[:, config.TEMPORAL_INDICES]).sum())
        gate("Temporal indices still zeroed in augmented train set", temporal_sum == 0.0,
             f"sum(abs(TEMPORAL_INDICES))={temporal_sum}", gates)
    else:
        print(f"    (no {aug_path.name} found)")
    summary_candidates = list(splits.parent.glob("augmentation/*.group_summary.json"))
    if summary_candidates:
        with open(summary_candidates[-1]) as f:
            gsum = json.load(f)
        print(f"    New-batch diversity ratio (from Stage 3): "
              f"{gsum['diversity']['ratio']*100:.1f}%  "
              f"({gsum['diversity']['distinct']}/{gsum['diversity']['sampled']} distinct)")
        print(f"    NOTE: this is scoped to the NEW batch only — full metadata for the "
              f"pre-existing training samples no longer exists on disk (see plan), so "
              f"this is not a complete deep_shortcut_audit.py re-run.")

    print("\n[7] Gate 9: leakage sanity (val F1 not suspiciously perfect)...")
    val_path = splits / f"X_val_{args.suffix}.npy"
    if val_path.exists():
        X_val_aug = np.load(val_path)
        y_val_aug = np.load(splits / f"y_val_{args.suffix}.npy")
        val_metrics = metrics_at(cand, X_val_aug, y_val_aug, config.LGBM_THRESHOLD)
        gate("Augmented val F1 is not suspiciously near-perfect (<0.999)",
             val_metrics["f1"] < 0.999,
             f"val F1={val_metrics['f1']:.6f} "
             f"(near 1.0 would suggest contamination, matching check_leakage.py's framing)", gates)

    print("\n[8] Known-FP canary (reported only, n=1, never gates the decision)...")
    if KNOWN_FP_CANARY.exists():
        from avscan.engine import Engine
        eng = Engine(load_if=False)
        with open(KNOWN_FP_CANARY, "rb") as f:
            data = f.read()
        vec = eng.processed_vector(data)
        if vec is not None:
            row = vec.reshape(1, -1)
            p_prod = float(prod.predict_proba(row)[0, 1])
            p_cand = float(cand.predict_proba(row)[0, 1])
            print(f"    {KNOWN_FP_CANARY.name}: production={p_prod:.4f}  candidate={p_cand:.4f}  "
                  f"(threshold={config.LGBM_THRESHOLD})")
            if (p_prod >= config.LGBM_THRESHOLD) != (p_cand >= config.LGBM_THRESHOLD):
                print(f"    Verdict flipped — see the feature-importance diff above for why, "
                      f"rather than assuming a specific feature without checking.")
    else:
        print(f"    (canary file not found at {KNOWN_FP_CANARY} — skipped)")

    print(f"\n{'='*70}")
    print("GATE SUMMARY")
    print(f"{'='*70}")
    n_pass = sum(1 for g in gates if g["passed"])
    n_fail = sum(1 for g in gates if not g["passed"])
    for g in gates:
        print(f"  [{'PASS' if g['passed'] else 'FAIL'}]  {g['gate']}")
    print(f"\n  {n_pass}/{len(gates)} gates passed.")
    if n_fail:
        print(f"  {n_fail} gate(s) FAILED — do not recommend a production swap.")
    else:
        print(f"  All gates passed. Report to the user for the final go/no-go — "
              f"still requires explicit approval before any swap.")

    report_path = models_dir / f"validation_report_{args.suffix}.json"
    with open(report_path, "w") as f:
        json.dump({"gates": gates,
                   "production_test_balanced": prod_bal,
                   "candidate_test_balanced": cand_bal,
                   "production_test_imbalanced": prod_imb,
                   "candidate_test_imbalanced": cand_imb}, f, indent=2)
    print(f"\n  Full report: {report_path}")
    return 0 if n_fail == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
