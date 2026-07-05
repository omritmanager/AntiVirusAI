"""
Phase 13: Generate final academic report.
Consolidates all results into a comprehensive summary.
"""

import json
import numpy as np
from pathlib import Path
from datetime import datetime

ROOT = Path(r"C:\Users\omri9\Desktop\School\Final Project")
EVAL = ROOT / "evaluation"
MODELS = ROOT / "models" / "v7"

print("=" * 70)
print("PHASE 13: FINAL ACADEMIC REPORT")
print("=" * 70)

# Load all results
with open(MODELS / "training_results_correct.json") as f:
    train_results = json.load(f)
with open(EVAL / "phase11_sanity_check.json") as f:
    sanity = json.load(f)
with open(EVAL / "phase12_zeroday.json") as f:
    zeroday = json.load(f)
with open(MODELS / "thresholds.json") as f:
    thresholds = json.load(f)
with open(MODELS / "if_config.json") as f:
    if_config = json.load(f)

m_test = train_results["metrics"]["test_balanced"]
m_imb  = train_results["metrics"]["test_imbalanced"]
m_val  = train_results["metrics"]["val_threshold05"]

report = f"""
================================================================================
ANTIVIRUSAI V7 — FINAL ACADEMIC REPORT
================================================================================
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. PROJECT OVERVIEW
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

V6 Failure Analysis:
  - Temporal drift: trained on 2018 benign + 2024-2026 malware
    Model learned "modern timestamp = malware" → 90%+ FPR on Windows 11
  - LIEF version mismatch: EMBER used LIEF 0.9.0, engine used LIEF 0.17.5
    Feature vectors at inference were different from training
  - No real test set: validation set was reused → inflated accuracy

V7 Architecture:
  - Layer 1: LightGBM supervised classifier (trained on modern data only)
  - Layer 2: Isolation Forest anomaly detector (trained on benign only)
  - Hybrid decision: MALWARE | POTENTIAL_ZERODAY | SAFE

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
2. DATASET
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Collection:
  Benign:  32,329 PE files (Windows System32, SysWOW64, Program Files, AppData)
  Malware: 48,682 PE files (MalwareBazaar daily dumps, 2026)
  TOTAL:   81,011 samples

Feature Extraction:
  Tool:    EMBER v2 (elastic/ember) with PEFeatureExtractor
  LIEF:    0.17.6-08dc3b7f (IDENTICAL on all machines)
  Dim:     2,381 features per file
  Bug fix: FeatureHasher double-bracket patch applied (line 192)

Preprocessing:
  - SHA-256 deduplication (removed 5 cross-dataset hash collisions)
  - Temporal features zeroed (10 indices: timestamps, version numbers)
  - DLL/EXE flag zeroed (idx 1599) to prevent structural shortcut

Train/Val/Test Split (seed=42, stratified):
  Train:           56,707 (70%)
  Validation:      12,151 (15%)  — truly held-out
  Test balanced:   12,153 (15%)  — never seen
  Test imbalanced: 17,002        — 1:1.3 benign:malware

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
3. MODEL TRAINING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LightGBM — Hyperparameter Tuning (Optuna, 30 trials):
  Best params:
    n_estimators:      {train_results['best_params']['n_estimators']}
    learning_rate:     {train_results['best_params']['learning_rate']:.4f}
    num_leaves:        {train_results['best_params']['num_leaves']}
    max_depth:         {train_results['best_params']['max_depth']}
    min_child_samples: {train_results['best_params']['min_child_samples']}
    subsample:         {train_results['best_params']['subsample']:.4f}
    colsample_bytree:  {train_results['best_params']['colsample_bytree']:.4f}
  Early stopping: {train_results['best_iteration']} iterations
  Threshold:      {thresholds['recommended']:.2f} (best F1 with FPR<1% on val)

Isolation Forest:
  n_estimators:   300
  contamination:  0.01
  max_samples:    10,000
  trained_on:     benign only ({if_config['n_training_samples']:,} samples)
  IF threshold:   {if_config['anomaly_threshold']:.4f}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
4. RESULTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Primary Model — LightGBM (threshold={thresholds['recommended']:.2f}):

  Metric            Validation    Test Balanced  Test Imbalanced
  ─────────────────────────────────────────────────────────────
  F1                {m_val['f1']:.4f}        {m_test['f1']:.4f}         {m_imb['f1']:.4f}
  Precision         {m_val['precision']:.4f}        {m_test['precision']:.4f}         {m_imb['precision']:.4f}
  Recall            {m_val['recall']:.4f}        {m_test['recall']:.4f}         {m_imb['recall']:.4f}
  ROC AUC           {m_val['roc_auc']:.4f}        {m_test['roc_auc']:.4f}         {m_imb['roc_auc']:.4f}
  FPR               {m_val['fpr']*100:.2f}%          {m_test['fpr']*100:.2f}%           {m_imb['fpr']*100:.2f}%
  FNR               {m_val['fnr']*100:.2f}%          {m_test['fnr']*100:.2f}%           {m_imb['fnr']*100:.2f}%
  TP                {m_val['tp']:,}         {m_test['tp']:,}          {m_imb['tp']:,}
  FP                {m_val['fp']:,}            {m_test['fp']:,}             {m_imb['fp']:,}
  FN                {m_val['fn']:,}            {m_test['fn']:,}             {m_imb['fn']:,}
  TN                {m_val['tn']:,}          {m_test['tn']:,}           {m_imb['tn']:,}

Anomaly Layer — Isolation Forest:
  AUC:              {if_config['test_metrics']['auc']:.4f}
  Detection Rate:   {if_config['test_metrics']['tpr']*100:.1f}%  (standalone)
  FPR:              {if_config['test_metrics']['fpr']*100:.1f}%  (standalone)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
5. REAL-WORLD SANITY CHECK (Phase 11)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Scanning live system files (NEVER in training):
  {sanity['total_scanned']:,} files scanned across Windows and installed apps

  Directory                  Scanned   FPR
  ─────────────────────────────────────────"""

for dname, ddata in sanity["by_directory"].items():
    fpr = ddata.get("fpr_pct", 0)
    flag = "  *** HIGH ***" if fpr > 5 else ("  * elevated" if fpr > 1 else "")
    report += f"\n  {dname:<27} {ddata['scanned']:>5,}  {fpr:>5.2f}%{flag}"

report += f"""

  Overall FPR on live system:  {sanity['overall_fpr']:.2f}%
  V6 FPR (reference):          ~90%
  Improvement factor:          ~{int(90 / max(sanity['overall_fpr'], 0.01))}x

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
6. ZERO-DAY ANALYSIS (Phase 12)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Temporal holdout: most recent 20% of malware dataset
  Date range: {zeroday['zeroday_results'].get('date_range', 'N/A')}
  N samples:  {zeroday['zeroday_results'].get('n_samples', 0):,}

  Model                Detection Rate
  ────────────────────────────────────
  LightGBM alone:      {zeroday['zeroday_results'].get('lgbm_dr', 0):.1f}%
  IsolationForest:     {zeroday['zeroday_results'].get('if_dr', 0):.1f}%
  Hybrid:              {zeroday['zeroday_results'].get('hybrid_dr', 0):.1f}%

Note: All malware from same temporal window (2026-05).
True zero-day testing would require malware from after training completion.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
7. V6 vs V7 COMPARISON
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Metric                    V6            V7         Improvement
  ──────────────────────────────────────────────────────────────
  FPR (System32)            ~90%          0.20%      ~450x better
  FPR (overall live)        ~90%          0.36%      ~250x better
  Detection Rate (test)     ~85%*         99.3%      +14.3%
  ROC AUC                   N/A           0.9995     ---
  Methodology               Flawed        Rigorous   ---
  LIEF consistency          No            Yes        ---
  Temporal leakage          Yes           No         ---

  * V6 detection rate was on a contaminated test set (not comparable)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
8. KEY FINDINGS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  F1.  The primary cause of V6's failure was temporal feature leakage:
       the model learned compilation timestamps as proxies for malware.
       Removing 10 temporal features in V7 reduced FPR from ~90% to 0.36%.

  F2.  LIEF version consistency is critical for PE feature extraction.
       Using LIEF 0.9.0 for training and 0.17.6 for inference creates
       measurable distribution shift (domain classifier: 99.4% accuracy).

  F3.  LightGBM trained on modern data (2026) achieves 99.3% recall with
       0.80% FPR on held-out modern test data. The primary discriminative
       features are Strings (FeatureHasher) and ByteHistogram — both
       behavioral rather than structural indicators.

  F4.  The Isolation Forest anomaly layer achieves 7.1% standalone detection
       with 1.84% FPR. It does not significantly improve the hybrid model
       when test malware shares temporal/structural characteristics with
       training data. This finding suggests IF adds most value against
       truly novel malware architectures not present in training.

  F5.  Domain adaptation is essential when combining historical (EMBER 2018)
       and modern datasets. A classifier trained to distinguish dataset
       source achieves 99.4% accuracy, indicating irreconcilable distribution
       shift. Modern-only training avoids this confound.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
9. LIMITATIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  L1.  All malware from single source (MalwareBazaar). Samples that
       successfully evade existing antivirus are underrepresented.

  L2.  Benign dataset skewed toward Microsoft system files (88.1% DLL).
       Model may underperform on novel benign EXE architectures.

  L3.  True zero-day testing not possible without malware published
       after training completion. The temporal holdout (80/20 split
       within same month) is a proxy, not a genuine zero-day scenario.

  L4.  Static analysis only. Packed/obfuscated malware that hides its
       true feature profile may evade detection.

  L5.  Dataset size (81,011) is modest compared to production systems.
       Results may not generalize to the full diversity of real-world PE files.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
10. FILES SAVED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  models/v7/
    lgbm_v7_correct.pkl          LightGBM model (train-only training)
    isolation_forest.pkl          Isolation Forest anomaly detector
    thresholds.json               Calibrated thresholds
    training_results_correct.json Full training metadata
    if_config.json                IF configuration and metrics

  data/splits_clean/
    X_train.npy / y_train.npy
    X_val.npy   / y_val.npy
    X_test_balanced.npy / y_test_balanced.npy
    X_test_imbalanced.npy / y_test_imbalanced.npy

  evaluation/
    phase10_results.json          Hybrid evaluation results
    phase11_sanity_check.json     Live system FPR analysis
    phase12_zeroday.json          Temporal holdout analysis

================================================================================
"""

print(report)

# Save to file
report_path = EVAL / "FINAL_REPORT.txt"
with open(report_path, "w", encoding="utf-8") as f:
    f.write(report)
print(f"Saved: {report_path}")

# Save JSON version
json_report = {
    "created_at":    datetime.now().isoformat(),
    "model":         "LightGBM + Isolation Forest (Hybrid)",
    "dataset_size":  81011,
    "key_metrics": {
        "val_f1":        m_val["f1"],
        "test_f1":       m_test["f1"],
        "test_fpr":      m_test["fpr"],
        "test_recall":   m_test["recall"],
        "test_roc_auc":  m_test["roc_auc"],
        "live_fpr":      sanity["overall_fpr"] / 100,
        "system32_fpr":  sanity["by_directory"].get(
                            "Windows System32", {}).get("fpr_pct", 0) / 100,
    },
    "v6_comparison": {
        "v6_fpr":    0.90,
        "v7_fpr":    sanity["overall_fpr"] / 100,
        "improvement_factor": round(0.90 / max(sanity["overall_fpr"]/100, 0.001)),
    },
}
with open(EVAL / "final_results.json", "w") as f:
    json.dump(json_report, f, indent=2)
print(f"Saved: {EVAL / 'final_results.json'}")