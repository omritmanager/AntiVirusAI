"""
Measure the actual distribution shift between EMBER 2018 features and our 2026 features.
EMBER stores raw fields (histogram, header, etc.) and we vectorize using ember v2.
"""
import json
import numpy as np
from pathlib import Path

# --- Same monkey-patches as our extraction ---
import lief
for attr in ['bad_format','bad_file','pe_error','parser_error',
             'read_out_of_bound','not_found']:
    if not hasattr(lief, attr):
        setattr(lief, attr, type(attr, (Exception,), {}))

if not hasattr(np, 'int'):    np.int = int
if not hasattr(np, 'bool'):   np.bool = bool
if not hasattr(np, 'float'):  np.float = float
if not hasattr(np, 'object'): np.object = object

from ember import PEFeatureExtractor

ROOT = Path(r"C:\Users\omri9\Desktop\School\Final Project")
DATASETS = ROOT / "data" / "datasets"
BENIGN  = DATASETS / "modern_benign_features.json"
MALWARE = DATASETS / "modern_malware_features.json"
EMBER_FILES = sorted(DATASETS.glob("train_features_*.jsonl"))

print("=" * 70)
print("EMBER vs MODERN: distribution shift measurement (FIXED)")
print("=" * 70)

# Load modern
print("\n[1] Loading modern data...")
with open(BENIGN) as f:  modern_benign = json.load(f)
with open(MALWARE) as f: modern_malware = json.load(f)

mb_feats = np.array([s["features"] for s in modern_benign["samples"][:5000]], dtype=np.float32)
mm_feats = np.array([s["features"] for s in modern_malware["samples"][:5000]], dtype=np.float32)

print(f"  Modern benign:  {mb_feats.shape}")
print(f"  Modern malware: {mm_feats.shape}")

# Load EMBER raw fields and VECTORIZE with our ember
print("\n[2] Vectorizing EMBER samples with OUR ember + LIEF 0.17.6...")
print("    (This takes a few minutes)")
extractor = PEFeatureExtractor(feature_version=2)

ember_benign  = []
ember_malware = []

TARGET_PER_CLASS = 3000

for ember_file in EMBER_FILES:
    if len(ember_benign) >= TARGET_PER_CLASS and len(ember_malware) >= TARGET_PER_CLASS:
        break
    print(f"  Reading {ember_file.name}...")
    
    with open(ember_file) as f:
        for line in f:
            try:
                s = json.loads(line)
            except json.JSONDecodeError:
                continue
            
            label = s.get("label", -2)
            if label not in (0, 1):
                continue
            
            # Skip if class is full
            if label == 0 and len(ember_benign) >= TARGET_PER_CLASS:
                continue
            if label == 1 and len(ember_malware) >= TARGET_PER_CLASS:
                continue
            
            # Vectorize using EMBER's process_raw_features
            try:
                vec = extractor.process_raw_features(s)
            except Exception:
                continue
            
            if vec is None or len(vec) != 2381:
                continue
            if np.isnan(vec).any() or np.isinf(vec).any():
                continue
            
            if label == 0:
                ember_benign.append(vec)
            else:
                ember_malware.append(vec)
            
            if (len(ember_benign) >= TARGET_PER_CLASS and 
                len(ember_malware) >= TARGET_PER_CLASS):
                break

print(f"\n  EMBER benign vectorized:  {len(ember_benign)}")
print(f"  EMBER malware vectorized: {len(ember_malware)}")

if len(ember_benign) < 100 or len(ember_malware) < 100:
    print("  FATAL: could not vectorize EMBER samples")
    print("  process_raw_features may have a different signature")
    print("  Check ember version - inspecting record:")
    with open(EMBER_FILES[0]) as f:
        first = json.loads(f.readline())
    print(f"  Top keys: {list(first.keys())[:15]}")
    exit(1)

eb = np.array(ember_benign, dtype=np.float32)
em = np.array(ember_malware, dtype=np.float32)

# ── 1. Mean shift ──────────────────────────────────────────
print("\n[3] Mean feature vectors comparison")
eb_mean = eb.mean(axis=0)
mb_mean = mb_feats.mean(axis=0)
em_mean = em.mean(axis=0)
mm_mean = mm_feats.mean(axis=0)

same_benign  = float(np.abs(eb_mean - mb_mean).sum())
same_malware = float(np.abs(em_mean - mm_mean).sum())
diff_ember   = float(np.abs(eb_mean - em_mean).sum())
diff_modern  = float(np.abs(mb_mean - mm_mean).sum())

print(f"\n  Same-class shift (EMBER benign vs Modern benign):  {same_benign:>15,.0f}")
print(f"  Same-class shift (EMBER malware vs Modern malware):{same_malware:>15,.0f}")
print(f"  Different-class shift within EMBER (benign-malware):{diff_ember:>15,.0f}")
print(f"  Different-class shift within Modern (benign-malware):{diff_modern:>15,.0f}")

# ── 2. Sparsity ────────────────────────────────────────────
print("\n[4] Sparsity comparison")
def sp(X): return 100 * (X == 0).sum() / X.size
print(f"  EMBER benign:    {sp(eb):.1f}%")
print(f"  Modern benign:   {sp(mb_feats):.1f}%")
print(f"  EMBER malware:   {sp(em):.1f}%")
print(f"  Modern malware:  {sp(mm_feats):.1f}%")

# ── 3. Domain classifier (THE KEY TEST) ────────────────────
print("\n[5] Domain classifier: can model distinguish EMBER from Modern?")
print("    Trying to separate same-class samples by source only.")

try:
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import cross_val_score

    # Same-class only: EMBER benign vs Modern benign
    X = np.vstack([eb, mb_feats])
    y_src = np.array([1] * len(eb) + [0] * len(mb_feats))
    
    varying = X.std(axis=0) > 1e-6
    X_v = X[:, varying]
    
    scaler = StandardScaler()
    X_s = scaler.fit_transform(X_v)
    
    lr = LogisticRegression(max_iter=500, C=0.1)
    scores = cross_val_score(lr, X_s, y_src, cv=3, scoring='accuracy', n_jobs=1)
    acc_benign = scores.mean() * 100
    
    print(f"\n  Benign-source classifier (EMBER vs Modern):  {acc_benign:.1f}%")
    
    # Same for malware
    X = np.vstack([em, mm_feats])
    y_src = np.array([1] * len(em) + [0] * len(mm_feats))
    
    varying = X.std(axis=0) > 1e-6
    X_v = X[:, varying]
    X_s = scaler.fit_transform(X_v)
    
    scores = cross_val_score(lr, X_s, y_src, cv=3, scoring='accuracy', n_jobs=1)
    acc_malware = scores.mean() * 100
    
    print(f"  Malware-source classifier (EMBER vs Modern): {acc_malware:.1f}%")
    
    avg = (acc_benign + acc_malware) / 2
    print(f"\n  Average source-discrimination: {avg:.1f}%")
    
    print("\n  VERDICT:")
    if avg > 98:
        print("  CRITICAL: EMBER and Modern are completely distinguishable.")
        print("  Merging would teach model to learn 'source' = label.")
        print("  RECOMMENDATION: Do NOT merge EMBER. Train on 80K modern only.")
    elif avg > 90:
        print("  HIGH RISK: significant distribution shift.")
        print("  Merging will dilute signal heavily.")
        print("  RECOMMENDATION: Train on modern only, use EMBER only for evaluation.")
    elif avg > 75:
        print("  MODERATE RISK: shift exists but workable.")
        print("  Phase 7 (temporal feature removal) MANDATORY.")
        print("  Consider domain adaptation techniques.")
    else:
        print("  LOW RISK: EMBER and Modern occupy similar feature space.")
        print("  Safe to merge with Phase 7 in place.")

except Exception as e:
    print(f"  Could not run classifier: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 70)