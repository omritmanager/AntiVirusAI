"""
Smoke test: verify all critical libraries work together.
Tests feature extraction on a real Windows PE file.
"""
import sys
import os
print(f"Python: {sys.version}")
print(f"Executable: {sys.executable}")
print()

# Test 1: LIEF
print("[1] Testing LIEF...")
import lief
lief_version = lief.__version__
print(f"    LIEF version: {lief_version}")
assert lief_version.startswith("0.17.6"), f"WRONG LIEF VERSION: {lief_version}"
print(f"    OK")

# Monkey-patches for older code compatibility
for missing_attr in ['bad_format', 'bad_file', 'pe_error', 'parser_error',
                      'read_out_of_bound', 'not_found']:
    if not hasattr(lief, missing_attr):
        setattr(lief, missing_attr, type(missing_attr, (Exception,), {}))

import numpy as np
if not hasattr(np, 'int'):    np.int = int
if not hasattr(np, 'bool'):   np.bool = bool
if not hasattr(np, 'float'):  np.float = float
if not hasattr(np, 'object'): np.object = object

# Test 2: NumPy
print("[2] Testing NumPy...")
print(f"    NumPy version: {np.__version__}")
print(f"    OK")

# Test 3: EMBER
print("[3] Testing EMBER...")
from ember import PEFeatureExtractor
extractor = PEFeatureExtractor(feature_version=2)
print(f"    EMBER feature dim: {extractor.dim}")
assert extractor.dim == 2381, f"WRONG FEATURE DIM: {extractor.dim}"
print(f"    OK")

# Test 4: LightGBM
print("[4] Testing LightGBM...")
import lightgbm as lgb
print(f"    LightGBM version: {lgb.__version__}")
print(f"    OK")

# Test 5: scikit-learn
print("[5] Testing scikit-learn...")
import sklearn
from sklearn.ensemble import IsolationForest
print(f"    scikit-learn version: {sklearn.__version__}")
print(f"    OK")

# Test 6: shap & optuna
print("[6] Testing SHAP and Optuna...")
import shap, optuna
print(f"    shap version: {shap.__version__}")
print(f"    optuna version: {optuna.__version__}")
print(f"    OK")

# Test 7: Real feature extraction
print("[7] Testing feature extraction on real file...")
test_files = [
    r"C:\Windows\System32\notepad.exe",
    r"C:\Windows\notepad.exe",
    r"C:\Windows\System32\calc.exe",
]
test_file = None
for f in test_files:
    if os.path.exists(f):
        test_file = f
        break

if test_file is None:
    print(f"    SKIPPED — no test file found")
else:
    print(f"    Using: {test_file}")
    with open(test_file, "rb") as f:
        data = f.read()
    print(f"    File size: {len(data):,} bytes")
    
    try:
        features = extractor.feature_vector(data)
        print(f"    Extracted {len(features)} features")
        print(f"    First 5 values: {features[:5]}")
        print(f"    Range: [{features.min():.4f}, {features.max():.4f}]")
        print(f"    NaN count: {np.isnan(features).sum()}")
        print(f"    Sparsity: {100 * (features == 0).sum() / len(features):.1f}% zeros")
        print(f"    OK")
    except Exception as e:
        print(f"    FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

print()
print("=" * 60)
print("ALL TESTS PASSED!")
print("Environment is ready for V7 development.")
print("=" * 60)