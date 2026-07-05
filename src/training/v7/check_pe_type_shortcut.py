"""
Quick check: does the DLL/EXE skew create a shortcut?
EMBER feature 1599 maps to the DLL flag in header.coff.characteristics.
"""
import json
import numpy as np
from pathlib import Path

ROOT = Path(r"C:\Users\omri9\Desktop\School\Final Project")
BENIGN  = ROOT / "data" / "datasets" / "modern_benign_features.json"
MALWARE = ROOT / "data" / "datasets" / "modern_malware_features.json"

print("Loading...")
with open(BENIGN) as f:  b = json.load(f)
with open(MALWARE) as f: m = json.load(f)

# Check DLL/EXE filename labels
b_dll = sum(1 for s in b["samples"] if (s.get("file_name") or "").lower().endswith(".dll"))
b_exe = sum(1 for s in b["samples"] if (s.get("file_name") or "").lower().endswith(".exe"))
m_exe = sum(1 for s in m["samples"] if (s.get("file_name") or "").lower().endswith(".exe") or (s.get("file_name") or "").lower().endswith(".bin"))

print(f"\nBenign:  DLL={b_dll:,}  EXE={b_exe:,}")
print(f"Malware: EXE-like={m_exe:,}  DLL=0")

# Feature analysis - find features that correlate 0.9+ with the DLL/EXE label
print("\nLoading features...")
n = 5000
B = np.array([s["features"] for s in b["samples"][:n]], dtype=np.float32)
M = np.array([s["features"] for s in m["samples"][:n]], dtype=np.float32)

X = np.vstack([B, M])
# Pseudo-label: 1 if from benign DLL bucket, 0 otherwise
# Better: actual binary labels and check feature separation
y_class = np.array([0]*n + [1]*n)

# Train a tiny logistic regression to see what's predictive
print("Training quick logistic regression to find shortcut features...")
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

# Subset features that vary
varying = X.std(axis=0) > 1e-6
X_v = X[:, varying]
varying_idx = np.where(varying)[0]

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X_v)

lr = LogisticRegression(max_iter=200, C=1.0)
lr.fit(X_scaled, y_class)
acc = lr.score(X_scaled, y_class)
print(f"\nLogistic regression accuracy on this binary split: {acc*100:.2f}%")
print("(If >95%, separation is too easy = shortcut likely)")

# Top 10 most influential features
weights = np.abs(lr.coef_[0])
top_idx = np.argsort(weights)[::-1][:10]

print(f"\nTop 10 most influential feature indices:")
for rank, i in enumerate(top_idx, 1):
    orig_idx = varying_idx[i]
    if orig_idx < 256:   group = "ByteHistogram"
    elif orig_idx < 512: group = "ByteEntropy"
    elif orig_idx < 1536: group = "Strings"
    elif orig_idx < 1598: group = "GeneralFileInfo"
    elif orig_idx < 1667: group = "HeaderInfo"
    elif orig_idx < 1923: group = "SectionInfo"
    elif orig_idx < 2179: group = "ImportsInfo"
    elif orig_idx < 2307: group = "ExportsInfo"
    else:                group = "DataDirectories"
    print(f"  {rank}. idx={orig_idx:<5}  weight={weights[i]:.3f}  group={group}")

print("\nIf 'HeaderInfo' or 'GeneralFileInfo' dominates → DLL/EXE shortcut")
print("If 'Strings' or 'Imports' dominates → real behavioral learning")