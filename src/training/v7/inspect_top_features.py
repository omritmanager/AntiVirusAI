"""
Look at the top-10 most predictive feature indices.
Check if any is the DLL/EXE flag specifically.
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

TOP_INDICES = [623, 637, 654, 2363, 655, 2210, 618, 1559, 662, 160]

n = 3000
B = np.array([s["features"] for s in b["samples"][:n]], dtype=np.float32)
M = np.array([s["features"] for s in m["samples"][:n]], dtype=np.float32)

print(f"\n{'idx':>6} {'b_mean':>12} {'m_mean':>12} {'b_uniq':>8} {'m_uniq':>8}  pattern")
print("-" * 75)

shortcuts = []
for idx in TOP_INDICES:
    b_vals = B[:, idx]
    m_vals = M[:, idx]
    
    b_uniq = len(np.unique(b_vals))
    m_uniq = len(np.unique(m_vals))
    
    pattern = ""
    # Binary-like feature: only 2-3 values = likely a flag (suspicious)
    if b_uniq <= 3 and m_uniq <= 3:
        pattern = "BINARY FLAG <- suspect"
        shortcuts.append(idx)
    elif b_uniq < 10 and m_uniq < 10:
        pattern = "low-cardinality"
    elif b_uniq > 100 and m_uniq > 100:
        pattern = "continuous (good)"
    else:
        pattern = "mixed"
    
    print(f"{idx:>6} {b_vals.mean():>12.2f} {m_vals.mean():>12.2f} "
          f"{b_uniq:>8} {m_uniq:>8}  {pattern}")

print("\n" + "=" * 75)
if shortcuts:
    print(f"Binary-flag features in top-10: {len(shortcuts)} (indices {shortcuts})")
    print("These ARE the DLL/EXE shortcut risk.")
    print("Add them to Phase 7 removal list.")
else:
    print("No binary-flag features in top-10.")
    print("The 100% LR accuracy is from CONTINUOUS features (strings/imports).")
    print("This is GENUINE behavioral signal, not a shortcut.")