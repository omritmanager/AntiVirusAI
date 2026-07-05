"""
Deep inspection: are the top-10 'binary' features actually shortcuts,
or are they legitimate string-hash counters?
"""
import json
import numpy as np
from pathlib import Path
from collections import Counter

ROOT = Path(r"C:\Users\omri9\Desktop\School\Final Project")
BENIGN  = ROOT / "data" / "datasets" / "modern_benign_features.json"
MALWARE = ROOT / "data" / "datasets" / "modern_malware_features.json"

print("Loading...")
with open(BENIGN) as f:  b = json.load(f)
with open(MALWARE) as f: m = json.load(f)

# All 10 suspicious indices
INDICES = [623, 637, 654, 2363, 655, 2210, 618, 1559, 662, 160]

# Larger sample for accuracy
n = 10000
B = np.array([s["features"] for s in b["samples"][:n]], dtype=np.float32)
M = np.array([s["features"] for s in m["samples"][:n]], dtype=np.float32)

print(f"\nSampled {n:,} from each class\n")

for idx in INDICES:
    if idx < 256:   group = "ByteHistogram"
    elif idx < 512: group = "ByteEntropy"
    elif idx < 1536: group = "Strings (FeatureHasher)"
    elif idx < 1598: group = "GeneralFileInfo"
    elif idx < 1667: group = "HeaderInfo (TIMESTAMPS!)"
    elif idx < 1923: group = "SectionInfo"
    elif idx < 2179: group = "ImportsInfo"
    elif idx < 2307: group = "ExportsInfo"
    else:            group = "DataDirectories"
    
    b_vals = B[:, idx]
    m_vals = M[:, idx]
    
    print(f"=== Feature {idx} ({group}) ===")
    
    # Show ACTUAL unique values
    b_uniq = np.unique(b_vals)
    m_uniq = np.unique(m_vals)
    
    print(f"  Benign  unique values: {b_uniq[:8]} {'...' if len(b_uniq) > 8 else ''}")
    print(f"  Malware unique values: {m_uniq[:8]} {'...' if len(m_uniq) > 8 else ''}")
    
    # Distribution
    if len(b_uniq) <= 10 and len(m_uniq) <= 10:
        print(f"  Benign distribution:")
        bc = Counter(b_vals.tolist())
        for val, cnt in sorted(bc.items()):
            pct = 100 * cnt / len(b_vals)
            print(f"    {val:>10.4f}: {cnt:>6,} ({pct:>5.1f}%)")
        print(f"  Malware distribution:")
        mc = Counter(m_vals.tolist())
        for val, cnt in sorted(mc.items()):
            pct = 100 * cnt / len(m_vals)
            print(f"    {val:>10.4f}: {cnt:>6,} ({pct:>5.1f}%)")
    
    # Is this a TRUE shortcut?
    # True shortcut = perfect or near-perfect separation
    b_dominant_val, b_dominant_count = Counter(b_vals.tolist()).most_common(1)[0]
    m_dominant_val, m_dominant_count = Counter(m_vals.tolist()).most_common(1)[0]
    
    b_dom_pct = 100 * b_dominant_count / len(b_vals)
    m_dom_pct = 100 * m_dominant_count / len(m_vals)
    
    print(f"  Benign:  most-common value = {b_dominant_val:.4f} ({b_dom_pct:.1f}%)")
    print(f"  Malware: most-common value = {m_dominant_val:.4f} ({m_dom_pct:.1f}%)")
    
    # If both classes have >90% concentration on DIFFERENT dominant values = shortcut
    if (b_dom_pct > 90 and m_dom_pct > 90 and 
        abs(b_dominant_val - m_dominant_val) > 0.01):
        print(f"  *** TRUE SHORTCUT: clean split on this one feature ***")
    else:
        print(f"  OK: overlapping distributions, no clean shortcut")
    print()

print("=" * 70)
print("INTERPRETATION GUIDE")
print("=" * 70)
print("""
True shortcut = both classes have >90% concentration on DIFFERENT values.
  Example: benign always = 0.0, malware always = 1.0.
  
Legitimate signal = overlapping distributions where one value is more common 
in one class but exists in both.
  Example: benign 70% zero, malware 30% zero. Both have zero, just different rates.
  
EMBER's string hasher creates many sparse features that look "binary" but 
actually represent specific string patterns. These are NOT shortcuts.
""")