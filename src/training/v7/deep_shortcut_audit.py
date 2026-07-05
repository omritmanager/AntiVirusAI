"""
Deep audit for shortcut learning risks.
Checks the things that destroyed V6: metadata shortcuts, feature shortcuts,
broken extractions, and within-class redundancy.
"""
import json
import numpy as np
from pathlib import Path
from collections import Counter

ROOT = Path(r"C:\Users\omri9\Desktop\School\Final Project")
BENIGN_FILE  = ROOT / "data" / "datasets" / "modern_benign_features.json"
MALWARE_FILE = ROOT / "data" / "datasets" / "modern_malware_features.json"


def section(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


print("Loading datasets...")
with open(BENIGN_FILE) as f:
    benign = json.load(f)
with open(MALWARE_FILE) as f:
    malware = json.load(f)

b_samples = benign["samples"]
m_samples = malware["samples"]

shortcuts_found = []
warnings_found  = []


# ── 1. FILE SIZE SHORTCUT ─────────────────────────────────────────
section("[1] FILE SIZE DISTRIBUTION (shortcut risk)")
b_sizes = np.array([s.get("file_size", 0) for s in b_samples])
m_sizes = np.array([s.get("file_size", 0) for s in m_samples])

def pct_stats(arr, name):
    print(f"\n  {name}:")
    for p in [5, 25, 50, 75, 95]:
        print(f"    p{p:>3}: {int(np.percentile(arr, p)):>15,} bytes")
    print(f"    mean: {int(arr.mean()):>15,}")

pct_stats(b_sizes, "Benign")
pct_stats(m_sizes, "Malware")

# If medians differ by 10x+, model will use size as a shortcut
ratio = max(np.median(b_sizes), 1) / max(np.median(m_sizes), 1)
ratio = max(ratio, 1/ratio)
print(f"\n  Median ratio: {ratio:.1f}x")
if ratio > 10:
    shortcuts_found.append(
        f"File size: benign median {int(np.median(b_sizes)):,} vs malware {int(np.median(m_sizes)):,} "
        f"({ratio:.1f}x apart). Model will learn 'size = label'."
    )
elif ratio > 3:
    warnings_found.append(f"File size differs {ratio:.1f}x between classes")
else:
    print(f"  Acceptable size overlap")


# ── 2. SIGNATURE/PUBLISHER SHORTCUT ────────────────────────────────
section("[2] DIGITAL SIGNATURE DISTRIBUTION")

# Benign data may not have signature field, that's OK
b_has_sig_field = sum(1 for s in b_samples if "signature" in s)
m_has_sig_field = sum(1 for s in m_samples if "signature" in s)
print(f"\n  Samples with 'signature' metadata field:")
print(f"    Benign:  {b_has_sig_field:>6}/{len(b_samples):,}")
print(f"    Malware: {m_has_sig_field:>6}/{len(m_samples):,}")

# Check unsigned ratio
m_unsigned = sum(1 for s in m_samples if not s.get("signature"))
print(f"\n  Malware unsigned: {m_unsigned:,}/{len(m_samples):,} "
      f"({100*m_unsigned/len(m_samples):.1f}%)")
print("  Note: signature info is in METADATA not features, so this is informational only.")


# ── 3. TEMPORAL DISTRIBUTION (V6's killer) ─────────────────────────
section("[3] TEMPORAL DISTRIBUTION (V6 killer)")

def year_dist(samples, name):
    years = Counter()
    for s in samples:
        fs = s.get("first_seen", "") or ""
        y = fs[:4] if fs else "unknown"
        years[y] += 1
    print(f"\n  {name}:")
    for y, c in sorted(years.items()):
        bar = "#" * int(50 * c / len(samples))
        print(f"    {y}: {c:>6,}  {bar}")
    return years

b_years = year_dist(b_samples, "Benign")
m_years = year_dist(m_samples, "Malware")

# Warning: if benign has years and malware has years but they don't overlap, that's V6 redux
b_known = {y for y in b_years if y != "unknown" and y.isdigit()}
m_known = {y for y in m_years if y != "unknown" and y.isdigit()}
if b_known and m_known:
    overlap_years = b_known & m_known
    if not overlap_years:
        shortcuts_found.append(
            f"Temporal disjoint: benign years {sorted(b_known)}, malware years {sorted(m_known)}. "
            f"This is V6's failure mode."
        )


# ── 4. PE FILE TYPE SHORTCUT ─────────────────────────────────────
section("[4] PE FILE TYPE (exe/dll/sys) DISTRIBUTION")

def ext_dist(samples):
    ext = Counter()
    for s in samples:
        fn = (s.get("file_name") or "").lower()
        if fn.endswith(".dll"): ext["dll"] += 1
        elif fn.endswith(".exe"): ext["exe"] += 1
        elif fn.endswith(".sys"): ext["sys"] += 1
        elif fn.endswith(".bin"): ext["bin"] += 1
        else: ext["other"] += 1
    return ext

b_ext = ext_dist(b_samples)
m_ext = ext_dist(m_samples)

print(f"\n  {'Type':<8} {'Benign':>12} {'Malware':>12}")
all_types = sorted(set(b_ext) | set(m_ext))
for t in all_types:
    b_pct = 100 * b_ext.get(t, 0) / len(b_samples)
    m_pct = 100 * m_ext.get(t, 0) / len(m_samples)
    print(f"  {t:<8} {b_ext.get(t, 0):>6,} ({b_pct:>5.1f}%)  "
          f"{m_ext.get(t, 0):>6,} ({m_pct:>5.1f}%)")

# Malware mostly .bin (SHA-named from MalwareBazaar) vs benign mostly .dll/.exe
# This is fine because .bin is just MalwareBazaar's naming, the PE inside is real
# But check the actual PE machine type via features instead


# ── 5. BROKEN/EMPTY FEATURE VECTORS ────────────────────────────────
section("[5] BROKEN EXTRACTION DETECTION")
print("Looking for samples with >95% zero features (likely broken extraction)")

def find_broken(samples, name):
    broken_count = 0
    for s in samples:
        feats = s.get("features", [])
        if len(feats) != 2381:
            continue
        zero_ratio = sum(1 for x in feats if x == 0) / 2381
        if zero_ratio > 0.95:
            broken_count += 1
    print(f"  {name}: {broken_count:,} samples >95% zero "
          f"({100*broken_count/len(samples):.2f}%)")
    return broken_count

b_broken = find_broken(b_samples, "Benign")
m_broken = find_broken(m_samples, "Malware")

# 1-3% broken is expected from corrupt PE files. 10%+ is a problem.
b_pct = 100 * b_broken / len(b_samples)
m_pct = 100 * m_broken / len(m_samples)
if b_pct > 5 or m_pct > 5:
    warnings_found.append(
        f"High broken extractions: benign={b_pct:.1f}%, malware={m_pct:.1f}%. "
        f"Consider filtering these out before training."
    )


# ── 6. TOP DISCRIMINATIVE FEATURES (audit) ─────────────────────────
section("[6] TOP DISCRIMINATIVE FEATURE INDICES")
print("Which feature dimensions differ MOST between classes?")
print("If a temporal feature (linker version etc.) is in top 5 = SHORTCUT RISK")

# Sample 5K from each for speed
n = 5000
B = np.array([s["features"] for s in b_samples[:n]], dtype=np.float32)
M = np.array([s["features"] for s in m_samples[:n]], dtype=np.float32)

# Standardize first to make comparison meaningful
combined = np.vstack([B, M])
mean = combined.mean(axis=0)
std  = combined.std(axis=0) + 1e-8
B_norm = (B - mean) / std
M_norm = (M - mean) / std

# Mean diff after normalization = "z-score gap"
diff = np.abs(B_norm.mean(axis=0) - M_norm.mean(axis=0))
top20_idx = np.argsort(diff)[::-1][:20]

# EMBER feature 2381 layout (approx, from ember source):
#   0-255:     ByteHistogram
#   256-511:   ByteEntropyHistogram  
#   512-1535:  StringExtractor (1024 features)
#   1536-1597: GeneralFileInfo (62)
#   1598-1666: HeaderFileInfo (68)         <-- TIMESTAMPS LIVE HERE
#   1667-1922: SectionInfo (256)
#   1923-2178: ImportsInfo (256)
#   2179-2306: ExportsInfo (128)
#   2307-2380: DataDirectories (74)

def feat_group(idx):
    if idx < 256:   return "ByteHistogram"
    if idx < 512:   return "ByteEntropy"
    if idx < 1536:  return "Strings"
    if idx < 1598:  return "GeneralFileInfo"
    if idx < 1667:  return "HeaderInfo (timestamp/version!)"
    if idx < 1923:  return "SectionInfo"
    if idx < 2179:  return "ImportsInfo"
    if idx < 2307:  return "ExportsInfo"
    return                  "DataDirectories"

print(f"\n  {'Rank':<4} {'Idx':<6} {'Group':<35} {'Z-gap':>8}")
header_warnings = 0
for rank, idx in enumerate(top20_idx, 1):
    group = feat_group(idx)
    z = diff[idx]
    flag = ""
    if "Header" in group or "timestamp" in group.lower():
        flag = "  <-- TEMPORAL/SHORTCUT RISK"
        header_warnings += 1
    print(f"  {rank:<4} {idx:<6} {group:<35} {z:>8.2f}{flag}")

if header_warnings >= 3:
    warnings_found.append(
        f"{header_warnings} of top-20 discriminative features are HeaderInfo (timestamps/versions). "
        f"Phase 7 (Remove Temporal Features) is MANDATORY."
    )
elif header_warnings >= 1:
    print(f"\n  {header_warnings} header features in top-20. Phase 7 will handle this.")
else:
    print(f"\n  No header/temporal features in top-20. Good sign.")


# ── 7. WITHIN-CLASS REDUNDANCY (malware family clustering) ─────────
section("[7] MALWARE WITHIN-CLASS DIVERSITY")
print("Are 90% of malware samples basically the same file with renamed hash?")

# Quick check: how many UNIQUE feature vectors are there in malware?
# Round to reduce noise; if all malware looks nearly identical, this exposes it
n = min(10000, len(m_samples))
M_check = np.array([s["features"] for s in m_samples[:n]], dtype=np.float32)
# Quantize each row's first 100 features to detect near-duplicates
M_quant = np.round(M_check[:, :100], decimals=2)
unique_signatures = len({tuple(row) for row in M_quant})
print(f"\n  Sampled malware: {n:,}")
print(f"  Distinct 'signatures' (first 100 features rounded): {unique_signatures:,}")
print(f"  Diversity ratio: {100*unique_signatures/n:.1f}%")

if unique_signatures / n < 0.20:
    warnings_found.append(
        f"Malware diversity low: only {100*unique_signatures/n:.1f}% unique signatures. "
        f"Model may overfit to dominant family."
    )
else:
    print(f"  Healthy diversity")


# ── 8. FINAL SUMMARY ───────────────────────────────────────────────
section("FINAL AUDIT SUMMARY")

if shortcuts_found:
    print("\nSHORTCUTS DETECTED (model WILL exploit these):")
    for i, s in enumerate(shortcuts_found, 1):
        print(f"  {i}. {s}")
    print("\nFIX REQUIRED before training.")
elif warnings_found:
    print(f"\nWARNINGS ({len(warnings_found)}):")
    for w in warnings_found:
        print(f"  - {w}")
    print("\nProceed with caution. Phase 7 (temporal removal) is mandatory.")
else:
    print("\nNO SHORTCUTS DETECTED")
    print("Dataset is robust. Ready for Phase 6.")