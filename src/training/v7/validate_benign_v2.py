"""
Compare V2 benign dataset to V1 - did the diversity improve?
"""
import json
import numpy as np
from pathlib import Path
from collections import Counter

ROOT = Path(r"C:\Users\omri9\Desktop\School\Final Project")
V1_FILE = ROOT / "data" / "datasets" / "modern_benign_features.json"
V2_FILE = ROOT / "data" / "datasets" / "modern_benign_features_v2.json"
MALWARE_FILE = ROOT / "data" / "datasets" / "modern_malware_features.json"


def classify_path(fname):
    f = fname.lower()
    if any(x in f for x in ["chrome", "firefox", "edge", "brave", "opera", "vivaldi"]):
        return "Browser"
    if any(x in f for x in ["discord", "slack", "teams", "whatsapp", "telegram", "zoom"]):
        return "Communication"
    if any(x in f for x in ["python", "node", "git", "docker", "rust", "java", "go"]):
        return "Dev Tools"
    if any(x in f for x in ["vscode", "pycharm", "intellij", "sublime", "atom"]):
        return "Code Editor"
    if any(x in f for x in ["steam", "epic", "unity"]):
        return "Gaming"
    if any(x in f for x in ["adobe", "obs", "blender", "vlc", "audacity"]):
        return "Creative"
    if any(x in f for x in ["7zip", "winrar", "notepad", "putty"]):
        return "Utilities"
    return "System/Other"


def analyze(filepath, name):
    print(f"\n{'='*70}")
    print(f"{name}: {filepath.name}")
    print(f"{'='*70}")
    
    if not filepath.exists():
        print(f"NOT FOUND")
        return None
    
    size_mb = filepath.stat().st_size / (1024**2)
    print(f"Size: {size_mb:.1f} MB")
    
    with open(filepath, encoding="utf-8") as f:
        data = json.load(f)
    
    samples = data["samples"]
    print(f"Samples: {len(samples):,}")
    print(f"LIEF version: {data.get('lief_version')}")
    print(f"Feature dim:  {data.get('feature_dim')}")
    
    # Extension breakdown
    exts = Counter()
    for s in samples:
        fname = (s.get("file_name") or "").lower()
        # Get extension - may be in metadata or filename
        if s.get("extension"):
            exts[s["extension"]] += 1
        elif fname.endswith(".dll"): exts[".dll"] += 1
        elif fname.endswith(".exe"): exts[".exe"] += 1
        elif fname.endswith(".sys"): exts[".sys"] += 1
        else: exts["other"] += 1
    
    print(f"\nExtensions:")
    for ext, c in exts.most_common():
        pct = 100 * c / len(samples)
        print(f"  {ext:<8} {c:>6,} ({pct:>5.1f}%)")
    
    # Category breakdown
    cats = Counter()
    for s in samples:
        fname = s.get("file_name") or ""
        # If V2 file has 'category' field, use it. Otherwise guess.
        cat = s.get("category") or classify_path(fname)
        cats[cat] += 1
    
    print(f"\nCategories:")
    for cat, c in cats.most_common():
        pct = 100 * c / len(samples)
        bar = "#" * int(pct / 2)
        print(f"  {cat:<20} {c:>6,} ({pct:>5.1f}%) {bar}")
    
    return {
        "total": len(samples),
        "exts": exts,
        "cats": cats,
        "lief": data.get("lief_version"),
        "dim":  data.get("feature_dim"),
    }


def main():
    print("BENIGN DATASET COMPARISON: V1 vs V2")
    
    v1 = analyze(V1_FILE, "V1 (original)")
    v2 = analyze(V2_FILE, "V2 (improved)")
    
    if v1 is None:
        v1_backup = ROOT / "data" / "datasets" / "modern_benign_features_v1.json.backup"
        if v1_backup.exists():
            print("\nTrying V1 backup...")
            v1 = analyze(v1_backup, "V1 (from backup)")
    
    if v1 is None or v2 is None:
        print("\nCannot compare - missing files")
        return
    
    # Comparison
    print(f"\n{'='*70}")
    print("IMPROVEMENT METRICS")
    print(f"{'='*70}")
    print(f"\n{'Metric':<25} {'V1':>15} {'V2':>15} {'Change':>15}")
    print("-" * 70)
    
    # Total samples
    diff = v2["total"] - v1["total"]
    print(f"{'Total samples':<25} {v1['total']:>15,} {v2['total']:>15,} {diff:>+15,}")
    
    # EXE count
    v1_exe = v1["exts"].get(".exe", 0)
    v2_exe = v2["exts"].get(".exe", 0)
    v1_exe_pct = 100 * v1_exe / v1["total"]
    v2_exe_pct = 100 * v2_exe / v2["total"]
    print(f"{'EXE count':<25} {v1_exe:>10,} ({v1_exe_pct:>4.1f}%) {v2_exe:>10,} ({v2_exe_pct:>4.1f}%) {v2_exe_pct - v1_exe_pct:>+13.1f}%")
    
    # DLL count
    v1_dll = v1["exts"].get(".dll", 0)
    v2_dll = v2["exts"].get(".dll", 0)
    v1_dll_pct = 100 * v1_dll / v1["total"]
    v2_dll_pct = 100 * v2_dll / v2["total"]
    print(f"{'DLL count':<25} {v1_dll:>10,} ({v1_dll_pct:>4.1f}%) {v2_dll:>10,} ({v2_dll_pct:>4.1f}%) {v2_dll_pct - v1_dll_pct:>+13.1f}%")
    
    # System/Other percentage
    v1_sys = v1["cats"].get("System/Other", 0)
    v2_sys = v2["cats"].get("System/Other", 0)
    v1_sys_pct = 100 * v1_sys / v1["total"]
    v2_sys_pct = 100 * v2_sys / v2["total"]
    print(f"{'System/Other %':<25} {v1_sys_pct:>15.1f}% {v2_sys_pct:>15.1f}% {v2_sys_pct - v1_sys_pct:>+14.1f}%")
    
    # Verdict
    print(f"\n{'='*70}")
    print("VERDICT")
    print(f"{'='*70}")
    
    improvements = []
    concerns = []
    
    if v2_exe_pct > v1_exe_pct + 5:
        improvements.append(f"EXE percentage rose from {v1_exe_pct:.1f}% to {v2_exe_pct:.1f}%")
    elif v2_exe_pct < v1_exe_pct + 3:
        concerns.append(f"EXE percentage barely changed ({v1_exe_pct:.1f}% to {v2_exe_pct:.1f}%)")
    
    if v2_sys_pct < v1_sys_pct - 10:
        improvements.append(f"System/Other dropped from {v1_sys_pct:.1f}% to {v2_sys_pct:.1f}%")
    elif v2_sys_pct < v1_sys_pct - 5:
        improvements.append(f"System/Other modestly down: {v1_sys_pct:.1f}% to {v2_sys_pct:.1f}%")
    else:
        concerns.append(f"System/Other still dominant: {v2_sys_pct:.1f}%")
    
    if v2["total"] > v1["total"] + 5000:
        improvements.append(f"Added {v2['total'] - v1['total']:,} new samples")
    
    if v2["lief"] != "0.17.6-08dc3b7f":
        concerns.append(f"LIEF version mismatch: {v2['lief']} (must be 0.17.6-08dc3b7f)")
    
    if v2["dim"] != 2381:
        concerns.append(f"Wrong feature dim: {v2['dim']}")
    
    if improvements:
        print("\nIMPROVEMENTS:")
        for x in improvements: print(f"  + {x}")
    
    if concerns:
        print("\nCONCERNS:")
        for x in concerns: print(f"  - {x}")
    
    if not concerns:
        print("\nV2 is a clear improvement. Proceed to update validators.")
    else:
        print("\nReview concerns before proceeding.")


if __name__ == "__main__":
    main()