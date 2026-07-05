"""
Remove overlapping SHA-256 hashes from benign dataset.
Hashes that appear in BOTH benign and malware are kept ONLY in malware
(because MalwareBazaar has verified them as malicious).
"""
import json
from pathlib import Path
import shutil
from datetime import datetime

ROOT = Path(r"C:\Users\omri9\Desktop\School\Final Project")
BENIGN_FILE  = ROOT / "data" / "datasets" / "modern_benign_features.json"
MALWARE_FILE = ROOT / "data" / "datasets" / "modern_malware_features.json"

print("=" * 70)
print("FIX DATASET OVERLAP")
print("=" * 70)

# Load both
print("\n[1] Loading datasets...")
with open(BENIGN_FILE) as f:
    benign = json.load(f)
with open(MALWARE_FILE) as f:
    malware = json.load(f)

print(f"  Benign before:  {len(benign['samples']):,}")
print(f"  Malware before: {len(malware['samples']):,}")

# Find overlap
print("\n[2] Finding overlapping hashes...")
malware_hashes = {s["sha256"].lower() for s in malware["samples"]}
overlapping = [s for s in benign["samples"] if s["sha256"].lower() in malware_hashes]

print(f"  Overlapping samples: {len(overlapping)}")
for s in overlapping:
    print(f"    - {s['sha256'][:16]}...  file: {s.get('file_name', 'unknown')}")

# Save details of removed samples
removed_log = ROOT / "data" / "datasets" / "removed_overlap_samples.json"
with open(removed_log, "w", encoding="utf-8") as f:
    json.dump({
        "removed_at": datetime.now().isoformat(),
        "reason": "Sample appears in both benign and malware datasets - kept as malware",
        "removed_from": "benign",
        "count": len(overlapping),
        "samples": [
            {
                "sha256": s["sha256"],
                "file_name": s.get("file_name", ""),
                "file_size": s.get("file_size", 0),
            }
            for s in overlapping
        ]
    }, f, indent=2)
print(f"\n  Log saved: {removed_log}")

# Backup original
backup = BENIGN_FILE.with_suffix(".json.backup_before_overlap_fix")
if not backup.exists():
    print(f"\n[3] Backing up original to:\n    {backup.name}")
    shutil.copy2(BENIGN_FILE, backup)
else:
    print(f"\n[3] Backup already exists: {backup.name}")

# Remove from benign
print(f"\n[4] Removing {len(overlapping)} overlapping samples from benign...")
clean_samples = [
    s for s in benign["samples"]
    if s["sha256"].lower() not in malware_hashes
]

benign["samples"]       = clean_samples
benign["total_samples"] = len(clean_samples)
benign["cleaned_at"]    = datetime.now().isoformat()
benign["removed_overlap_count"] = len(overlapping)

# Save cleaned benign
print(f"\n[5] Saving cleaned benign file...")
with open(BENIGN_FILE, "w", encoding="utf-8") as f:
    json.dump(benign, f)

# Verify
print("\n[6] Verifying...")
with open(BENIGN_FILE) as f:
    check = json.load(f)
check_hashes = {s["sha256"].lower() for s in check["samples"]}
remaining_overlap = check_hashes & malware_hashes

print(f"  Benign after:   {len(check['samples']):,}")
print(f"  Removed:        {len(benign['samples']) - len(check['samples']) + len(overlapping)} (verify=clean)")
print(f"  Remaining overlap: {len(remaining_overlap)}")

if remaining_overlap == set():
    print("\n" + "=" * 70)
    print("SUCCESS - datasets are now clean")
    print("=" * 70)
    print(f"\n  Benign:  {len(check['samples']):,}")
    print(f"  Malware: {len(malware['samples']):,}")
    print(f"  Total:   {len(check['samples']) + len(malware['samples']):,}")
    print(f"\n  Backup of original benign: {backup.name}")
    print(f"  Re-run final_dataset_validation.py to confirm")
else:
    print("\nERROR: overlap still present!")