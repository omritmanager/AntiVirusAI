"""
anti_poison_filter.py — Stage 2 of the benign-corpus augmentation pipeline.

Takes Stage 1's extraction JSONL and decides, per file, whether it is safe to
label as ground-truth benign. Two independent checks, in order:

1. AUTO-DROP (mandatory, not a judgment call): cross-check every SHA-256
   against the full known-malware hash set from
   data/datasets/modern_malware_features.json (48k+ hashes), reusing the same
   streaming regex reader build_hash_db.py already uses (~2s for the 1GB
   file). Anything that matches is dropped regardless of what the current
   model said about it — this is the check that actually protects against
   label poisoning.

2. TIERED LABELING for the survivors, keyed off the CURRENT production
   model's verdict (captured by Stage 1):
     - model already says SAFE          -> auto-accept (still subject to
       Stage 3's dedup/diversity checks before it's really used for training)
     - model says MALWARE/POTENTIAL_ZERODAY, but the file carries a TRUSTED
       Authenticode signature from a publisher on the curated allowlist below
                                          -> auto-accept, tagged so it's
                                             traceable later
     - anything else in the flagged bucket (unsigned, untrusted chain, or a
       signer not on the allowlist)       -> NOT auto-labeled. Written to a
       CSV for one-batch human review; nothing here becomes ground-truth
       benign until a person has looked at the list.

This mirrors this project's own precedent in merge_and_validate_benign.py
(hash cross-check against the malware set before merging a new benign batch),
extended with the signature-based tiering because trusting an 18k-file corpus
wholesale — including the subset the model itself is suspicious of — is
exactly the label-poisoning risk this stage exists to catch.

Usage:
  python src/augmentation/anti_poison_filter.py \\
      --input data/augmentation/extracted_dry_run.jsonl \\
      --out-dir data/augmentation
"""
from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from avscan import config  # noqa: E402

# build_hash_db.py is a top-level script, not a package module — load it by
# path rather than duplicating its streaming SHA-256 reader.
_spec = importlib.util.spec_from_file_location("build_hash_db", ROOT / "build_hash_db.py")
_build_hash_db = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_build_hash_db)
stream_sha_firstseen = _build_hash_db.stream_sha_firstseen

MALWARE_JSON = config.MALWARE_FEATURES_JSON

# Curated starting list — publishers actually expected in a "software installed
# on a real machine" harvest. Not exhaustive by design: anything genuinely
# legitimate but missing here falls through to human review rather than being
# silently mislabeled, which is the safe failure direction. The script also
# prints every TRUSTED-but-not-allowlisted signer it saw among the flagged
# bucket, so the list can be extended deliberately rather than guessed at.
TRUSTED_PUBLISHER_ALLOWLIST = {
    "microsoft corporation", "microsoft windows", "microsoft windows publisher",
    "adobe inc.", "adobe systems incorporated",
    "google llc", "google inc",
    "mozilla corporation",
    "oracle america, inc.",
    "jetbrains s.r.o.",
    "autodesk, inc.",
    "postgresql global development group",
    "the document foundation",
    "valve corp.", "valve corporation",
    "dropbox, inc.",
    "apple inc.",
    "intel corporation",
    "nvidia corporation",
    "advanced micro devices, inc.",
    "lenovo", "lenovo pccg",
    "anthropic, pbc",
    "vmware, inc.", "vmware inc",
    "docker inc",
    "steam", "epic games, inc.",
    "7-zip",

    # Added after the dry run surfaced these as TRUSTED-but-unlisted signers
    # (2026-07-26, 300-file sample) — all recognizable, well-established
    # publishers/open-source maintainers, added deliberately rather than
    # blanket-trusting every unlisted signer. Two individual signers seen in
    # that same dry run ("David Sparer", "Fotis Zafiropoulos") were NOT added
    # here — not confidently identifiable — and still fall through to manual
    # review.
    "amazon.com services llc",
    "signpath foundation",              # OSS code-signing service (e.g. Wireshark)
    "glarysoft ltd",                    # Glary Utilities
    "bandisoft international inc.",     # Bandizip / Bandicam
    "kovid goyal",                      # Calibre e-book manager author
    "cyberghost srl",                   # CyberGhost VPN
    "kicad services corporation",       # KiCad EDA
    "idm computer solutions, inc.",     # UltraEdit
    "g10 code gmbh",                    # GnuPG (Werner Koch)
    "openvpn inc.",
    "barco n.v.",
    "discord inc.",
    "iobit co., ltd",                   # Advanced SystemCare / Driver Booster
    "safer-networking ltd.",            # Spybot Search & Destroy
    "code sector pty ltd",              # TeraCopy
    "sublime hq pty ltd",               # Sublime Text
    "opera norway as",
    "imagemagick studio llc",
    "irfan skiljan",                    # IrfanView author
    "hashicorp, inc.",
    "cloudflare, inc.",
    "iterate gmbh",                     # Cyberduck
    "mirillis sp. z o.o.",              # Mirillis Action!
    "now.gg, inc",
}


def normalize_signer(name: str | None) -> str:
    return (name or "").strip().lower()


def load_malware_hashes(path: Path) -> set[str]:
    print(f"  Streaming {path.name} for known-malware SHA-256 hashes...")
    hashes = set()
    for sha, _first_seen in stream_sha_firstseen(path):
        hashes.add(sha)
    print(f"  {len(hashes):,} unique malware hashes loaded")
    return hashes


def read_jsonl(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", type=Path, required=True,
                    help="Stage 1 extraction JSONL")
    ap.add_argument("--out-dir", type=Path, default=ROOT / "data" / "augmentation")
    ap.add_argument("--reports-dir", type=Path, default=ROOT / "reports")
    ap.add_argument("--trust-all-valid-signatures", action="store_true",
                    help="Accept ANY file whose Authenticode signature verifies as "
                         "TRUSTED against Windows' trust store, instead of requiring "
                         "the signer to be on TRUSTED_PUBLISHER_ALLOWLIST. The full "
                         "run surfaced 346 distinct legitimate signers, far past what "
                         "a hand-curated list can cover; a valid chain to a Windows "
                         "root already means a CA identity-verified a legal entity, "
                         "and the known-malware hash drop still runs first either way. "
                         "Signer names are still recorded per accepted record so the "
                         "decision stays auditable.")
    args = ap.parse_args()

    if not args.input.exists():
        print(f"[STOP] input not found: {args.input}")
        return 1
    if not MALWARE_JSON.exists():
        print(f"[STOP] malware features JSON not found: {MALWARE_JSON}")
        return 1

    print("=" * 70)
    print("STAGE 2: ANTI-POISONING FILTER + SIGNATURE TIERING")
    print("=" * 70)

    print("\n[1] Loading known-malware hash set...")
    malware_hashes = load_malware_hashes(MALWARE_JSON)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    args.reports_dir.mkdir(parents=True, exist_ok=True)
    accepted_path = args.out_dir / (args.input.stem + ".accepted.jsonl")
    dropped_path = args.out_dir / (args.input.stem + ".dropped_malware_match.jsonl")
    review_csv = args.reports_dir / "manual_review_flagged_benign.csv"

    print(f"\n[2] Scanning {args.input.name}...")
    n_total = n_poisoned = n_auto_safe = n_trusted_override = n_review = n_error = 0
    unlisted_trusted_signers = {}   # signer -> count, seen but not on the allowlist

    with open(accepted_path, "w", encoding="utf-8") as acc_f, \
         open(dropped_path, "w", encoding="utf-8") as drop_f, \
         open(review_csv, "w", newline="", encoding="utf-8") as rev_f:

        rev_writer = csv.writer(rev_f)
        rev_writer.writerow(["path", "sha256", "size", "ml_verdict", "lgbm_prob",
                             "signature_status", "signature_signer"])

        for rec in read_jsonl(args.input):
            n_total += 1
            sha = rec["sha256"]

            if sha in malware_hashes:
                n_poisoned += 1
                drop_f.write(json.dumps({"path": rec["path"], "sha256": sha,
                                         "reason": "sha256 matches known-malware hash"}) + "\n")
                continue

            verdict = rec.get("ml_verdict")
            sig_status = rec.get("signature_status")
            signer = normalize_signer(rec.get("signature_signer"))

            if verdict == "SAFE":
                n_auto_safe += 1
                rec["accept_reason"] = "model_safe"
                acc_f.write(json.dumps(rec) + "\n")
            elif verdict in ("MALWARE", "POTENTIAL_ZERODAY"):
                allowlisted = signer in TRUSTED_PUBLISHER_ALLOWLIST
                if sig_status == "TRUSTED" and (allowlisted
                                                or args.trust_all_valid_signatures):
                    n_trusted_override += 1
                    rec["accept_reason"] = ("trusted_signer_override" if allowlisted
                                            else "valid_signature_any_signer")
                    acc_f.write(json.dumps(rec) + "\n")
                else:
                    n_review += 1
                    if sig_status == "TRUSTED" and signer:
                        unlisted_trusted_signers[signer] = unlisted_trusted_signers.get(signer, 0) + 1
                    rev_writer.writerow([rec["path"], sha, rec.get("size"),
                                        verdict, rec.get("lgbm_prob"),
                                        sig_status, rec.get("signature_signer")])
            else:  # ERROR or unexpected verdict — safest default is human review
                n_review += 1
                rev_writer.writerow([rec["path"], sha, rec.get("size"),
                                    verdict, rec.get("lgbm_prob"),
                                    sig_status, rec.get("signature_signer")])
                n_error += 1

    print(f"\n{'='*70}")
    print("STAGE 2 COMPLETE")
    print(f"{'='*70}")
    print(f"  Total records:            {n_total:,}")
    print(f"  Dropped (malware hash):   {n_poisoned:,}")
    print(f"  Auto-accepted (SAFE):     {n_auto_safe:,}")
    print(f"  Auto-accepted (signed):   {n_trusted_override:,}")
    print(f"  Sent to manual review:    {n_review:,}  (of which ERROR verdict: {n_error:,})")
    print(f"\n  Accepted:      {accepted_path}")
    print(f"  Dropped log:   {dropped_path}")
    print(f"  Review CSV:    {review_csv}")

    if unlisted_trusted_signers:
        print(f"\n  TRUSTED signers seen but NOT on the allowlist "
              f"(consider adding to TRUSTED_PUBLISHER_ALLOWLIST):")
        for signer, count in sorted(unlisted_trusted_signers.items(),
                                    key=lambda kv: -kv[1]):
            # Windows consoles are frequently cp1252, which chokes on some
            # signer names (accents, non-Latin scripts). Never let a print
            # crash a run whose output files are already safely written.
            line = f"    {count:>4}x  {signer}"
            print(line.encode(sys.stdout.encoding or "utf-8", errors="replace")
                 .decode(sys.stdout.encoding or "utf-8"))

    if n_review > 0:
        print(f"\n  ACTION NEEDED: review {review_csv} before Stage 3 — "
              f"nothing in it is treated as benign yet.")

    print(f"\nNext: Stage 3 - dedup + grouping")
    print(f"      python src\\augmentation\\cluster_and_dedup.py --input {accepted_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
