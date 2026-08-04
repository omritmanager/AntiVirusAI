"""
classify_friend_extraction.py — one-off: add ml_verdict/lgbm_prob/if_score to
a JSONL extracted by friend_extract_verify.py in extraction-only mode (no
--models-dir, so those fields are missing).

Uses the SAME production Engine.classify_vector — the vectors were already
extracted with the exact pinned library versions and verified byte-for-byte
identical to this project's own pipeline (see the parity check earlier this
session), so classifying them locally is equivalent to classifying the
original files directly. No PE parsing needed here, just predict_proba on
already-extracted vectors — fast.

Usage:
  python src/augmentation/classify_friend_extraction.py \\
      --input "C:\\Users\\omri9\\Desktop\\results.jsonl" \\
      --output data/augmentation/extracted_full.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from avscan.engine import Engine  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()

    print("Loading Engine...")
    engine = Engine(load_if=True)

    print(f"Classifying {args.input.name}...")
    t0 = time.time()
    n = n_err = 0
    counts = {"MALWARE": 0, "POTENTIAL_ZERODAY": 0, "SAFE": 0, "ERROR": 0}

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.input, "r", encoding="utf-8") as in_f, \
         open(args.output, "w", encoding="utf-8") as out_f:
        for line in in_f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            n += 1
            if "ml_verdict" in rec and rec["ml_verdict"]:
                # already classified (e.g. a re-run) — keep as-is
                out_f.write(json.dumps(rec) + "\n")
                counts[rec["ml_verdict"]] = counts.get(rec["ml_verdict"], 0) + 1
                continue
            try:
                vec = np.array(rec["features"], dtype=np.float32)
                ml = engine.classify_vector(vec, use_if=True)
                rec["ml_verdict"] = ml.ml_verdict
                rec["lgbm_prob"] = ml.lgbm_prob
                rec["if_score"] = ml.if_score
                counts[ml.ml_verdict] += 1
            except Exception as e:
                rec["ml_verdict"] = "ERROR"
                rec["lgbm_prob"] = None
                rec["if_score"] = None
                rec["error"] = str(e)
                counts["ERROR"] += 1
                n_err += 1
            out_f.write(json.dumps(rec) + "\n")

            if n % 2000 == 0:
                print(f"  [{n:,}]  malware={counts['MALWARE']:,} "
                      f"zeroday={counts['POTENTIAL_ZERODAY']:,} safe={counts['SAFE']:,}")

    elapsed = time.time() - t0
    flagged = counts["MALWARE"] + counts["POTENTIAL_ZERODAY"]
    print(f"\n{'='*70}")
    print(f"DONE — {n:,} records classified in {elapsed:.1f}s")
    print(f"{'='*70}")
    print(f"  MALWARE:           {counts['MALWARE']:,}")
    print(f"  POTENTIAL_ZERODAY: {counts['POTENTIAL_ZERODAY']:,}")
    print(f"  SAFE:              {counts['SAFE']:,}")
    print(f"  ERROR:             {counts['ERROR']:,}")
    print(f"\n  FLAGGED on real clean software: {flagged:,}/{n:,} = {100*flagged/n:.1f}%")
    print(f"\n  Output: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
