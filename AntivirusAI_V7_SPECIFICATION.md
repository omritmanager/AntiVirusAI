# AntivirusAI V7 — Technical Specification

**Document version:** 1.1 (adds SHA-256 hash-lookup comparison layer)
**Target:** Claude Code build agent
**Project root:** `C:\Users\<user>\Desktop\School\Final Project`
**Status of models:** Trained, validated, and verified (96.83% detection on real MalwareBazaar samples, 0.36% FPR on live system files)

---

## 0. Purpose & Critical Context

This document specifies a desktop malware scanner built around an already-trained, already-validated ML pipeline (LightGBM + optional Isolation Forest) operating on EMBER v2 PE feature vectors.

**The single most important rule of this project:** the inference environment MUST be byte-for-byte identical to the training environment. A long debugging history (project versions V6 and V7) proved that mismatched library versions silently corrupt predictions. The software must enforce and verify this.

### Locked environment (NON-NEGOTIABLE)
The build MUST pin and verify exactly these versions:

| Package | Version | Why it matters |
|---|---|---|
| python | 3.11.x | venv baseline |
| lief | 0.17.6 (`0.17.6-08dc3b7f`) | feature extraction parity; V6 failed on LIEF mismatch |
| scikit-learn | 1.3.2 | model was pickled under 1.3.2; 1.8.0 silently broke predictions |
| lightgbm | 4.5.0 | trained under 4.5.0 |
| numpy | 1.26.4 | array semantics |
| ember | git `elastic/ember` @ commit `d97a0b523de02f3fe5ea6089d080abacab6ee931`, **with the FeatureHasher patch below** | feature extraction |

### Required EMBER source patch
The installed `ember/features.py` has a bug at the `entry_name_hashed` line (~line 192). The single-bracket call:
```python
entry_name_hashed = FeatureHasher(50, input_type="string").transform([raw_obj['entry']]).toarray()[0]
```
MUST be patched to double-bracket:
```python
entry_name_hashed = FeatureHasher(50, input_type="string").transform([[raw_obj['entry']]]).toarray()[0]
```
The installer/setup step must apply this patch automatically and verify it took effect, because under scikit-learn 1.3.2 the unpatched version raises `ValueError: Samples can not be a single string`.

---

## 1. High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Presentation Layer                                       │
│    • CLI (argparse)        • GUI (Claude Code's choice)   │
└───────────────────────────┬─────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────┐
│  Scan Orchestrator                                        │
│    • folder walk (recursive)  • whitelist filter          │
│    • progress reporting       • result aggregation        │
└───────────────────────────┬─────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────┐
│  Inference Engine  (the validated core — DO NOT alter     │
│                     the math)                             │
│    0. SHA-256 hash-lookup against local baseline DB       │
│         (signature-based baseline — runs alongside ML,    │
│          NEVER changes the ML verdict)                    │
│    1. read bytes                                          │
│    2. EMBER PEFeatureExtractor(feature_version=2)         │
│    3. validate vector (len==2381, no NaN/Inf)             │
│    4. zero temporal indices                               │
│    5. LightGBM.predict_proba → threshold 0.40             │
│    6. (optional) Isolation Forest second opinion          │
│    → ml_verdict:   MALWARE | POTENTIAL_ZERODAY | SAFE     │
│    → hash_verdict: KNOWN_MALWARE | NOT_IN_DB              │
└───────────────────────────┬─────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────┐
│  Action Layer                                             │
│    • quarantine (move + neutralize)                       │
│    • JSON report writer                                   │
└─────────────────────────────────────────────────────────┘
```

Both CLI and GUI call the SAME orchestrator and engine. No duplicated inference logic.

---

## 2. The Inference Engine (Core — reference implementation exists)

A working, validated reference implementation already exists as `scan_folder_v7.py`. The engine module MUST reproduce its logic exactly. Key constants:

```python
TEMPORAL_INDICES = [1557, 1558, 1599, 1602, 1609, 1610, 1612, 1613, 1616, 1617]
LGBM_THRESHOLD   = 0.40          # loaded from thresholds.json "recommended"
IF_THRESHOLD     = 0.3694358641837102   # from if_config.json "anomaly_threshold"
EXPECTED_DIM     = 2381
VALID_EXT        = {".exe", ".dll", ".sys", ".scr", ".com", ".ocx", ".cpl", ".drv"}
```

### Compatibility shims (must run before importing ember)
```python
import lief
for a in ['bad_format','bad_file','pe_error','parser_error','read_out_of_bound','not_found']:
    if not hasattr(lief, a):
        setattr(lief, a, type(a, (Exception,), {}))
import numpy as np
for nm, ty in [('int',int),('bool',bool),('float',float),('object',object)]:
    if not hasattr(np, nm): setattr(np, nm, ty)
```

### Verdict logic (exact)
```
vec = extractor.feature_vector(bytes)            # len must be 2381
if invalid(vec): return ERROR
vec[TEMPORAL_INDICES] = 0.0
p = lgbm.predict_proba(vec.reshape(1,-1))[0,1]
if p >= LGBM_THRESHOLD: return MALWARE (prob=p)
if IF_enabled:
    s = -iso.score_samples(vec.reshape(1,-1))[0]
    if s >= IF_THRESHOLD: return POTENTIAL_ZERODAY (if_score=s)
return SAFE (prob=p)
```

**Do not** change thresholds, indices, or the order of operations. These are the validated values.

---

## 3. Model & Asset Locations

```
models/v7/
    lgbm_v7_correct.pkl     ← PRIMARY model (train-only, no leakage). USE THIS ONE.
    isolation_forest.pkl    ← optional second layer
    thresholds.json         ← load "recommended" (=0.40) for LightGBM
    if_config.json          ← load "anomaly_threshold" for IF
```

**Important:** Use `lgbm_v7_correct.pkl`, NOT `lgbm_v7.pkl`. The latter was trained on train+val (data leakage) and must never be used for inference. The build should ideally refuse to load the leaky model, or warn loudly.

---

## 3.5. Feature: SHA-256 Hash-Lookup Baseline (the key academic comparison)

This is a deliberate experiment, not a production feature. Its purpose is to **demonstrate the value of the ML model over traditional signature-based detection**: a hash lookup only catches malware whose exact hash is already known, whereas the ML model catches novel/unseen variants. The headline result we want to produce and display is:

> "Simulated zero-day malware is invisible to SHA-256 signature matching, but our model detects ~96% of it."

### 3.5.1 The simulated zero-day split (why and how)

Because all malware originates from MalwareBazaar, putting every hash into the baseline DB would let the lookup catch 100% and leave nothing to demonstrate. So we split the malware hashes:

- **80% → "known"**: their SHA-256 goes INTO the baseline DB. These simulate malware already published to global signature feeds.
- **20% → "simulated zero-day"**: their SHA-256 is deliberately **withheld** from the DB. These simulate brand-new malware that has not yet reached any signature feed.

The split MUST be:
- **Deterministic** (seed=42) so results are reproducible.
- **Disjoint from / aligned with the model's training split is NOT required** — the model already detects these samples regardless; what matters is only which hashes are in the baseline DB.
- Logged: the builder script writes which hashes went to "known" vs "zero-day" so the experiment is auditable.

### 3.5.2 Builder script: `build_hash_db.py`

A standalone script (NOT part of the runtime scanner) that constructs the baseline DB from the malware dataset:

```
Input:  data/datasets/modern_malware_features.json   (has per-sample sha256 + first_seen)
        (and/or a plain list of known-malware SHA-256 hashes)
Process:
  1. Collect all malware SHA-256 hashes.
  2. Shuffle deterministically (seed=42).
  3. Take first 80% → insert into SQLite DB table `known_malware`.
  4. Hold out last 20% → write to data/hashdb/simulated_zeroday_hashes.txt (NOT inserted).
Output: data/hashdb/baseline.sqlite
        data/hashdb/known_hashes.txt        (the 80% that were inserted)
        data/hashdb/simulated_zeroday_hashes.txt  (the withheld 20%)
        data/hashdb/split_manifest.json     (counts, seed, timestamps)
```

If the dataset JSON lacks a `sha256` field per sample, the script must compute it from the original file bytes if available, or fall back to a user-supplied hash list. Surface clearly which path was used.

### 3.5.3 SQLite schema

```sql
CREATE TABLE known_malware (
    sha256      TEXT PRIMARY KEY,   -- lowercase hex
    family      TEXT,               -- nullable (dataset has no family labels → "unknown")
    first_seen  TEXT,               -- nullable
    added_at    TEXT
);
CREATE INDEX idx_sha ON known_malware(sha256);
```

PRIMARY KEY on sha256 gives O(log n) lookups and scales to millions of rows. Lookups normalize to lowercase hex before querying.

### 3.5.4 Lookup module: `hashdb.py`

```python
class HashDB:
    def __init__(self, sqlite_path): ...
    def contains(self, sha256_hex: str) -> bool        # single lookup
    def lookup(self, sha256_hex: str) -> dict | None    # returns row or None
    def count(self) -> int
```

- Must open the DB read-only during scans.
- Must handle a missing DB file gracefully: if no DB is present, the hash layer is simply reported as "unavailable" and the scan proceeds with ML only. The scanner must NEVER crash because the hash DB is absent.

### 3.5.5 How the two verdicts combine in the engine

The hash lookup and the ML model are computed **independently** for every file. The hash result NEVER overrides or feeds into the ML result — they are reported side by side so the comparison is honest. For each scanned file record both:

- `hash_verdict`: `KNOWN_MALWARE` (sha256 in DB) or `NOT_IN_DB`.
- `ml_verdict`: `MALWARE` / `POTENTIAL_ZERODAY` / `SAFE` (unchanged from §2).

Then derive a `comparison_tag` for reporting:

| ml_verdict | hash_verdict | comparison_tag | meaning |
|---|---|---|---|
| MALWARE | KNOWN_MALWARE | `BOTH_CAUGHT` | both methods agree |
| MALWARE / ZERODAY | NOT_IN_DB | `ML_ONLY_CATCH` | **the headline case** — ML caught what signatures missed |
| SAFE | KNOWN_MALWARE | `HASH_ONLY_CATCH` | ML missed a known sample (a model false-negative worth inspecting) |
| SAFE | NOT_IN_DB | `BOTH_CLEAR` | agree it's clean |

### 3.5.6 Reporting the experiment

The JSON report (see §8) gains a `hash_comparison` block summarizing the experiment, e.g.:

```json
"hash_comparison": {
  "db_path": "data/hashdb/baseline.sqlite",
  "known_hashes_in_db": 38945,
  "files": {
    "BOTH_CAUGHT": 98,
    "ML_ONLY_CATCH": 24,
    "HASH_ONLY_CATCH": 0,
    "BOTH_CLEAR": 25
  },
  "headline": {
    "simulated_zeroday_scanned": 24,
    "caught_by_hash": 0,
    "caught_by_ml": 23,
    "ml_zeroday_detection_rate": 0.958
  }
}
```

For the academic demo specifically, provide a dedicated CLI subcommand and GUI view that scans a folder of the **simulated-zeroday** samples and prints the comparison table, making the point in one screen:

```
SIGNATURE (SHA-256) vs ML — simulated zero-day folder
  Files scanned:            24
  Caught by SHA-256 lookup:  0   (0.0%)   ← signatures are blind to new malware
  Caught by ML model:       23   (95.8%)  ← model generalizes
```

### 3.5.7 CLI / GUI surface for the hash layer

- CLI: `--hash-db <path>` to point at the SQLite DB; `--hash-compare` to include the comparison block; a dedicated `avscan demo-zeroday <folder>` subcommand for the headline table above.
- GUI: a column "Signature match (SHA-256)" alongside the ML verdict column, and a summary card showing the ML-only-catch count. A checkbox "Compare against signature DB".

---



- Input: a folder path.
- Walk recursively (`Path.rglob("*")`), include only files whose suffix is in `VALID_EXT`.
- Sequential processing (one file after another) — chosen for simplicity and determinism. No multiprocessing required.
- Per-file: run engine (ML + SHA-256 hash lookup), collect ml_verdict + hash_verdict + comparison_tag + probability/scores + full path + SHA-256.
- Show live progress; print flagged files as they're found.
- Skipped/whitelisted files counted separately from scanned files.

---

## 5. Feature: System-File Whitelist (FP avoidance)

Goal: avoid false positives on legitimate OS files (e.g. cmd.exe scored 0.556 in testing — near threshold).

Requirements:
- Skip files located under (case-insensitive, configurable):
  - `C:\Windows\System32`
  - `C:\Windows\SysWOW64`
  - `C:\Windows\WinSxS`
- Whitelisted files are NOT sent to the engine; they're tallied as `SKIPPED_SYSTEM`.
- The whitelist must be a config file (JSON list of path prefixes) so it can be edited without code changes.
- The whitelist must be toggleable (a `--no-whitelist` CLI flag and a GUI checkbox) so the academic evaluation can still scan System32 when needed for the sanity-check demonstration.

---

## 6. Feature: Quarantine

When a file is classified MALWARE (only MALWARE; POTENTIAL_ZERODAY is reported but NOT auto-quarantined — it needs human review):

- Move the file to a quarantine directory: `quarantine/` under project root (configurable).
- Neutralize it so it can't execute from quarantine:
  - rename with a `.quarantine` suffix, AND
  - optionally XOR the bytes with a fixed key (e.g. 0x55) so the stored copy is not a live executable. Store the fact that it was XOR'd in the metadata so restore is possible.
- Write a quarantine manifest entry: original path, quarantine path, SHA-256, timestamp, lgbm_prob, whether XOR'd.
- Provide a restore function (CLI subcommand + GUI button) that reverses the move and XOR using the manifest.
- Quarantine must be atomic-ish: copy → verify hash → remove original. Never delete the original before the quarantined copy is verified.
- Handle permission errors gracefully (system files in use, access denied) — log and continue, never crash the scan.

---

## 7. Feature: Isolation Forest Toggle

- IF is an optional second layer, **off by default is acceptable** but must be toggleable:
  - CLI: `--use-if` to enable.
  - GUI: a checkbox "Enable zero-day anomaly layer (experimental)".
- Document in the UI that the IF layer has limited standalone value on this dataset (this is a known, reported research finding — ~7% standalone detection). It exists for completeness and zero-day exploration.

---

## 8. Output: JSON Report

Single detailed JSON file per scan. Suggested location: `evaluation/scan_<timestamp>.json`. Structure:

```json
{
  "scan_id": "2026-06-05T08-30-00",
  "started_at": "...",
  "finished_at": "...",
  "duration_seconds": 12.4,
  "config": {
    "folder": "C:\\...",
    "lgbm_threshold": 0.40,
    "if_enabled": false,
    "if_threshold": 0.3694358641837102,
    "whitelist_enabled": true,
    "hash_db": "data/hashdb/baseline.sqlite",
    "hash_compare_enabled": true,
    "model": "lgbm_v7_correct.pkl"
  },
  "environment": {
    "lief": "0.17.6-08dc3b7f",
    "sklearn": "1.3.2",
    "lightgbm": "4.5.0",
    "numpy": "1.26.4"
  },
  "summary": {
    "total_files_seen": 200,
    "scanned": 151,
    "skipped_system": 45,
    "errors": 4,
    "malware": 122,
    "potential_zeroday": 0,
    "safe": 25,
    "flagged_pct": 80.79
  },
  "hash_comparison": {
    "db_path": "data/hashdb/baseline.sqlite",
    "known_hashes_in_db": 38945,
    "files": {
      "BOTH_CAUGHT": 98,
      "ML_ONLY_CATCH": 24,
      "HASH_ONLY_CATCH": 0,
      "BOTH_CLEAR": 25
    },
    "headline": {
      "simulated_zeroday_scanned": 24,
      "caught_by_hash": 0,
      "caught_by_ml": 23,
      "ml_zeroday_detection_rate": 0.958
    }
  },
  "results": [
    {
      "path": "C:\\...\\sample.exe",
      "sha256": "...",
      "ml_verdict": "MALWARE",
      "hash_verdict": "NOT_IN_DB",
      "comparison_tag": "ML_ONLY_CATCH",
      "lgbm_prob": 0.998,
      "if_score": null,
      "quarantined": true,
      "quarantine_path": "quarantine\\sample.exe.quarantine"
    }
  ]
}
```

---

## 9. Startup Self-Check (MANDATORY)

On every launch (CLI and GUI), before any scan, run a self-check and refuse to proceed if it fails:

1. Verify installed versions == locked versions (lief, sklearn, lightgbm, numpy). Hard-fail with a clear message naming the offending package if any mismatch.
2. Verify the EMBER FeatureHasher patch is present (e.g. test-extract a tiny known PE, or inspect the source line).
3. Verify all model assets exist and load.
4. Run a built-in regression test: load `data/splits_clean/X_test_balanced.npy` + `y_test_balanced.npy` if present, predict, and assert F1 ≈ 0.9936 (within tolerance, e.g. ≥ 0.98). This catches silent model corruption. If the test arrays aren't shipped, embed a small handful of known feature vectors + expected probabilities instead.

This self-check is the project's core defense against the class of bug that broke V6/V7. It must be prominent and non-skippable (a `--skip-selfcheck` escape hatch is allowed but should warn loudly).

---

## 10. CLI Specification

```
avscan scan <folder> [--use-if] [--no-whitelist] [--quarantine|--report-only]
                     [--hash-db <path>] [--hash-compare] [--output <path.json>]
avscan demo-zeroday <folder> [--hash-db <path>]   # headline SHA-256 vs ML table
avscan restore <sha256|all>          # restore from quarantine
avscan selfcheck                     # run environment + regression check only
avscan list-quarantine               # show manifest
```

(The baseline hash DB is built separately, once, with `build_hash_db.py` — not a runtime subcommand.)

- Default action on MALWARE: quarantine (per user's choice). `--report-only` overrides to report without moving.
- Exit codes: 0 = clean, 1 = malware found, 2 = scan error/self-check failed.
- Progress bar (e.g. `tqdm`) acceptable but must degrade gracefully to plain prints if unavailable.

---

## 11. GUI Specification

Claude Code chooses the toolkit (recommendation: a clean, native-feeling option; PySide6 or a lightweight web-based shell are both fine). Required elements:

- Folder picker + "Scan" button.
- Live progress (count, current file, % done).
- Results table with columns: file name, ML verdict (color-coded: red=MALWARE, amber=POTENTIAL_ZERODAY, green=SAFE), "Signature match (SHA-256)" (KNOWN_MALWARE / NOT_IN_DB), probability, path.
- A summary card highlighting the **ML-only-catch count** (malware the model caught but the signature DB missed) — the headline academic result.
- Verdict filter (show only malware / all / ML-only catches).
- Toggles: "Enable zero-day anomaly layer", "Skip system files", "Auto-quarantine malware", "Compare against signature DB".
- Buttons: "Open JSON report", "Open quarantine folder", "Restore selected".
- A status bar showing the startup self-check result (green check = environment verified).
- Must never freeze the UI during a scan — run the scan on a worker thread, marshal updates back to the UI thread.

Three tiers only (MALWARE / POTENTIAL_ZERODAY / SAFE) — no confidence band or extra SUSPICIOUS tier, per spec.

---

## 12. Project Structure (suggested)

```
Final Project/
  avscan/
    __init__.py
    engine.py          # inference core (the validated logic)
    hashdb.py          # SHA-256 baseline lookup (SQLite, read-only at scan time)
    orchestrator.py    # folder walk, whitelist, aggregation, ML+hash comparison
    quarantine.py      # move/neutralize/restore + manifest
    selfcheck.py       # environment + regression verification
    report.py          # JSON writer (incl. hash_comparison block)
    config.py          # paths, thresholds, whitelist loading
    cli.py             # argparse entry point
    gui.py             # GUI entry point
  build_hash_db.py     # one-time builder: 80/20 split → SQLite baseline DB
  config/
    whitelist.json
    settings.json
  data/hashdb/         # baseline.sqlite, known_hashes.txt, simulated_zeroday_hashes.txt, split_manifest.json
  models/v7/           # (existing) model assets
  data/splits_clean/   # (existing) regression test arrays
  quarantine/
  evaluation/          # scan reports land here
  requirements.txt     # PINNED versions
  setup_environment.py # installs pinned deps + applies EMBER patch + verifies
  README.md
```

---

## 13. Testing Requirements

- Unit test the engine on a few known feature vectors (malware → MALWARE, benign → SAFE).
- Integration test: scan a small mixed folder, assert summary counts.
- Test quarantine + restore round-trip preserves the original file's SHA-256.
- Test the self-check fails loudly when a version is wrong (can mock).
- Test whitelist correctly skips System32 paths.
- Test the hash DB: a known hash returns KNOWN_MALWARE, a withheld (simulated-zeroday) hash returns NOT_IN_DB, and a missing DB file degrades gracefully (ML-only, no crash).
- Test the comparison_tag logic for all four combinations in §3.5.5.

---

## 14. Non-Goals (explicitly out of scope)

- Real-time / on-access scanning (no kernel driver, no file-system hooks).
- Network calls during scan (the SHA-256 baseline is a LOCAL SQLite DB; no VirusTotal or cloud lookups). The hash layer is offline by design.
- Retraining the model (the model is frozen; this is an inference application).
- Dynamic/behavioral analysis (static features only — a documented limitation).

---

## 15. Known Findings to Surface in the README

For academic context, the README should state:
- Detection: ~96.8% on held-out MalwareBazaar malware; FNR ~0.74% on the balanced test set.
- False positives: 0.36% on live system files (vs ~90% in the failed V6).
- **Signature vs ML comparison: simulated zero-day malware (hashes withheld from the baseline DB) is caught by the ML model at ~96% while SHA-256 signature matching catches 0% of it — the core demonstration of why ML detection generalizes beyond known signatures.**
- The Isolation Forest adds little standalone value (~7%) and is included as an optional, experimental layer.
- The environment-parity requirement is the central engineering lesson; the self-check enforces it.
