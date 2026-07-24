# AntivirusAI V7

A desktop malware scanner built around a **frozen, validated** machine-learning
pipeline (LightGBM + optional Isolation Forest) operating on EMBER v2 PE feature
vectors. This repository is the **application layer** — orchestration, a
signature-vs-ML comparison experiment, quarantine, reporting, a CLI, and a GUI —
wrapped around a model that is *not* retrained here.

> Final-year academic project. The model is frozen and proven: **96.8% detection**
> on real MalwareBazaar malware and **0.36% false positives** on live system files.

---

## The central engineering lesson

This project has a documented history of **silent failures caused by library
version mismatches** between the training machine and the inference machine. Two
earlier versions (V6, V7-early) produced catastrophically wrong predictions
because LIEF / scikit-learn versions differed from training.

The defense is a **mandatory startup self-check** (`avscan selfcheck`) that runs
before *any* scan and refuses to proceed unless:

1. the installed versions exactly match the locked set,
2. the EMBER FeatureHasher patch is present (verified by a live PE extraction),
3. all model assets load, and
4. a built-in regression test reproduces **F1 ≥ 0.98** (expected ≈ 0.9936) on the
   held-out test set — catching silent model corruption.

### Locked environment (NON-NEGOTIABLE)

| Package | Version |
|---|---|
| Python | 3.11.x |
| lief | `0.17.6-08dc3b7f` |
| scikit-learn | `1.3.2` |
| lightgbm | `4.5.0` |
| numpy | `1.26.4` |
| ember | git `elastic/ember@d97a0b52…` **with the FeatureHasher double-bracket patch** |

The EMBER patch (in `ember/features.py`, the `entry_name_hashed` line):

```python
# before (raises ValueError under scikit-learn 1.3.2):
FeatureHasher(50, input_type="string").transform([raw_obj['entry']])
# after (correct):
FeatureHasher(50, input_type="string").transform([[raw_obj['entry']]])
```

---

## Setup

```bash
# 1) Create / activate a Python 3.11 virtual environment, then:
python setup_environment.py            # installs pinned deps, EMBER, applies the patch, verifies
#    (idempotent — safe to re-run; use --verify-only to check without installing)

# 2) Build the SHA-256 signature baseline (one time):
python build_hash_db.py                # 80/20 "simulated zero-day" split, seed=42

# 3) Confirm the environment is locked and the model is intact:
python -m avscan selfcheck
```

`setup_environment.py` **stops** rather than substituting a different version if a
pinned library fails to install — version fidelity is the whole point.

---

## Usage

### CLI

```bash
# Scan a folder (default action quarantines MALWARE; POTENTIAL_ZERODAY is reported only)
python -m avscan scan "C:\path\to\folder"

# Report without moving anything; enable the experimental zero-day layer
python -m avscan scan "C:\path" --report-only --use-if

# Also scan protected OS folders (disables the System32/SysWOW64/WinSxS whitelist)
python -m avscan scan "C:\Windows\System32" --no-whitelist

# The headline experiment: SHA-256 signatures vs ML on simulated zero-day samples
python -m avscan demo-zeroday "C:\path\to\zeroday_samples"

# Quick scan of ONE file, with a popup verdict + AI "why" (see below)
python -m avscan quickscan "C:\path\to\file.exe"
python -m avscan quickscan "C:\path\to\file.exe" --text   # headless, prints instead of popup

# Quarantine management
python -m avscan list-quarantine
python -m avscan restore <sha256>        # or: restore all
```

**Exit codes:** `0` = clean, `1` = malware found, `2` = scan error / self-check failed.

Useful flags: `--hash-db <path>`, `--no-hash-compare`, `--output <report.json>`,
`--explain` (add a Gemini "why" to flagged files), `--skip-selfcheck`.

---

## AI explanation layer (Gemini) — "why does the model think this is malware?"

An **optional** layer explains a verdict in plain language. It runs *after* the
ML verdict, **never changes it**, and the core scan stays fully offline. It uses
LightGBM **SHAP contributions** to find which EMBER feature groups pushed the
decision toward malware, then asks Gemini to explain them.

**Privacy:** only the verdict, probability, and abstract feature-group names
(e.g. "byte-entropy patterns", "imported functions") are sent — **never the file
bytes, file name, or path.** Uses only the Python standard library (`urllib`).

Set your own Gemini API key (never committed):

```bash
setx GEMINI_API_KEY "your-key-here"          # recommended (Windows, per-user)
# or put the key in  config/gemini_key.txt   (git-ignored)
```

Model/language are configurable in `config/settings.json` (`gemini_model`,
`gemini_language` = `he`/`en`). Without a key it degrades gracefully to a local
feature-group summary — the scan still works.

## Right-click "Quick Scan" on any .exe

Add an Explorer context-menu entry so you can right-click an executable and get a
popup verdict (with the Gemini explanation if it looks malicious):

```bash
REM run with the project venv so the entry points at it; per-user, no admin needed
venv_v7\Scripts\python.exe register_context_menu.py --register
venv_v7\Scripts\python.exe register_context_menu.py --status
venv_v7\Scripts\python.exe register_context_menu.py --unregister   REM to remove
```

`--register` sets up three ways to reach it, and `--unregister` removes them all:

- **Right-click a .exe.** On Windows 11 the entry is under **"Show more options"**
  (classic menu) — press **Shift+F10** or Shift+right-click to open it directly.
- **Quick access (no menu): drag any file onto the "AntivirusAI Quick Scan"
  desktop icon.**
- **Send to:** right-click a file ▸ *Send to* ▸ *AntivirusAI Quick Scan*.

The command is `pythonw.exe avscan\quickscan.py "<file>"` — a self-check +
single-file scan + a Tkinter popup that shows a live "scanning…" screen, then the
verdict, the plain-language explanation, and a **"Send to Quarantine"** button for
flagged files. Re-run `--register` if you move the project folder.

> Putting an entry in the Windows 11 **top-level** modern menu (not under "Show
> more options") requires a packaged shell extension (MSIX / `IExplorerCommand`),
> which a plain script cannot create — hence the desktop/Send-To shortcuts above.

### GUI

```bash
python -m avscan.gui
```

Folder picker, threaded scan (never freezes), color-coded results table with a
**"Signature match (SHA-256)"** column, a summary card highlighting the
**ML-only-catch count**, verdict filters, toggles, quarantine/restore buttons, and
a status bar showing the self-check result. Requires PySide6 (`pip install PySide6`).

---

## The SHA-256-vs-ML experiment (the key academic comparison)

A traditional signature scanner only catches malware whose **exact hash** is
already known. To demonstrate why ML generalizes, the malware hashes are split
deterministically (seed=42):

- **80% "known"** → inserted into `data/hashdb/baseline.sqlite` (this build: **38,945** hashes).
- **20% "simulated zero-day"** → deliberately **withheld** (this build: **9,737** hashes).

The hash lookup and the ML model run **independently** for every file — the hash
result never changes the ML verdict. Each file gets a `comparison_tag`:

| ML | Signature (SHA-256) | tag | meaning |
|---|---|---|---|
| flagged | KNOWN_MALWARE | `BOTH_CAUGHT` | both agree |
| flagged | NOT_IN_DB | `ML_ONLY_CATCH` | **headline** — ML caught what signatures missed |
| SAFE | KNOWN_MALWARE | `HASH_ONLY_CATCH` | model false-negative worth inspecting |
| SAFE | NOT_IN_DB | `BOTH_CLEAR` | both agree it's clean |

```
SIGNATURE (SHA-256) vs ML - simulated zero-day folder
  Files scanned:            24
  Caught by SHA-256 lookup:  0   (0.0%)    <- signatures are blind to new malware
  Caught by ML model:       23   (95.8%)   <- model generalizes
```

All hash lookups are **offline** against a local SQLite DB — no VirusTotal, no
cloud, no network calls at scan time.

---

## Known findings (academic context)

- **Detection:** ~96.8% on held-out MalwareBazaar malware; balanced-test FNR ≈ 0.74%
  (validated `test_balanced`: F1 = 0.9936, precision = 0.9946, recall = 0.9926,
  FPR = 0.80%).
- **False positives:** 0.36% on live system files (vs ~90% in the failed V6).
- **Signature vs ML:** simulated zero-day malware (hashes withheld from the
  baseline DB) is caught by ML at **~96%** while SHA-256 matching catches **0%** —
  the core demonstration that ML detection generalizes beyond known signatures.
- **Isolation Forest** adds little standalone value (~7% detection on this dataset)
  and is included only as an optional, experimental zero-day layer (off by default).
- **Environment parity** is the central engineering lesson; the self-check enforces it.

---

## Project structure

```
avscan/
  config.py          paths, validated constants, locked versions, threshold/whitelist loaders
  compat.py          LIEF/NumPy compatibility shims (run before importing ember)
  engine.py          the validated inference core (DO NOT alter the math)
  hashdb.py          read-only SHA-256 baseline lookup (SQLite)
  orchestrator.py    folder walk, whitelist, per-file ML+hash, comparison tags, aggregation
  quarantine.py      move/neutralize (XOR)/restore + manifest
  report.py          JSON report writer (incl. hash_comparison block)
  selfcheck.py       environment + regression verification (the safety net)
  cli.py / gui.py    presentation layers (share the same orchestrator/engine)
build_hash_db.py     one-time builder: 80/20 split -> baseline.sqlite
setup_environment.py installs pinned deps + applies EMBER patch + verifies
requirements.txt     PINNED versions
tests/avscan_tests/  pytest suite (engine, hashdb, orchestrator, quarantine, selfcheck)
```

Run the tests:

```bash
python -m pytest          # 28 tests
```

---

## Non-goals (out of scope)

- Real-time / on-access scanning (no kernel driver or filesystem hooks).
- Network lookups during scan (the SHA-256 baseline is a local SQLite DB, by design).
- Retraining the model (it is frozen; this is an inference application).
- Dynamic/behavioral analysis (static PE features only — a documented limitation).
```
