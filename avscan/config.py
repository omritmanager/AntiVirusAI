"""
config.py — Central configuration for AntivirusAI V7.

Single source of truth for paths, validated inference constants, the locked
environment versions, and the user-editable thresholds / whitelist / settings.

NOTHING here changes the inference math. The constants in this file are the
*validated* values from `scan_folder_v7.py` and the model asset JSONs. The
threshold loaders read the on-disk JSONs (the same ones the model was
calibrated with) and fall back to the validated literals if a file is missing.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Paths — derived from this file's location, NEVER hardcoded to a user folder.
#   avscan/config.py  ->  ROOT = <project root>
# ─────────────────────────────────────────────────────────────────────────────
AVSCAN_DIR = Path(__file__).resolve().parent
ROOT = AVSCAN_DIR.parent

MODELS_DIR = ROOT / "models" / "v7"
LGBM_PATH = MODELS_DIR / "lgbm_v7_correct.pkl"          # PRIMARY model — USE THIS

# Optional override for EVALUATING a candidate model without swapping the
# production file (set AVSCAN_MODEL to a .pkl path). The startup self-check
# still runs its full regression gate against whatever is loaded, so a bad
# candidate is still refused rather than silently trusted. Relative paths
# resolve against the project root. Never set this in normal use.
_model_override = (os.environ.get("AVSCAN_MODEL") or "").strip()
if _model_override:
    _p = Path(_model_override)
    LGBM_PATH = _p if _p.is_absolute() else (ROOT / _p)
LGBM_LEAKY_PATH = MODELS_DIR / "lgbm_v7.pkl"            # data leakage — REFUSE
THRESHOLDS_JSON = MODELS_DIR / "thresholds.json"

# Regression-test arrays for the startup self-check (§9.4)
SPLITS_CLEAN_DIR = ROOT / "data" / "splits_clean"
X_TEST_BALANCED = SPLITS_CLEAN_DIR / "X_test_balanced.npy"
Y_TEST_BALANCED = SPLITS_CLEAN_DIR / "y_test_balanced.npy"

# Hash-lookup baseline (§3.5)
HASHDB_DIR = ROOT / "data" / "hashdb"
BASELINE_SQLITE = HASHDB_DIR / "baseline.sqlite"
KNOWN_HASHES_TXT = HASHDB_DIR / "known_hashes.txt"
SIMULATED_ZERODAY_TXT = HASHDB_DIR / "simulated_zeroday_hashes.txt"
SPLIT_MANIFEST_JSON = HASHDB_DIR / "split_manifest.json"
# Source dataset the hash DB builder reads (per-sample sha256 + first_seen)
MALWARE_FEATURES_JSON = ROOT / "data" / "datasets" / "modern_malware_features.json"

# Quarantine (§6)
QUARANTINE_DIR = ROOT / "quarantine"
QUARANTINE_MANIFEST = QUARANTINE_DIR / "manifest.json"

# Reports (§8)
EVALUATION_DIR = ROOT / "evaluation"

# ─────────────────────────────────────────────────────────────────────────────
# Writable-location fallback.
# The project directory is not always writable: it may live on a read-only
# network share (e.g. a VM reaching the host over \\host\Final Project), where
# every write the app needs — quarantine copies, scan reports — fails with
# PermissionError mid-scan. Anything the app MUST be able to write falls back
# to a local per-user directory on the system drive instead of crashing.
# ─────────────────────────────────────────────────────────────────────────────
LOCAL_FALLBACK_ROOT = Path(
    os.environ.get("LOCALAPPDATA", r"C:\ProgramData")) / "AntivirusAI_V7"


def resolve_writable_dir(preferred: Path, fallback: Path) -> tuple[Path, bool]:
    """Return (usable_dir, used_fallback). Probes `preferred` with a real write
    (mkdir alone succeeds on some shares that then refuse file creation), and
    on any OSError falls back to `fallback`."""
    try:
        preferred.mkdir(parents=True, exist_ok=True)
        probe = preferred / ".write_test"
        probe.write_bytes(b"")
        probe.unlink()
        return preferred, False
    except OSError:
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback, True

# User-editable config files
CONFIG_DIR = ROOT / "config"
WHITELIST_JSON = CONFIG_DIR / "whitelist.json"
SETTINGS_JSON = CONFIG_DIR / "settings.json"
GEMINI_KEY_FILE = CONFIG_DIR / "gemini_key.txt"  # optional; git-ignored

# ─────────────────────────────────────────────────────────────────────────────
# Validated inference constants (DO NOT CHANGE — see scan_folder_v7.py / spec §2)
# ─────────────────────────────────────────────────────────────────────────────
TEMPORAL_INDICES = [1557, 1558, 1599, 1602, 1609, 1610, 1612, 1613, 1616, 1617]
EXPECTED_DIM = 2381
DEFAULT_LGBM_THRESHOLD = 0.40
VALID_EXT = {".exe", ".dll", ".sys", ".scr", ".com", ".ocx", ".cpl", ".drv"}
MIN_FILE_BYTES = 100  # files smaller than this are treated as ERROR (per reference)

# ─────────────────────────────────────────────────────────────────────────────
# Locked environment (NON-NEGOTIABLE — spec §0). The self-check verifies these.
# ─────────────────────────────────────────────────────────────────────────────
PYTHON_VERSION_PREFIX = "3.11"
LOCKED_VERSIONS = {
    "lief": "0.17.6-08dc3b7f",
    "sklearn": "1.3.2",
    "lightgbm": "4.5.0",
    "numpy": "1.26.4",
}
EMBER_COMMIT = "d97a0b523de02f3fe5ea6089d080abacab6ee931"

# Regression self-check tolerance (§9.4): expected F1 ≈ 0.9933, must be ≥ 0.98.
# 2026-08-05: updated for the promoted candidate model (augmented benign-corpus
# retrain) at its recall-matched threshold 0.225 — see thresholds.json.
REGRESSION_F1_EXPECTED = 0.993286
REGRESSION_F1_MIN = 0.98

# Quarantine neutralization (§6)
XOR_KEY_DEFAULT = 0x55

# ─────────────────────────────────────────────────────────────────────────────
# Gemini explanation layer (OPTIONAL, opt-in, uses the network).
# This is an ADD-ON that produces a short human-readable "why this looks like
# malware". It is completely separate from the ML verdict and the hash lookup —
# it runs AFTER a verdict, NEVER changes it, and the core scan stays offline.
# Privacy: only the verdict, probability, and ABSTRACT feature-group names are
# sent — never the file bytes, file name, or path.
# ─────────────────────────────────────────────────────────────────────────────
GEMINI_ENDPOINT = (
    "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
)
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"

# Whitelist defaults (§5) — used only if config/whitelist.json is absent.
DEFAULT_WHITELIST_PREFIXES = [
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Windows\WinSxS",
]

# Behavioral defaults (§5, §6, §7) — overridden by config/settings.json then CLI.
DEFAULT_SETTINGS = {
    "whitelist_enabled": True,  # skip system files by default (§5)
    "auto_quarantine": True,    # auto-quarantine MALWARE by default (§6, §10)
    "hash_compare": True,       # include hash comparison by default (§3.5)
    "xor_quarantine": True,     # XOR-neutralize quarantined files (§6)
    "xor_key": XOR_KEY_DEFAULT,
    "hash_db_path": str(BASELINE_SQLITE),
    # Authenticode layer (avscan/signature.py). Independent of the ML verdict:
    # it NEVER changes it, but a validly signed file is not AUTO-quarantined
    # (still reported). Guards against the model's known false positives on
    # signed installers/Go binaries. Set False to quarantine regardless.
    "check_signature": True,    # verify Authenticode on flagged files
    "trust_signed": True,       # skip auto-quarantine for validly signed files
    # Gemini explanation layer (opt-in; needs an API key — see get_gemini_api_key)
    "explain_enabled": True,        # try to produce a "why" for flagged files
    "gemini_model": DEFAULT_GEMINI_MODEL,
    "gemini_language": "he",        # explanation language ("he" Hebrew / "en" English)
    "gemini_timeout": 15,           # seconds for the API call
}


# ─────────────────────────────────────────────────────────────────────────────
# Loaders — robust: every loader degrades to the validated default, never raises.
# ─────────────────────────────────────────────────────────────────────────────
def _read_json(path: Path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def load_lgbm_threshold() -> float:
    """LightGBM threshold: AVSCAN_THRESHOLD env override, else thresholds.json
    'recommended', else 0.40 (§2)."""
    env = (os.environ.get("AVSCAN_THRESHOLD") or "").strip()
    if env:
        try:
            val = float(env)
            if 0.0 < val < 1.0:
                return val
        except ValueError:
            pass  # unparseable -> fall through to the validated sources below
    data = _read_json(THRESHOLDS_JSON)
    if isinstance(data, dict):
        val = data.get("recommended")
        if isinstance(val, (int, float)):
            return float(val)
    return DEFAULT_LGBM_THRESHOLD


def load_whitelist() -> list[str]:
    """Path-prefix whitelist from config/whitelist.json, else built-in defaults."""
    data = _read_json(WHITELIST_JSON)
    if isinstance(data, dict):
        prefixes = data.get("prefixes")
        if isinstance(prefixes, list) and all(isinstance(p, str) for p in prefixes):
            return prefixes
    if isinstance(data, list) and all(isinstance(p, str) for p in data):
        return data
    return list(DEFAULT_WHITELIST_PREFIXES)


def load_settings() -> dict:
    """Behavioral defaults from config/settings.json merged over DEFAULT_SETTINGS."""
    settings = dict(DEFAULT_SETTINGS)
    data = _read_json(SETTINGS_JSON)
    if isinstance(data, dict):
        for k, v in data.items():
            if k in settings:
                settings[k] = v
    return settings


def get_gemini_api_key() -> str | None:
    """Resolve the user's Gemini API key. NEVER hardcoded. Checked in order:
    1. environment variable GEMINI_API_KEY  (recommended)
    2. config/settings.json  "gemini_api_key"
    3. config/gemini_key.txt  (git-ignored)
    Returns None if none is set — the explanation layer then stays disabled."""
    import os

    key = (os.environ.get("GEMINI_API_KEY") or "").strip()
    if key:
        return key
    data = _read_json(SETTINGS_JSON)
    if isinstance(data, dict):
        k = (data.get("gemini_api_key") or "").strip()
        if k:
            return k
    try:
        if GEMINI_KEY_FILE.exists():
            k = GEMINI_KEY_FILE.read_text(encoding="utf-8").strip()
            if k:
                return k
    except Exception:
        pass
    return None


# Convenience module-level values (loaded once at import; loaders stay available).
LGBM_THRESHOLD = load_lgbm_threshold()
