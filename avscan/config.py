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
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Paths — derived from this file's location, NEVER hardcoded to a user folder.
#   avscan/config.py  ->  ROOT = <project root>
# ─────────────────────────────────────────────────────────────────────────────
AVSCAN_DIR = Path(__file__).resolve().parent
ROOT = AVSCAN_DIR.parent

MODELS_DIR = ROOT / "models" / "v7"
LGBM_PATH = MODELS_DIR / "lgbm_v7_correct.pkl"          # PRIMARY model — USE THIS
LGBM_LEAKY_PATH = MODELS_DIR / "lgbm_v7.pkl"            # data leakage — REFUSE
IF_PATH = MODELS_DIR / "isolation_forest.pkl"
THRESHOLDS_JSON = MODELS_DIR / "thresholds.json"
IF_CONFIG_JSON = MODELS_DIR / "if_config.json"

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

# User-editable config files
CONFIG_DIR = ROOT / "config"
WHITELIST_JSON = CONFIG_DIR / "whitelist.json"
SETTINGS_JSON = CONFIG_DIR / "settings.json"

# ─────────────────────────────────────────────────────────────────────────────
# Validated inference constants (DO NOT CHANGE — see scan_folder_v7.py / spec §2)
# ─────────────────────────────────────────────────────────────────────────────
TEMPORAL_INDICES = [1557, 1558, 1599, 1602, 1609, 1610, 1612, 1613, 1616, 1617]
EXPECTED_DIM = 2381
DEFAULT_LGBM_THRESHOLD = 0.40
DEFAULT_IF_THRESHOLD = 0.3694358641837102
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

# Regression self-check tolerance (§9.4): expected F1 ≈ 0.9936, must be ≥ 0.98.
REGRESSION_F1_EXPECTED = 0.9936262079363992
REGRESSION_F1_MIN = 0.98

# Quarantine neutralization (§6)
XOR_KEY_DEFAULT = 0x55

# Whitelist defaults (§5) — used only if config/whitelist.json is absent.
DEFAULT_WHITELIST_PREFIXES = [
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Windows\WinSxS",
]

# Behavioral defaults (§5, §6, §7) — overridden by config/settings.json then CLI.
DEFAULT_SETTINGS = {
    "use_if": False,            # Isolation Forest off by default (§7)
    "whitelist_enabled": True,  # skip system files by default (§5)
    "auto_quarantine": True,    # auto-quarantine MALWARE by default (§6, §10)
    "hash_compare": True,       # include hash comparison by default (§3.5)
    "xor_quarantine": True,     # XOR-neutralize quarantined files (§6)
    "xor_key": XOR_KEY_DEFAULT,
    "hash_db_path": str(BASELINE_SQLITE),
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
    """LightGBM threshold from thresholds.json 'recommended', else 0.40 (§2)."""
    data = _read_json(THRESHOLDS_JSON)
    if isinstance(data, dict):
        val = data.get("recommended")
        if isinstance(val, (int, float)):
            return float(val)
    return DEFAULT_LGBM_THRESHOLD


def load_if_threshold() -> float:
    """IF threshold from if_config.json 'anomaly_threshold', else 0.3694... (§2)."""
    data = _read_json(IF_CONFIG_JSON)
    if isinstance(data, dict):
        val = data.get("anomaly_threshold")
        if isinstance(val, (int, float)):
            return float(val)
    return DEFAULT_IF_THRESHOLD


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


# Convenience module-level values (loaded once at import; loaders stay available).
LGBM_THRESHOLD = load_lgbm_threshold()
IF_THRESHOLD = load_if_threshold()
