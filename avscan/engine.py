"""
engine.py — The validated inference core (spec §2). DO NOT alter the math.

This is a faithful port of `scan_folder_v7.py`'s classify logic, restructured for
reuse (models load once; the orchestrator reads bytes once and feeds them here).

Pipeline for one file (exactly as validated):
  0. (hash lookup happens in the orchestrator, independently — never here)
  1. read bytes               (caller's responsibility; classify_bytes takes bytes)
  2. EMBER PEFeatureExtractor(feature_version=2).feature_vector(bytes)  -> 2381 dims
  3. validate vector          (len == 2381, no NaN/Inf)
  4. zero the 10 temporal indices
  5. LightGBM.predict_proba   -> P(malware); >= 0.40 => MALWARE
  -> ml_verdict: MALWARE | SAFE | ERROR

The compatibility shims (compat.apply_compat_shims) run BEFORE importing ember.
"""
from __future__ import annotations

import pickle
from dataclasses import dataclass

import numpy as np

from . import config
from .compat import apply_compat_shims
from .hashing import sha256_bytes, sha256_file  # re-exported for callers

# Verdict constants
MALWARE = "MALWARE"
SAFE = "SAFE"
ERROR = "ERROR"


@dataclass
class MLResult:
    """The ML verdict for one input (independent of any hash lookup)."""
    ml_verdict: str                 # MALWARE | SAFE | ERROR
    lgbm_prob: float | None = None
    error: str | None = None        # populated only when ml_verdict == ERROR


class LeakyModelError(RuntimeError):
    """Raised if something tries to load the data-leaking lgbm_v7.pkl."""


class Engine:
    """Loads the frozen model once and classifies feature vectors / bytes.

    Reuse a single instance across a scan (the model is loaded in __init__).
    """

    def __init__(self):
        apply_compat_shims()
        from ember import PEFeatureExtractor  # imported AFTER shims (spec §2)

        self.extractor = PEFeatureExtractor(feature_version=2, print_feature_warning=False)
        self.lgbm = self._load_lgbm()
        self.lgbm_threshold = config.LGBM_THRESHOLD

    # ── model loading ────────────────────────────────────────────────────────
    @staticmethod
    def _assert_not_leaky(path) -> None:
        if str(path).lower().endswith("lgbm_v7.pkl"):
            raise LeakyModelError(
                "Refusing to load lgbm_v7.pkl: it was trained on train+val "
                "(data leakage). Use lgbm_v7_correct.pkl instead (spec §3)."
            )

    def _load_lgbm(self):
        self._assert_not_leaky(config.LGBM_PATH)
        if not config.LGBM_PATH.exists():
            raise FileNotFoundError(f"Primary model not found: {config.LGBM_PATH}")
        with open(config.LGBM_PATH, "rb") as f:
            return pickle.load(f)

    # ── inference core (the validated math) ──────────────────────────────────
    def classify_vector(self, vec) -> MLResult:
        """Classify an already-extracted EMBER vector. Pure math; never raises.

        A copy is made before zeroing temporal indices so the caller's array
        (e.g. a row of X_test) is never mutated.
        """
        try:
            vec = np.array(vec, dtype=np.float32)  # always copies
            if vec.shape[0] != config.EXPECTED_DIM:
                return MLResult(ERROR, error=f"bad dim {vec.shape[0]} != {config.EXPECTED_DIM}")
            if np.isnan(vec).any() or np.isinf(vec).any():
                return MLResult(ERROR, error="vector contains NaN/Inf")

            vec[config.TEMPORAL_INDICES] = 0.0
            row = vec.reshape(1, -1)

            lgbm_prob = float(self.lgbm.predict_proba(row)[0, 1])
            if lgbm_prob >= self.lgbm_threshold:
                return MLResult(MALWARE, lgbm_prob=lgbm_prob)
            return MLResult(SAFE, lgbm_prob=lgbm_prob)
        except Exception as e:  # never crash on one vector
            return MLResult(ERROR, error=f"classify failed: {e}")

    def classify_with_vector(self, data: bytes):
        """Extract features ONCE and return (MLResult, processed vector | None).

        Feature extraction is the dominant cost of a scan — 84s on an 846MB
        installer — so a caller that needs both the verdict and the vector the
        model saw (the explanation layer) must not ask for them separately.
        The returned vector matches processed_vector's contract exactly
        (validated, temporal indices zeroed); it is None whenever no valid
        vector exists, which is also when the verdict is ERROR.
        """
        try:
            if data is None or len(data) < config.MIN_FILE_BYTES:
                return MLResult(ERROR, error="file too small / empty"), None
            vec = np.array(self.extractor.feature_vector(data), dtype=np.float32)
        except Exception as e:
            return MLResult(ERROR, error=f"feature extraction failed: {e}"), None
        if vec.shape[0] != config.EXPECTED_DIM or np.isnan(vec).any() or np.isinf(vec).any():
            return self.classify_vector(vec), None
        vec[config.TEMPORAL_INDICES] = 0.0
        return self.classify_vector(vec), vec

    def classify_bytes(self, data: bytes) -> MLResult:
        """Extract features from raw bytes and classify. Never raises."""
        return self.classify_with_vector(data)[0]

    def processed_vector(self, data: bytes):
        """Return the exact 2381-dim feature vector the model predicts on
        (temporal indices zeroed), or None on any failure. Used by the optional
        explanation layer to attribute the decision; does NOT affect verdicts.
        """
        try:
            if data is None or len(data) < config.MIN_FILE_BYTES:
                return None
            vec = np.array(self.extractor.feature_vector(data), dtype=np.float32)
            if vec.shape[0] != config.EXPECTED_DIM or np.isnan(vec).any() or np.isinf(vec).any():
                return None
            vec[config.TEMPORAL_INDICES] = 0.0
            return vec
        except Exception:
            return None

    def classify_file(self, path) -> tuple[MLResult, str | None, int]:
        """Convenience: read a file, hash it, classify it.

        Returns (MLResult, sha256_or_None, size_bytes). Reads the file once;
        the SHA-256 is computed from the same bytes used for extraction so the
        hash layer and ML layer see identical content.
        """
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception as e:
            return MLResult(ERROR, error=f"read failed: {e}"), None, 0
        sha = sha256_bytes(data)
        return self.classify_bytes(data), sha, len(data)


# ── module-level singleton (so CLI/GUI/orchestrator share one load) ──────────
_ENGINE: Engine | None = None


def get_engine() -> Engine:
    """Return a shared Engine, constructing it on first use."""
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = Engine()
    return _ENGINE


def reset_engine() -> None:
    """Drop the cached Engine so the next get_engine() re-reads config.

    Needed when the model being evaluated changes at runtime (the GUI's model
    picker): Engine reads config.LGBM_PATH and config.LGBM_THRESHOLD once, in
    __init__, so without this the process would keep scoring with the model it
    loaded first no matter what the config now says.
    """
    global _ENGINE
    _ENGINE = None
