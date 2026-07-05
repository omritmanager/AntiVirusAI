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
  6. (optional) Isolation Forest second opinion -> POTENTIAL_ZERODAY
  -> ml_verdict: MALWARE | POTENTIAL_ZERODAY | SAFE | ERROR

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
POTENTIAL_ZERODAY = "POTENTIAL_ZERODAY"
SAFE = "SAFE"
ERROR = "ERROR"


@dataclass
class MLResult:
    """The ML verdict for one input (independent of any hash lookup)."""
    ml_verdict: str                 # MALWARE | POTENTIAL_ZERODAY | SAFE | ERROR
    lgbm_prob: float | None = None
    if_score: float | None = None
    error: str | None = None        # populated only when ml_verdict == ERROR


class LeakyModelError(RuntimeError):
    """Raised if something tries to load the data-leaking lgbm_v7.pkl."""


class Engine:
    """Loads the frozen models once and classifies feature vectors / bytes.

    Reuse a single instance across a scan (models are loaded in __init__).
    """

    def __init__(self, load_if: bool = True):
        apply_compat_shims()
        from ember import PEFeatureExtractor  # imported AFTER shims (spec §2)

        self.extractor = PEFeatureExtractor(feature_version=2, print_feature_warning=False)
        self.lgbm = self._load_lgbm()
        self.iso = self._load_if() if load_if else None
        self.lgbm_threshold = config.LGBM_THRESHOLD
        self.if_threshold = config.IF_THRESHOLD

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

    def _load_if(self):
        if not config.IF_PATH.exists():
            return None
        try:
            with open(config.IF_PATH, "rb") as f:
                return pickle.load(f)
        except Exception:
            return None

    @property
    def if_available(self) -> bool:
        return self.iso is not None

    # ── inference core (the validated math) ──────────────────────────────────
    def classify_vector(self, vec, use_if: bool = False) -> MLResult:
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

            # Layer 1: LightGBM
            lgbm_prob = float(self.lgbm.predict_proba(row)[0, 1])
            if lgbm_prob >= self.lgbm_threshold:
                return MLResult(MALWARE, lgbm_prob=lgbm_prob)

            # Layer 2: Isolation Forest (only on files LightGBM cleared)
            if use_if and self.iso is not None:
                if_score = float(-self.iso.score_samples(row)[0])
                if if_score >= self.if_threshold:
                    return MLResult(POTENTIAL_ZERODAY, lgbm_prob=lgbm_prob, if_score=if_score)

            return MLResult(SAFE, lgbm_prob=lgbm_prob)
        except Exception as e:  # never crash on one vector
            return MLResult(ERROR, error=f"classify failed: {e}")

    def classify_bytes(self, data: bytes, use_if: bool = False) -> MLResult:
        """Extract features from raw bytes and classify. Never raises."""
        try:
            if data is None or len(data) < config.MIN_FILE_BYTES:
                return MLResult(ERROR, error="file too small / empty")
            vec = self.extractor.feature_vector(data)
        except Exception as e:
            return MLResult(ERROR, error=f"feature extraction failed: {e}")
        return self.classify_vector(vec, use_if=use_if)

    def classify_file(self, path, use_if: bool = False) -> tuple[MLResult, str | None, int]:
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
        return self.classify_bytes(data, use_if=use_if), sha, len(data)


# ── module-level singleton (so CLI/GUI/orchestrator share one load) ──────────
_ENGINE: Engine | None = None


def get_engine(load_if: bool = True) -> Engine:
    """Return a shared Engine, constructing it on first use."""
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = Engine(load_if=load_if)
    return _ENGINE
