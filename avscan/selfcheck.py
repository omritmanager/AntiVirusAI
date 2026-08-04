"""
selfcheck.py — Startup environment + model integrity verification (spec §9).

This is the project's core defense against the class of bug that broke V6/V7:
mismatched library versions silently corrupting predictions. It runs on every
launch (CLI and GUI) BEFORE any scan, and refuses to proceed if anything is off.

Checks (in order):
  1. Python version is 3.11.x.
  2. Installed versions == locked versions (lief, sklearn, lightgbm, numpy).
     Hard-fails naming the offending package.
  3. EMBER FeatureHasher patch present (source inspection + a live extraction of
     a real PE that would raise ValueError if unpatched).
  4. Model assets exist and load (lgbm_v7_correct.pkl, thresholds.json). Warns
     loudly if the leaky model is present.
  5. Regression test: predict the held-out test set and assert F1 >= 0.98
     (expected ~0.9936). Catches silent model corruption.

Public API:
  run_selfcheck(run_regression=True, verbose=True) -> SelfCheckResult
  SelfCheckResult.ok  -> bool  (all hard checks passed)
"""
from __future__ import annotations

import importlib
import pickle
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import config
from .compat import apply_compat_shims

# Double-bracket form of the entry_name_hashed FeatureHasher call (the patch).
_EMBER_PATCH_RE = re.compile(
    r"\.transform\(\s*\[\[\s*raw_obj\[\s*['\"]entry['\"]\s*\]\s*\]\]\s*\)"
)


# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Check:
    name: str
    passed: bool
    detail: str = ""
    warning: bool = False  # passed-but-noteworthy (does not fail the suite)


@dataclass
class SelfCheckResult:
    checks: list[Check] = field(default_factory=list)
    regression_f1: float | None = None

    @property
    def ok(self) -> bool:
        return all(c.passed for c in self.checks)

    @property
    def warnings(self) -> list[Check]:
        return [c for c in self.checks if c.warning]

    def format(self) -> str:
        lines = []
        for c in self.checks:
            mark = "[ OK ]" if c.passed else "[FAIL]"
            if c.warning and c.passed:
                mark = "[WARN]"
            lines.append(f"  {mark}  {c.name}" + (f" - {c.detail}" if c.detail else ""))
        lines.append("")
        lines.append("  RESULT: " + ("PASS - environment verified"
                                     if self.ok else "FAIL - scanning is blocked"))
        return "\n".join(lines)


# ── Individual checks ────────────────────────────────────────────────────────
def check_python() -> Check:
    v = sys.version.split()[0]
    passed = v.startswith(config.PYTHON_VERSION_PREFIX)
    return Check("Python version", passed,
                 f"{v}" + ("" if passed else f" (locked: {config.PYTHON_VERSION_PREFIX}.x)"))


def check_versions() -> list[Check]:
    """One Check per locked package; names the offender on mismatch."""
    checks: list[Check] = []
    for import_name, expected in config.LOCKED_VERSIONS.items():
        try:
            mod = importlib.import_module(import_name)
            actual = getattr(mod, "__version__", "?")
        except Exception as e:
            checks.append(Check(f"version: {import_name}", False, f"import failed: {e}"))
            continue
        passed = actual == expected
        detail = actual if passed else f"{actual}  (locked: {expected})"
        checks.append(Check(f"version: {import_name}", passed, detail))
    return checks


def _ember_features_file() -> Path | None:
    try:
        import ember
        return Path(ember.__file__).resolve().parent / "features.py"
    except Exception:
        return None


def check_ember_patch() -> Check:
    """Source inspection + live extraction of a real PE (sys.executable)."""
    path = _ember_features_file()
    if path is None or not path.exists():
        return Check("EMBER FeatureHasher patch", False, "ember/features.py not found")
    try:
        src = path.read_text(encoding="utf-8")
    except Exception as e:
        return Check("EMBER FeatureHasher patch", False, f"cannot read features.py: {e}")
    if not _EMBER_PATCH_RE.search(src):
        return Check("EMBER FeatureHasher patch", False,
                     "double-bracket patch NOT present in features.py")

    # Live extraction: the running interpreter's own .exe is a guaranteed PE.
    # Unpatched, this raises ValueError: Samples can not be a single string.
    try:
        apply_compat_shims()
        from ember import PEFeatureExtractor
        import numpy as np

        exe = Path(sys.executable)
        data = exe.read_bytes()
        extractor = PEFeatureExtractor(feature_version=2, print_feature_warning=False)
        vec = np.asarray(extractor.feature_vector(data), dtype=np.float32)
        if vec.shape[0] != config.EXPECTED_DIM:
            return Check("EMBER FeatureHasher patch", False,
                         f"extraction returned dim {vec.shape[0]} (expected {config.EXPECTED_DIM})")
    except Exception as e:
        return Check("EMBER FeatureHasher patch", False, f"live extraction failed: {e}")
    return Check("EMBER FeatureHasher patch", True, "source patched + live PE extraction OK")


def check_assets() -> list[Check]:
    checks: list[Check] = []

    # Primary model must exist and load. The label reports the file ACTUALLY
    # loaded, not the default name — otherwise an AVSCAN_MODEL override would
    # silently report the production filename while scoring with something else.
    label = f"model: {config.LGBM_PATH.name}"
    overridden = config.LGBM_PATH != config.MODELS_DIR / "lgbm_v7_correct.pkl"
    if not config.LGBM_PATH.exists():
        checks.append(Check(label, False, "file missing"))
    else:
        try:
            with open(config.LGBM_PATH, "rb") as f:
                pickle.load(f)
            checks.append(Check(label, True,
                                "loads (AVSCAN_MODEL override active — NOT the "
                                "production model)" if overridden else "loads",
                                warning=overridden))
        except Exception as e:
            checks.append(Check(label, False, f"load failed: {e}"))

    # Leaky model: warn loudly if present (engine refuses to load it).
    if config.LGBM_LEAKY_PATH.exists():
        checks.append(Check("leaky model present", True, warning=True,
                            detail="lgbm_v7.pkl exists (data leakage) - engine refuses to load it"))

    # Config JSONs.
    for label, p in [("thresholds.json", config.THRESHOLDS_JSON)]:
        checks.append(Check(f"asset: {label}", p.exists(),
                            "present" if p.exists() else "missing (using validated defaults)",
                            warning=not p.exists()))
    return checks


def _load_regression_data():
    """Prefer the full held-out arrays; fall back to the embedded mini set.
    Returns (X, y, source_label) or (None, None, reason)."""
    import numpy as np

    if config.X_TEST_BALANCED.exists() and config.Y_TEST_BALANCED.exists():
        X = np.load(config.X_TEST_BALANCED)
        y = np.load(config.Y_TEST_BALANCED)
        return X, y, f"held-out test set ({len(y)} samples)"

    mini = config.AVSCAN_DIR / "_assets" / "regression_mini.npz"
    if mini.exists():
        d = np.load(mini)
        return d["X"], d["y"], f"embedded mini set ({len(d['y'])} samples)"

    return None, None, "no regression data found"


def check_regression() -> tuple[Check, float | None]:
    """Predict the test set and assert F1 >= REGRESSION_F1_MIN (spec §9.4)."""
    import numpy as np
    from sklearn.metrics import f1_score

    X, y, source = _load_regression_data()
    if X is None:
        return Check("regression F1", False,
                     f"{source} — cannot verify model integrity"), None
    try:
        with open(config.LGBM_PATH, "rb") as f:
            lgbm = pickle.load(f)
        Xz = np.asarray(X, dtype=np.float32).copy()
        Xz[:, config.TEMPORAL_INDICES] = 0.0  # faithful to engine; no-op if pre-zeroed
        prob = lgbm.predict_proba(Xz)[:, 1]
        pred = (prob >= config.LGBM_THRESHOLD).astype(int)
        f1 = float(f1_score(y, pred))
    except Exception as e:
        return Check("regression F1", False, f"prediction failed: {e}"), None

    passed = f1 >= config.REGRESSION_F1_MIN
    detail = (f"F1={f1:.6f} on {source} "
              f"(min {config.REGRESSION_F1_MIN}, expected ~{config.REGRESSION_F1_EXPECTED:.4f})")
    return Check("regression F1", passed, detail), f1


# ── Orchestration ────────────────────────────────────────────────────────────
def run_selfcheck(run_regression: bool = True, verbose: bool = True) -> SelfCheckResult:
    result = SelfCheckResult()
    result.checks.append(check_python())
    result.checks.extend(check_versions())
    result.checks.append(check_ember_patch())
    result.checks.extend(check_assets())
    if run_regression:
        reg, f1 = check_regression()
        result.checks.append(reg)
        result.regression_f1 = f1

    if verbose:
        print("=" * 64)
        print("AntivirusAI V7 - startup self-check (spec section 9)")
        print("=" * 64)
        print(result.format())
    return result


def status_line(result: SelfCheckResult) -> str:
    """Short one-line summary for a GUI status bar."""
    if result.ok:
        f1 = f"F1={result.regression_f1:.4f}" if result.regression_f1 else "F1=n/a"
        return f"Environment verified ({f1})"
    failed = [c.name for c in result.checks if not c.passed]
    return "Self-check FAILED: " + ", ".join(failed)


if __name__ == "__main__":
    res = run_selfcheck()
    sys.exit(0 if res.ok else 2)
