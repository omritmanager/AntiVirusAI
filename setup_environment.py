"""
setup_environment.py — Reproduce the LOCKED AntivirusAI V7 environment (spec §0).

What it does (idempotent — safe to run twice):
  1. Installs the pinned core dependencies (numpy, scikit-learn, lightgbm, lief,
     tqdm) into the CURRENT interpreter (sys.executable).
  2. Installs EMBER from the pinned git commit.
  3. Applies the FeatureHasher double-bracket patch to ember/features.py and
     verifies it took effect.
  4. (Optional) installs the GUI toolkit PySide6.
  5. Verifies every installed version against the locked set and runs a small
     FeatureHasher smoke test.

Version fidelity is the whole point of this project: if a pinned library fails
to install, this script STOPS with a clear message rather than substituting a
different version.

Usage:
  python setup_environment.py                # full install + patch + verify
  python setup_environment.py --verify-only  # no installs; verify env + patch
  python setup_environment.py --no-gui       # skip PySide6
"""
from __future__ import annotations

import argparse
import importlib
import re
import subprocess
import sys
from pathlib import Path

# ── Locked specification (must match avscan/config.py and requirements.txt) ──
PYTHON_PREFIX = "3.11"
EMBER_COMMIT = "d97a0b523de02f3fe5ea6089d080abacab6ee931"
EMBER_GIT = f"git+https://github.com/elastic/ember.git@{EMBER_COMMIT}"

# pip name -> pinned version (the spec's NON-NEGOTIABLE core)
CORE_PINS = {
    "numpy": "1.26.4",
    "scikit-learn": "1.3.2",
    "lightgbm": "4.5.0",
    "lief": "0.17.6",
    "tqdm": "4.67.3",
}
# pip name -> (import name, expected runtime __version__) for verification
VERIFY = {
    "numpy": ("numpy", "1.26.4"),
    "scikit-learn": ("sklearn", "1.3.2"),
    "lightgbm": ("lightgbm", "4.5.0"),
    "lief": ("lief", "0.17.6-08dc3b7f"),
}
GUI_PIN = "PySide6==6.8.1.1"


# ── Pretty logging ───────────────────────────────────────────────────────────
def step(msg: str) -> None:
    print(f"\n=== {msg} ===")


def ok(msg: str) -> None:
    print(f"  [OK]   {msg}")


def warn(msg: str) -> None:
    print(f"  [WARN] {msg}")


def fail(msg: str) -> None:
    print(f"  [FAIL] {msg}")


# ── pip helpers ──────────────────────────────────────────────────────────────
def pip_install(*args: str) -> bool:
    """Run `pip install <args>` in the current interpreter. True on success."""
    cmd = [sys.executable, "-m", "pip", "install", *args]
    print(f"  $ {' '.join(cmd)}")
    return subprocess.run(cmd).returncode == 0


# ── EMBER patch ──────────────────────────────────────────────────────────────
# The single-bracket form raises `ValueError: Samples can not be a single
# string` under scikit-learn 1.3.2; the double-bracket form is correct.
_DOUBLE_RE = re.compile(
    r"\.transform\(\s*\[\[\s*raw_obj\[\s*['\"]entry['\"]\s*\]\s*\]\]\s*\)"
)
_SINGLE_RE = re.compile(
    r"(\.transform\(\s*)\[\s*raw_obj\[\s*['\"]entry['\"]\s*\]\s*\](\s*\))"
)


def ember_features_path() -> Path:
    import ember  # noqa: F401  (import to locate the package on disk)

    return Path(ember.__file__).resolve().parent / "features.py"


def is_ember_patched(path: Path | None = None) -> bool:
    path = path or ember_features_path()
    src = path.read_text(encoding="utf-8")
    return bool(_DOUBLE_RE.search(src))


def apply_ember_patch(path: Path | None = None) -> str:
    """Apply the double-bracket patch idempotently. Returns a status string:
    'already' | 'patched' | raises RuntimeError if the target line is missing."""
    path = path or ember_features_path()
    src = path.read_text(encoding="utf-8")
    if _DOUBLE_RE.search(src):
        return "already"
    if not _SINGLE_RE.search(src):
        raise RuntimeError(
            f"Could not find the entry_name_hashed FeatureHasher line in {path}. "
            "EMBER source may differ from the pinned commit."
        )
    patched = _SINGLE_RE.sub(r"\1[[raw_obj['entry']]]\2", src, count=1)
    path.write_text(patched, encoding="utf-8")
    if not _DOUBLE_RE.search(path.read_text(encoding="utf-8")):
        raise RuntimeError("Patch write did not take effect — aborting.")
    return "patched"


# ── Verification ─────────────────────────────────────────────────────────────
def verify_versions() -> bool:
    all_ok = True
    for pip_name, (import_name, expected) in VERIFY.items():
        try:
            mod = importlib.import_module(import_name)
            actual = getattr(mod, "__version__", "?")
        except Exception as e:
            fail(f"{import_name}: import failed ({e})")
            all_ok = False
            continue
        if actual == expected:
            ok(f"{import_name} == {actual}")
        else:
            fail(f"{import_name} == {actual}  (locked: {expected})")
            all_ok = False
    return all_ok


def verify_featurehasher() -> bool:
    """Confirm the installed sklearn accepts the patched (double-bracket) form."""
    try:
        from sklearn.feature_extraction import FeatureHasher

        FeatureHasher(50, input_type="string").transform([["entry"]]).toarray()
        ok("sklearn FeatureHasher accepts double-bracket input")
        return True
    except Exception as e:
        fail(f"FeatureHasher smoke test failed: {e}")
        return False


# ── Main flow ────────────────────────────────────────────────────────────────
def run(verify_only: bool, install_gui: bool) -> int:
    print("=" * 64)
    print("AntivirusAI V7 - environment setup")
    print("=" * 64)
    print(f"Interpreter: {sys.executable}")
    print(f"Python:      {sys.version.split()[0]}")

    step("Python version")
    if sys.version.split()[0].startswith(PYTHON_PREFIX):
        ok(f"Python {PYTHON_PREFIX}.x")
    else:
        warn(f"Python is not {PYTHON_PREFIX}.x — locked baseline is 3.11. "
             "Predictions were validated only on 3.11.")

    if not verify_only:
        step("Install pinned core dependencies")
        for name, ver in CORE_PINS.items():
            if not pip_install(f"{name}=={ver}"):
                fail(f"Could not install {name}=={ver}. "
                     "STOPPING — version fidelity is required; not substituting.")
                return 1
            ok(f"{name}=={ver}")

        step("Install EMBER (pinned git commit)")
        if not pip_install(EMBER_GIT):
            fail("Could not install EMBER from the pinned commit. STOPPING.")
            return 1
        ok(f"ember @ {EMBER_COMMIT[:12]}")

    step("Apply EMBER FeatureHasher patch")
    try:
        status = apply_ember_patch()
        path = ember_features_path()
        if status == "already":
            ok(f"already patched: {path}")
        else:
            ok(f"patched: {path}")
    except Exception as e:
        fail(str(e))
        return 1

    if not verify_only and install_gui:
        step("Install GUI toolkit (optional)")
        if pip_install(GUI_PIN):
            ok(GUI_PIN)
        else:
            warn(f"Could not install {GUI_PIN}. The CLI/engine still work; "
                 "the GUI will be unavailable until it is installed.")

    step("Verify locked versions")
    versions_ok = verify_versions()

    step("Verify EMBER import + patch")
    patch_ok = True
    try:
        import ember  # noqa: F401
        from ember import PEFeatureExtractor  # noqa: F401

        if is_ember_patched():
            ok("ember imports and features.py is patched")
        else:
            fail("ember features.py is NOT patched")
            patch_ok = False
    except Exception as e:
        fail(f"ember import failed: {e}")
        patch_ok = False

    step("FeatureHasher smoke test")
    fh_ok = verify_featurehasher()

    step("Summary")
    if versions_ok and patch_ok and fh_ok:
        ok("Environment is correctly locked and patched.")
        print("\nNext: python -m avscan selfcheck")
        return 0
    fail("Environment is NOT fully valid — see messages above.")
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description="Set up the locked AntivirusAI V7 env.")
    ap.add_argument("--verify-only", action="store_true",
                    help="Do not install anything; only verify env + apply/verify patch.")
    ap.add_argument("--no-gui", action="store_true",
                    help="Skip installing PySide6 (GUI toolkit).")
    args = ap.parse_args()
    return run(verify_only=args.verify_only, install_gui=not args.no_gui)


if __name__ == "__main__":
    raise SystemExit(main())
