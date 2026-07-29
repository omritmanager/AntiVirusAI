"""
friend_extract_verify.py — standalone extractor for a benign-file corpus,
built to be handed to someone else's machine (no AntivirusAI repo needed).

WHY THIS EXISTS
---------------
The full corpus of .exe files is too large / became unavailable to transfer
whole (122GB). Rather than moving the files, this script runs the SAME
feature-extraction and signature-verification pipeline locally on YOUR
machine, and produces a much smaller output file (one JSON record per input
file — a 2381-number feature vector + a SHA-256 + a signature verdict, NOT
the original binary). You send back the output file, not the .exe files.

Feature-vector determinism depends on exact library versions (a different
lief/numpy build can produce different numbers for the same file), so this
script REFUSES to run with the wrong versions rather than silently producing
data that wouldn't match the original pipeline. See PINNED below.

WHAT TO DO
----------
1. Install Python 3.11.x if you don't have it: https://www.python.org/downloads/
2. Open a terminal in the folder containing this script and run:

     python -m venv friend_venv
     friend_venv\\Scripts\\activate          (Windows)
     python friend_extract_verify.py --check-env

   This tells you exactly what to install. Typically:

     pip install numpy==1.26.4 lief==0.17.6 lightgbm==4.5.0
     pip install "git+https://github.com/elastic/ember.git@d97a0b523de02f3fe5ea6089d080abacab6ee931"

   (lightgbm is optional — only needed if you also want this script to tell
   you the model's current verdict on each file, not just extract features.
   If you were given lgbm_v7_correct.pkl / isolation_forest.pkl / thresholds.json
   / if_config.json, put them in the SAME folder as this script.)

3. Run the real extraction:

     python friend_extract_verify.py --input-dir "C:\\path\\to\\your\\exe\\files" --output results.jsonl

   This is resumable — if it gets interrupted, just run the exact same
   command again and it will skip files already in results.jsonl.

4. Send back results.jsonl (and results.failures.txt if one was created).
   That's it — no need to send the original .exe files.

Everything below is self-contained: no import of any project-specific
package, only Python's standard library plus numpy / lief / ember / lightgbm
(the last one optional).
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import re
import subprocess
import sys
import time
import warnings
from pathlib import Path

# ── Pinned versions (must match exactly — see the project's setup_environment.py) ──
PYTHON_PREFIX = "3.11"
EMBER_COMMIT = "d97a0b523de02f3fe5ea6089d080abacab6ee931"
EMBER_GIT = f"git+https://github.com/elastic/ember.git@{EMBER_COMMIT}"
VERIFY = {
    "numpy":   ("numpy",   "1.26.4"),
    "lief":    ("lief",    "0.17.6-08dc3b7f"),
}
OPTIONAL_VERIFY = {
    "lightgbm": ("lightgbm", "4.5.0"),   # only needed for --models-dir classification
}

EXPECTED_DIM = 2381
TEMPORAL_INDICES = [1557, 1558, 1599, 1602, 1609, 1610, 1612, 1613, 1616, 1617]
# Fallback thresholds if thresholds.json / if_config.json aren't shipped alongside
# this script (matching models/v7/thresholds.json "recommended" and
# models/v7/if_config.json "anomaly_threshold" at time of writing).
DEFAULT_LGBM_THRESHOLD = 0.40000000000000013
DEFAULT_IF_THRESHOLD = 0.3694358641837102

MALWARE, POTENTIAL_ZERODAY, SAFE, ERROR = "MALWARE", "POTENTIAL_ZERODAY", "SAFE", "ERROR"


def ok(msg): print(f"  [OK]   {msg}")
def warn(msg): print(f"  [WARN] {msg}")
def fail(msg): print(f"  [FAIL] {msg}")


# ── Step 1: version check ────────────────────────────────────────────────────
def check_versions(include_optional: bool) -> bool:
    print("\n=== Checking pinned library versions ===")
    all_ok = True
    if not sys.version.startswith(PYTHON_PREFIX):
        warn(f"Python {sys.version.split()[0]} (expected {PYTHON_PREFIX}.x) — "
             f"may still work, but the original pipeline used {PYTHON_PREFIX}.x")

    checks = dict(VERIFY)
    if include_optional:
        checks.update(OPTIONAL_VERIFY)

    for pip_name, (import_name, expected) in checks.items():
        try:
            mod = importlib.import_module(import_name)
            actual = getattr(mod, "__version__", "?")
            if actual == expected:
                ok(f"{pip_name} {actual}")
            else:
                fail(f"{pip_name} {actual}  (expected EXACTLY {expected})")
                all_ok = False
        except Exception as e:
            fail(f"{pip_name}: not installed ({e})")
            all_ok = False

    try:
        import ember  # noqa: F401
        from ember import PEFeatureExtractor  # noqa: F401
        ok("ember imports")
        if is_ember_patched():
            ok("ember features.py is patched (FeatureHasher double-bracket)")
        else:
            fail("ember features.py is NOT patched — see --apply-ember-patch")
            all_ok = False
    except Exception as e:
        fail(f"ember: import failed ({e})")
        all_ok = False

    if not all_ok:
        print("\nInstall commands:")
        print("  pip install numpy==1.26.4 lief==0.17.6")
        print(f'  pip install "{EMBER_GIT}"')
        if include_optional:
            print("  pip install lightgbm==4.5.0   # only if using --models-dir")
        print("\nThen re-run with --check-env, or just run the real extraction "
              "(it checks versions first and stops if they're wrong).")
    return all_ok


# ── Step 2: EMBER patch (idempotent, same regex as setup_environment.py) ────
_DOUBLE_RE = re.compile(r"\.transform\(\s*\[\[\s*raw_obj\[\s*['\"]entry['\"]\s*\]\s*\]\]\s*\)")
_SINGLE_RE = re.compile(r"(\.transform\(\s*)\[\s*raw_obj\[\s*['\"]entry['\"]\s*\]\s*\](\s*\))")


def ember_features_path() -> Path:
    import ember
    return Path(ember.__file__).resolve().parent / "features.py"


def is_ember_patched() -> bool:
    try:
        src = ember_features_path().read_text(encoding="utf-8")
    except Exception:
        return False
    return bool(_DOUBLE_RE.search(src))


def apply_ember_patch() -> str:
    path = ember_features_path()
    src = path.read_text(encoding="utf-8")
    if _DOUBLE_RE.search(src):
        return "already patched"
    if not _SINGLE_RE.search(src):
        raise RuntimeError(
            f"Could not find the entry_name_hashed FeatureHasher line in {path}. "
            "Your EMBER install may not be the pinned commit.")
    patched = _SINGLE_RE.sub(r"\1[[raw_obj['entry']]]\2", src, count=1)
    path.write_text(patched, encoding="utf-8")
    if not is_ember_patched():
        raise RuntimeError("Patch write did not take effect.")
    return "patched"


# ── Step 3: compat shims (verbatim from avscan/compat.py) — must run before
# `import ember` for real. ────────────────────────────────────────────────────
def apply_compat_shims() -> None:
    import lief
    for attr in ["bad_format", "bad_file", "pe_error", "parser_error",
                "read_out_of_bound", "not_found"]:
        if not hasattr(lief, attr):
            setattr(lief, attr, type(attr, (Exception,), {}))

    import numpy as np
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", FutureWarning)
        for name, ty in [("int", int), ("bool", bool), ("float", float), ("object", object)]:
            if not hasattr(np, name):
                setattr(np, name, ty)


# ── Step 4: SHA-256 + EMBER feature extraction + imphash ────────────────────
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def processed_vector(extractor, np_mod, data: bytes):
    """The exact inference-time 2381-dim vector: extract, validate, zero the
    temporal indices. Returns None on any failure — never raises."""
    try:
        vec = np_mod.array(extractor.feature_vector(data), dtype=np_mod.float32)
        if vec.shape[0] != EXPECTED_DIM:
            return None
        if np_mod.isnan(vec).any() or np_mod.isinf(vec).any():
            return None
        vec[TEMPORAL_INDICES] = 0.0
        return vec
    except Exception:
        return None


def compute_imphash(lief_mod, data: bytes):
    try:
        binary = lief_mod.PE.parse(data)
        if binary is None:
            return None
        return lief_mod.PE.get_imphash(binary)
    except Exception:
        return None


# ── Step 5: Authenticode signature verification (verbatim logic from
# avscan/signature.py — offline only: WTD_REVOKE_NONE + cache-only URL
# retrieval, so this never makes a network call). ───────────────────────────
TRUSTED, UNSIGNED, UNTRUSTED, UNKNOWN = "TRUSTED", "UNSIGNED", "UNTRUSTED", "UNKNOWN"

_TRUST_E_NOSIGNATURE = 0x800B0100


def verify_signature(path: str):
    """Returns (status, signer_or_None). Never raises; offline only."""
    if not sys.platform.startswith("win"):
        return UNKNOWN, None
    try:
        import ctypes
        from ctypes import wintypes

        class GUID(ctypes.Structure):
            _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                        ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]

        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
                        ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.c_void_p)]

        class WINTRUST_DATA(ctypes.Structure):
            _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                        ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                        ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)), ("dwStateAction", wintypes.DWORD),
                        ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPWSTR),
                        ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD),
                        ("pSignatureSettings", ctypes.c_void_p)]

        action = GUID(0x00AAC56B, 0xCD44, 0x11D0,
                      (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
        fi = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), path, None, None)
        wd = WINTRUST_DATA()
        wd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        wd.dwUIChoice = 2                     # WTD_UI_NONE
        wd.fdwRevocationChecks = 0             # WTD_REVOKE_NONE -> offline
        wd.dwUnionChoice = 1                   # WTD_CHOICE_FILE
        wd.pFile = ctypes.pointer(fi)
        wd.dwStateAction = 1                   # WTD_STATEACTION_VERIFY
        wd.dwProvFlags = 0x00000100 | 0x00001000  # WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL

        wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
        wintrust.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(GUID),
                                            ctypes.POINTER(WINTRUST_DATA)]
        wintrust.WinVerifyTrust.restype = ctypes.c_long
        try:
            rc = wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(wd))
        finally:
            wd.dwStateAction = 2               # WTD_STATEACTION_CLOSE
            try:
                wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(wd))
            except Exception:
                pass

        code = rc & 0xFFFFFFFF
        if code == 0:
            status = TRUSTED
        elif code == _TRUST_E_NOSIGNATURE:
            return UNSIGNED, None
        else:
            status = UNTRUSTED

        signer = _signer_name(path) if status in (TRUSTED, UNTRUSTED) else None
        return status, signer
    except Exception:
        return UNKNOWN, None


def _signer_name(path: str):
    try:
        import ctypes
        from ctypes import wintypes

        c32 = ctypes.WinDLL("crypt32", use_last_error=True)
        c32.CryptQueryObject.restype = wintypes.BOOL
        c32.CryptMsgGetParam.restype = wintypes.BOOL
        c32.CertFindCertificateInStore.restype = ctypes.c_void_p
        c32.CertFindCertificateInStore.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                                   wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p]
        c32.CertGetNameStringW.restype = wintypes.DWORD
        c32.CertGetNameStringW.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                           ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
        c32.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
        c32.CertCloseStore.argtypes = [ctypes.c_void_p, wintypes.DWORD]
        c32.CryptMsgClose.argtypes = [ctypes.c_void_p]

        store, msg = ctypes.c_void_p(), ctypes.c_void_p()
        ok_ = c32.CryptQueryObject(1, ctypes.c_wchar_p(path), 1 << 10, 1 << 1, 0, None, None,
                                   None, ctypes.byref(store), ctypes.byref(msg), None)
        if not ok_:
            return None
        try:
            size = wintypes.DWORD(0)
            if not c32.CryptMsgGetParam(msg, 7, 0, None, ctypes.byref(size)):
                return None
            buf = ctypes.create_string_buffer(size.value)
            if not c32.CryptMsgGetParam(msg, 7, 0, buf, ctypes.byref(size)):
                return None
            cert = c32.CertFindCertificateInStore(store, 0x1 | 0x10000, 0, 11 << 16, buf, None)
            if not cert:
                return None
            try:
                n = c32.CertGetNameStringW(cert, 4, 0, None, None, 0)
                if n <= 1:
                    return None
                out = ctypes.create_unicode_buffer(n)
                c32.CertGetNameStringW(cert, 4, 0, None, out, n)
                return out.value or None
            finally:
                c32.CertFreeCertificateContext(cert)
        finally:
            if msg:
                c32.CryptMsgClose(msg)
            if store:
                c32.CertCloseStore(store, 0)
    except Exception:
        return None


# ── Step 6: optional classification (mirrors avscan/engine.py's math exactly) ─
def load_models(models_dir: Path):
    """Returns (lgbm, iso_or_None, lgbm_threshold, if_threshold) or None if the
    primary model isn't present."""
    import pickle
    lgbm_path = models_dir / "lgbm_v7_correct.pkl"
    if not lgbm_path.exists():
        return None
    if str(lgbm_path).lower().endswith("lgbm_v7.pkl"):
        raise RuntimeError("refusing to load lgbm_v7.pkl (the known-leaky model)")
    with open(lgbm_path, "rb") as f:
        lgbm = pickle.load(f)

    iso = None
    iso_path = models_dir / "isolation_forest.pkl"
    if iso_path.exists():
        try:
            with open(iso_path, "rb") as f:
                iso = pickle.load(f)
        except Exception:
            iso = None

    lgbm_threshold = DEFAULT_LGBM_THRESHOLD
    th_path = models_dir / "thresholds.json"
    if th_path.exists():
        try:
            lgbm_threshold = json.loads(th_path.read_text())["recommended"]
        except Exception:
            pass

    if_threshold = DEFAULT_IF_THRESHOLD
    if_path = models_dir / "if_config.json"
    if if_path.exists():
        try:
            if_threshold = json.loads(if_path.read_text())["anomaly_threshold"]
        except Exception:
            pass

    return lgbm, iso, lgbm_threshold, if_threshold


def classify(lgbm, iso, vec, lgbm_threshold, if_threshold):
    row = vec.reshape(1, -1)
    lgbm_prob = float(lgbm.predict_proba(row)[0, 1])
    if lgbm_prob >= lgbm_threshold:
        return MALWARE, lgbm_prob, None
    if iso is not None:
        if_score = float(-iso.score_samples(row)[0])
        if if_score >= if_threshold:
            return POTENTIAL_ZERODAY, lgbm_prob, if_score
        return SAFE, lgbm_prob, if_score
    return SAFE, lgbm_prob, None


# ── Main extraction loop (checkpointed, size-ascending, same design as the
# project's extract_new_benign.py) ───────────────────────────────────────────
def already_done(output_path: Path) -> set[str]:
    done = set()
    if not output_path.exists():
        return done
    with open(output_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                if "path" in rec:
                    done.add(rec["path"])
            except json.JSONDecodeError:
                continue
    return done


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input-dir", type=Path, default=None)
    ap.add_argument("--output", type=Path, default=Path("results.jsonl"))
    ap.add_argument("--models-dir", type=Path, default=Path("."),
                    help="folder containing lgbm_v7_correct.pkl etc. (optional)")
    ap.add_argument("--check-env", action="store_true",
                    help="only check versions, don't extract anything")
    ap.add_argument("--apply-ember-patch", action="store_true",
                    help="patch ember/features.py if needed, then exit")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--progress-every", type=int, default=25)
    args = ap.parse_args()

    print("=" * 70)
    print("FRIEND EXTRACT + VERIFY — standalone benign-corpus extractor")
    print("=" * 70)

    if args.apply_ember_patch:
        try:
            print(f"  EMBER patch: {apply_ember_patch()}")
        except Exception as e:
            fail(str(e))
            return 1
        return 0

    include_optional = (args.models_dir / "lgbm_v7_correct.pkl").exists()
    if not check_versions(include_optional):
        return 1
    if args.check_env:
        print("\nEnvironment OK.")
        return 0

    if not is_ember_patched():
        print("\nApplying EMBER patch (one-time)...")
        try:
            print(f"  {apply_ember_patch()}")
        except Exception as e:
            fail(str(e))
            return 1

    if args.input_dir is None:
        fail("--input-dir is required for extraction (use --check-env to only verify versions)")
        return 1
    if not args.input_dir.is_dir():
        fail(f"input dir not found: {args.input_dir}")
        return 1

    print("\nLoading libraries (after compat shims)...")
    apply_compat_shims()
    import numpy as np
    import lief
    from ember import PEFeatureExtractor
    extractor = PEFeatureExtractor(feature_version=2, print_feature_warning=False)
    ok("ember / lief / numpy ready")

    models = None
    try:
        models = load_models(args.models_dir)
    except Exception as e:
        warn(f"models not loaded ({e}) — continuing in extraction-only mode")
    if models:
        ok(f"models loaded from {args.models_dir} — will also report the current verdict")
    else:
        warn(f"no models found in {args.models_dir} — extraction + signature only "
             f"(this is fine; classification is optional)")

    print(f"\nListing .exe files in {args.input_dir}...")
    all_files = [p for p in args.input_dir.iterdir()
                if p.is_file() and p.suffix.lower() == ".exe"]
    all_files.sort(key=lambda p: p.stat().st_size)
    total_bytes = sum(p.stat().st_size for p in all_files)
    print(f"  Found {len(all_files):,} files, {total_bytes/1e9:.1f} GB total")

    targets = all_files[:args.limit] if args.limit else all_files
    done_paths = already_done(args.output)
    if done_paths:
        print(f"  Resuming: {len(done_paths):,} already done, skipping them")
    remaining = [p for p in targets if str(p) not in done_paths]
    print(f"  {len(remaining):,} file(s) to process")

    if not remaining:
        print("\nNothing to do.")
        return 0

    t0 = time.time()
    bytes_done = ok_n = fail_n = 0
    fail_log = []

    with open(args.output, "a", encoding="utf-8") as out_f:
        for i, path in enumerate(remaining, 1):
            try:
                with open(path, "rb") as f:
                    data = f.read()
            except Exception as e:
                fail_n += 1
                fail_log.append((str(path), f"read failed: {e}"))
                continue

            bytes_done += len(data)
            sha = sha256_bytes(data)
            vec = processed_vector(extractor, np, data)
            if vec is None:
                fail_n += 1
                fail_log.append((str(path), "feature extraction failed (corrupt/non-PE/bad dim)"))
                continue

            imphash = compute_imphash(lief, data)
            sig_status, signer = verify_signature(str(path))

            rec = {
                "path": str(path), "sha256": sha, "size": len(data),
                "features": vec.tolist(),
                "signature_status": sig_status, "signature_signer": signer,
                "imphash": imphash,
            }
            if models:
                lgbm, iso, lgbm_t, if_t = models
                verdict, prob, if_score = classify(lgbm, iso, vec, lgbm_t, if_t)
                rec.update(ml_verdict=verdict, lgbm_prob=prob, if_score=if_score)

            out_f.write(json.dumps(rec) + "\n")
            out_f.flush()
            ok_n += 1

            if i % args.progress_every == 0 or i == len(remaining):
                elapsed = time.time() - t0
                rate = i / elapsed if elapsed else 0
                mb_s = (bytes_done / 1e6) / elapsed if elapsed else 0
                print(f"  [{i:>6,}/{len(remaining):,}]  ok={ok_n:,} fail={fail_n:,}  "
                      f"{rate:.2f} files/s  {mb_s:.1f} MB/s")

    print(f"\n{'='*70}")
    print("DONE")
    print(f"{'='*70}")
    print(f"  Succeeded: {ok_n:,}   Failed: {fail_n:,}")
    print(f"  Output:    {args.output}")
    if fail_log:
        fail_path = args.output.with_suffix(".failures.txt")
        with open(fail_path, "w", encoding="utf-8") as f:
            for p, r in fail_log:
                f.write(f"{p}\t{r}\n")
        print(f"  Failures:  {fail_path}")
    print(f"\nPlease send back: {args.output}"
          + (f" and {args.output.with_suffix('.failures.txt')}" if fail_log else "")
          + "\n(No need to send the original .exe files.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
