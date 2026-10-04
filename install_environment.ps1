<#
.SYNOPSIS
  Install / repair the AntivirusAI V7 environment (venv_v7) on this machine and
  verify it end-to-end. Designed to work on a brand-new VM that has nothing but
  this project folder on it.

.DESCRIPTION
  1. Finds a Python 3.11 base interpreter (py -3.11, then C:\Python311\python.exe).
  2. Creates venv_v7 from scratch if it is missing or broken (or if -Force).
  3. Delegates all pinned package installs + the EMBER FeatureHasher patch +
     version verification to setup_environment.py (the single source of truth
     for the locked spec - see requirements.txt).
  4. Optionally prompts for a Gemini API key and stores it as a persistent
     Windows User environment variable (never written to a file).
  5. Registers the right-click "Quick Scan" context-menu entry for this folder.
  6. Runs `python -m avscan selfcheck` and the full pytest suite so the whole
     pipeline is proven working, not just "installed".

.PARAMETER Force
  Delete and recreate venv_v7 even if it already looks healthy.

.PARAMETER VerifyOnly
  Do not install or create anything; only verify what is already there. Fails
  loudly if venv_v7 is missing or broken.

.PARAMETER NoGui
  Skip installing PySide6 (the desktop GUI will be unavailable).

.PARAMETER SkipSelfcheck
  Skip the `python -m avscan selfcheck` step at the end.

.PARAMETER SkipTests
  Skip running the pytest suite at the end.

.PARAMETER SkipGeminiPrompt
  Skip the Gemini API key check/prompt (for unattended runs).
#>
[CmdletBinding()]
param(
    [switch]$Force,
    [switch]$VerifyOnly,
    [switch]$NoGui,
    [switch]$SkipSelfcheck,
    [switch]$SkipTests,
    [switch]$SkipGeminiPrompt
)

$Root       = $PSScriptRoot
$Venv       = Join-Path $Root 'venv_v7'
$VenvPython = Join-Path $Venv 'Scripts\python.exe'
$SetupPy    = Join-Path $Root 'setup_environment.py'

# Embedded fallback copy of setup_environment.py. If this script is copied to
# a new machine on its own (or the copy job dropped a file), the installer
# still works end to end - it materializes the file itself instead of failing
# on a missing dependency.
$SetupPyEmbedded = @'
"""
setup_environment.py - Reproduce the LOCKED AntivirusAI V7 environment (spec section 0).

What it does (idempotent - safe to run twice):
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

# -- Locked specification (must match avscan/config.py and requirements.txt) --
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


# -- Pretty logging -----------------------------------------------------------
def step(msg: str) -> None:
    print(f"\n=== {msg} ===")


def ok(msg: str) -> None:
    print(f"  [OK]   {msg}")


def warn(msg: str) -> None:
    print(f"  [WARN] {msg}")


def fail(msg: str) -> None:
    print(f"  [FAIL] {msg}")


# -- pip helpers --------------------------------------------------------------
def pip_install(*args: str) -> bool:
    """Run `pip install <args>` in the current interpreter. True on success."""
    cmd = [sys.executable, "-m", "pip", "install", *args]
    print(f"  $ {' '.join(cmd)}")
    return subprocess.run(cmd).returncode == 0


# -- EMBER patch --------------------------------------------------------------
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
        raise RuntimeError("Patch write did not take effect - aborting.")
    return "patched"


# -- Verification -------------------------------------------------------------
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


# -- Main flow ----------------------------------------------------------------
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
        warn(f"Python is not {PYTHON_PREFIX}.x - locked baseline is 3.11. "
             "Predictions were validated only on 3.11.")

    if not verify_only:
        step("Install pinned core dependencies")
        for name, ver in CORE_PINS.items():
            if not pip_install(f"{name}=={ver}"):
                fail(f"Could not install {name}=={ver}. "
                     "STOPPING - version fidelity is required; not substituting.")
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
    fail("Environment is NOT fully valid - see messages above.")
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
'@

function Ensure-SetupScript {
    if (-not (Test-Path $SetupPy)) {
        Write-Warn "setup_environment.py missing from this copy - writing the embedded fallback copy"
        Set-Content -Path $SetupPy -Value $SetupPyEmbedded -Encoding utf8 -NoNewline
    }
}

function Write-Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "  [OK]   $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "  [FAIL] $msg" -ForegroundColor Red }

function Find-Python311 {
    $candidates = New-Object System.Collections.Generic.List[string]
    try {
        $out = & py -3.11 -c "import sys; print(sys.executable)" 2>$null
        if ($LASTEXITCODE -eq 0 -and $out) { $candidates.Add($out.Trim()) }
    } catch {}
    $candidates.Add('C:\Python311\python.exe')
    $candidates.Add('C:\Program Files\Python311\python.exe')
    $candidates.Add((Join-Path $env:LOCALAPPDATA 'Programs\Python\Python311\python.exe'))
    foreach ($c in $candidates) {
        if (Test-Path $c) {
            $ver = & $c -c "import sys; print(sys.version)" 2>$null
            if ($LASTEXITCODE -eq 0 -and $ver -match '^3\.11') { return $c }
        }
    }
    return $null
}

function Install-Python311 {
    # Official python.org build - installed silently, per-user (no admin needed),
    # with PATH + the py launcher included so this box is usable outside this
    # script too, not just for this venv.
    Write-Step 'Python 3.11 not found - downloading and installing it automatically'
    $version = '3.11.9'
    $url = "https://www.python.org/ftp/python/$version/python-$version-amd64.exe"
    $installer = Join-Path $env:TEMP "python-$version-amd64.exe"
    try {
        # Fresh/older Windows images often default .NET to TLS 1.0, which
        # python.org rejects - force TLS 1.2 for this download.
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Write-Host "  Downloading $url"
        Invoke-WebRequest -Uri $url -OutFile $installer -UseBasicParsing
    } catch {
        Write-Fail "Could not download the Python installer: $_"
        return $null
    }
    Write-Host '  Installing Python 3.11 silently (current user, added to PATH)...'
    $args = @(
        '/quiet',
        'InstallAllUsers=0',
        'InstallLauncherAllUsers=0',
        'PrependPath=1',
        'Include_test=0'
    )
    $proc = Start-Process -FilePath $installer -ArgumentList $args -Wait -PassThru
    Remove-Item $installer -ErrorAction SilentlyContinue
    if ($proc.ExitCode -ne 0) {
        Write-Fail "Python installer exited with code $($proc.ExitCode)"
        return $null
    }
    Write-Ok "Python $version installed"
    $found = Find-Python311
    if (-not $found) {
        Write-Fail 'Python was installed but could not be located afterwards.'
    }
    return $found
}

function Test-VenvHealthy {
    if (-not (Test-Path $VenvPython)) { return $false }
    & $VenvPython -c "import sys" 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { return $false }
    & $VenvPython -m pip --version 2>$null | Out-Null
    return ($LASTEXITCODE -eq 0)
}

Write-Host '============================================================'
Write-Host 'AntivirusAI V7 - environment installer'
Write-Host '============================================================'
Write-Host "Project root: $Root"

Write-Step 'Checking for an existing venv_v7'
$healthy = Test-VenvHealthy
if ($healthy -and -not $Force) {
    Write-Ok 'venv_v7 already present and healthy - reusing it (pass -Force to recreate)'
} else {
    if ($VerifyOnly) {
        Write-Fail 'venv_v7 is missing or broken and -VerifyOnly was passed. Aborting.'
        exit 1
    }
    if (Test-Path $Venv) {
        Write-Warn 'Removing existing venv_v7 (missing/broken, or -Force was passed)...'
        Remove-Item -Recurse -Force $Venv
    }

    Write-Step 'Locating a Python 3.11 base interpreter'
    $basePy = Find-Python311
    if (-not $basePy) {
        Write-Warn "No Python 3.11 interpreter found (tried 'py -3.11' and common install paths)."
        $basePy = Install-Python311
        if (-not $basePy) {
            Write-Fail 'Automatic Python install failed. Install Python 3.11 manually from'
            Write-Host '  https://www.python.org/downloads/release/python-3119/ and re-run this script.'
            exit 1
        }
    }
    Write-Ok "Using base interpreter: $basePy"

    Write-Step 'Creating venv_v7'
    & $basePy -m venv $Venv
    if ($LASTEXITCODE -ne 0) { Write-Fail 'venv creation failed.'; exit 1 }
    Write-Ok "Created $Venv"

    Write-Step 'Upgrading pip'
    & $VenvPython -m pip install --upgrade pip | Out-Null
}

Ensure-SetupScript
Write-Step 'Installing pinned packages + EMBER patch (setup_environment.py)'
$setupArgs = @()
if ($VerifyOnly) { $setupArgs += '--verify-only' }
if ($NoGui)      { $setupArgs += '--no-gui' }
& $VenvPython $SetupPy @setupArgs
if ($LASTEXITCODE -ne 0) {
    Write-Fail 'setup_environment.py reported failures - see above. Aborting.'
    exit 1
}
Write-Ok 'Environment matches the locked spec'

if (-not $SkipGeminiPrompt) {
    Write-Step 'Checking for GEMINI_API_KEY (optional - powers the "why" explain layer)'
    Push-Location $Root
    $existing = & $VenvPython -c "from avscan.config import get_gemini_api_key; print(get_gemini_api_key() or '')" 2>$null
    Pop-Location
    if ($existing) {
        Write-Ok 'Gemini API key already configured'
    } else {
        Write-Warn 'No Gemini API key found. Core scanning works fully offline without it.'
        try {
            Add-Type -AssemblyName Microsoft.VisualBasic
            $key = [Microsoft.VisualBasic.Interaction]::InputBox(
                "Optional: paste a Gemini API key to enable the ""why"" explanation layer.`nLeave blank to skip.",
                'AntivirusAI V7 - Gemini API key', '')
        } catch {
            $key = $null
        }
        if ($key) {
            [System.Environment]::SetEnvironmentVariable('GEMINI_API_KEY', $key, 'User')
            $env:GEMINI_API_KEY = $key
            Write-Ok 'Saved GEMINI_API_KEY as a persistent User environment variable'
        } else {
            Write-Warn 'Skipped. You can set it later with:'
            Write-Host '    [System.Environment]::SetEnvironmentVariable("GEMINI_API_KEY", "<key>", "User")'
        }
    }
}

$registerScript = Join-Path $Root 'register_quickscan.ps1'
if (Test-Path $registerScript) {
    Write-Step 'Registering right-click Quick Scan menu entry'
    try {
        & powershell -NoProfile -ExecutionPolicy Bypass -File $registerScript -Quiet
        Write-Ok 'Right-click Quick Scan registered'
    } catch {
        Write-Warn "Could not register right-click menu: $_"
    }
}

if (-not $SkipSelfcheck) {
    Write-Step 'Running app self-check (python -m avscan selfcheck)'
    Push-Location $Root
    & $VenvPython -m avscan selfcheck
    $selfcheckExit = $LASTEXITCODE
    Pop-Location
    if ($selfcheckExit -ne 0) {
        Write-Fail 'Self-check FAILED - environment is not fully valid.'
        exit 1
    }
    Write-Ok 'Self-check PASSED'
}

if (-not $SkipTests -and -not $VerifyOnly) {
    Write-Step 'Running test suite (pytest)'
    Push-Location $Root
    & $VenvPython -m pytest tests -q
    $testExit = $LASTEXITCODE
    Pop-Location
    if ($testExit -ne 0) {
        Write-Fail 'Some tests FAILED - see above.'
        exit 1
    }
    Write-Ok 'All tests passed'
}

Write-Host ''
Write-Host '============================================================' -ForegroundColor Green
Write-Host 'AntivirusAI V7 environment is installed and verified.' -ForegroundColor Green
Write-Host '============================================================' -ForegroundColor Green
Write-Host 'Launch the GUI with: AntiVirusGUI.BAT'
exit 0
