<#
.SYNOPSIS
  AntivirusAI V7 — install the locked venv_v7 environment from scratch, or repair
  a broken one, then delegate package installation to setup_environment.py.

.DESCRIPTION
  This script owns the VENV layer (create/recreate venv_v7 from a Python 3.11
  base interpreter). Package pins, the EMBER git install, the FeatureHasher
  patch, and version verification are ALL still owned by setup_environment.py
  (the single source of truth for the locked spec) — this script just makes
  sure a healthy venv exists, then runs that script inside it.

  NOTE: if you change the locked versions, the EMBER commit/patch, or the GUI
  pin in setup_environment.py / requirements.txt, this script does not need
  edits UNLESS you also change how the venv itself is created (e.g. Python
  version bump) — keep the two in sync.

.PARAMETER Force
  Recreate venv_v7 from scratch even if it currently looks healthy.

.PARAMETER NoGui
  Skip installing the PySide6 GUI toolkit (passed through to setup_environment.py).

.PARAMETER VerifyOnly
  Do not create/repair anything or install packages; only verify the existing
  venv_v7 and its packages. Fails loudly if venv_v7 is missing or broken.

.PARAMETER SkipSelfcheck
  Skip the final `python -m avscan selfcheck` regression check.

.PARAMETER SkipGeminiPrompt
  Do not check for / prompt for a Gemini API key. Use this for unattended runs
  (no interactive desktop session available for the input box).

.EXAMPLE
  .\install_environment.ps1
  First-time install, or auto-repair if venv_v7 is broken.

.EXAMPLE
  .\install_environment.ps1 -Force
  Nuke venv_v7 and rebuild it from zero even though it looks fine.

.EXAMPLE
  .\install_environment.ps1 -VerifyOnly
  Just check whether the current environment matches the locked spec.
#>
param(
    [switch]$Force,
    [switch]$NoGui,
    [switch]$VerifyOnly,
    [switch]$SkipSelfcheck,
    [switch]$SkipGeminiPrompt
)

$RequiredPythonVersion = "3.11"
$RepoRoot    = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvPath    = Join-Path $RepoRoot "venv_v7"
$VenvPython  = Join-Path $VenvPath "Scripts\python.exe"
$SetupScript = Join-Path $RepoRoot "setup_environment.py"

function Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "  [OK]   $msg" -ForegroundColor Green }
function Warn($msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow }
function Fail($msg) { Write-Host "  [FAIL] $msg" -ForegroundColor Red }

function Test-VenvHealthy {
    if (-not (Test-Path $VenvPython)) { return $false }
    try {
        $verOutput = & $VenvPython --version 2>&1
        if ($LASTEXITCODE -ne 0) { return $false }
        if ($verOutput -notmatch [regex]::Escape($RequiredPythonVersion)) { return $false }
    } catch { return $false }
    try {
        & $VenvPython -m pip --version *> $null
        if ($LASTEXITCODE -ne 0) { return $false }
    } catch { return $false }
    return $true
}

function Find-BasePython311 {
    try {
        $exe = & py "-$RequiredPythonVersion" -c "import sys; print(sys.executable)" 2>$null
        if ($LASTEXITCODE -eq 0 -and $exe) { return $exe.Trim() }
    } catch {}
    $fallback = "C:\Python311\python.exe"
    if (Test-Path $fallback) { return $fallback }
    return $null
}

Step "AntivirusAI V7 - install / repair environment"
Write-Host "Repo root: $RepoRoot"

if (-not (Test-Path $SetupScript)) {
    Fail "setup_environment.py not found at $SetupScript."
    Fail "Run this script from the project root (or keep both files together)."
    exit 1
}

if (-not $VerifyOnly) {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Fail "git is not on PATH. EMBER is installed from a git commit (pip install git+...)."
        Fail "Install Git for Windows (https://git-scm.com/download/win) and re-run this script."
        exit 1
    }
}

$venvExists  = Test-Path $VenvPath
$venvHealthy = if ($venvExists) { Test-VenvHealthy } else { $false }

Step "Checking venv_v7"
if ($venvExists -and $venvHealthy -and -not $Force) {
    Ok "venv_v7 exists and its Python/pip are working"
}
elseif ($VerifyOnly) {
    if (-not $venvExists)  { Fail "venv_v7 does not exist. Run without -VerifyOnly to create it."; exit 1 }
    if (-not $venvHealthy) { Fail "venv_v7 exists but looks broken. Run without -VerifyOnly to repair it."; exit 1 }
}
else {
    if ($venvExists) {
        if ($Force) { Warn "-Force passed: recreating venv_v7 from scratch even though it looked healthy." }
        else        { Warn "venv_v7 exists but looks broken (python/pip not working) - recreating it." }
        Step "Removing old venv_v7"
        Remove-Item -Recurse -Force $VenvPath
        Ok "removed"
    }

    Step "Locating a Python $RequiredPythonVersion base interpreter"
    $basePython = Find-BasePython311
    if (-not $basePython) {
        Fail "Could not find Python $RequiredPythonVersion (checked 'py -$RequiredPythonVersion' and C:\Python311\python.exe)."
        Fail "Install Python 3.11.x from https://www.python.org/downloads/ and re-run this script."
        exit 1
    }
    Ok "using $basePython"

    Step "Creating venv_v7"
    & $basePython -m venv $VenvPath
    if ($LASTEXITCODE -ne 0) { Fail "venv creation failed."; exit 1 }
    Ok "created $VenvPath"

    Step "Upgrading pip"
    & $VenvPython -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) { Warn "pip upgrade failed - continuing with the venv's bundled pip." }
}

Step "Running setup_environment.py inside venv_v7"
$setupArgs = @()
if ($VerifyOnly) { $setupArgs += "--verify-only" }
if ($NoGui)      { $setupArgs += "--no-gui" }

Push-Location $RepoRoot
& $VenvPython $SetupScript @setupArgs
$setupExit = $LASTEXITCODE
Pop-Location

if ($setupExit -ne 0) {
    Fail "setup_environment.py reported problems (exit $setupExit). See the log above."
    exit $setupExit
}
Ok "packages match the locked spec"

if (-not $SkipSelfcheck -and -not $VerifyOnly) {
    Step "Running avscan selfcheck (regression test against locked models)"
    Push-Location $RepoRoot
    & $VenvPython -m avscan selfcheck
    $selfcheckExit = $LASTEXITCODE
    Pop-Location
    if ($selfcheckExit -ne 0) {
        Fail "avscan selfcheck failed (exit $selfcheckExit)."
        exit $selfcheckExit
    }
    Ok "avscan selfcheck passed"
}

if (-not $VerifyOnly -and -not $SkipGeminiPrompt) {
    Step "Checking Gemini API key (optional 'why is this malware' layer)"
    Push-Location $RepoRoot
    & $VenvPython -c "from avscan import config; import sys; sys.exit(0 if config.get_gemini_api_key() else 1)" *> $null
    $hasGeminiKey = ($LASTEXITCODE -eq 0)
    Pop-Location

    if ($hasGeminiKey) {
        Ok "Gemini API key found (GEMINI_API_KEY env var, or config\settings.json / config\gemini_key.txt)."
    } else {
        Warn "No Gemini API key found. This is OPTIONAL: the scanner is fully offline and works"
        Warn "without it - only the 'why is this malware' explanation layer needs it."
        $geminiKey = $null
        try {
            Add-Type -AssemblyName Microsoft.VisualBasic
            $geminiKey = [Microsoft.VisualBasic.Interaction]::InputBox(
                "Enter your Gemini API key to enable the optional AI explanation layer." + "`n" +
                "Leave empty and click OK (or Cancel) to skip - the scanner still works fully offline.",
                "AntivirusAI V7 - Gemini API key",
                "")
        } catch {
            Warn "Could not open the input box (no interactive desktop session?) - skipping."
        }
        if ($geminiKey -and $geminiKey.Trim()) {
            $trimmedKey = $geminiKey.Trim()
            [System.Environment]::SetEnvironmentVariable("GEMINI_API_KEY", $trimmedKey, "User")
            $env:GEMINI_API_KEY = $trimmedKey
            Ok "Saved as a permanent User environment variable (GEMINI_API_KEY)."
            Warn "Already-open terminals/apps won't see it until restarted; new ones will."
        } else {
            Warn "Skipped. Add a key later by setting the GEMINI_API_KEY environment variable,"
            Warn "or by re-running this script."
        }
    }
}

Step "Done"
Ok "Environment is installed and verified."
Write-Host "Activate it with: venv_v7\Scripts\Activate.ps1"
Write-Host "Run the scanner with: venv_v7\Scripts\python.exe -m avscan --help"
exit 0
