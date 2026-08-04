<#
.SYNOPSIS
  AntivirusAI V7 — launch the main desktop GUI (avscan.gui).

.DESCRIPTION
  Checks that venv_v7 is healthy and PySide6 is installed, then launches
  `python -m avscan.gui` from the repo root (the same entry point documented
  in the build status memory / README). By default it launches detached with
  pythonw.exe (no console window). Use -Console to run attached with
  python.exe so you can see errors/tracebacks if the window doesn't appear.

  If venv_v7 is missing/broken or PySide6 isn't installed, this script does
  NOT try to fix it — it points you at install_environment.ps1, which owns
  that job.

.PARAMETER Console
  Run attached to a console (python.exe) instead of detached (pythonw.exe),
  so you can see stdout/stderr/tracebacks. Blocks until the GUI is closed.

.EXAMPLE
  .\run_gui.ps1
  Launch the GUI normally (no console window).

.EXAMPLE
  .\run_gui.ps1 -Console
  Launch the GUI with a console attached, to debug a startup failure.
#>
param(
    [switch]$Console
)

$RepoRoot   = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvPath   = Join-Path $RepoRoot "venv_v7"
$PythonExe  = Join-Path $VenvPath "Scripts\python.exe"
$PythonwExe = Join-Path $VenvPath "Scripts\pythonw.exe"

function Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "  [OK]   $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "  [FAIL] $msg" -ForegroundColor Red }

function Test-VenvHealthy {
    if (-not (Test-Path $PythonExe)) { return $false }
    try {
        & $PythonExe --version *> $null
        if ($LASTEXITCODE -ne 0) { return $false }
    } catch { return $false }
    return $true
}

Step "AntivirusAI V7 - launching GUI"

if (-not (Test-VenvHealthy)) {
    Fail "venv_v7 is missing or broken."
    Fail "Run install_environment.ps1 first:  .\install_environment.ps1"
    exit 1
}

if (-not (Test-Path $PythonwExe)) {
    Fail "pythonw.exe not found in venv_v7\Scripts (venv looks incomplete)."
    Fail "Run install_environment.ps1 -Force to rebuild it."
    exit 1
}

Step "Checking PySide6 (GUI toolkit)"
& $PythonExe -c "import PySide6" *> $null
if ($LASTEXITCODE -ne 0) {
    Fail "PySide6 is not installed in venv_v7."
    Fail "Install it with:  .\install_environment.ps1   (do not pass -NoGui)"
    exit 1
}
Ok "PySide6 available"

if ($Console) {
    Step "Launching GUI (console mode - errors will print here, window blocks until closed)"
    Push-Location $RepoRoot
    & $PythonExe -m avscan.gui
    $exitCode = $LASTEXITCODE
    Pop-Location
    exit $exitCode
}

Step "Launching GUI"
Start-Process -FilePath $PythonwExe -ArgumentList "-m", "avscan.gui" -WorkingDirectory $RepoRoot
Ok "GUI launched (no console window)."
Write-Host "If nothing appears in a few seconds, re-run with -Console to see the error:  .\run_gui.ps1 -Console"
exit 0
