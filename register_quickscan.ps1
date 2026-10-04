<#
    register_quickscan.ps1 — add the "AntivirusAI: quick scan" entry to the
    right-click menu of .exe files.

    Writes to HKCU only, so it needs no administrator rights and affects just
    the current user. Every path is derived from this script's own location,
    so it works unchanged on another machine, another user name, or inside a
    VM — which the previous hard-coded registration did not.

    Idempotent: re-running it after moving the project simply corrects the
    stored paths, and running it when nothing changed does nothing.

    Run directly to (re)register:
        powershell -NoProfile -ExecutionPolicy Bypass -File .\register_quickscan.ps1
    Remove the menu entry again:
        powershell -NoProfile -ExecutionPolicy Bypass -File .\register_quickscan.ps1 -Remove
#>
[CmdletBinding()]
param(
    [switch]$Remove,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'

$Root    = $PSScriptRoot
$PythonW = Join-Path $Root 'venv_v7\Scripts\pythonw.exe'
$Script  = Join-Path $Root 'avscan\quickscan.py'

$KeyName  = 'AntivirusAIQuickScan'
$ShellKey = "HKCU:\Software\Classes\exefile\shell\$KeyName"
$CmdKey   = "$ShellKey\command"
$Label    = 'AntivirusAI: סריקה מהירה'

function Say($msg) { if (-not $Quiet) { Write-Host $msg } }

if ($Remove) {
    if (Test-Path $ShellKey) {
        Remove-Item -Path $ShellKey -Recurse -Force
        Say "Removed the right-click entry."
    } else {
        Say "Nothing to remove."
    }
    exit 0
}

# Refuse to register a menu entry that would point at files that do not exist —
# a broken entry fails silently under pythonw (no console to show the error).
foreach ($p in @($PythonW, $Script)) {
    if (-not (Test-Path -LiteralPath $p)) {
        Write-Warning "Not registering the right-click entry - missing: $p"
        if ($p -eq $PythonW) {
            Write-Warning "The venv is tied to the Python it was built from and cannot be copied between machines. Recreate it on this machine first."
        }
        exit 1
    }
}

$Command = '"{0}" "{1}" "%1"' -f $PythonW, $Script

$current = $null
if (Test-Path $CmdKey) {
    $current = (Get-ItemProperty -Path $CmdKey -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
}
if ($current -eq $Command) {
    Say "Right-click entry already registered."
    exit 0
}

New-Item -Path $CmdKey -Force | Out-Null
Set-ItemProperty -Path $ShellKey -Name '(default)' -Value $Label
Set-ItemProperty -Path $ShellKey -Name 'Icon'      -Value $PythonW
Set-ItemProperty -Path $CmdKey   -Name '(default)' -Value $Command

if ($current) {
    Say "Right-click entry updated to this folder:`n  $Root"
} else {
    Say "Right-click entry registered. Right-click any .exe to scan it."
}
exit 0
