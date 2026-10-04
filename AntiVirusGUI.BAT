@echo off
rem ---------------------------------------------------------------------------
rem Start AntivirusAI: check the environment, make sure the right-click "quick
rem scan" entry points at THIS folder, then open the GUI.
rem
rem Every path comes from %~dp0 (this file's own folder) rather than from the
rem current directory. "call venv_v7\Scripts\activate" resolves relative to the
rem current directory, which is not this folder when the file is run as
rem administrator, from a shortcut, or from a shared folder in a VM - cmd
rem cannot cd to a \\host\share path and silently leaves you in C:\Windows.
rem That is why the old version did nothing in the VM: activate was never
rem found, and pythonw has no console to show the error.
rem
rem A venv's own python.exe already knows its environment, so calling it by
rem absolute path needs no activation at all.
rem ---------------------------------------------------------------------------
setlocal

set "ROOT=%~dp0"
set "PYW=%ROOT%venv_v7\Scripts\pythonw.exe"

rem Lets "-m avscan.gui" find the package without depending on the current dir.
set "PYTHONPATH=%ROOT%"

if not exist "%PYW%" (
    echo.
    echo Cannot find the virtual environment:
    echo   %PYW%
    echo.
    echo A venv is tied to the Python installation it was created from, so it
    echo cannot simply be copied to another machine or VM. Recreate it here,
    echo then run this file again.
    echo.
    pause
    exit /b 1
)

rem Point the right-click menu entry at this folder. Runs on every launch so a
rem moved or copied project self-corrects. HKCU only - no admin rights needed.
rem Never blocks the GUI: if it fails, the app still opens.
powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%register_quickscan.ps1" -Quiet 2>nul

start "" "%PYW%" -m avscan.gui
exit /b 0
