@echo off
REM Double-click convenience wrapper around run_gui.ps1.
REM   run_gui.bat            -> launch GUI normally (no console window)
REM   run_gui.bat -Console   -> launch with console attached, to see errors
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_gui.ps1" %*
exit
