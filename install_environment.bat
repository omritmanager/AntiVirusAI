@echo off
REM Double-click convenience wrapper around install_environment.ps1.
REM Any arguments are forwarded as-is, e.g.:
REM   install_environment.bat -Force
REM   install_environment.bat -VerifyOnly
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install_environment.ps1" %*
pause
