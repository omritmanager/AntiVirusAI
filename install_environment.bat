@echo off
rem Double-click wrapper for install_environment.ps1. Uses %~dp0 so it works
rem no matter where this folder is copied to on the new machine/VM.
setlocal
set "ROOT=%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%install_environment.ps1" %*
set "EXITCODE=%ERRORLEVEL%"
echo.
pause
exit /b %EXITCODE%
