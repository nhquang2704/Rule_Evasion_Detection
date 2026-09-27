@echo off
setlocal

net session >nul 2>&1
if not "%errorlevel%"=="0" (
    echo Run this file as Administrator.
    echo Right-click install_velociraptor_client_windows.cmd and choose "Run as administrator".
    pause
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install_velociraptor_client_windows.ps1" %*
exit /b %errorlevel%
