@echo off
title winopsec
cd /d "%~dp0"

where pwsh >nul 2>&1
if %errorLevel% == 0 (
    pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0WinOpSec.ps1" %*
) else (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0WinOpSec.ps1" %*
)
