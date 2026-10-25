@echo off
title winopsec
cd /d "%~dp0"

:: Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Elevating to Administrator...
    where pwsh >nul 2>&1
    if %errorLevel% == 0 (
        powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process pwsh -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"\"%~dp0WinOpSec.ps1\"\"' -Verb RunAs"
    ) else (
        powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"\"%~dp0WinOpSec.ps1\"\"' -Verb RunAs"
    )
    exit /b
)

where pwsh >nul 2>&1
if %errorLevel% == 0 (
    pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0WinOpSec.ps1" %*
) else (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0WinOpSec.ps1" %*
)
