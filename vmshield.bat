@echo off
title WinOpSec VmShield - VM Sentry & Leak Guard
cd /d "%~dp0"

net session >nul 2>&1
if %errorLevel% neq 0 (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"\"%~dp0WinOpSec.ps1\"\" -VmShield' -Verb RunAs"
    exit /b
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0WinOpSec.ps1" -VmShield

