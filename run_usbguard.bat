@echo off
title USBGuard Pro - Smart USB Intrusion Prevention System
color 0A

echo.
echo ================================================
echo    USBGuard Pro - Starting Application
echo ================================================
echo.
echo Checking administrator privileges...

net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Running with administrator privileges
    echo.
    echo Starting USBGuard Pro...
    echo.
    python gui_application.py
) else (
    echo [ERROR] Administrator privileges required!
    echo.
    echo Please right-click this file and select "Run as administrator"
    echo.
    pause
)
