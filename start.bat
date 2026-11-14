@echo off
setlocal
cd /d "%~dp0"
title WinSecX Security Suite
set "PYTHONUTF8=1"
if not exist ".venv\Scripts\python.exe" (
    echo [!] Once install.bat dosyasini calistirin.
    pause
    exit /b 1
)
".venv\Scripts\python.exe" kalisuite.py
if errorlevel 1 (
    echo [!] Program hata ile kapandi. Yukaridaki mesaji kontrol edin.
    pause
    exit /b 1
)
endlocal
