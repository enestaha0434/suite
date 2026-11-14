@echo off
setlocal
cd /d "%~dp0"
title WinSecX Bagimlilik Kurulumu
set "PYTHONUTF8=1"
if exist ".venv\Scripts\python.exe" goto install
where py >nul 2>&1
if not errorlevel 1 (
    py -3 -m venv .venv
) else (
    python -m venv .venv
)
if errorlevel 1 (
    echo [!] Python sanal ortami olusturulamadi. Python 3.10 veya ustunu kurun.
    pause
    exit /b 1
)
:install
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
    echo [!] Bagimlilik kurulumu basarisiz oldu. Yukaridaki hatayi kontrol edin.
    pause
    exit /b 1
)
echo [OK] Kurulum tamamlandi. start.bat ile baslatabilirsiniz.
pause
endlocal
