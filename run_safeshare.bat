@echo off
title SafeShare Desktop Guardian - Google Gemma 4
echo =================================================================
echo   SafeShare: Enterprise AI Privacy & Secret Firewall
echo   Powered by Google Gemma 4 (Zero-Trust Air-Gapped Mode)
echo =================================================================
echo.
echo [*] Checking dependencies...
python -m pip install -r requirements.txt --quiet
echo [OK] Launching SafeShare Desktop Application...
echo.
python desktop_app.py
if errorlevel 1 (
    echo.
    echo [!] An error occurred. Press any key to exit.
    pause
)
