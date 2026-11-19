@echo off
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" run.py
) else (
    where py >nul 2>&1
    if %errorlevel%==0 (
        py -3 run.py
    ) else (
        python run.py
    )
)
if errorlevel 1 pause
