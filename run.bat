@echo off
REM PhishGuard - one-command local run for Windows.
REM   Double-click this file, or run:  run.bat
REM   Optional:  run.bat 8080    (custom port)
setlocal enabledelayedexpansion
cd /d "%~dp0"
set "PORT=%~1"
if "%PORT%"=="" set "PORT=8000"

where py >nul 2>nul
if %errorlevel%==0 (
  set "PY=py -3"
) else (
  where python >nul 2>nul
  if !errorlevel!==0 (
    set "PY=python"
  ) else (
    echo ERROR: Python 3.9+ not found.
    echo   Install from https://www.python.org/downloads/
    echo   IMPORTANT: tick "Add python.exe to PATH" during install.
    pause
    exit /b 1
  )
)

echo Using:
%PY% -V

if not exist ".venv" (
  echo Creating virtual environment...
  %PY% -m venv .venv
  if errorlevel 1 (
    echo ERROR: could not create .venv
    pause
    exit /b 1
  )
)

call .venv\Scripts\activate.bat

echo Installing dependencies ^(first run only, ~30s^)...
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r backend\requirements.txt
python -m pip install --quiet pytest

cd /d "%~dp0backend"

if not exist "data\phishguard.db" (
  echo Seeding demo baselines...
  python scripts\seed_demo.py
)

echo Running engine tests...
python -m pytest tests\ -q
if errorlevel 1 (
  echo TESTS FAILED - not starting.
  pause
  exit /b 1
)

echo.
echo ====================================================
echo   PhishGuard running  -^>  http://localhost:%PORT%
echo   Stop with Ctrl+C
echo ====================================================
echo.
set "PORT=%PORT%"
python app.py
pause
