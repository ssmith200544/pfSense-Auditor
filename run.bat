@echo off
REM ============================================================
REM   pfsense-audit  -  Windows wrapper script
REM
REM   Usage:
REM     run.bat <path-to-config.xml> [options]
REM
REM   Examples:
REM     run.bat tests\fixtures\sample_config.xml
REM     run.bat C:\path\to\config.xml -f json
REM     run.bat C:\path\to\config.xml -o report.txt
REM ============================================================

setlocal

REM Always run from the directory this script lives in,
REM so relative paths like tests\fixtures\... work no matter
REM where the user invokes us from.
cd /d "%~dp0"

REM Verify Python is installed and on PATH.
where python >nul 2>&1
if errorlevel 1 (
    echo Error: Python was not found on PATH.
    echo Install Python 3.10 or later from https://www.python.org/downloads/
    echo Be sure to check "Add Python to PATH" during installation.
    exit /b 1
)

REM Install dependencies. pip is idempotent so this is safe to run
REM on every invocation; takes ~1 second when already installed.
python -m pip install --quiet --disable-pip-version-check -r requirements.txt
if errorlevel 1 (
    echo Error: Failed to install dependencies.
    echo Try running manually: python -m pip install -r requirements.txt
    exit /b 1
)

REM Forward all script arguments to the tool.
python -m pfsense_auditor %*
exit /b %errorlevel%
