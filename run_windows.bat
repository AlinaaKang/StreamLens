@echo off
setlocal
chcp 65001 >nul
title Token Security
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python not found.
  echo Please install Python 3.12+ from https://www.python.org/downloads/
  echo IMPORTANT: check "Add Python to PATH" during install, then run this again.
  pause
  exit /b 1
)

where uv >nul 2>nul
if errorlevel 1 (
  echo [SETUP] Installing uv package manager ...
  python -m pip install -q uv
)

echo [SETUP] Installing dependencies, first run takes a few minutes ...
uv sync --quiet 2>nul
if errorlevel 1 python -m pip install -q -r requirements.txt

if not exist "config\credentials.env" (
  echo [TIP] config\credentials.env not found. Copy credentials.env.example and fill your API key for full LLM features.
)

set "PYTHON_BIN=python"
if exist ".venv\Scripts\python.exe" set "PYTHON_BIN=%~dp0.venv\Scripts\python.exe"
echo [START] Starting server in background window ...
start "StreamLens Server" /min "%PYTHON_BIN%" "%~dp0src\main.py" -m http -p 5000
echo [WAIT] Waiting for server ...
timeout /t 10 /nobreak >nul
start "" http://127.0.0.1:5000/web
echo.
echo ================================================
echo  StreamLens 明鉴 is running at:
echo  http://127.0.0.1:5000/web
echo  Close the minimized "TokenSecurity Server"
echo  window to stop. Close this window anytime.
echo ================================================
pause
