@echo off
setlocal
chcp 65001 >nul
title Token Security
cd /d "%~dp0"

rem Local bundles run the Agent entrypoint directly. Hosted Coze deployments
rem inject these values themselves, but a desktop launch does not.
set "COZE_PROJECT_TYPE=agent"
set "COZE_PROJECT_ENV=LOCAL"
set "COZE_WORKSPACE_PATH=%~dp0"
set "PYTHONPATH=%~dp0src;%PYTHONPATH%"
set "COZE_LOG_DIR=%~dp0tmp\logs"

where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python not found.
  echo Please install Python 3.12+ from https://www.python.org/downloads/
  echo IMPORTANT: check "Add Python to PATH" during install, then run this again.
  pause
  exit /b 1
)

if exist ".venv\Scripts\python.exe" (
  echo [SETUP] Existing .venv found, skipping dependency installation.
) else (
  where uv >nul 2>nul
  if errorlevel 1 (
    echo [SETUP] Installing uv package manager ...
    python -m pip install -q uv
    if errorlevel 1 (
      echo [ERROR] Could not install uv. Check Python and network access.
      pause
      exit /b 1
    )
  )

  echo [SETUP] Installing dependencies, first run takes a few minutes ...
  uv sync --quiet 2>nul
  if errorlevel 1 (
    echo [SETUP] uv sync failed, trying pip fallback ...
    python -m pip install -q -r requirements.txt
    if errorlevel 1 (
      echo [ERROR] Dependency installation failed. Check network access.
      pause
      exit /b 1
    )
  )
)

if not exist "config\credentials.env" (
  echo [TIP] config\credentials.env not found. Copy credentials.env.example and fill your API key for full LLM features.
)

set "PYTHON_BIN=python"
if exist ".venv\Scripts\python.exe" set "PYTHON_BIN=%~dp0.venv\Scripts\python.exe"
echo [START] Starting server in background window ...
start "StreamLens Server" /min "%PYTHON_BIN%" "%~dp0src\main.py" -m http -p 5000
echo [WAIT] Waiting for server health check ...
for /l %%I in (1,1,30) do (
  curl.exe --fail --silent --max-time 1 http://127.0.0.1:5000/health >nul 2>nul
  if not errorlevel 1 goto :server_ready
  rem ping provides a one-second delay without reading console input
  ping -n 2 127.0.0.1 >nul
)
echo [ERROR] StreamLens failed to start.
echo [ERROR] Check tmp\logs\app.log for the startup traceback.
pause
exit /b 1

:server_ready
start "" http://127.0.0.1:5000/web
echo.
echo ================================================
echo  StreamLens 明鉴 is running at:
echo  http://127.0.0.1:5000/web
echo  Close the minimized "TokenSecurity Server"
echo  window to stop. Close this window anytime.
echo ================================================
pause
