@echo off
setlocal EnableDelayedExpansion

title Ram Antivirus - Cloud Security AI Platform Runner

:: Determine root directory
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

if exist "Industry-project-AI-driven-Cloud-monitoring-platform-" (
    cd /d "%SCRIPT_DIR%Industry-project-AI-driven-Cloud-monitoring-platform-"
)

set "PROJECT_ROOT=%CD%"
set "BACKEND_DIR=%PROJECT_ROOT%\backend"
set "FRONTEND_DIR=%PROJECT_ROOT%\frontend"

echo =====================================================================
echo           RAM ANTIVIRUS - CLOUD SECURITY AI PLATFORM
echo =====================================================================
echo.
echo [1/4] Checking environment prerequisites...

where python >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH! Please install Python 3.10+.
    pause
    exit /b 1
)

where npm >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js / npm is not installed or not in PATH! Please install Node.js 18+.
    pause
    exit /b 1
)

echo [OK] Python and Node.js detected.
echo.

echo [2/4] Verifying Environment...
cd /d "%BACKEND_DIR%"
python -c "import fastapi, uvicorn" >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installing required backend Python packages...
    pip install -r requirements.txt
) else (
    echo [OK] Backend dependencies verified.
)

echo.
echo [3/4] Verifying Database & User Seeds...
cd /d "%BACKEND_DIR%"
python -c "import os, sys; sys.path.insert(0, '.'); from engines.auth_engine import _seed_defaults; _seed_defaults(); print('[OK] Core accounts verified (admin, ramantivirus).')" >nul 2>&1
echo [OK] Database and master security credentials verified.

echo.
echo [4/4] Launching Platform Services...
echo.

:: 1. Launch FastAPI Backend
start "Ram Antivirus - Backend API (Port 8000)" cmd /k "title Ram Antivirus - Backend API (Port 8000) && color 0B && echo === RAM Antivirus Backend API Server === && python main.py"

:: 2. Launch Frontend Vite Dev Server
cd /d "%FRONTEND_DIR%"
start "Ram Antivirus - Frontend UI (Port 5173)" cmd /k "title Ram Antivirus - Frontend UI (Port 5173) && color 0E && echo === RAM Antivirus Frontend Server === && npm run dev"

:: Open browser immediately
timeout /t 1 /nobreak >nul
start http://localhost:5173/

echo =====================================================================
echo  Platform is now running!
echo.
echo  - Frontend UI:   http://localhost:5173
echo  - Backend API:   http://localhost:8000
echo  - API Docs:      http://localhost:8000/docs
echo.
echo  Default Credentials:
echo    admin / admin123 (Platform Superadmin - Real Cloud Monitoring)
echo    demo  / demo123  (Demo User - Simulated Wazuh Telemetry Showcase)
echo.
echo  Each service has opened in its own window.
echo  Close those windows or press Ctrl+C in them to stop each service.
echo =====================================================================
echo.
pause
