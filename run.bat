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
echo [1/5] Checking environment prerequisites...

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

echo [2/5] Checking Backend Python dependencies...
cd /d "%BACKEND_DIR%"
python -c "import fastapi, uvicorn, pyod, pandas, numpy, sklearn, jwt, websockets" >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installing required backend Python packages...
    pip install -r requirements.txt
    pip install pyod
) else (
    echo [OK] Backend dependencies verified.
)

echo.
echo [3/6] Checking ML Models...
if not exist "%BACKEND_DIR%\models\iforest.pkl" (
    echo [INFO] Trained models not found. Running train_model.py...
    python train_model.py
) else (
    echo [OK] Pre-trained models found: iforest, knn, hbos.
)

echo.
echo [4/6] Verifying Database & Telemetry Seeds...
cd /d "%BACKEND_DIR%"
python -c "import os, sys; sys.path.insert(0, '.'); from engines.auth_engine import _seed_defaults; _seed_defaults(); print('[OK] Default user accounts verified in security.db (admin, analyst1, viewer1).')"
if not exist "%BACKEND_DIR%\data\alerts.json" (
    echo [INFO] Seeding initial Wazuh telemetry batch to data/alerts.json...
    python -c "import os, sys; sys.path.insert(0, '.'); from simulator.log_generator import generate_batch, append_to_log; append_to_log(generate_batch())"
    echo [OK] Initial telemetry alerts seeded.
) else (
    echo [OK] Telemetry alerts found in data/alerts.json.
)

echo.
echo [5/6] Checking Frontend dependencies...
cd /d "%FRONTEND_DIR%"
if not exist "%FRONTEND_DIR%\node_modules" (
    echo [INFO] Installing frontend npm packages...
    call npm install
) else (
    echo [OK] Frontend packages verified.
)

echo.
echo [6/6] Launching Platform Services...
echo.

:: 1. Launch Wazuh Live Log Generator in separate window
cd /d "%BACKEND_DIR%"
start "Ram Antivirus - Live Log Generator" cmd /k "title Ram Antivirus - Live Log Generator && color 0A && echo === Live Log Generator === && python simulator/log_generator.py 10"

:: 2. Launch FastAPI Backend in separate window
start "Ram Antivirus - Backend API (Port 8000)" cmd /k "title Ram Antivirus - Backend API (Port 8000) && color 0B && echo === Backend API Server === && set WAZUH_LOG_PATH=data/alerts.json && python main.py"

:: 3. Launch Frontend in separate window
cd /d "%FRONTEND_DIR%"
start "Ram Antivirus - Frontend UI (Port 5173)" cmd /k "title Ram Antivirus - Frontend UI (Port 5173) && color 0E && echo === Frontend Vite Server === && npm run dev"

:: Wait 3 seconds and open browser
timeout /t 3 /nobreak >nul
start http://localhost:5173/

echo =====================================================================
echo  Platform is now running!
echo.
echo  - Frontend UI:   http://localhost:5173
echo  - Backend API:   http://localhost:8000
echo  - API Docs:      http://localhost:8000/docs
echo.
echo  Default Credentials:
echo    admin    / admin123   (Administrator)
echo    analyst1 / analyst123 (Security Analyst)
echo    viewer1  / viewer123  (Viewer)
echo.
echo  Each service has opened in its own window.
echo  Close those windows or press Ctrl+C in them to stop each service.
echo =====================================================================
echo.
pause
