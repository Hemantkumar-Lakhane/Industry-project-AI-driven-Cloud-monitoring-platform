@echo off
title RAM Antivirus - Member 2 EDA and ML Pipeline Runner
cd /d "%~dp0"

echo =====================================================================
echo    RAM ANTIVIRUS — MEMBER 2: EDA & MACHINE LEARNING PIPELINE
echo =====================================================================
echo.
echo [*] Executing Python EDA and Anomaly Model Training...
echo [*] Dataset: NSL-KDD (KDDTrain+ N=125,973 ^| KDDTest+ N=22,544)
echo.

python backend\ml_pipeline_eda_visualizer.py

if errorlevel 1 (
    echo.
    echo [ERROR] Pipeline execution failed. Please check the error message above.
    pause
    exit /b 1
)

echo.
echo =====================================================================
echo [OK] Execution completed successfully!
echo [OK] Generated 8 high-resolution graphs in:
echo      docs\images\ml_visualizations\
echo.
echo Opening visualization folder...
start "" "%~dp0docs\images\ml_visualizations"
echo =====================================================================
echo.
pause
