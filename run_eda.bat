@echo off
title RAM Antivirus - Member 2 Complete EDA and ML Master Runner
cd /d "%~dp0"

echo =====================================================================
echo    RAM ANTIVIRUS — MEMBER 2: MASTER EDA & ML PIPELINE RUNNER
echo =====================================================================
echo.
echo [*] Executing Master Pipeline:
echo     - Phase 1: Data Ingestion (Head / Tail)
echo     - Phase 2: Structural Understanding (Rows/Cols, info, describe)
echo     - Phase 3: Data Quality (Nulls, Duplicates, Cardinality)
echo     - Phase 4: Categorical Exploration (Protocols, Services, Flags)
echo     - Phase 5: Categorical Encoding & Attack Taxonomy Mapping
echo     - Phase 6: Random Forest Feature Importance Ranking
echo     - Phase 7: Multi-Dimensional Visualizations & Heatmaps
echo     - Phase 8: StandardScaler Normalization & PyOD Model Training
echo.

python backend\eda_master_pipeline.py

if errorlevel 1 (
    echo.
    echo [ERROR] Pipeline execution failed. Please check the error message above.
    pause
    exit /b 1
)

echo.
echo =====================================================================
echo [OK] Execution completed successfully!
echo [OK] Generated high-resolution EDA and Model graphs in:
echo      docs\images\ml_visualizations\
echo.
echo Opening visualization folder...
start "" "%~dp0docs\images\ml_visualizations"
echo =====================================================================
echo.
pause
