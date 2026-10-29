@echo off
title AegisCloud - LocalStack Resource Seeder
cd /d "%~dp0backend"
echo =====================================================================
echo           AEGISCLOUD - LOCALSTACK AWS RESOURCE SEEDER
echo =====================================================================
echo.
python seed_localstack.py
echo.
pause
