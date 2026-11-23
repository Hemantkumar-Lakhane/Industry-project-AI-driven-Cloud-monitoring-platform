@echo off
setlocal
echo ==============================================================================
echo RAM Antivirus -- Launching Full Security Verification Suite
echo ==============================================================================
python "%~dp0scripts\cloud_security_tests\run_all_security_tests.py"
pause
