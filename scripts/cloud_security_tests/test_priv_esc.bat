@echo off
setlocal
echo ==============================================================================
echo RAM Antivirus -- Running IAM Privilege Escalation Test
echo ==============================================================================
python "%~dp0test_privilege_escalation.py"
pause
