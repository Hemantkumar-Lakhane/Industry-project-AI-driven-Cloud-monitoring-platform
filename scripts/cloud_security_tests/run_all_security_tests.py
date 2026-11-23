#!/usr/bin/env python3
"""
RAM Antivirus — Full Defensive Security Verification Suite
Runs Brute Force, Reconnaissance, and Privilege Escalation tests against the connected cloud.
"""
import sys
import os
import subprocess
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, PARENT_DIR)

from verify_cloud_detection import AUDIT_ACCOUNT_ID

def main():
    print("=" * 80)
    print(" RAM ANTIVIRUS — AUTOMATED CLOUD SECURITY VERIFICATION SUITE")
    print(f" Verifying real-time threat detection across AWS environment {AUDIT_ACCOUNT_ID}")
    print("=" * 80)

    tests = [
        ("test_brute_force.py", "Brute Force & Credential Stuffing (T1110.001)"),
        ("test_reconnaissance.py", "Network & API Reconnaissance (T1046)"),
        ("test_privilege_escalation.py", "IAM Privilege Escalation (T1078.004)")
    ]

    results = []

    for script, name in tests:
        script_path = os.path.join(SCRIPT_DIR, script)
        print(f"\n>>> Running: {name} ...\n")
        proc = subprocess.run([sys.executable, script_path])
        results.append((name, proc.returncode == 0))
        time.sleep(1)

    print("\n" + "=" * 80)
    print(" SECURITY TEST SUITE RESULTS SUMMARY")
    print("=" * 80)
    all_passed = True
    for name, passed in results:
        status_str = "\033[38;5;46m[PASS]\033[0m" if passed else "\033[38;5;196m[FAIL]\033[0m"
        print(f" {status_str} {name}")
        if not passed:
            all_passed = False

    print("=" * 80)
    if all_passed:
        print("\033[38;5;46m[SUCCESS] All cloud threat detection scenarios verified against RAM Antivirus!\033[0m\n")
    else:
        print("\033[38;5;220m[NOTICE] One or more scenarios reported warnings. Check dashboard: https://d3sa9ma9swl1ef.cloudfront.net\033[0m\n")

    sys.exit(0 if all_passed else 1)

if __name__ == "__main__":
    main()
