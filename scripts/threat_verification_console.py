#!/usr/bin/env python3
"""
RAM Antivirus — Interactive Cloud Threat & Attack Verification Console
Launchable interactive console to simulate, stream, and verify real-time attacks.
"""
import sys
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from verify_cloud_detection import main

if __name__ == "__main__":
    if "-i" not in sys.argv and "--interactive" not in sys.argv and "--vector" not in sys.argv:
        sys.argv.append("--interactive")
    main()
