#!/usr/bin/env python3
"""
AegisCloud Root Runner for Render
==================================
Handles Render deployments where Root Directory is left blank (workspace root).
Navigates into backend/, configures sys.path, and starts uvicorn on $PORT.
"""
import os
import sys

_ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
_BACKEND_DIR = os.path.join(_ROOT_DIR, "backend")

if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

os.chdir(_BACKEND_DIR)

import uvicorn

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    host = os.environ.get("HOST", "0.0.0.0")
    print(f"[*] Starting AegisCloud Backend from root runner on {host}:{port}...", flush=True)
    uvicorn.run("main:app", host=host, port=port, log_level="info")
