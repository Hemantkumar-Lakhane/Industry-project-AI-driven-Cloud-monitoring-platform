#!/usr/bin/env python3
"""
AegisCloud Render Server Runner
================================
Reliable production runner for Render web service deployments.
Dynamically binds to the port provided in the PORT environment variable
(defaulting to 10000 on Render, or 8000 locally), binds to 0.0.0.0,
and ensures unbuffered standard output for real-time log streaming.
"""
import os
import sys

# Ensure backend directory is in sys.path
_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import uvicorn

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    host = os.environ.get("HOST", "0.0.0.0")
    print(f"[*] Starting AegisCloud Backend on {host}:{port}...", flush=True)
    uvicorn.run("main:app", host=host, port=port, log_level="info")

