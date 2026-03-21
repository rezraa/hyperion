#!/bin/bash
# Hyperion Dashboard — Real-time security monitoring
cd "$(dirname "$0")"
source .venv/bin/activate 2>/dev/null || true
PYTHONPATH=src python3 -m uvicorn hyperion.dashboard.app:app --host 0.0.0.0 --port 8300 --reload
