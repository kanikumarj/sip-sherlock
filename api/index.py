"""
Vercel Serverless Function entry point for SIP Sherlock backend.
Vercel's Python runtime requires the FastAPI `app` object to be importable
from this file. All routes are defined in backend/main.py and are
re-exported here via sys.path manipulation.
"""
import sys
import os

# Add the backend directory to the path so all imports resolve correctly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

# Re-export the FastAPI app — Vercel looks for an object named `app`
from main import app  # noqa: F401, E402
