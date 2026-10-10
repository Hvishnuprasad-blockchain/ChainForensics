"""
ChainForensics — Root pytest configuration.

Sprint 6: ensures consistent test environment across all sprints.
"""
from __future__ import annotations

import os
import sys

# Ensure project root is on the import path.
sys.path.insert(0, os.path.dirname(__file__))

# Default test environment variables (safe for CI — no real secrets).
os.environ.setdefault("CHAINFORENSIS_DATABASE_URL", "sqlite:///./test_chainforensics.db")
os.environ.setdefault("CHAINFORENSIS_API_KEY", "test-api-key-for-ci")
