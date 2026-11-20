"""
Global pytest configuration and fixtures for SENTINEL AI test suite.
Ensures tests always run in isolation against an in-memory SQLite database.
"""

from __future__ import annotations

import os

# Enforce isolated testing database before settings or models are imported
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./sentinel_test.db"
os.environ["APP_ENV"] = "development"
os.environ["SIEM_PROVIDER"] = "synthetic"
os.environ["SENTINEL_DATA_MODE"] = "synthetic"
