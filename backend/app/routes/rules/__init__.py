"""
Rules API Package

DEPRECATED (2026-02-10): This package has been deprecated as part of MongoDB removal.
All MongoDB-dependent rule endpoints have been replaced by Aegis native YAML rules.

The following routes were removed:
    - management.py (~783 LOC) - Enhanced rule CRUD (/rules/*)
    - scanning.py (~539 LOC) - Rule-specific scanning (/rule-scanning/*)
    - compliance.py (~1,086 LOC) - MongoDB compliance rules (/compliance-rules/*)

Replacement:
    Use Aegis compliance scanning endpoints at /api/scans/aegis/*
    - GET /api/scans/aegis/frameworks - List available frameworks (CIS, STIG)
    - POST /api/scans/aegis/ - Execute Aegis compliance scan
    - GET /api/scans/aegis/compliance-state/{host_id} - Get compliance state

For historical reference, see:
    - docs/plans/MONGODB_DEPRECATION_PLAN.md
    - .claude/plans/mongodb-deprecation-plan.md
"""

from fastapi import APIRouter

# Empty router for backward compatibility
# This ensures existing includes don't break but routes return 404
router = APIRouter(tags=["Rules (Deprecated)"])

# NOTE: All rules routes removed during MongoDB deprecation (2026-02-10)
# - management.py (~783 LOC) - Rule CRUD - Replaced by Aegis
# - scanning.py (~539 LOC) - Rule scanning - Replaced by Aegis
# - compliance.py (~1,086 LOC) - MongoDB compliance rules - Replaced by Aegis

__all__ = [
    "router",
]
