"""
Content API Package

DEPRECATED (2026-02-10): This package has been deprecated as part of MongoDB removal.
All SCAP content management endpoints have been replaced by Aegis native YAML rules.

The following routes were removed:
    - scap.py (152 LOC) - SCAP content management (/content/*)
    - import_.py (307 LOC) - SCAP import (/scap-import/*)
    - xccdf.py (294 LOC) - XCCDF generation (/xccdf/*)

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
router = APIRouter(tags=["Content (Deprecated)"])

# NOTE: All content routes removed during MongoDB deprecation (2026-02-10)
# - scap.py (152 LOC) - SCAP content management - Replaced by Aegis
# - import_.py (307 LOC) - SCAP import - Replaced by Aegis
# - xccdf.py (294 LOC) - XCCDF generation - Replaced by Aegis

__all__ = [
    "router",
]
