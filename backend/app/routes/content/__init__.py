"""
Content API Package

DEPRECATED (2026-02-10): This package has been deprecated as part of MongoDB removal.
All SCAP content management endpoints have been replaced by Kensa native YAML rules.

The following routes were removed:
    - scap.py (152 LOC) - SCAP content management (/content/*)
    - import_.py (307 LOC) - SCAP import (/scap-import/*)
    - xccdf.py (294 LOC) - XCCDF generation (/xccdf/*)

Replacement:
    Use Kensa compliance scanning endpoints at /api/scans/kensa/*
    - GET /api/scans/kensa/frameworks - List available frameworks (CIS, STIG)
    - POST /api/scans/kensa/ - Execute Kensa compliance scan
    - GET /api/scans/kensa/compliance-state/{host_id} - Get compliance state

For historical reference, see:
    - docs/plans/MONGODB_DEPRECATION_PLAN.md
    - .claude/plans/mongodb-deprecation-plan.md
"""

from fastapi import APIRouter

# Empty router for backward compatibility
# This ensures existing includes don't break but routes return 404
router = APIRouter(tags=["Content (Deprecated)"])

# NOTE: All content routes removed during MongoDB deprecation (2026-02-10)
# - scap.py (152 LOC) - SCAP content management - Replaced by Kensa
# - import_.py (307 LOC) - SCAP import - Replaced by Kensa
# - xccdf.py (294 LOC) - XCCDF generation - Replaced by Kensa

__all__ = [
    "router",
]
