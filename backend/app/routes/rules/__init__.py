"""
Rules API Package

Consolidates all rule-related REST API endpoints.

Package Structure:
    rules/
    ├── __init__.py         # This file - router aggregation
    ├── management.py       # Enhanced rule CRUD (/rules/*)
    ├── scanning.py         # Rule-specific scanning (/rule-scanning/*)
    └── compliance.py       # MongoDB compliance rules (/compliance-rules/*)

Migration Status (E1-S5 - Route Consolidation):
    - rule_management.py -> rules/management.py
    - rule_scanning.py -> rules/scanning.py
    - compliance_rules_api.py -> rules/compliance.py

Usage:
    from app.routes.rules import router
    app.include_router(router, prefix="/api")
"""

from fastapi import APIRouter

# Create main router that aggregates all sub-routers
router = APIRouter(tags=["Rules"])

# Import sub-routers from modular files
try:
    from .compliance import router as compliance_router
    from .management import router as management_router
    from .scanning import router as scanning_router

    # Include all sub-routers into main router
    # Rule management endpoints (/rules/*)
    router.include_router(management_router)

    # Rule scanning endpoints (/rule-scanning/*)
    router.include_router(scanning_router)

    # MongoDB compliance rules endpoints (/compliance-rules/*)
    router.include_router(compliance_router)

except ImportError as e:
    import logging

    logger = logging.getLogger(__name__)
    logger.error(f"Failed to load rules sub-routers: {e}")

__all__ = [
    "router",
]
