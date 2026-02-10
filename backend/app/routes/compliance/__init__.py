"""
Compliance API Package

This package consolidates all compliance-related endpoints into a modular structure.
Part of Phase 4 API Standardization: System & Integrations.

Package Structure:
    - intelligence.py: Semantic SCAP intelligence and cross-framework compliance data
    - owca.py: OpenWatch Compliance Algorithm (OWCA) endpoints
    - drift.py: Compliance drift event endpoints
    - posture.py: Temporal compliance posture queries (Phase 2)
    - exceptions.py: Structured exception management (Phase 3)
    - audit.py: Audit query builder and exports (Phase 6)

Endpoint Structure:
    /compliance/                    - Intelligence endpoints (overview, semantic-rules, etc.)
    /compliance/owca/*              - OWCA compliance scoring and analytics
    /compliance/drift/*             - Drift detection events
    /compliance/posture             - Point-in-time posture queries
    /compliance/posture/history     - Posture history over time
    /compliance/posture/drift       - Compliance drift analysis
    /compliance/exceptions          - Exception management (Phase 3)
    /compliance/audit/*             - Audit query builder and exports (Phase 6)

Migration Status:
    - compliance.py -> compliance/intelligence.py
    - owca.py -> compliance/owca.py
    - drift_events.py -> compliance/drift.py
    - NEW: posture.py (Phase 2 Temporal Compliance)
    - NEW: exceptions.py (Phase 3 Governance Primitives)
    - NEW: remediation.py (Phase 4 Remediation + Subscription)
    - NEW: audit.py (Phase 6 Audit Queries)
"""

import logging

from fastapi import APIRouter

logger = logging.getLogger(__name__)

# Create main compliance router with prefix
router = APIRouter(prefix="/compliance", tags=["Compliance"])

# Track module loading status
_modules_loaded = False

try:
    # Import sub-routers from package modules
    from .audit import router as audit_router
    from .drift import router as drift_router
    from .exceptions import router as exceptions_router
    from .intelligence import router as intelligence_router
    from .owca import router as owca_router
    from .posture import router as posture_router
    from .remediation import router as remediation_router
    from .scheduler import router as scheduler_router

    # Include sub-routers
    # Intelligence endpoints are at the root of /compliance (no additional prefix)
    router.include_router(intelligence_router)

    # OWCA endpoints at /compliance/owca/*
    router.include_router(owca_router)

    # Drift endpoints at /compliance/drift/*
    router.include_router(drift_router)

    # Posture endpoints at /compliance/posture/* (Phase 2 Temporal Compliance)
    router.include_router(posture_router)

    # Exception endpoints at /compliance/exceptions/* (Phase 3 Governance Primitives)
    router.include_router(exceptions_router)

    # Remediation endpoints at /compliance/remediation/* (Phase 4 Remediation)
    router.include_router(remediation_router)

    # Audit endpoints at /compliance/audit/* (Phase 6 Audit Queries)
    router.include_router(audit_router)

    # Scheduler endpoints at /compliance/scheduler/* (OpenWatch OS)
    router.include_router(scheduler_router)

    _modules_loaded = True
    logger.info("Compliance package: All modules loaded successfully")

except ImportError as e:
    logger.error(f"Compliance package: Failed to load modules: {e}")
    # Re-raise to get a clear error instead of failing silently
    raise


def is_fully_loaded() -> bool:
    """Check if all compliance modules are loaded from the new package structure."""
    return _modules_loaded


__all__ = ["router", "is_fully_loaded"]
