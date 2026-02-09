"""
Compliance API Package

This package consolidates all compliance-related endpoints into a modular structure.
Part of Phase 4 API Standardization: System & Integrations.

Package Structure:
    - intelligence.py: Semantic SCAP intelligence and cross-framework compliance data
    - owca.py: OpenWatch Compliance Algorithm (OWCA) endpoints
    - drift.py: Compliance drift event endpoints
    - posture.py: Temporal compliance posture queries (Phase 2)

Endpoint Structure:
    /compliance/                    - Intelligence endpoints (overview, semantic-rules, etc.)
    /compliance/owca/*              - OWCA compliance scoring and analytics
    /compliance/drift/*             - Drift detection events
    /compliance/posture             - Point-in-time posture queries
    /compliance/posture/history     - Posture history over time
    /compliance/posture/drift       - Compliance drift analysis

Migration Status:
    - compliance.py -> compliance/intelligence.py
    - owca.py -> compliance/owca.py
    - drift_events.py -> compliance/drift.py
    - NEW: posture.py (Phase 2 Temporal Compliance)
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
    from .drift import router as drift_router
    from .intelligence import router as intelligence_router
    from .owca import router as owca_router
    from .posture import router as posture_router

    # Include sub-routers
    # Intelligence endpoints are at the root of /compliance (no additional prefix)
    router.include_router(intelligence_router)

    # OWCA endpoints at /compliance/owca/*
    router.include_router(owca_router)

    # Drift endpoints at /compliance/drift/*
    router.include_router(drift_router)

    # Posture endpoints at /compliance/posture/* (Phase 2 Temporal Compliance)
    router.include_router(posture_router)

    _modules_loaded = True
    logger.info("Compliance package: All modules loaded successfully")

except ImportError as e:
    logger.warning(f"Compliance package: Failed to load modules: {e}")
    logger.warning("Compliance package: Falling back to legacy routers")

    # Fallback: Import from legacy locations if new modules aren't ready
    try:
        from ..compliance import router as legacy_intelligence_router
        from ..drift_events import router as legacy_drift_router
        from ..owca import router as legacy_owca_router

        # Include legacy routers with adjusted prefixes
        router.include_router(legacy_intelligence_router)
        router.include_router(legacy_owca_router)
        router.include_router(legacy_drift_router)

        logger.info("Compliance package: Legacy routers loaded as fallback")
    except ImportError as fallback_error:
        logger.error(f"Compliance package: Fallback also failed: {fallback_error}")
        raise


def is_fully_loaded() -> bool:
    """Check if all compliance modules are loaded from the new package structure."""
    return _modules_loaded


__all__ = ["router", "is_fully_loaded"]
