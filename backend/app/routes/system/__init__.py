"""
System Management API Package

Provides system-level endpoints for version info, capabilities,
health monitoring, OS discovery, adaptive scheduling, and settings.

Usage:
    from app.routes.system import router
    app.include_router(router, prefix="/api")
"""

from fastapi import APIRouter

# Create main router that aggregates all sub-routers
router = APIRouter()

# Import and include sub-routers
from .capabilities import router as capabilities_router  # noqa: E402
from .discovery import router as discovery_router  # noqa: E402
from .health import router as health_router  # noqa: E402
from .scheduler import router as scheduler_router  # noqa: E402
from .settings import router as settings_router  # noqa: E402
from .version import router as version_router  # noqa: E402

# Version and capabilities have no prefix in their routers
router.include_router(version_router, tags=["Version"])
router.include_router(capabilities_router, tags=["System Capabilities"])

# Health monitoring was registered with prefix="/api/health-monitoring" in main.py
# The sub-router has no prefix, so we add it here
router.include_router(health_router, prefix="/health-monitoring", tags=["Health Monitoring"])

# These sub-routers already have /system/* prefixes in their router definitions
router.include_router(scheduler_router, tags=["Adaptive Scheduler"])
router.include_router(discovery_router, tags=["OS Discovery"])
router.include_router(settings_router, tags=["System Settings"])

# NOTE: MongoDB test endpoints removed during MongoDB deprecation (2026-02-10)
# - mongodb_test.py (199 LOC) - MongoDB integration tests - No longer needed

__all__ = ["router"]
