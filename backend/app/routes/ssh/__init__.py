"""
SSH Management API Package

This package provides the REST API for SSH management operations.
The package follows a modular architecture for maintainability.

Package Structure:
    ssh/
    ├── __init__.py         # This file - public API and router aggregation
    ├── models.py           # Pydantic request/response models
    ├── settings.py         # SSH policy and known hosts management
    └── debug.py            # SSH debugging and diagnostics

Migration Status (API Standardization - Phase 4):
    Phase 4: System & Integrations
    - ssh_settings.py endpoints consolidated under /settings
    - ssh_debug.py endpoints consolidated under /debug

Usage:
    # Import the router in main.py
    from backend.app.routes.ssh import router
    app.include_router(router, prefix="/api")

    # Import models directly
    from backend.app.routes.ssh.models import SSHPolicyRequest

Router Organization:
    The main router aggregates all sub-routers with their endpoints:

    Settings Router (settings.py):
        GET  /settings/policy           - Get SSH policy configuration
        POST /settings/policy           - Set SSH policy configuration
        GET  /settings/known-hosts      - List SSH known hosts
        POST /settings/known-hosts      - Add SSH known host
        DELETE /settings/known-hosts/{hostname} - Remove SSH known host
        GET  /settings/test-connectivity/{host_id} - Test SSH connectivity

    Debug Router (debug.py):
        POST /debug/test-authentication - Debug SSH authentication
        GET  /debug/paramiko-log        - Get paramiko debug log
"""

from fastapi import APIRouter

# Create main router that aggregates all sub-routers
# Note: prefix="/ssh" ensures all endpoints are under /api/ssh/*
router = APIRouter(prefix="/ssh", tags=["SSH"])

# Import sub-routers from modular files
# Using try/except for graceful fallback during migration
_modules_loaded = False

try:
    # Core SSH routers - use relative imports within package
    from .debug import router as debug_router
    from .settings import router as settings_router

    # Include all sub-routers into main router
    router.include_router(settings_router)
    router.include_router(debug_router)

    _modules_loaded = True

except ImportError as e:
    # Fall back to legacy routers during migration
    import logging

    logger = logging.getLogger(__name__)
    logger.warning(f"Failed to load modular SSH routers, falling back to legacy: {e}")

    try:
        from ..ssh_debug_legacy import router as debug_legacy_router
        from ..ssh_settings_legacy import router as settings_legacy_router

        router.include_router(settings_legacy_router)
        router.include_router(debug_legacy_router)
    except ImportError:
        # If even legacy fails, create empty router
        logger.error("Failed to load any SSH router - API will be incomplete")


# Re-export models for convenient access - use relative imports
from .models import (  # noqa: E402
    KnownHostRequest,
    KnownHostResponse,
    SSHDebugRequest,
    SSHDebugResponse,
    SSHPolicyRequest,
    SSHPolicyResponse,
)

__all__ = [
    # Router
    "router",
    # Settings models
    "SSHPolicyRequest",
    "SSHPolicyResponse",
    "KnownHostRequest",
    "KnownHostResponse",
    # Debug models
    "SSHDebugRequest",
    "SSHDebugResponse",
]
