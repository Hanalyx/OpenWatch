"""
Administration API Package

Consolidates administrative REST API endpoints.

Package Structure:
    admin/
    ├── __init__.py         # This file - router aggregation
    ├── users.py            # User management (/users/*)
    ├── audit.py            # Audit logs (/audit/*)
    └── credentials.py      # Credential sharing (/credentials/*)

Migration Status (E1-S6 - Route Consolidation):
    - users.py -> admin/users.py
    - audit.py -> admin/audit.py
    - credentials.py -> admin/credentials.py

Usage:
    from app.routes.admin import router
    app.include_router(router, prefix="/api")
"""

from fastapi import APIRouter

# Create main router that aggregates all sub-routers
router = APIRouter(tags=["Administration"])

# Import sub-routers from modular files
try:
    from .audit import router as audit_router
    from .authorization import router as authorization_router
    from .credentials import router as credentials_router
    from .security import router as security_router
    from .users import router as users_router

    # Include all sub-routers into main router
    # User management endpoints (/users/*)
    router.include_router(users_router)

    # Audit log endpoints (/audit/*)
    router.include_router(audit_router)

    # Credential sharing endpoints (/credentials/*)
    router.include_router(credentials_router)

    # Authorization management endpoints (/authorization/*)
    router.include_router(authorization_router)

    # Security configuration endpoints (/security/config/*)
    router.include_router(security_router)

except ImportError as e:
    import logging

    logger = logging.getLogger(__name__)
    logger.error(f"Failed to load admin sub-routers: {e}")

__all__ = [
    "router",
]
