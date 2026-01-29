"""
Content API Package

Consolidates SCAP content management REST API endpoints.

Package Structure:
    content/
    ├── __init__.py     # This file - router aggregation
    ├── scap.py         # SCAP content management (/content/*)
    ├── import_.py      # SCAP import (/scap-import/*)
    └── xccdf.py        # XCCDF generation (/xccdf/*)

Migration Status (E1-S7 - Route Consolidation):
    - content.py -> content/scap.py
    - scap_import.py -> content/import_.py
    - xccdf_api.py -> content/xccdf.py

Usage:
    from app.routes.content import router
    app.include_router(router, prefix="/api")
"""

from fastapi import APIRouter

# Create main router that aggregates all sub-routers
router = APIRouter(tags=["Content"])

# Import sub-routers from modular files
try:
    from .import_ import router as import_router
    from .scap import router as scap_router
    from .xccdf import router as xccdf_router

    # SCAP content management endpoints (/content/*)
    # scap.py has no prefix; apply it here to preserve /api/content/* URLs
    router.include_router(scap_router, prefix="/content", tags=["Legacy Content"])

    # SCAP import endpoints (/scap-import/*)
    # import_.py already has prefix="/scap-import"
    router.include_router(import_router)

    # XCCDF generation endpoints (/xccdf/*)
    # xccdf.py has no prefix; apply it here to preserve /api/xccdf/* URLs
    router.include_router(xccdf_router, prefix="/xccdf", tags=["XCCDF Generator"])

except ImportError as e:
    import logging

    logger = logging.getLogger(__name__)
    logger.error(f"Failed to load content sub-routers: {e}")

__all__ = [
    "router",
]
