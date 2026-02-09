"""
Plugin Routes Package

API endpoints for plugin management and updates.

Part of Phase 5: Control Plane (Aegis Integration Plan)
"""

from fastapi import APIRouter

from .updates import router as updates_router

router = APIRouter(prefix="/plugins", tags=["Plugins"])

# Include sub-routers
router.include_router(updates_router)

__all__ = ["router"]
