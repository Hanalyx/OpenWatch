"""
Rules API Package

This package provides API endpoints for browsing and exploring Kensa
compliance rules. Replaces the deprecated MongoDB-based rule management.

Endpoint Structure:
    /api/rules/reference/*  - Rule Reference API for browsing Kensa rules

The Rule Reference API provides:
    - Rule listing with search and filtering
    - Full rule details with rationale and framework mappings
    - Framework, category, and capability metadata
    - Configurable variable documentation

For compliance scanning, use:
    /api/scans/kensa/*  - Kensa compliance scanning endpoints
"""

from fastapi import APIRouter

from .reference import router as reference_router

# Main router that combines all sub-routers
router = APIRouter(prefix="/rules", tags=["Rules"])

# Include the reference router
# Full path: /api/rules/reference/*
router.include_router(reference_router)

__all__ = [
    "router",
]
