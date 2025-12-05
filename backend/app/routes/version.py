"""
Version API Endpoint

Provides public version information for the OpenWatch application.
No authentication required for basic version info.

See docs/core/VERSIONING.md for versioning plan.
"""

from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel

from ..version import get_version_info

router = APIRouter(tags=["Version"])


class VersionResponse(BaseModel):
    """Version information response model."""

    version: str
    codename: str
    api_version: str
    git_commit: Optional[str] = None
    build_date: Optional[str] = None


@router.get("/version", response_model=VersionResponse)
async def get_version() -> VersionResponse:
    """
    Get OpenWatch version information.

    This endpoint is public and does not require authentication.
    Use it for health checks, compatibility verification, and display.

    Returns:
        VersionResponse with:
        - version: SemVer version string (e.g., "0.1.0")
        - codename: Release codename (e.g., "Eyrie")
        - api_version: API version for header-based versioning
        - git_commit: Short git commit hash (if available)
        - build_date: ISO build date (if set during CI/CD)

    Example Response:
        {
            "version": "0.1.0",
            "codename": "Eyrie",
            "api_version": "1",
            "git_commit": "abc1234",
            "build_date": "2025-12-04T00:00:00Z"
        }
    """
    info = get_version_info()
    return VersionResponse(**info)
