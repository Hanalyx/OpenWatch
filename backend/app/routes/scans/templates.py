"""
Scan Template Management Endpoints

This module provides endpoints for scan configuration templates.

Active Endpoints:
    GET    /templates/quick                - Get predefined quick templates (Kensa-based)
    GET    /templates/host/{host_id}       - Get templates for specific host

DEPRECATED (2026-02-10 - MongoDB removal):
    MongoDB-backed template CRUD endpoints have been deprecated.
    Use Kensa framework endpoints at /api/scans/kensa/frameworks instead.

    The following endpoints return deprecation notices:
    - GET    /templates                    - List templates (deprecated)
    - POST   /templates                    - Create template (deprecated)
    - GET    /templates/{template_id}      - Get template (deprecated)
    - PUT    /templates/{template_id}      - Update template (deprecated)
    - DELETE /templates/{template_id}      - Delete template (deprecated)
    - POST   /templates/{template_id}/apply - Apply template (deprecated)
    - POST   /templates/{template_id}/clone - Clone template (deprecated)
    - POST   /templates/{template_id}/set-default - Set default (deprecated)

Migration Path:
    - Use quick templates for common scan configurations
    - Use Kensa frameworks directly for compliance scanning
    - PostgreSQL scan_templates table is available for future template storage

Security Notes:
    - All endpoints require JWT authentication
"""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Scan Templates"])


# =============================================================================
# PYDANTIC MODELS FOR QUICK TEMPLATES
# =============================================================================


class QuickScanTemplate(BaseModel):
    """Model representing a predefined quick scan template."""

    id: str
    name: str
    description: str
    contentId: int = 1
    profileId: str
    scope: str = "system"
    scopeId: Optional[str] = None
    isDefault: bool = False
    estimatedDuration: str
    ruleCount: Optional[int] = None


# Deprecation message for MongoDB template endpoints
MONGODB_DEPRECATION_MESSAGE = (
    "MongoDB templates deprecated (2026-02-10). "
    "Use quick templates at /templates/quick or Kensa frameworks at /api/scans/kensa/frameworks"
)


# =============================================================================
# QUICK TEMPLATE ENDPOINTS (Static/Predefined)
# =============================================================================


@router.get("/templates/quick")
async def list_quick_templates(
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, List[Dict[str, Any]]]:
    """
    List predefined quick scan templates using Kensa frameworks.

    Returns a list of predefined templates for common compliance and
    security scanning use cases. These templates use Kensa native YAML
    rules for accurate compliance checking.

    Args:
        db: SQLAlchemy database session.
        current_user: Authenticated user from JWT token.

    Returns:
        Dictionary with list of quick templates.

    Example Response:
        {
          "templates": [
            {
              "id": "kensa-cis-rhel9",
              "name": "CIS RHEL 9 Benchmark",
              "description": "CIS Level 1 Server benchmark",
              "framework": "cis-rhel9-v2.0.0",
              "estimatedDuration": "2-5 min",
              "ruleCount": 271
            }
          ]
        }

    Security:
        - Requires authenticated user
    """
    # Kensa-based quick templates (replaces legacy SCAP profiles)
    templates = [
        {
            "id": "kensa-cis-rhel9",
            "name": "CIS RHEL 9 Benchmark",
            "description": "CIS Level 1 Server benchmark for RHEL 9 (95.1% coverage)",
            "framework": "cis-rhel9-v2.0.0",
            "scope": "system",
            "isDefault": True,
            "estimatedDuration": "2-5 min",
            "ruleCount": 271,
            "scanEngine": "kensa",
        },
        {
            "id": "kensa-stig-rhel9",
            "name": "STIG RHEL 9",
            "description": "DISA STIG for RHEL 9 V2R7 (75.8% coverage)",
            "framework": "stig-rhel9-v2r7",
            "scope": "system",
            "isDefault": False,
            "estimatedDuration": "3-7 min",
            "ruleCount": 338,
            "scanEngine": "kensa",
        },
        {
            "id": "kensa-full-scan",
            "name": "Full Compliance Scan",
            "description": "All 338 Kensa canonical rules across frameworks",
            "framework": "all",
            "scope": "system",
            "isDefault": False,
            "estimatedDuration": "5-10 min",
            "ruleCount": 338,
            "scanEngine": "kensa",
        },
    ]

    return {"templates": templates}


@router.get("/templates/host/{host_id}")
async def get_host_templates(
    host_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get scan templates available for a specific host.

    Returns templates applicable to the specified host, including
    system templates and any host-specific configurations.

    Args:
        host_id: UUID of the target host.
        db: SQLAlchemy database session.
        current_user: Authenticated user from JWT token.

    Returns:
        Dictionary with list of templates.

    Security:
        - Requires authenticated user
    """
    # For now, return the same system templates
    # In full implementation, would include host-specific templates
    return await list_quick_templates(db, current_user)


# =============================================================================
# DEPRECATED MONGODB-BACKED TEMPLATE ENDPOINTS
# =============================================================================
# These endpoints are deprecated as part of MongoDB removal (2026-02-10).
# Use quick templates or Kensa frameworks directly.


@router.get("/templates")
async def list_templates(
    framework: Optional[str] = Query(None, description="Filter by framework"),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    DEPRECATED: List scan templates.

    MongoDB templates have been deprecated. Use quick templates or Kensa frameworks.
    """
    logger.warning("Deprecated endpoint called: GET /templates")
    raise HTTPException(
        status_code=410,
        detail=MONGODB_DEPRECATION_MESSAGE,
    )


@router.post("/templates")
async def create_template(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """DEPRECATED: Create a scan configuration template."""
    logger.warning("Deprecated endpoint called: POST /templates")
    raise HTTPException(
        status_code=410,
        detail=MONGODB_DEPRECATION_MESSAGE,
    )


@router.get("/templates/{template_id}")
async def get_template(
    template_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """DEPRECATED: Get template by ID."""
    logger.warning(f"Deprecated endpoint called: GET /templates/{template_id}")
    raise HTTPException(
        status_code=410,
        detail=MONGODB_DEPRECATION_MESSAGE,
    )


@router.put("/templates/{template_id}")
async def update_template(
    template_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """DEPRECATED: Update template fields."""
    logger.warning(f"Deprecated endpoint called: PUT /templates/{template_id}")
    raise HTTPException(
        status_code=410,
        detail=MONGODB_DEPRECATION_MESSAGE,
    )


@router.delete("/templates/{template_id}")
async def delete_template(
    template_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, str]:
    """DEPRECATED: Delete template."""
    logger.warning(f"Deprecated endpoint called: DELETE /templates/{template_id}")
    raise HTTPException(
        status_code=410,
        detail=MONGODB_DEPRECATION_MESSAGE,
    )


@router.post("/templates/{template_id}/apply")
async def apply_template(
    template_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """DEPRECATED: Apply template to target for scanning."""
    logger.warning(f"Deprecated endpoint called: POST /templates/{template_id}/apply")
    raise HTTPException(
        status_code=410,
        detail=MONGODB_DEPRECATION_MESSAGE,
    )


@router.post("/templates/{template_id}/clone")
async def clone_template(
    template_id: str,
    new_name: str = Query(..., description="New template name"),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """DEPRECATED: Clone an existing template."""
    logger.warning(f"Deprecated endpoint called: POST /templates/{template_id}/clone")
    raise HTTPException(
        status_code=410,
        detail=MONGODB_DEPRECATION_MESSAGE,
    )


@router.post("/templates/{template_id}/set-default")
async def set_default_template(
    template_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """DEPRECATED: Set template as default for framework."""
    logger.warning(f"Deprecated endpoint called: POST /templates/{template_id}/set-default")
    raise HTTPException(
        status_code=410,
        detail=MONGODB_DEPRECATION_MESSAGE,
    )


# =============================================================================
# PUBLIC API EXPORTS
# =============================================================================

__all__ = [
    "router",
    "list_quick_templates",
    "get_host_templates",
]
