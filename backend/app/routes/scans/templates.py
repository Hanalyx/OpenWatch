"""
Scan Template Management Endpoints

This module provides endpoints for creating, managing, and applying
scan configuration templates. Consolidates functionality from
scan_config_api.py and scan_templates.py as part of Phase 2 API Standardization.

Endpoints:
    GET    /templates                      - List scan templates
    POST   /templates                      - Create scan template
    GET    /templates/quick                - Get predefined quick templates
    GET    /templates/host/{host_id}       - Get templates for specific host
    GET    /templates/{template_id}        - Get template by ID
    PUT    /templates/{template_id}        - Update template
    DELETE /templates/{template_id}        - Delete template
    POST   /templates/{template_id}/apply  - Apply template to target
    POST   /templates/{template_id}/clone  - Clone template
    POST   /templates/{template_id}/set-default - Set as default template

Architecture Notes:
    - MongoDB-backed templates provide full CRUD with variable management
    - Quick templates are predefined configurations for common use cases
    - Templates can be shared (public) or private to users
    - Default templates are per-user per-framework

Security Notes:
    - All endpoints require JWT authentication
    - Users can only modify their own templates
    - Admins can modify any template
    - Authorization checks on template access
"""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.app.auth import get_current_user
from backend.app.database import get_db
from backend.app.models.scan_config_models import (
    ApplyTemplateRequest,
    CreateTemplateRequest,
    ScanTemplate,
    UpdateTemplateRequest,
)
from backend.app.services.mongo_integration_service import (
    MongoIntegrationService,
    get_mongo_service,
)
from backend.app.services.scan_template_service import ScanTemplateService

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


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def _get_database(mongo_service: MongoIntegrationService) -> AsyncIOMotorDatabase:
    """
    Get MongoDB database from service with null safety.

    Args:
        mongo_service: The MongoIntegrationService instance.

    Returns:
        AsyncIOMotorDatabase instance.

    Raises:
        HTTPException: 503 if MongoDB connection unavailable.
    """
    if mongo_service.mongo_manager is None or mongo_service.mongo_manager.database is None:
        raise HTTPException(status_code=503, detail="MongoDB connection unavailable")
    return mongo_service.mongo_manager.database


# =============================================================================
# QUICK TEMPLATE ENDPOINTS (Static/Predefined)
# =============================================================================


@router.get("/templates/quick")
async def list_quick_templates(
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, List[Dict[str, Any]]]:
    """
    List predefined quick scan templates.

    Returns a list of predefined templates for common compliance and
    security scanning use cases. These are static configurations that
    provide quick access to common scan profiles.

    Args:
        db: SQLAlchemy database session.
        current_user: Authenticated user from JWT token.

    Returns:
        Dictionary with list of quick templates.

    Example Response:
        {
          "templates": [
            {
              "id": "quick-compliance",
              "name": "Quick Compliance",
              "description": "Essential compliance checks",
              "profileId": "xccdf_org.ssgproject.content_profile_cui",
              "estimatedDuration": "5-10 min",
              "ruleCount": 120
            }
          ]
        }

    Security:
        - Requires authenticated user
    """
    templates = [
        {
            "id": "quick-compliance",
            "name": "Quick Compliance",
            "description": "Essential compliance checks for regulatory requirements",
            "contentId": 1,
            "profileId": "xccdf_org.ssgproject.content_profile_cui",
            "scope": "system",
            "isDefault": True,
            "estimatedDuration": "5-10 min",
            "ruleCount": 120,
        },
        {
            "id": "security-audit",
            "name": "Security Audit",
            "description": "Comprehensive security configuration review",
            "contentId": 1,
            "profileId": "xccdf_org.ssgproject.content_profile_stig",
            "scope": "system",
            "isDefault": False,
            "estimatedDuration": "15-25 min",
            "ruleCount": 340,
        },
        {
            "id": "vulnerability-scan",
            "name": "Vulnerability Check",
            "description": "Scan for known security vulnerabilities",
            "contentId": 1,
            "profileId": "xccdf_org.ssgproject.content_profile_cis",
            "scope": "system",
            "isDefault": False,
            "estimatedDuration": "10-15 min",
            "ruleCount": 200,
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
# MONGODB-BACKED TEMPLATE ENDPOINTS
# =============================================================================


@router.get("/templates", response_model=List[ScanTemplate])
async def list_templates(
    framework: Optional[str] = Query(None, description="Filter by framework"),
    tags: Optional[str] = Query(None, description="Filter by tags (comma-separated)"),
    is_public: Optional[bool] = Query(None, description="Filter by visibility"),
    skip: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(50, ge=1, le=100, description="Max results"),
    mongo_service: MongoIntegrationService = Depends(get_mongo_service),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[ScanTemplate]:
    """
    List scan templates with filters.

    Returns user's own templates and public templates.

    Args:
        framework: Filter by framework.
        tags: Filter by tags (comma-separated).
        is_public: Filter by visibility.
        skip: Pagination offset.
        limit: Max results (default: 50, max: 100).
        mongo_service: MongoDB integration service.
        current_user: Authenticated user from JWT token.

    Returns:
        List of ScanTemplate objects.

    Security:
        - Requires authenticated user
        - Non-admin users see only their own + public templates
    """
    db = _get_database(mongo_service)
    service = ScanTemplateService(db)

    # Parse tags
    tag_list = None
    if tags:
        tag_list = [t.strip() for t in tags.split(",")]

    # Non-admin users see only their own + public templates
    created_by = None
    if current_user.get("role") != "admin":
        created_by = current_user.get("username")

    templates = await service.list_templates(
        created_by=created_by,
        framework=framework,
        tags=tag_list,
        is_public=is_public,
        skip=skip,
        limit=limit,
    )

    return templates


@router.post("/templates", response_model=ScanTemplate)
async def create_template(
    request: CreateTemplateRequest,
    mongo_service: MongoIntegrationService = Depends(get_mongo_service),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> ScanTemplate:
    """
    Create a scan configuration template.

    Saves a reusable scan configuration with framework, variables,
    and rule filters.

    Args:
        request: Template creation request.
        mongo_service: MongoDB integration service.
        current_user: Authenticated user from JWT token.

    Returns:
        Created ScanTemplate.

    Example Request:
        {
          "name": "Production NIST 800-53r5 High Baseline",
          "description": "NIST 800-53r5 high baseline for production servers",
          "framework": "nist",
          "framework_version": "rev5",
          "target_type": "ssh_host",
          "variable_overrides": {
            "var_accounts_tmout": "300",
            "var_password_pam_minlen": "16"
          },
          "rule_filter": {
            "impact_level": ["high"]
          },
          "tags": ["production", "nist", "high-security"],
          "is_public": false
        }

    Security:
        - Requires authenticated user
    """
    db = _get_database(mongo_service)
    service = ScanTemplateService(db)

    username = str(current_user.get("username", ""))
    template = await service.create_template(
        name=request.name,
        description=request.description,
        framework=request.framework,
        framework_version=request.framework_version,
        target_type=request.target_type,
        variable_overrides=request.variable_overrides,
        rule_filter=request.rule_filter,
        tags=request.tags,
        created_by=username,
        is_public=request.is_public,
    )

    return template


@router.get("/templates/{template_id}", response_model=ScanTemplate)
async def get_template(
    template_id: str,
    mongo_service: MongoIntegrationService = Depends(get_mongo_service),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> ScanTemplate:
    """
    Get template by ID.

    Args:
        template_id: Template UUID.
        mongo_service: MongoDB integration service.
        current_user: Authenticated user from JWT token.

    Returns:
        ScanTemplate.

    Raises:
        HTTPException 404: Template not found.
        HTTPException 403: Access denied.

    Security:
        - Requires authenticated user
        - Users can access their own templates, public templates, and shared templates
        - Admins can access all templates
    """
    db = _get_database(mongo_service)
    service = ScanTemplateService(db)
    template = await service.get_template(template_id)

    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    # Authorization check
    if current_user.get("role") != "admin":
        if (
            template.created_by != current_user.get("username")
            and not template.is_public
            and current_user.get("username") not in template.shared_with
        ):
            raise HTTPException(status_code=403, detail="Access denied")

    return template


@router.put("/templates/{template_id}", response_model=ScanTemplate)
async def update_template(
    template_id: str,
    request: UpdateTemplateRequest,
    mongo_service: MongoIntegrationService = Depends(get_mongo_service),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> ScanTemplate:
    """
    Update template fields.

    Args:
        template_id: Template UUID.
        request: Update request with fields to modify.
        mongo_service: MongoDB integration service.
        current_user: Authenticated user from JWT token.

    Returns:
        Updated ScanTemplate.

    Raises:
        HTTPException 404: Template not found.
        HTTPException 403: Access denied (not owner).

    Security:
        - Requires authenticated user
        - Only template owner or admin can update
    """
    db = _get_database(mongo_service)
    service = ScanTemplateService(db)

    # Get template for authorization
    template = await service.get_template(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    # Authorization: only owner can update
    if current_user.get("role") != "admin":
        if template.created_by != current_user.get("username"):
            raise HTTPException(status_code=403, detail="Only template owner can update")

    # Update
    updated = await service.update_template(
        template_id=template_id,
        name=request.name,
        description=request.description,
        variable_overrides=request.variable_overrides,
        rule_filter=request.rule_filter,
        tags=request.tags,
        is_public=request.is_public,
    )

    return updated


@router.delete("/templates/{template_id}")
async def delete_template(
    template_id: str,
    mongo_service: MongoIntegrationService = Depends(get_mongo_service),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Delete template.

    Args:
        template_id: Template UUID.
        mongo_service: MongoDB integration service.
        current_user: Authenticated user from JWT token.

    Returns:
        Success message.

    Raises:
        HTTPException 404: Template not found.
        HTTPException 403: Access denied (not owner).

    Security:
        - Requires authenticated user
        - Owner can delete their templates
        - Admins can delete any template
    """
    db = _get_database(mongo_service)
    service = ScanTemplateService(db)

    # Get template for authorization
    template = await service.get_template(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    # Authorization
    if current_user.get("role") != "admin":
        if template.created_by != current_user.get("username"):
            raise HTTPException(status_code=403, detail="Only template owner can delete")

    # Delete
    await service.delete_template(template_id)

    return {"message": f"Template {template_id} deleted"}


@router.post("/templates/{template_id}/apply")
async def apply_template(
    template_id: str,
    request: ApplyTemplateRequest,
    mongo_service: MongoIntegrationService = Depends(get_mongo_service),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Apply template to target for scanning.

    Merges template configuration with target to create ScanConfiguration
    ready for the scan service.

    Args:
        template_id: Template UUID.
        request: Apply request with target and optional overrides.
        mongo_service: MongoDB integration service.
        current_user: Authenticated user from JWT token.

    Returns:
        ScanConfiguration dict ready for /api/scans.

    Raises:
        HTTPException 404: Template not found.
        HTTPException 403: Access denied.

    Example Request:
        {
          "target": {
            "type": "ssh_host",
            "identifier": "prod-web-01.example.com",
            "credentials": {
              "username": "root",
              "ssh_key": "..."
            }
          },
          "variable_overrides": {
            "var_accounts_tmout": "600"
          }
        }

    Security:
        - Requires authenticated user
        - User must have access to the template
    """
    db = _get_database(mongo_service)
    service = ScanTemplateService(db)

    # Get template with authorization check
    template = await service.get_template(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    # Authorization
    if current_user.get("role") != "admin":
        if (
            template.created_by != current_user.get("username")
            and not template.is_public
            and current_user.get("username") not in template.shared_with
        ):
            raise HTTPException(status_code=403, detail="Access denied")

    # Apply template
    scan_config = await service.apply_template(
        template_id=template_id,
        target=request.target,
        additional_overrides=request.variable_overrides,
    )

    return scan_config


@router.post("/templates/{template_id}/clone", response_model=ScanTemplate)
async def clone_template(
    template_id: str,
    new_name: str = Query(..., description="New template name"),
    mongo_service: MongoIntegrationService = Depends(get_mongo_service),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> ScanTemplate:
    """
    Clone an existing template.

    Creates a copy of template owned by current user.

    Args:
        template_id: Source template UUID.
        new_name: New template name (query param).
        mongo_service: MongoDB integration service.
        current_user: Authenticated user from JWT token.

    Returns:
        Cloned ScanTemplate.

    Raises:
        HTTPException 404: Template not found.

    Security:
        - Requires authenticated user
        - New template is owned by current user
    """
    db = _get_database(mongo_service)
    service = ScanTemplateService(db)

    try:
        clone = await service.clone_template(
            template_id=template_id,
            new_name=new_name,
            created_by=str(current_user.get("username", "")),
        )
        return clone
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/templates/{template_id}/set-default", response_model=ScanTemplate)
async def set_default_template(
    template_id: str,
    mongo_service: MongoIntegrationService = Depends(get_mongo_service),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> ScanTemplate:
    """
    Set template as default for framework.

    Marks template as default for current user and framework.
    Clears any existing default.

    Args:
        template_id: Template UUID.
        mongo_service: MongoDB integration service.
        current_user: Authenticated user from JWT token.

    Returns:
        Updated ScanTemplate.

    Raises:
        HTTPException 404: Template not found.
        HTTPException 403: Access denied (not owner).

    Security:
        - Requires authenticated user
        - Only template owner can set as default
    """
    db = _get_database(mongo_service)
    service = ScanTemplateService(db)

    # Get template for authorization
    template = await service.get_template(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    # Authorization: only owner can set as default
    if template.created_by != current_user.get("username"):
        raise HTTPException(status_code=403, detail="Only template owner can set as default")

    # Set default
    updated = await service.set_as_default(
        template_id=template_id,
        created_by=str(current_user.get("username", "")),
    )

    return updated


# =============================================================================
# PUBLIC API EXPORTS
# =============================================================================

__all__ = [
    "router",
    "list_quick_templates",
    "get_host_templates",
    "list_templates",
    "create_template",
    "get_template",
    "update_template",
    "delete_template",
    "apply_template",
    "clone_template",
    "set_default_template",
]
