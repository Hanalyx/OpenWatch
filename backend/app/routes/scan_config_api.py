"""
Scan configuration API endpoints.

Provides REST API for framework discovery, variable management, and
scan template operations.
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from ..auth import get_current_user
from ..models.scan_config_models import (
    ApplyTemplateRequest,
    CreateTemplateRequest,
    FrameworkMetadata,
    FrameworkVersion,
    ScanTemplate,
    TemplateStatistics,
    UpdateTemplateRequest,
    ValidateVariablesRequest,
    ValidationResult,
    VariableDefinition,
)
from ..services.framework import FrameworkMetadataService
from ..services.mongo_integration_service import MongoIntegrationService, get_mongo_service
from ..services.scan_template_service import ScanTemplateService

router = APIRouter()


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


# Framework Discovery Endpoints


@router.get("/frameworks", response_model=List[FrameworkMetadata])
async def list_frameworks(
    mongo_service: MongoIntegrationService = Depends(get_mongo_service),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[FrameworkMetadata]:
    """
    List all available compliance frameworks.

    Returns summary information about available frameworks including
    versions, rule counts, and variable counts.

    **Returns:**
    - List of FrameworkMetadata objects

    **Example Response:**
    ```json
    [
      {
        "framework": "nist",
        "display_name": "NIST 800-53",
        "versions": ["rev4", "rev5"],
        "description": "NIST Special Publication 800-53",
        "rule_count": 487,
        "variable_count": 62
      },
      {
        "framework": "cis",
        "display_name": "CIS Benchmarks",
        "versions": ["rhel8-2.0.0", "ubuntu2004-1.1.0"],
        "rule_count": 312,
        "variable_count": 45
      }
    ]
    ```
    """
    db = _get_database(mongo_service)

    service = FrameworkMetadataService(db)
    frameworks = await service.list_frameworks()
    return frameworks


@router.get("/frameworks/{framework}/{version}", response_model=FrameworkVersion)
async def get_framework_details(
    framework: str,
    version: str,
    mongo_service: MongoIntegrationService = Depends(get_mongo_service),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> FrameworkVersion:
    """
    Get detailed information about a specific framework version.

    Includes complete variable definitions, categories, and supported
    target types.

    **Parameters:**
    - `framework`: Framework identifier (e.g., "nist", "cis")
    - `version`: Framework version (e.g., "rev5", "1.0.0")

    **Returns:**
    - FrameworkVersion with complete metadata

    **Errors:**
    - 404: Framework/version not found
    """
    try:
        db = _get_database(mongo_service)

        service = FrameworkMetadataService(db)
        details = await service.get_framework_details(framework, version)
        return details
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get(
    "/frameworks/{framework}/{version}/variables",
    response_model=List[VariableDefinition],
)
async def get_framework_variables(
    framework: str,
    version: str,
    category: Optional[str] = Query(None, description="Filter by category"),
    mongo_service: MongoIntegrationService = Depends(get_mongo_service),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[VariableDefinition]:
    """
    Get variable definitions for a framework/version.

    Returns all customizable variables with types, defaults, and constraints.

    **Parameters:**
    - `framework`: Framework identifier
    - `version`: Framework version
    - `category`: Optional category filter

    **Returns:**
    - List of VariableDefinition objects

    **Example Response:**
    ```json
    [
      {
        "id": "var_accounts_tmout",
        "title": "Account Inactivity Timeout",
        "description": "Timeout for inactive user sessions (seconds)",
        "type": "number",
        "default": 600,
        "constraints": {
          "lower_bound": 60,
          "upper_bound": 900
        },
        "interactive": true,
        "category": "Session Management"
      },
      {
        "id": "var_password_pam_minlen",
        "title": "Minimum Password Length",
        "description": "Minimum number of characters in password",
        "type": "number",
        "default": 14,
        "constraints": {
          "lower_bound": 8,
          "upper_bound": 64
        },
        "interactive": true,
        "category": "Authentication"
      }
    ]
    ```
    """
    db = _get_database(mongo_service)

    service = FrameworkMetadataService(db)
    variables = await service.get_variables(framework, version)

    # Filter by category if specified
    if category:
        variables = [v for v in variables if v.category == category]

    return variables


@router.post("/frameworks/{framework}/{version}/validate", response_model=ValidationResult)
async def validate_variables(
    framework: str,
    version: str,
    request: ValidateVariablesRequest,
    mongo_service: MongoIntegrationService = Depends(get_mongo_service),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> ValidationResult:
    """
    Validate variable values against constraints.

    Checks type compliance and constraint violations (range, choices, patterns).

    **Parameters:**
    - `framework`: Framework identifier
    - `version`: Framework version
    - Request body with variable values

    **Request Body:**
    ```json
    {
      "variables": {
        "var_accounts_tmout": "300",
        "var_password_pam_minlen": "16"
      }
    }
    ```

    **Returns:**
    - ValidationResult with errors if any

    **Example Success:**
    ```json
    {
      "valid": true,
      "errors": {},
      "warnings": {}
    }
    ```

    **Example Failure:**
    ```json
    {
      "valid": false,
      "errors": {
        "var_accounts_tmout": "Value 30 is below lower bound 60",
        "var_password_pam_minlen": "Value 100 exceeds upper bound 64"
      },
      "warnings": {}
    }
    ```
    """
    db = _get_database(mongo_service)

    service = FrameworkMetadataService(db)

    valid, errors = await service.validate_variables(framework=framework, version=version, variables=request.variables)

    return ValidationResult(valid=valid, errors=errors)


# Template Management Endpoints


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

    **Request Body:**
    ```json
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
    ```

    **Returns:**
    - Created ScanTemplate
    """
    db = _get_database(mongo_service)

    service = ScanTemplateService(db)

    # created_by must be a string, not Optional[Any]
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

    **Query Parameters:**
    - `framework`: Filter by framework
    - `tags`: Filter by tags (comma-separated)
    - `is_public`: Filter by visibility
    - `skip`: Pagination offset
    - `limit`: Max results (default: 50, max: 100)

    **Returns:**
    - List of ScanTemplate objects
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


@router.get("/templates/{template_id}", response_model=ScanTemplate)
async def get_template(
    template_id: str,
    mongo_service: MongoIntegrationService = Depends(get_mongo_service),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> ScanTemplate:
    """
    Get template by ID.

    **Parameters:**
    - `template_id`: Template UUID

    **Returns:**
    - ScanTemplate

    **Errors:**
    - 404: Template not found
    - 403: Access denied
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

    **Parameters:**
    - `template_id`: Template UUID
    - Request body with fields to update

    **Request Body:**
    ```json
    {
      "name": "Updated Template Name",
      "description": "Updated description",
      "variable_overrides": {...},
      "tags": ["new", "tags"]
    }
    ```

    **Returns:**
    - Updated ScanTemplate

    **Errors:**
    - 404: Template not found
    - 403: Access denied (not owner)
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

    **Parameters:**
    - `template_id`: Template UUID

    **Returns:**
    - Success message

    **Errors:**
    - 404: Template not found
    - 403: Access denied (not owner)

    **Authorization:**
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

    **Parameters:**
    - `template_id`: Template UUID
    - Request body with target and optional overrides

    **Request Body:**
    ```json
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
    ```

    **Returns:**
    - ScanConfiguration dict ready for `/api/scans`

    **Errors:**
    - 404: Template not found
    - 403: Access denied
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

    **Parameters:**
    - `template_id`: Source template UUID
    - `new_name`: New template name (query param)

    **Returns:**
    - Cloned ScanTemplate

    **Errors:**
    - 404: Template not found
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

    **Parameters:**
    - `template_id`: Template UUID

    **Returns:**
    - Updated ScanTemplate

    **Errors:**
    - 404: Template not found
    - 403: Access denied (not owner)
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


@router.get("/statistics", response_model=TemplateStatistics)
async def get_template_statistics(
    mongo_service: MongoIntegrationService = Depends(get_mongo_service),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> TemplateStatistics:
    """
    Get template usage statistics.

    Returns aggregated statistics about templates.

    **Returns:**
    - TemplateStatistics

    **Example Response:**
    ```json
    {
      "total_templates": 45,
      "by_framework": {
        "nist": 20,
        "cis": 15,
        "pci-dss": 10
      },
      "by_user": {
        "admin": 30,
        "user1": 10,
        "user2": 5
      },
      "public_templates": 12,
      "most_used": []
    }
    ```

    **Authorization:**
    - Users see their own statistics
    - Admins see global statistics
    """
    db = _get_database(mongo_service)

    service = ScanTemplateService(db)

    # Non-admin users see only their own stats
    created_by = None
    if current_user.get("role") != "admin":
        created_by = current_user.get("username")

    stats = await service.get_statistics(created_by=created_by)
    return stats
