"""
Scan Configuration API Endpoints

This module provides endpoints for framework discovery, variable management,
and scan configuration operations. Moved from scan_config_api.py as part of
Phase 2 API Standardization.

Endpoints:
    GET  /config/frameworks                           - List available frameworks
    GET  /config/frameworks/{framework}/{version}     - Get framework details
    GET  /config/frameworks/{framework}/{version}/variables - Get framework variables
    POST /config/frameworks/{framework}/{version}/validate  - Validate variables
    GET  /config/statistics                           - Get template statistics

Architecture Notes:
    - Uses MongoDB for framework metadata storage
    - Framework discovery is dynamic based on compliance_rules collection
    - Variables are extracted from SCAP content metadata
    - Template statistics aggregate usage across users

Security Notes:
    - All endpoints require JWT authentication
    - Admin users see global statistics
    - Non-admin users see only their own statistics
"""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from backend.app.auth import get_current_user
from backend.app.models.scan_config_models import (
    FrameworkMetadata,
    FrameworkVersion,
    TemplateStatistics,
    ValidateVariablesRequest,
    ValidationResult,
    VariableDefinition,
)
from backend.app.services.framework_metadata_service import FrameworkMetadataService
from backend.app.services.mongo_integration_service import MongoIntegrationService, get_mongo_service
from backend.app.services.scan_template_service import ScanTemplateService

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Scan Configuration"])


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
# FRAMEWORK DISCOVERY ENDPOINTS
# =============================================================================


@router.get("/config/frameworks", response_model=List[FrameworkMetadata])
async def list_frameworks(
    mongo_service: MongoIntegrationService = Depends(get_mongo_service),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[FrameworkMetadata]:
    """
    List all available compliance frameworks.

    Returns summary information about available frameworks including
    versions, rule counts, and variable counts.

    Args:
        mongo_service: MongoDB integration service.
        current_user: Authenticated user from JWT token.

    Returns:
        List of FrameworkMetadata objects.

    Example Response:
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

    Security:
        - Requires authenticated user
    """
    db = _get_database(mongo_service)
    service = FrameworkMetadataService(db)
    frameworks = await service.list_frameworks()
    return frameworks


@router.get("/config/frameworks/{framework}/{version}", response_model=FrameworkVersion)
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

    Args:
        framework: Framework identifier (e.g., "nist", "cis").
        version: Framework version (e.g., "rev5", "1.0.0").
        mongo_service: MongoDB integration service.
        current_user: Authenticated user from JWT token.

    Returns:
        FrameworkVersion with complete metadata.

    Raises:
        HTTPException 404: Framework/version not found.

    Security:
        - Requires authenticated user
    """
    try:
        db = _get_database(mongo_service)
        service = FrameworkMetadataService(db)
        details = await service.get_framework_details(framework, version)
        return details
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get(
    "/config/frameworks/{framework}/{version}/variables",
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

    Args:
        framework: Framework identifier.
        version: Framework version.
        category: Optional category filter.
        mongo_service: MongoDB integration service.
        current_user: Authenticated user from JWT token.

    Returns:
        List of VariableDefinition objects.

    Example Response:
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
          }
        ]

    Security:
        - Requires authenticated user
    """
    db = _get_database(mongo_service)
    service = FrameworkMetadataService(db)
    variables = await service.get_variables(framework, version)

    # Filter by category if specified
    if category:
        variables = [v for v in variables if v.category == category]

    return variables


@router.post("/config/frameworks/{framework}/{version}/validate", response_model=ValidationResult)
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

    Args:
        framework: Framework identifier.
        version: Framework version.
        request: Request body with variable values.
        mongo_service: MongoDB integration service.
        current_user: Authenticated user from JWT token.

    Returns:
        ValidationResult with errors if any.

    Example Request:
        {
          "variables": {
            "var_accounts_tmout": "300",
            "var_password_pam_minlen": "16"
          }
        }

    Example Success Response:
        {
          "valid": true,
          "errors": {},
          "warnings": {}
        }

    Example Failure Response:
        {
          "valid": false,
          "errors": {
            "var_accounts_tmout": "Value 30 is below lower bound 60"
          },
          "warnings": {}
        }

    Security:
        - Requires authenticated user
    """
    db = _get_database(mongo_service)
    service = FrameworkMetadataService(db)

    valid, errors = await service.validate_variables(framework=framework, version=version, variables=request.variables)

    return ValidationResult(valid=valid, errors=errors)


# =============================================================================
# STATISTICS ENDPOINT
# =============================================================================


@router.get("/config/statistics", response_model=TemplateStatistics)
async def get_template_statistics(
    mongo_service: MongoIntegrationService = Depends(get_mongo_service),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> TemplateStatistics:
    """
    Get template usage statistics.

    Returns aggregated statistics about templates.

    Args:
        mongo_service: MongoDB integration service.
        current_user: Authenticated user from JWT token.

    Returns:
        TemplateStatistics object.

    Example Response:
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

    Authorization:
        - Users see their own statistics
        - Admins see global statistics

    Security:
        - Requires authenticated user
    """
    db = _get_database(mongo_service)
    service = ScanTemplateService(db)

    # Non-admin users see only their own stats
    created_by = None
    if current_user.get("role") != "admin":
        created_by = current_user.get("username")

    stats = await service.get_statistics(created_by=created_by)
    return stats


# =============================================================================
# PUBLIC API EXPORTS
# =============================================================================

__all__ = [
    "router",
    "list_frameworks",
    "get_framework_details",
    "get_framework_variables",
    "validate_variables",
    "get_template_statistics",
]
