"""
Plugin Management API Endpoints
Secure REST API for plugin import, management, and execution
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi import status as http_status
from fastapi.security import HTTPBearer
from pydantic import BaseModel, Field, field_validator

from ....auth import get_current_user
from ....database import User
from ....models.plugin_models import InstalledPlugin, PluginStatus, PluginTrustLevel, PluginType
from ....rbac import check_permission

# Phase 2: Import all plugin services from modular plugins package
from ....services.plugins import PluginImportService, PluginSignatureService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/plugins", tags=["Plugin Management"])
security = HTTPBearer()


# Request/Response Models
class PluginImportResponse(BaseModel):
    """Response for plugin import operations."""

    success: bool
    import_id: str
    plugin_id: Optional[str] = None
    plugin_name: Optional[str] = None
    version: Optional[str] = None
    trust_level: Optional[str] = None
    plugin_status: Optional[str] = Field(default=None, alias="status")
    security_score: Optional[int] = None
    security_checks: Optional[int] = None
    total_checks: Optional[int] = None
    error: Optional[str] = None
    stage: str
    warnings: List[str] = Field(default_factory=list)


class PluginListResponse(BaseModel):
    """Response for plugin listing."""

    plugins: List[Dict[str, Any]]
    total_count: int
    page: int
    page_size: int
    has_next: bool
    filters_applied: Dict[str, Any]


class PluginDetailsResponse(BaseModel):
    """Response for detailed plugin information."""

    plugin_id: str
    manifest: Dict[str, Any]
    plugin_status: str = Field(alias="status")
    trust_level: str
    imported_at: str
    imported_by: str
    usage_stats: Dict[str, Any]
    security_info: Dict[str, Any]
    execution_history: List[Dict[str, Any]]


class PluginStatusUpdateRequest(BaseModel):
    """Request to update plugin status."""

    new_status: PluginStatus = Field(alias="status")
    reason: Optional[str] = None


class PluginConfigUpdateRequest(BaseModel):
    """Request to update plugin configuration."""

    config: Dict[str, Any]
    enabled_platforms: Optional[List[str]] = None


class TrustedKeyAddRequest(BaseModel):
    """Request to add trusted public key."""

    public_key_pem: str = Field(..., min_length=200)
    key_name: str = Field(..., min_length=3, max_length=50, pattern="^[a-zA-Z0-9-_]+$")
    signer_email: str = Field(..., pattern=r"^[^@]+@[^@]+\.[^@]+$")
    organization: Optional[str] = None
    description: Optional[str] = None

    @field_validator("public_key_pem")
    @classmethod
    def validate_pem_format(cls, v: str) -> str:
        """Validate that public key is in proper PEM format."""
        if not v.startswith("-----BEGIN PUBLIC KEY-----"):
            raise ValueError("Must be a valid PEM formatted public key")
        if not v.strip().endswith("-----END PUBLIC KEY-----"):
            raise ValueError("Must be a valid PEM formatted public key")
        return v.strip()


# Plugin Import Endpoints
@router.post("/import/file", response_model=PluginImportResponse)
async def import_plugin_from_file(
    file: UploadFile = File(..., description="Plugin package file (.tar.gz, .zip, .owplugin)"),
    verify_signature: bool = Query(True, description="Verify plugin signature"),
    trust_level_override: Optional[PluginTrustLevel] = Query(
        None, description="Override trust level (admin only)"
    ),
    current_user: User = Depends(get_current_user),
    import_service: PluginImportService = Depends(lambda: PluginImportService()),
) -> PluginImportResponse:
    """
    Import plugin from uploaded file.

    Security measures:
    - File size limits enforced
    - Comprehensive security scanning
    - Signature verification (optional but recommended)
    - Sandbox validation
    """
    try:
        # Check permissions - rbac.check_permission takes (role, resource, action)
        check_permission(str(current_user.role), "plugins", "import")

        # Admin-only trust level override
        if trust_level_override and current_user.role != "admin":
            raise HTTPException(
                status_code=http_status.HTTP_403_FORBIDDEN,
                detail="Trust level override requires admin privileges",
            )

        # Validate file type
        if not file.filename:
            raise HTTPException(
                status_code=http_status.HTTP_400_BAD_REQUEST, detail="Filename is required"
            )

        allowed_extensions = {".tar.gz", ".tgz", ".zip", ".owplugin"}
        # file_extension extracted for potential future use (logging, validation)
        _file_extension = "".join(file.filename.lower().split(".")[1:])  # noqa: F841
        if not any(file.filename.lower().endswith(ext) for ext in allowed_extensions):
            raise HTTPException(
                status_code=http_status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported file type. Allowed: {', '.join(allowed_extensions)}",
            )

        # Read file content
        file_content = await file.read()

        # Import plugin
        result = await import_service.import_plugin_from_file(
            file_content=file_content,
            filename=file.filename,
            user_id=str(current_user.username),
            verify_signature=verify_signature,
            trust_level_override=trust_level_override,
        )

        # Log import attempt
        logger.info(
            "Plugin import attempt",
            extra={
                "user": str(current_user.username),
                "filename": file.filename,
                "success": result["success"],
                "import_id": result["import_id"],
            },
        )

        return PluginImportResponse(**result)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Plugin import error: {e}")
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Import failed: {str(e)}",
        )


@router.post("/import/url", response_model=PluginImportResponse)
async def import_plugin_from_url(
    plugin_url: str = Query(..., description="HTTPS URL to plugin package"),
    verify_signature: bool = Query(True, description="Verify plugin signature"),
    max_size_mb: int = Query(50, ge=1, le=100, description="Maximum download size in MB"),
    current_user: User = Depends(get_current_user),
    import_service: PluginImportService = Depends(lambda: PluginImportService()),
) -> PluginImportResponse:
    """
    Import plugin from URL.

    Security measures:
    - HTTPS-only downloads
    - Size limits enforced
    - URL validation against private networks
    - Same security scanning as file uploads
    """
    try:
        # Check permissions - rbac.check_permission takes (role, resource, action)
        check_permission(str(current_user.role), "plugins", "import")

        # Validate URL format
        if not plugin_url.startswith("https://"):
            raise HTTPException(
                status_code=http_status.HTTP_400_BAD_REQUEST,
                detail="Only HTTPS URLs are allowed for security",
            )

        # Import plugin
        result = await import_service.import_plugin_from_url(
            plugin_url=plugin_url,
            user_id=str(current_user.username),
            verify_signature=verify_signature,
            max_size=max_size_mb * 1024 * 1024,
        )

        # Log import attempt
        logger.info(
            "Plugin URL import attempt",
            extra={
                "user": str(current_user.username),
                "url": plugin_url,
                "success": result["success"],
                "import_id": result["import_id"],
            },
        )

        return PluginImportResponse(**result)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Plugin URL import error: {e}")
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"URL import failed: {str(e)}",
        )


# Plugin Management Endpoints
@router.get("/", response_model=PluginListResponse)
async def list_plugins(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(25, ge=1, le=100, description="Items per page"),
    filter_status: Optional[PluginStatus] = Query(
        None, alias="status", description="Filter by status"
    ),
    trust_level: Optional[PluginTrustLevel] = Query(None, description="Filter by trust level"),
    plugin_type: Optional[PluginType] = Query(None, description="Filter by plugin type"),
    platform: Optional[str] = Query(None, description="Filter by supported platform"),
    search: Optional[str] = Query(None, description="Search in name and description"),
    current_user: User = Depends(get_current_user),
) -> PluginListResponse:
    """List installed plugins with filtering and pagination."""
    try:
        # Check permissions - rbac.check_permission takes (role, resource, action)
        check_permission(str(current_user.role), "plugins", "read")

        # Build query
        query: Dict[str, Any] = {}

        if filter_status:
            query["status"] = filter_status
        if trust_level:
            query["trust_level"] = trust_level
        if plugin_type:
            query["manifest.type"] = plugin_type
        if platform:
            query["enabled_platforms"] = platform
        if search:
            query["$or"] = [
                {"manifest.name": {"$regex": search, "$options": "i"}},
                {"manifest.description": {"$regex": search, "$options": "i"}},
            ]

        # Get total count
        total_count = await InstalledPlugin.find(query).count()

        # Get paginated results - use tuple syntax for MongoDB sorting
        skip = (page - 1) * page_size
        plugins = (
            await InstalledPlugin.find(query)
            .skip(skip)
            .limit(page_size)
            .sort([("imported_at", -1)])
            .to_list()
        )

        # Format response
        plugin_list: List[Dict[str, Any]] = []
        for plugin in plugins:
            plugin_data: Dict[str, Any] = {
                "plugin_id": plugin.plugin_id,
                "name": plugin.manifest.name,
                "version": plugin.manifest.version,
                "type": plugin.manifest.type.value,
                "author": plugin.manifest.author,
                "description": plugin.manifest.description,
                "status": plugin.status.value,
                "trust_level": plugin.trust_level.value,
                "platforms": plugin.enabled_platforms,
                "capabilities": [cap.value for cap in plugin.manifest.capabilities],
                "imported_at": plugin.imported_at.isoformat(),
                "imported_by": plugin.imported_by,
                "usage_count": plugin.usage_count,
                "last_used": plugin.last_used.isoformat() if plugin.last_used else None,
                "risk_score": plugin.get_risk_score(),
                "signature_verified": plugin.signature_verified,
            }
            plugin_list.append(plugin_data)

        has_next = (skip + page_size) < total_count

        return PluginListResponse(
            plugins=plugin_list,
            total_count=total_count,
            page=page,
            page_size=page_size,
            has_next=has_next,
            filters_applied={
                "status": filter_status.value if filter_status else None,
                "trust_level": trust_level.value if trust_level else None,
                "plugin_type": plugin_type.value if plugin_type else None,
                "platform": platform,
                "search": search,
            },
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Plugin listing error: {e}")
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list plugins: {str(e)}",
        )


@router.get("/{plugin_id}", response_model=PluginDetailsResponse)
async def get_plugin_details(
    plugin_id: str, current_user: User = Depends(get_current_user)
) -> PluginDetailsResponse:
    """Get detailed information about a specific plugin."""
    try:
        # Check permissions - rbac.check_permission takes (role, resource, action)
        check_permission(str(current_user.role), "plugins", "read")

        plugin = await InstalledPlugin.find_one(InstalledPlugin.plugin_id == plugin_id)
        if not plugin:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND,
                detail=f"Plugin not found: {plugin_id}",
            )

        # Prepare security information
        security_info: Dict[str, Any] = {
            "trust_level": plugin.trust_level.value,
            "signature_verified": plugin.signature_verified,
            "risk_score": plugin.get_risk_score(),
            "security_checks": len(plugin.security_checks),
            "checks_passed": len([c for c in plugin.security_checks if c.passed]),
            "last_security_scan": (
                max([c.timestamp for c in plugin.security_checks]).isoformat()
                if plugin.security_checks
                else None
            ),
        }

        # Usage statistics
        usage_stats: Dict[str, Any] = {
            "usage_count": plugin.usage_count,
            "last_used": plugin.last_used.isoformat() if plugin.last_used else None,
            "applied_to_rules": len(plugin.applied_to_rules),
            "execution_success_rate": 0,  # Would calculate from execution history
        }

        # Recent execution history (limited)
        execution_history: List[Dict[str, Any]] = (
            plugin.execution_history[-10:] if plugin.execution_history else []
        )

        return PluginDetailsResponse(
            plugin_id=plugin.plugin_id,
            manifest=plugin.manifest.dict(),
            status=plugin.status.value,
            trust_level=plugin.trust_level.value,
            imported_at=plugin.imported_at.isoformat(),
            imported_by=plugin.imported_by,
            usage_stats=usage_stats,
            security_info=security_info,
            execution_history=execution_history,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Plugin details error: {e}")
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get plugin details: {str(e)}",
        )


@router.patch("/{plugin_id}/status", response_model=Dict[str, str])
async def update_plugin_status(
    plugin_id: str,
    status_update: PluginStatusUpdateRequest,
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """Update plugin status (enable/disable/quarantine)."""
    try:
        # Check permissions - rbac.check_permission takes (role, resource, action)
        check_permission(str(current_user.role), "plugins", "manage")

        plugin = await InstalledPlugin.find_one(InstalledPlugin.plugin_id == plugin_id)
        if not plugin:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND,
                detail=f"Plugin not found: {plugin_id}",
            )

        # Validate status transition
        current_plugin_status = plugin.status
        new_plugin_status = status_update.new_status

        # Define valid transitions
        valid_transitions: Dict[PluginStatus, List[PluginStatus]] = {
            PluginStatus.PENDING_VALIDATION: [
                PluginStatus.ACTIVE,
                PluginStatus.QUARANTINED,
            ],
            PluginStatus.ACTIVE: [PluginStatus.DISABLED, PluginStatus.QUARANTINED],
            PluginStatus.DISABLED: [PluginStatus.ACTIVE],
            PluginStatus.QUARANTINED: [PluginStatus.ACTIVE, PluginStatus.DISABLED],
            PluginStatus.DEPRECATED: [PluginStatus.DISABLED],
        }

        if new_plugin_status not in valid_transitions.get(current_plugin_status, []):
            raise HTTPException(
                status_code=http_status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status transition from {current_plugin_status.value} to {new_plugin_status.value}",
            )

        # Update status
        plugin.status = new_plugin_status
        plugin.updated_at = datetime.utcnow()
        await plugin.save()

        # Log status change
        logger.info(
            "Plugin status updated",
            extra={
                "plugin_id": plugin_id,
                "old_status": current_plugin_status.value,
                "new_status": new_plugin_status.value,
                "user": str(current_user.username),
                "reason": status_update.reason,
            },
        )

        return {
            "plugin_id": plugin_id,
            "status": new_plugin_status.value,
            "message": f"Plugin status updated to {new_plugin_status.value}",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Plugin status update error: {e}")
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update plugin status: {str(e)}",
        )


@router.delete("/{plugin_id}")
async def uninstall_plugin(
    plugin_id: str,
    remove_from_rules: bool = Query(False, description="Remove plugin associations from rules"),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """Uninstall plugin and optionally remove rule associations."""
    try:
        # Check permissions - rbac.check_permission takes (role, resource, action)
        check_permission(str(current_user.role), "plugins", "delete")

        plugin = await InstalledPlugin.find_one(InstalledPlugin.plugin_id == plugin_id)
        if not plugin:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND,
                detail=f"Plugin not found: {plugin_id}",
            )

        # Check if plugin is in use
        if plugin.applied_to_rules and not remove_from_rules:
            raise HTTPException(
                status_code=http_status.HTTP_400_BAD_REQUEST,
                detail=f"Plugin is applied to {len(plugin.applied_to_rules)} rules. Set remove_from_rules=true to force removal.",
            )

        # Remove plugin associations from rules if requested
        if remove_from_rules and plugin.applied_to_rules:
            # This would integrate with the compliance rules system
            # For now, just log the action
            logger.info(
                f"Would remove plugin {plugin_id} from {len(plugin.applied_to_rules)} rules"
            )

        # Delete plugin
        await plugin.delete()

        # Log uninstallation
        logger.info(
            "Plugin uninstalled",
            extra={
                "plugin_id": plugin_id,
                "plugin_name": plugin.manifest.name,
                "user": str(current_user.username),
                "removed_from_rules": remove_from_rules,
            },
        )

        return {"plugin_id": plugin_id, "message": "Plugin uninstalled successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Plugin uninstall error: {e}")
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to uninstall plugin: {str(e)}",
        )


# Security and Trust Management
@router.get("/security/trusted-keys")
async def list_trusted_keys(
    current_user: User = Depends(get_current_user),
    signature_service: PluginSignatureService = Depends(lambda: PluginSignatureService()),
) -> Dict[str, Any]:
    """List trusted public keys for signature verification."""
    try:
        # Check permissions - rbac.check_permission takes (role, resource, action)
        check_permission(str(current_user.role), "plugins", "security")

        trusted_keys = signature_service.get_trusted_signers()

        return {"trusted_keys": trusted_keys, "count": len(trusted_keys)}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Trusted keys listing error: {e}")
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list trusted keys: {str(e)}",
        )


@router.post("/security/trusted-keys")
async def add_trusted_key(
    key_request: TrustedKeyAddRequest,
    current_user: User = Depends(get_current_user),
    signature_service: PluginSignatureService = Depends(lambda: PluginSignatureService()),
) -> Dict[str, Any]:
    """Add a trusted public key for plugin signature verification (admin only)."""
    try:
        # Admin only
        if current_user.role != "admin":
            raise HTTPException(
                status_code=http_status.HTTP_403_FORBIDDEN,
                detail="Adding trusted keys requires admin privileges",
            )

        signer_info: Dict[str, Any] = {
            "email": key_request.signer_email,
            "organization": key_request.organization,
            "description": key_request.description,
            "added_by": str(current_user.username),
            "added_at": datetime.utcnow().isoformat(),
        }

        result = await signature_service.add_trusted_key(
            public_key_pem=key_request.public_key_pem,
            key_name=key_request.key_name,
            signer_info=signer_info,
        )

        if not result["success"]:
            raise HTTPException(
                status_code=http_status.HTTP_400_BAD_REQUEST, detail=result["error"]
            )

        # Log key addition
        logger.info(
            "Trusted key added",
            extra={
                "key_id": result["key_id"],
                "key_name": result["key_name"],
                "signer_email": key_request.signer_email,
                "added_by": str(current_user.username),
            },
        )

        return {
            "success": True,
            "key_id": result["key_id"],
            "key_name": result["key_name"],
            "message": "Trusted key added successfully",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Add trusted key error: {e}")
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to add trusted key: {str(e)}",
        )


@router.get("/statistics")
async def get_plugin_statistics(
    current_user: User = Depends(get_current_user),
    import_service: PluginImportService = Depends(lambda: PluginImportService()),
) -> Dict[str, Any]:
    """Get plugin statistics and metrics."""
    try:
        # Check permissions - rbac.check_permission takes (role, resource, action)
        check_permission(str(current_user.role), "plugins", "read")

        stats = await import_service.get_import_statistics()

        # Add additional metrics
        recent_imports = await import_service.list_import_history(limit=10)

        stats["recent_imports"] = recent_imports
        stats["generated_at"] = datetime.utcnow().isoformat()

        return stats

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Plugin statistics error: {e}")
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get statistics: {str(e)}",
        )
