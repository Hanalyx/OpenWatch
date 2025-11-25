"""
Plugin Management API Routes
Handles plugin import, management, and lifecycle operations
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from pydantic import BaseModel

from ..audit_db import log_security_event
from ..auth import get_current_user
from ..database import User, get_db
from ..models.plugin_models import InstalledPlugin, PluginExecutionRequest, PluginStatus, PluginTrustLevel
from ..services.plugin_execution_service import PluginExecutionService
from ..services.plugin_import_service import PluginImportService
from ..services.plugin_security_service import PluginSecurityService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/plugins", tags=["Plugin Management"])

# Initialize services
plugin_import_service = PluginImportService()
plugin_security_service = PluginSecurityService()
plugin_execution_service = PluginExecutionService()


class PluginImportResponse(BaseModel):
    """Response model for plugin import operations"""

    success: bool
    import_id: str
    plugin_id: Optional[str] = None
    plugin_name: Optional[str] = None
    version: Optional[str] = None
    trust_level: Optional[str] = None
    status: Optional[str] = None
    security_score: Optional[int] = None
    error: Optional[str] = None
    warnings: List[str] = []
    stage: str


@router.post("/import", response_model=PluginImportResponse)
async def import_plugin_from_file(
    file: UploadFile = File(..., description="Plugin package file (.zip, .tar.gz, .owplugin)"),
    verify_signature: bool = Form(True, description="Whether to verify plugin signature"),
    trust_level_override: Optional[PluginTrustLevel] = Form(None, description="Override trust level (admin only)"),
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    """
    Import a plugin from uploaded file

    Accepts plugin packages in various formats:
    - .zip: Standard ZIP archive
    - .tar.gz/.tgz: Compressed tar archive
    - .owplugin: OpenWatch plugin package (renamed tar.gz)

    The package must contain a valid openwatch-plugin.yml manifest file.
    """
    try:
        # Read file content
        content = await file.read()

        # Log import attempt
        log_security_event(
            db=db,
            event_type="PLUGIN_IMPORT_ATTEMPT",
            user_id=current_user.id,
            ip_address="127.0.0.1",  # TODO: Get real IP
            details=f"Importing plugin: {file.filename}",
        )

        # Check admin permissions for trust level override
        if trust_level_override and not current_user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only administrators can override trust levels",
            )

        # Import plugin
        result = await plugin_import_service.import_plugin_from_file(
            file_content=content,
            filename=file.filename or "unknown.tar.gz",
            user_id=current_user.id,
            verify_signature=verify_signature,
            trust_level_override=trust_level_override,
        )

        # Log result
        if result["success"]:
            log_security_event(
                db=db,
                event_type="PLUGIN_IMPORTED",
                user_id=current_user.id,
                ip_address="127.0.0.1",
                details=f"Plugin imported: {result.get('plugin_id')}",
            )
            logger.info(f"Plugin {result.get('plugin_id')} imported by user {current_user.id}")
        else:
            log_security_event(
                db=db,
                event_type="PLUGIN_IMPORT_FAILED",
                user_id=current_user.id,
                ip_address="127.0.0.1",
                details=f"Import failed: {result.get('error')}",
            )

        return PluginImportResponse(**result)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Plugin import error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Plugin import failed",
        )


@router.get("/")
async def list_plugins(
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    status: Optional[PluginStatus] = Query(None, description="Filter by status"),
    trust_level: Optional[PluginTrustLevel] = Query(None, description="Filter by trust level"),
    platform: Optional[str] = Query(None, description="Filter by supported platform"),
    search: Optional[str] = Query(None, description="Search in name/description"),
    current_user: User = Depends(get_current_user),
):
    """
    List installed plugins with filtering and pagination

    Supports filtering by status, trust level, platform, and text search.
    Returns paginated results with plugin metadata.
    """
    try:
        # Build query filters
        query_filters = {}

        if status:
            query_filters["status"] = status

        if trust_level:
            query_filters["trust_level"] = trust_level

        if platform:
            query_filters["enabled_platforms"] = {"$in": [platform]}

        # Text search in name/description
        if search:
            query_filters["$or"] = [
                {"manifest.name": {"$regex": search, "$options": "i"}},
                {"manifest.description": {"$regex": search, "$options": "i"}},
            ]

        # Get total count
        total = await InstalledPlugin.find(query_filters).count()

        # Get paginated results
        skip = (page - 1) * per_page
        plugins_cursor = (
            InstalledPlugin.find(query_filters).sort(-InstalledPlugin.imported_at).skip(skip).limit(per_page)
        )
        plugins = await plugins_cursor.to_list()

        # Format response
        plugin_list = []
        for plugin in plugins:
            plugin_dict = {
                "plugin_id": plugin.plugin_id,
                "name": plugin.manifest.name,
                "version": plugin.manifest.version,
                "author": plugin.manifest.author,
                "description": plugin.manifest.description,
                "type": plugin.manifest.type.value,
                "status": plugin.status.value,
                "trust_level": plugin.trust_level.value,
                "platforms": plugin.enabled_platforms,
                "capabilities": [cap.value for cap in plugin.manifest.capabilities],
                "imported_at": plugin.imported_at.isoformat(),
                "imported_by": plugin.imported_by,
                "usage_count": plugin.usage_count,
                "last_used": plugin.last_used.isoformat() if plugin.last_used else None,
                "security_score": 100 - plugin.get_risk_score(),
                "applied_to_rules": len(plugin.applied_to_rules),
                "source_url": plugin.source_url,
            }
            plugin_list.append(plugin_dict)

        return {
            "plugins": plugin_list,
            "total": total,
            "page": page,
            "per_page": per_page,
            "filters_applied": {
                "status": status.value if status else None,
                "trust_level": trust_level.value if trust_level else None,
                "platform": platform,
                "search": search,
            },
        }

    except Exception as e:
        logger.error(f"Plugin listing error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve plugins",
        )


@router.get("/{plugin_id}")
async def get_plugin_details(
    plugin_id: str,
    include_files: bool = Query(False, description="Include plugin files in response"),
    current_user: User = Depends(get_current_user),
):
    """
    Get detailed information about a specific plugin

    Returns comprehensive plugin information including manifest, security status,
    usage statistics, and optionally the plugin files.
    """
    try:
        plugin = await InstalledPlugin.find_one(InstalledPlugin.plugin_id == plugin_id)
        if not plugin:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Plugin not found")

        # Build detailed response
        plugin_details = {
            "plugin_id": plugin.plugin_id,
            "manifest": plugin.manifest.dict(),
            "status": plugin.status.value,
            "trust_level": plugin.trust_level.value,
            "security": {
                "signature_verified": plugin.signature_verified,
                "security_checks": [check.dict() for check in plugin.security_checks],
                "risk_score": plugin.get_risk_score(),
                "security_score": 100 - plugin.get_risk_score(),
            },
            "import_info": {
                "imported_by": plugin.imported_by,
                "imported_at": plugin.imported_at.isoformat(),
                "import_method": plugin.import_method,
                "source_url": plugin.source_url,
                "source_hash": plugin.source_hash,
            },
            "configuration": {
                "user_config": plugin.user_config,
                "enabled_platforms": plugin.enabled_platforms,
                "executors": {name: executor.dict() for name, executor in plugin.executors.items()},
            },
            "usage": {
                "usage_count": plugin.usage_count,
                "last_used": plugin.last_used.isoformat() if plugin.last_used else None,
                "applied_to_rules": plugin.applied_to_rules,
                "execution_history": plugin.execution_history[-10:],  # Last 10 executions
            },
        }

        # Include files if requested (admin only for security)
        if include_files and current_user.is_admin:
            plugin_details["files"] = plugin.files
        elif include_files:
            plugin_details["files"] = {
                "note": "File contents available to administrators only",
                "file_count": len(plugin.files),
                "file_names": list(plugin.files.keys()),
            }

        return plugin_details

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Plugin details error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve plugin details",
        )


@router.delete("/{plugin_id}")
async def delete_plugin(
    plugin_id: str,
    force: bool = Query(False, description="Force delete even if plugin is in use"),
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    """
    Delete an installed plugin

    Removes plugin from the system. If the plugin is associated with rules,
    use force=true to remove those associations as well.
    """
    try:
        plugin = await InstalledPlugin.find_one(InstalledPlugin.plugin_id == plugin_id)
        if not plugin:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Plugin not found")

        # Check if plugin is in use
        if plugin.applied_to_rules and not force:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "message": "Plugin is associated with rules",
                    "applied_to_rules": plugin.applied_to_rules,
                    "suggestion": "Use force=true to delete anyway",
                },
            )

        # Delete plugin
        await plugin.delete()

        # Log deletion
        log_security_event(
            db=db,
            event_type="PLUGIN_DELETED",
            user_id=current_user.id,
            ip_address="127.0.0.1",
            details=f"Plugin deleted: {plugin_id} (force={force})",
        )

        logger.info(f"Plugin {plugin_id} deleted by user {current_user.id}")

        return {
            "success": True,
            "plugin_id": plugin_id,
            "message": "Plugin deleted successfully",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Plugin deletion error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete plugin",
        )


@router.get("/statistics/overview")
async def get_plugin_statistics(current_user: User = Depends(get_current_user)):
    """
    Get plugin system statistics and metrics

    Provides overview of plugin inventory, security status, and usage patterns.
    """
    try:
        stats = await plugin_import_service.get_import_statistics()

        # Add additional security metrics
        high_risk_count = 0
        total_security_checks = 0

        async for plugin in InstalledPlugin.find():
            risk_score = plugin.get_risk_score()
            if risk_score > 70:  # High risk threshold
                high_risk_count += 1
            total_security_checks += len(plugin.security_checks)

        stats.update(
            {
                "security_metrics": {
                    "high_risk_plugins": high_risk_count,
                    "total_security_checks": total_security_checks,
                    "average_checks_per_plugin": total_security_checks / max(stats["total_plugins"], 1),
                }
            }
        )

        return stats

    except Exception as e:
        logger.error(f"Plugin statistics error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve plugin statistics",
        )


@router.post("/{plugin_id}/execute")
async def execute_plugin(
    plugin_id: str,
    request: PluginExecutionRequest,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    """
    Execute a plugin against a target host

    Runs the plugin in a secure, isolated environment with comprehensive logging
    and safety checks. Supports dry-run mode for testing.
    """
    try:
        # Validate request
        if request.plugin_id != plugin_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Plugin ID mismatch in request",
            )

        # Log execution attempt
        log_security_event(
            db=db,
            event_type="PLUGIN_EXECUTION_REQUEST",
            user_id=current_user.id,
            ip_address="127.0.0.1",
            details=f"Plugin execution: {plugin_id} on host {request.host_id}",
        )

        # Execute plugin
        result = await plugin_execution_service.execute_plugin(request)

        # Log execution result
        log_security_event(
            db=db,
            event_type="PLUGIN_EXECUTED",
            user_id=current_user.id,
            ip_address="127.0.0.1",
            details=f"Plugin execution {result.execution_id}: {result.status}",
        )

        return result.dict()

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Plugin execution error: {e}")
        log_security_event(
            db=db,
            event_type="PLUGIN_EXECUTION_ERROR",
            user_id=current_user.id,
            ip_address="127.0.0.1",
            details=f"Execution error: {str(e)}",
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Plugin execution failed",
        )


@router.get("/{plugin_id}/executions")
async def get_plugin_executions(
    plugin_id: str,
    limit: int = Query(50, ge=1, le=200, description="Maximum number of results"),
    current_user: User = Depends(get_current_user),
):
    """
    Get execution history for a plugin

    Returns recent executions with timing, status, and basic output information.
    """
    try:
        history = await plugin_execution_service.get_plugin_execution_history(plugin_id, limit)

        return {
            "plugin_id": plugin_id,
            "execution_count": len(history),
            "executions": history,
        }

    except Exception as e:
        logger.error(f"Failed to get plugin execution history: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve execution history",
        )
