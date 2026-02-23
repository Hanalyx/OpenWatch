"""
ORSA Plugin Management API Endpoints

This module provides API endpoints for managing ORSA-compliant plugins.
ORSA (OpenWatch Remediation System Adapter) is the standard interface
for compliance scanning and remediation plugins.

Endpoint Structure:
    GET    /orsa/                       - List all registered ORSA plugins
    GET    /orsa/health                 - Health check for all plugins
    GET    /orsa/{plugin_id}            - Get plugin details
    GET    /orsa/{plugin_id}/capabilities - Get plugin capabilities
    GET    /orsa/{plugin_id}/rules      - Get available rules from plugin
    GET    /orsa/{plugin_id}/frameworks - Get supported frameworks

Phase 1: Kensa Integration (ORSA v2.0 Interface)
"""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi import status as http_status
from pydantic import BaseModel, Field

from ...auth import get_current_user
from ...database import User
from ...services.plugins.orsa import Capability, ORSAPluginRegistry, PluginInfo

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/orsa", tags=["ORSA Plugins"])


# =============================================================================
# PYDANTIC MODELS
# =============================================================================


class PluginInfoResponse(BaseModel):
    """Response model for plugin information."""

    plugin_id: str
    name: str
    version: str
    description: str
    author: str
    capabilities: List[str]
    supported_platforms: List[str]
    supported_frameworks: List[str]
    license_required: bool = False


class PluginListResponse(BaseModel):
    """Response model for plugin list."""

    plugins: List[PluginInfoResponse]
    total: int


class PluginCapabilitiesResponse(BaseModel):
    """Response model for plugin capabilities."""

    plugin_id: str
    capabilities: List[str]
    descriptions: Dict[str, str] = Field(default_factory=dict)


class PluginHealthResponse(BaseModel):
    """Response model for plugin health check."""

    registry_healthy: bool
    all_plugins_healthy: bool
    plugin_count: int
    initialized_at: Optional[str]
    plugins: Dict[str, Any]


class PluginRulesResponse(BaseModel):
    """Response model for plugin rules."""

    plugin_id: str
    total_rules: int
    rules: List[Dict[str, Any]]
    page: int
    per_page: int


class PluginFrameworksResponse(BaseModel):
    """Response model for plugin frameworks."""

    plugin_id: str
    frameworks: List[str]
    framework_details: Dict[str, Any] = Field(default_factory=dict)


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def plugin_info_to_response(info: PluginInfo) -> PluginInfoResponse:
    """Convert PluginInfo to API response model."""
    return PluginInfoResponse(
        plugin_id=info.plugin_id,
        name=info.name,
        version=info.version,
        description=info.description,
        author=info.author,
        capabilities=[cap.value for cap in info.capabilities],
        supported_platforms=info.supported_platforms,
        supported_frameworks=info.supported_frameworks,
        license_required=info.license_required,
    )


# =============================================================================
# API ENDPOINTS
# =============================================================================


@router.get("/", response_model=PluginListResponse)
async def list_orsa_plugins(
    capability: Optional[str] = Query(None, description="Filter by capability"),
    platform: Optional[str] = Query(None, description="Filter by platform"),
    framework: Optional[str] = Query(None, description="Filter by framework"),
    current_user: User = Depends(get_current_user),
) -> PluginListResponse:
    """
    List all registered ORSA plugins.

    Returns information about all plugins registered with the ORSA registry.
    Supports filtering by capability, platform, or framework.

    Args:
        capability: Filter by plugin capability (e.g., compliance_check, remediation)
        platform: Filter by supported platform (e.g., rhel9, ubuntu22)
        framework: Filter by supported framework (e.g., cis, stig)
        current_user: Authenticated user

    Returns:
        List of registered ORSA plugins with metadata
    """
    try:
        registry = ORSAPluginRegistry.instance()
        plugins: List[PluginInfo] = []

        # Apply filters
        if capability:
            try:
                cap = Capability(capability)
                filtered_plugins = await registry.get_by_capability(cap)
                for plugin in filtered_plugins:
                    info = await plugin.get_info()
                    plugins.append(info)
            except ValueError:
                raise HTTPException(
                    status_code=http_status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid capability: {capability}. Valid values: {[c.value for c in Capability]}",
                )
        elif platform:
            filtered_plugins = await registry.get_by_platform(platform)
            for plugin in filtered_plugins:
                info = await plugin.get_info()
                plugins.append(info)
        elif framework:
            filtered_plugins = await registry.get_by_framework(framework)
            for plugin in filtered_plugins:
                info = await plugin.get_info()
                plugins.append(info)
        else:
            plugins = await registry.list_all()

        return PluginListResponse(
            plugins=[plugin_info_to_response(p) for p in plugins],
            total=len(plugins),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to list ORSA plugins: {e}")
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve ORSA plugins",
        )


@router.get("/health", response_model=PluginHealthResponse)
async def orsa_health_check(
    current_user: User = Depends(get_current_user),
) -> PluginHealthResponse:
    """
    Perform health check on all ORSA plugins.

    Returns health status of the ORSA registry and all registered plugins.

    Args:
        current_user: Authenticated user

    Returns:
        Health status for registry and all plugins
    """
    try:
        registry = ORSAPluginRegistry.instance()
        health = await registry.health_check()

        return PluginHealthResponse(
            registry_healthy=health.get("registry_healthy", False),
            all_plugins_healthy=health.get("all_plugins_healthy", False),
            plugin_count=health.get("plugin_count", 0),
            initialized_at=health.get("initialized_at"),
            plugins=health.get("plugins", {}),
        )

    except Exception as e:
        logger.error(f"ORSA health check failed: {e}")
        return PluginHealthResponse(
            registry_healthy=False,
            all_plugins_healthy=False,
            plugin_count=0,
            initialized_at=None,
            plugins={"error": str(e)},
        )


@router.get("/{plugin_id}", response_model=PluginInfoResponse)
async def get_orsa_plugin(
    plugin_id: str,
    current_user: User = Depends(get_current_user),
) -> PluginInfoResponse:
    """
    Get detailed information about a specific ORSA plugin.

    Args:
        plugin_id: The plugin identifier (e.g., "kensa")
        current_user: Authenticated user

    Returns:
        Detailed plugin information

    Raises:
        HTTPException: 404 if plugin not found
    """
    try:
        registry = ORSAPluginRegistry.instance()
        info = await registry.get_info(plugin_id)

        if not info:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND,
                detail=f"ORSA plugin not found: {plugin_id}",
            )

        return plugin_info_to_response(info)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get ORSA plugin {plugin_id}: {e}")
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve plugin details",
        )


@router.get("/{plugin_id}/capabilities", response_model=PluginCapabilitiesResponse)
async def get_plugin_capabilities(
    plugin_id: str,
    current_user: User = Depends(get_current_user),
) -> PluginCapabilitiesResponse:
    """
    Get capabilities of a specific ORSA plugin.

    Returns the list of capabilities the plugin supports along with
    descriptions of what each capability provides.

    Args:
        plugin_id: The plugin identifier
        current_user: Authenticated user

    Returns:
        Plugin capabilities with descriptions

    Raises:
        HTTPException: 404 if plugin not found
    """
    try:
        registry = ORSAPluginRegistry.instance()
        plugin = await registry.get(plugin_id)

        if not plugin:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND,
                detail=f"ORSA plugin not found: {plugin_id}",
            )

        capabilities = await plugin.get_capabilities()

        # Capability descriptions
        capability_descriptions = {
            Capability.COMPLIANCE_CHECK.value: "Execute compliance checks against hosts",
            Capability.REMEDIATION.value: "Remediate failed compliance checks (license required)",
            Capability.ROLLBACK.value: "Rollback remediation changes (license required)",
            Capability.CAPABILITY_DETECTION.value: "Detect host capabilities (sudo, package managers)",
            Capability.DRY_RUN.value: "Preview remediation without applying changes",
            Capability.PARALLEL_EXECUTION.value: "Execute checks in parallel for faster scans",
            Capability.FRAMEWORK_MAPPING.value: "Map rules to compliance frameworks",
        }

        return PluginCapabilitiesResponse(
            plugin_id=plugin_id,
            capabilities=[cap.value for cap in capabilities],
            descriptions={cap.value: capability_descriptions.get(cap.value, "") for cap in capabilities},
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get capabilities for {plugin_id}: {e}")
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve plugin capabilities",
        )


@router.get("/{plugin_id}/rules", response_model=PluginRulesResponse)
async def get_plugin_rules(
    plugin_id: str,
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=200, description="Items per page"),
    framework: Optional[str] = Query(None, description="Filter by framework"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    current_user: User = Depends(get_current_user),
) -> PluginRulesResponse:
    """
    Get available rules from a specific ORSA plugin.

    Returns the canonical rules available from the plugin with pagination.
    Supports filtering by framework and severity.

    Args:
        plugin_id: The plugin identifier
        page: Page number (1-indexed)
        per_page: Items per page (1-200)
        framework: Filter by framework (e.g., cis, stig)
        severity: Filter by severity (high, medium, low)
        current_user: Authenticated user

    Returns:
        Paginated list of plugin rules

    Raises:
        HTTPException: 404 if plugin not found
    """
    try:
        registry = ORSAPluginRegistry.instance()
        plugin = await registry.get(plugin_id)

        if not plugin:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND,
                detail=f"ORSA plugin not found: {plugin_id}",
            )

        # Get rules from plugin
        rules = await plugin.get_rules(framework=framework)

        # Apply severity filter
        if severity:
            rules = [r for r in rules if r.severity.lower() == severity.lower()]

        # Calculate pagination
        total_rules = len(rules)
        start = (page - 1) * per_page
        end = start + per_page
        paginated_rules = rules[start:end]

        # Convert to dict for response
        rule_dicts = [
            {
                "rule_id": r.id,
                "title": r.title,
                "description": r.description,
                "severity": r.severity,
                "category": r.category,
                "tags": r.tags,
                "frameworks": r.references,
                "has_remediation": len(r.implementations) > 0,
            }
            for r in paginated_rules
        ]

        return PluginRulesResponse(
            plugin_id=plugin_id,
            total_rules=total_rules,
            rules=rule_dicts,
            page=page,
            per_page=per_page,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get rules for {plugin_id}: {e}")
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve plugin rules",
        )


@router.get("/{plugin_id}/frameworks", response_model=PluginFrameworksResponse)
async def get_plugin_frameworks(
    plugin_id: str,
    current_user: User = Depends(get_current_user),
) -> PluginFrameworksResponse:
    """
    Get supported frameworks for a specific ORSA plugin.

    Returns the list of compliance frameworks supported by the plugin
    along with details about coverage and rule counts.

    Args:
        plugin_id: The plugin identifier
        current_user: Authenticated user

    Returns:
        Supported frameworks with details

    Raises:
        HTTPException: 404 if plugin not found
    """
    try:
        registry = ORSAPluginRegistry.instance()
        plugin = await registry.get(plugin_id)

        if not plugin:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND,
                detail=f"ORSA plugin not found: {plugin_id}",
            )

        info = await plugin.get_info()
        frameworks = info.supported_frameworks

        # Get rule counts per framework
        framework_details: Dict[str, Any] = {}
        for fw in frameworks:
            rules = await plugin.get_rules(framework=fw)
            framework_details[fw] = {
                "rule_count": len(rules),
                "severity_breakdown": {},
            }

            # Count by severity
            severity_counts: Dict[str, int] = {}
            for rule in rules:
                sev = rule.severity.lower()
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            framework_details[fw]["severity_breakdown"] = severity_counts

        return PluginFrameworksResponse(
            plugin_id=plugin_id,
            frameworks=frameworks,
            framework_details=framework_details,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get frameworks for {plugin_id}: {e}")
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve plugin frameworks",
        )


__all__ = ["router"]
