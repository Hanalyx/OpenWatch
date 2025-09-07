"""
OpenWatch Capabilities API
Provides feature discovery and capability-based routing for OSS/Enterprise features
"""

import logging
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
import asyncio
import os

from ..auth import get_current_user
from ..config import get_settings
from ..database import get_db
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

router = APIRouter()


class FeatureFlags(BaseModel):
    """Feature flags for conditional functionality"""

    scanning: bool = True
    reporting: bool = True
    host_management: bool = True
    user_management: bool = True
    audit_logging: bool = True
    mfa: bool = True
    plugin_system: bool = True

    # Enterprise features (license-dependent)
    remediation: bool = False
    ai_assistance: bool = False
    advanced_reporting: bool = False
    siem_integration: bool = False
    compliance_frameworks: bool = False
    enterprise_auth: bool = False


class SystemLimits(BaseModel):
    """System limits and constraints"""

    max_hosts: int = 50
    concurrent_scans: int = 5
    max_users: int = 10
    storage_limit_gb: int = 100
    api_rate_limit: int = 1000  # requests per minute
    plugin_limit: int = 10


class IntegrationStatus(BaseModel):
    """Status of external integrations"""

    aegis_available: bool = False
    aegis_version: str = None
    ldap_enabled: bool = False
    smtp_configured: bool = False
    prometheus_enabled: bool = False

    # Container runtime detection
    container_runtime: str = "unknown"
    kubernetes_available: bool = False


class CapabilitiesResponse(BaseModel):
    """Complete capabilities response"""

    version: str
    build_info: Dict[str, Any]
    features: FeatureFlags
    limits: SystemLimits
    integrations: IntegrationStatus
    license_info: Dict[str, Any]
    system_info: Dict[str, Any]


@router.get("/capabilities", response_model=CapabilitiesResponse)
async def get_capabilities(
    current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)
) -> CapabilitiesResponse:
    """
    Get system capabilities and feature flags

    Returns comprehensive information about:
    - Available features and their status
    - System limits and constraints
    - Integration status with external systems
    - License information and limitations

    This endpoint enables frontend conditional rendering and
    API consumers to discover available functionality.
    """
    try:
        settings = get_settings()

        # Detect license type and enterprise features
        license_info = await _detect_license_info()

        # Check integration status
        integrations = await _check_integrations()

        # Determine feature flags based on license and configuration
        features = await _determine_feature_flags(license_info, settings)

        # Calculate system limits
        limits = await _calculate_system_limits(license_info, settings)

        # Get system information
        system_info = await _get_system_info()

        # Build version info
        build_info = {
            "version": "1.0.0",
            "build_date": "2025-08-20",
            "git_commit": "d84d2a3",
            "api_version": "v1",
            "environment": getattr(settings, "environment", "production"),
        }

        response = CapabilitiesResponse(
            version="1.0.0",
            build_info=build_info,
            features=features,
            limits=limits,
            integrations=integrations,
            license_info=license_info,
            system_info=system_info,
        )

        logger.info(f"Capabilities requested by user {current_user.get('user_id', 'unknown')}")

        return response

    except Exception as e:
        logger.error(f"Error getting capabilities: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve system capabilities",
        )


@router.get("/features", response_model=FeatureFlags)
async def get_feature_flags(current_user: dict = Depends(get_current_user)) -> FeatureFlags:
    """
    Get just the feature flags (lightweight endpoint)

    Returns only the feature availability flags without
    detailed system information. Useful for frequent polling
    by frontend applications.
    """
    try:
        settings = get_settings()
        license_info = await _detect_license_info()
        features = await _determine_feature_flags(license_info, settings)

        logger.debug(f"Feature flags requested by user {current_user.get('user_id', 'unknown')}")

        return features

    except Exception as e:
        logger.error(f"Error getting feature flags: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve feature flags",
        )


@router.get("/health/integrations", response_model=IntegrationStatus)
async def get_integration_status(
    current_user: dict = Depends(get_current_user),
) -> IntegrationStatus:
    """
    Get status of external integrations

    Returns the current status of all external system integrations
    including AEGIS, LDAP, SMTP, and container runtime information.
    """
    try:
        integrations = await _check_integrations()

        logger.debug(
            f"Integration status requested by user {current_user.get('user_id', 'unknown')}"
        )

        return integrations

    except Exception as e:
        logger.error(f"Error getting integration status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve integration status",
        )


# Helper functions
def _detect_license_info() -> Dict[str, Any]:
    """Detect license type and enterprise features availability"""
    # For OSS version, return basic license info
    # In enterprise version, this would check actual license files

    return {
        "type": "oss",
        "tier": "community",
        "expires": None,
        "features_enabled": ["scanning", "reporting", "host_management", "plugin_system"],
        "enterprise_available": False,
        "upgrade_url": "https://hanalyx.com/openwatch/enterprise",
    }


async def _determine_feature_flags(license_info: Dict, settings) -> FeatureFlags:
    """Determine which features are available based on license and config"""

    # Base OSS features (always available)
    features = FeatureFlags()

    # Check for enterprise license
    if license_info.get("type") == "enterprise":
        features.remediation = True
        features.ai_assistance = True
        features.advanced_reporting = True
        features.siem_integration = True
        features.compliance_frameworks = True
        features.enterprise_auth = True

    # Check configuration-dependent features
    features.mfa = getattr(settings, "mfa_enabled", True)

    # Check if AEGIS is available (affects remediation)
    if await _check_aegis_availability():
        # Even in OSS, basic remediation might be available if AEGIS is configured
        features.remediation = license_info.get("type") == "enterprise"

    return features


def _calculate_system_limits(license_info: Dict, settings) -> SystemLimits:
    """Calculate system limits based on license and configuration"""

    limits = SystemLimits()

    # Adjust limits based on license type
    if license_info.get("type") == "enterprise":
        limits.max_hosts = 1000
        limits.concurrent_scans = 50
        limits.max_users = 100
        limits.storage_limit_gb = 1000
        limits.api_rate_limit = 10000
        limits.plugin_limit = 100
    elif license_info.get("type") == "professional":
        limits.max_hosts = 200
        limits.concurrent_scans = 20
        limits.max_users = 25
        limits.storage_limit_gb = 500
        limits.api_rate_limit = 5000
        limits.plugin_limit = 50

    # OSS defaults are already set in the model

    return limits


async def _check_integrations() -> IntegrationStatus:
    """Check status of external integrations"""

    integrations = IntegrationStatus()

    # Check AEGIS availability
    integrations.aegis_available = await _check_aegis_availability()
    if integrations.aegis_available:
        integrations.aegis_version = await _get_aegis_version()

    # Check LDAP configuration
    integrations.ldap_enabled = _check_ldap_config()

    # Check SMTP configuration
    integrations.smtp_configured = _check_smtp_config()

    # Check Prometheus
    integrations.prometheus_enabled = _check_prometheus_config()

    # Detect container runtime
    integrations.container_runtime = await _detect_container_runtime()

    # Check Kubernetes availability
    integrations.kubernetes_available = await _check_kubernetes_availability()

    return integrations


def _check_aegis_availability() -> bool:
    """Check if AEGIS remediation service is available"""
    try:
        # In a real implementation, this would check AEGIS connectivity
        # For now, check if AEGIS configuration exists
        aegis_url = os.environ.get("AEGIS_URL")
        return aegis_url is not None
    except:
        return False


def _get_aegis_version() -> str:
    """Get AEGIS version if available"""
    try:
        # In a real implementation, this would query AEGIS API
        return "1.0.0"
    except:
        return None


def _check_ldap_config() -> bool:
    """Check if LDAP is configured"""
    return bool(os.environ.get("LDAP_SERVER"))


def _check_smtp_config() -> bool:
    """Check if SMTP is configured"""
    return bool(os.environ.get("SMTP_SERVER"))


def _check_prometheus_config() -> bool:
    """Check if Prometheus monitoring is enabled"""
    return bool(os.environ.get("PROMETHEUS_ENABLED", "").lower() == "true")


async def _detect_container_runtime() -> str:
    """Detect which container runtime is being used"""
    try:
        # Check for Podman
        result = await asyncio.create_subprocess_exec(
            "podman", "--version", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        if result.returncode == 0:
            return "podman"
    except:
        pass

    try:
        # Check for Docker
        result = await asyncio.create_subprocess_exec(
            "docker", "--version", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        if result.returncode == 0:
            return "docker"
    except:
        pass

    return "unknown"


async def _check_kubernetes_availability() -> bool:
    """Check if Kubernetes is available"""
    try:
        # Check for kubectl
        result = await asyncio.create_subprocess_exec(
            "kubectl",
            "version",
            "--client",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        return result.returncode == 0
    except:
        return False


def _get_system_info() -> Dict[str, Any]:
    """Get basic system information"""
    import platform
    import psutil

    try:
        return {
            "platform": platform.system(),
            "platform_version": platform.release(),
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
            "cpu_count": psutil.cpu_count(),
            "memory_total": psutil.virtual_memory().total,
            "disk_usage": dict(psutil.disk_usage("/")._asdict()),
            "uptime": psutil.boot_time(),
        }
    except Exception as e:
        logger.warning(f"Could not get system info: {e}")
        return {"error": "System information unavailable"}
