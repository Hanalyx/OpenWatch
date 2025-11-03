"""
API Versioning Strategy for OpenWatch
Provides comprehensive API versioning with backward compatibility and deprecation management
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class VersionStatus(Enum):
    """API version lifecycle status"""

    DEVELOPMENT = "development"  # In active development
    STABLE = "stable"  # Production ready
    DEPRECATED = "deprecated"  # Deprecated but supported
    SUNSET = "sunset"  # No longer supported


class VersionStrategy(Enum):
    """Versioning strategy types"""

    URL_PATH = "url_path"  # /api/v1/resource
    HEADER = "header"  # Accept: application/vnd.openwatch.v1+json
    QUERY_PARAM = "query_param"  # ?version=1
    MEDIA_TYPE = "media_type"  # Content-Type: application/vnd.openwatch.v1+json


@dataclass
class APIVersion:
    """API version specification"""

    version: str
    status: VersionStatus
    release_date: datetime
    deprecation_date: Optional[datetime] = None
    sunset_date: Optional[datetime] = None
    supported_features: Set[str] = field(default_factory=set)
    breaking_changes: List[str] = field(default_factory=list)
    migration_guide_url: Optional[str] = None

    def is_supported(self) -> bool:
        """Check if version is still supported"""
        if self.status == VersionStatus.SUNSET:
            return False
        if self.sunset_date and datetime.utcnow() > self.sunset_date:
            return False
        return True

    def is_deprecated(self) -> bool:
        """Check if version is deprecated"""
        if self.status == VersionStatus.DEPRECATED:
            return True
        if self.deprecation_date and datetime.utcnow() > self.deprecation_date:
            return True
        return False


class VersionRegistry:
    """Registry for API version management"""

    def __init__(self):
        self.versions: Dict[str, APIVersion] = {}
        self.default_version = "v1"
        self.latest_stable = "v1"

        # Initialize with OpenWatch API versions
        self._initialize_openwatch_versions()

    def _initialize_openwatch_versions(self):
        """Initialize OpenWatch API versions"""
        # Version 1 - Current stable
        self.register_version(
            APIVersion(
                version="v1",
                status=VersionStatus.STABLE,
                release_date=datetime(2024, 1, 1),
                supported_features={
                    "basic_rule_management",
                    "scap_scanning",
                    "host_management",
                    "authentication",
                    "audit_logging",
                },
            )
        )

        # Version 2 - Enhanced rule management (Phase 4)
        self.register_version(
            APIVersion(
                version="v2",
                status=VersionStatus.DEVELOPMENT,
                release_date=datetime.utcnow(),
                supported_features={
                    "enhanced_rule_management",
                    "rule_inheritance",
                    "platform_capabilities",
                    "advanced_caching",
                    "full_text_search",
                    "rule_dependencies",
                    "parameter_overrides",
                },
                breaking_changes=[
                    "Rule response format enhanced with inheritance data",
                    "New required fields in rule creation requests",
                    "Modified search response structure with relevance scoring",
                ],
            )
        )

        # Version 3 - Future planned version
        self.register_version(
            APIVersion(
                version="v3",
                status=VersionStatus.DEVELOPMENT,
                release_date=datetime(2025, 1, 1),
                supported_features={
                    "ai_powered_remediation",
                    "predictive_compliance",
                    "advanced_analytics",
                    "machine_learning_insights",
                },
            )
        )

    def register_version(self, version: APIVersion):
        """Register a new API version"""
        self.versions[version.version] = version
        logger.info(f"Registered API version {version.version} with status {version.status.value}")

    def get_version(self, version: str) -> Optional[APIVersion]:
        """Get version specification"""
        return self.versions.get(version)

    def get_supported_versions(self) -> List[APIVersion]:
        """Get all supported versions"""
        return [v for v in self.versions.values() if v.is_supported()]

    def get_latest_stable(self) -> APIVersion:
        """Get latest stable version"""
        stable_versions = [v for v in self.versions.values() if v.status == VersionStatus.STABLE and v.is_supported()]
        if stable_versions:
            return max(stable_versions, key=lambda x: x.release_date)
        return self.versions[self.default_version]

    def deprecate_version(
        self,
        version: str,
        sunset_date: datetime,
        migration_guide_url: Optional[str] = None,
    ):
        """Deprecate a version with sunset date"""
        if version in self.versions:
            api_version = self.versions[version]
            api_version.status = VersionStatus.DEPRECATED
            api_version.deprecation_date = datetime.utcnow()
            api_version.sunset_date = sunset_date
            api_version.migration_guide_url = migration_guide_url

            logger.warning(f"API version {version} deprecated. Sunset date: {sunset_date}")


class VersionDetector:
    """Detect API version from request"""

    def __init__(self, registry: VersionRegistry, strategies: List[VersionStrategy] = None):
        self.registry = registry
        self.strategies = strategies or [
            VersionStrategy.URL_PATH,
            VersionStrategy.HEADER,
            VersionStrategy.QUERY_PARAM,
        ]

    def detect_version(self, request: Request) -> str:
        """Detect API version from request using configured strategies"""
        for strategy in self.strategies:
            version = None

            if strategy == VersionStrategy.URL_PATH:
                version = self._detect_from_url_path(request)
            elif strategy == VersionStrategy.HEADER:
                version = self._detect_from_header(request)
            elif strategy == VersionStrategy.QUERY_PARAM:
                version = self._detect_from_query_param(request)
            elif strategy == VersionStrategy.MEDIA_TYPE:
                version = self._detect_from_media_type(request)

            if version and self.registry.get_version(version):
                return version

        # Fall back to default version
        return self.registry.default_version

    def _detect_from_url_path(self, request: Request) -> Optional[str]:
        """Detect version from URL path (/api/v1/...)"""
        path_parts = str(request.url.path).split("/")
        for part in path_parts:
            if part.startswith("v") and part[1:].isdigit():
                return part
        return None

    def _detect_from_header(self, request: Request) -> Optional[str]:
        """Detect version from Accept header"""
        accept_header = request.headers.get("accept", "")
        if "application/vnd.openwatch.v" in accept_header:
            # Extract version from media type like application/vnd.openwatch.v2+json
            parts = accept_header.split(".")
            for part in parts:
                if part.startswith("v") and part[1:].split("+")[0].isdigit():
                    return part.split("+")[0]

        # Check for custom version header
        version_header = request.headers.get("x-api-version")
        if version_header:
            return f"v{version_header}" if not version_header.startswith("v") else version_header

        return None

    def _detect_from_query_param(self, request: Request) -> Optional[str]:
        """Detect version from query parameter (?version=1)"""
        version_param = request.query_params.get("version")
        if version_param:
            return f"v{version_param}" if not version_param.startswith("v") else version_param
        return None

    def _detect_from_media_type(self, request: Request) -> Optional[str]:
        """Detect version from Content-Type header"""
        content_type = request.headers.get("content-type", "")
        if "application/vnd.openwatch.v" in content_type:
            parts = content_type.split(".")
            for part in parts:
                if part.startswith("v") and part[1:].split("+")[0].isdigit():
                    return part.split("+")[0]
        return None


class VersionMiddleware:
    """Middleware for API version management"""

    def __init__(self):
        self.registry = VersionRegistry()
        self.detector = VersionDetector(self.registry)

    async def __call__(self, request: Request, call_next):
        """Process API versioning"""
        # Detect version
        version = self.detector.detect_version(request)
        api_version = self.registry.get_version(version)

        if not api_version:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "error": "unsupported_api_version",
                    "message": f"API version '{version}' is not supported",
                    "supported_versions": [v.version for v in self.registry.get_supported_versions()],
                },
            )

        # Check if version is supported
        if not api_version.is_supported():
            return JSONResponse(
                status_code=status.HTTP_410_GONE,
                content={
                    "error": "api_version_sunset",
                    "message": f"API version '{version}' is no longer supported",
                    "sunset_date": (api_version.sunset_date.isoformat() if api_version.sunset_date else None),
                    "migration_guide": api_version.migration_guide_url,
                    "supported_versions": [v.version for v in self.registry.get_supported_versions()],
                },
            )

        # Add version information to request state
        request.state.api_version = version
        request.state.api_version_spec = api_version

        # Process request
        response = await call_next(request)

        # Add version headers to response
        response.headers["X-API-Version"] = version
        response.headers["X-API-Version-Status"] = api_version.status.value

        # Add deprecation warnings if applicable
        if api_version.is_deprecated():
            response.headers["Deprecation"] = (
                api_version.deprecation_date.isoformat() if api_version.deprecation_date else "true"
            )
            if api_version.sunset_date:
                response.headers["Sunset"] = api_version.sunset_date.isoformat()
            if api_version.migration_guide_url:
                response.headers["Link"] = f'<{api_version.migration_guide_url}>; rel="migration-guide"'

            # Add warning header (RFC 7234)
            warning_date = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
            response.headers["Warning"] = f'299 - "API version {version} is deprecated" "{warning_date}"'

        return response


class VersionInfo(BaseModel):
    """Version information response model"""

    version: str
    status: str
    release_date: datetime
    deprecation_date: Optional[datetime] = None
    sunset_date: Optional[datetime] = None
    supported_features: List[str]
    breaking_changes: List[str]
    migration_guide_url: Optional[str] = None

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class APIVersionsInfo(BaseModel):
    """Complete API versions information"""

    current_version: str
    latest_stable: str
    default_version: str
    supported_versions: List[VersionInfo]
    deprecated_versions: List[VersionInfo]
    version_detection_methods: List[str]


def get_current_version(request: Request) -> str:
    """Dependency to get current API version from request"""
    return getattr(request.state, "api_version", "v1")


def get_version_spec(request: Request) -> APIVersion:
    """Dependency to get current API version specification"""
    return getattr(request.state, "api_version_spec", None)


def require_version(min_version: str):
    """Decorator to require minimum API version"""

    def decorator(func: Callable):
        def wrapper(*args, **kwargs):
            # This would be implemented with proper version comparison
            # For now, just pass through
            return func(*args, **kwargs)

        return wrapper

    return decorator


def feature_flag(feature_name: str):
    """Decorator to enable features based on API version"""

    def decorator(func: Callable):
        def wrapper(request: Request, *args, **kwargs):
            version_spec = get_version_spec(request)
            if version_spec and feature_name in version_spec.supported_features:
                return func(request, *args, **kwargs)
            else:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Feature '{feature_name}' not available in API version {get_current_version(request)}",
                )

        return wrapper

    return decorator


def create_version_info_endpoint(registry: VersionRegistry):
    """Create endpoint for API version information"""

    async def get_api_versions():
        """Get comprehensive API version information"""
        supported = registry.get_supported_versions()
        deprecated = [v for v in registry.versions.values() if v.is_deprecated()]
        latest_stable = registry.get_latest_stable()

        return APIVersionsInfo(
            current_version=registry.default_version,
            latest_stable=latest_stable.version,
            default_version=registry.default_version,
            supported_versions=[
                VersionInfo(
                    version=v.version,
                    status=v.status.value,
                    release_date=v.release_date,
                    deprecation_date=v.deprecation_date,
                    sunset_date=v.sunset_date,
                    supported_features=list(v.supported_features),
                    breaking_changes=v.breaking_changes,
                    migration_guide_url=v.migration_guide_url,
                )
                for v in supported
            ],
            deprecated_versions=[
                VersionInfo(
                    version=v.version,
                    status=v.status.value,
                    release_date=v.release_date,
                    deprecation_date=v.deprecation_date,
                    sunset_date=v.sunset_date,
                    supported_features=list(v.supported_features),
                    breaking_changes=v.breaking_changes,
                    migration_guide_url=v.migration_guide_url,
                )
                for v in deprecated
            ],
            version_detection_methods=[
                "URL path (/api/v1/...)",
                "Accept header (application/vnd.openwatch.v1+json)",
                "X-API-Version header",
                "Query parameter (?version=1)",
            ],
        )

    return get_api_versions


# Global version middleware instance
_version_middleware = VersionMiddleware()


def get_version_middleware() -> VersionMiddleware:
    """Get the global version middleware instance"""
    return _version_middleware
