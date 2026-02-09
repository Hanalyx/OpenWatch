"""
License Service Implementation

Provides license validation and the @requires_license decorator for
feature gating in OpenWatch.

The license service validates licenses against a license server or
local license file, with caching for performance.

Future Implementation:
- License key validation against Hanalyx license server
- Offline license file support
- License expiry handling
- Usage tracking and reporting
"""

import logging
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, TypeVar

logger = logging.getLogger(__name__)

# Type variable for generic function decoration
F = TypeVar("F", bound=Callable[..., Any])


class LicenseRequiredError(Exception):
    """
    Raised when an operation requires a license that is not active.

    Attributes:
        feature: The feature that requires licensing.
        message: Human-readable error message.
    """

    def __init__(self, feature: str, message: Optional[str] = None) -> None:
        self.feature = feature
        self.message = message or (f"This operation requires OpenWatch+ subscription. " f"Feature required: {feature}")
        super().__init__(self.message)


class LicenseService:
    """
    Service for license validation and management.

    This service validates licenses and checks feature availability.
    It supports both online license validation and offline license files.

    Features by Tier:
        Core (Free):
            - compliance_check
            - framework_reporting
            - basic_dashboard

        OpenWatch+ (Licensed):
            - remediation
            - rollback
            - priority_updates
            - advanced_analytics
            - custom_rules
    """

    FEATURES: Dict[str, List[str]] = {
        "core": [
            "compliance_check",
            "framework_reporting",
            "basic_dashboard",
        ],
        "openwatch_plus": [
            "remediation",
            "rollback",
            "priority_updates",
            "advanced_analytics",
            "custom_rules",
        ],
    }

    def __init__(self) -> None:
        """Initialize the license service."""
        self._license_cache: Optional[Dict[str, Any]] = None
        self._cache_expires: Optional[datetime] = None

    async def has_feature(self, feature: str) -> bool:
        """
        Check if the current license includes a specific feature.

        Args:
            feature: The feature name to check.

        Returns:
            True if the feature is available, False otherwise.
        """
        # Core features are always available
        if feature in self.FEATURES["core"]:
            return True

        # Check for OpenWatch+ license
        license_info = await self._get_active_license()

        if license_info is None:
            # No license = free tier (core features only)
            logger.debug("No active license, feature '%s' not available", feature)
            return False

        # Check if license tier includes the feature
        tier = license_info.get("tier", "core")
        if tier == "openwatch_plus":
            # OpenWatch+ has all features
            return True

        # Check specific tier features
        tier_features = self.FEATURES.get(tier, [])
        return feature in tier_features

    async def get_license_info(self) -> Dict[str, Any]:
        """
        Get current license information.

        Returns:
            Dict with license details (tier, expiry, features, etc.)
        """
        license_info = await self._get_active_license()

        if license_info is None:
            return {
                "tier": "core",
                "licensed": False,
                "features": self.FEATURES["core"],
                "expires_at": None,
            }

        return {
            "tier": license_info.get("tier", "core"),
            "licensed": True,
            "organization": license_info.get("organization"),
            "expires_at": license_info.get("expires_at"),
            "features": self._get_tier_features(license_info.get("tier", "core")),
        }

    async def validate_license_key(self, key: str) -> Dict[str, Any]:
        """
        Validate a license key.

        Args:
            key: The license key to validate.

        Returns:
            Validation result with license details if valid.

        Note:
            This is a placeholder for future license validation against
            the Hanalyx license server.
        """
        # TODO: Implement license key validation
        # This would call the Hanalyx license server to validate the key
        # and return the license details

        logger.info("License key validation requested (not implemented)")

        return {
            "valid": False,
            "error": "License validation not yet implemented",
            "message": "Contact support@hanalyx.com for license information",
        }

    async def _get_active_license(self) -> Optional[Dict[str, Any]]:
        """
        Get the active license for the current organization.

        Returns:
            License details dict if active, None if no active license.

        Note:
            This is a placeholder. In production, this would:
            1. Check the cached license
            2. Query the database for license record
            3. Validate license hasn't expired
            4. Return license details
        """
        # Check cache first
        if self._license_cache and self._cache_expires:
            if datetime.now(timezone.utc) < self._cache_expires:
                return self._license_cache

        # TODO: Query database for license
        # async with get_session() as session:
        #     result = await session.execute(
        #         select(License)
        #         .where(License.organization_id == get_current_org_id())
        #         .where(License.expires_at > datetime.utcnow())
        #         .where(License.status == "active")
        #     )
        #     return result.scalar_one_or_none()

        # For now, return None (free tier)
        return None

    def _get_tier_features(self, tier: str) -> List[str]:
        """Get all features available for a license tier."""
        features = list(self.FEATURES.get("core", []))

        if tier == "openwatch_plus":
            features.extend(self.FEATURES.get("openwatch_plus", []))

        return features


def requires_license(feature: str = "remediation") -> Callable[[F], F]:
    """
    Decorator to enforce license check for specific features.

    This decorator wraps async methods to check for the required license
    before execution. If the license check fails, LicenseRequiredError
    is raised.

    Args:
        feature: The feature name that requires licensing.

    Returns:
        Decorated function that checks license before execution.

    Example:
        class AegisPlugin(ORSAPlugin):
            async def check(self, host_id: str) -> List[CheckResult]:
                # Checks are always free - no license check
                return await self._execute_checks(host_id)

            @requires_license("remediation")
            async def remediate(
                self, host_id: str, rule_ids: List[str], dry_run: bool = True
            ) -> List[RemediationResult]:
                # Remediation requires license
                return await self._execute_remediation(host_id, rule_ids, dry_run)

            @requires_license("remediation")
            async def rollback(self, host_id: str, job_id: str) -> RollbackResult:
                # Rollback requires license
                return await self._execute_rollback(host_id, job_id)

    Raises:
        LicenseRequiredError: If the required license is not active.
    """

    def decorator(func: F) -> F:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            license_service = LicenseService()

            if not await license_service.has_feature(feature):
                logger.warning(
                    "License check failed for feature '%s' in %s",
                    feature,
                    func.__name__,
                )
                raise LicenseRequiredError(feature)

            return await func(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator


__all__ = [
    "LicenseService",
    "LicenseRequiredError",
    "requires_license",
]
