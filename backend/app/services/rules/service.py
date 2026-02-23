"""
Enhanced Rule Service

Provides advanced rule management with inheritance, platform detection,
and dependency resolution for compliance scanning operations.

Features:
    - Platform-based rule filtering with version support
    - Rule inheritance resolution
    - Dependency graph building
    - Capability-based rule applicability
    - Full-text search across rules
    - Comprehensive rule statistics

Example:
    >>> from app.services.rules import RuleService, QueryPriority
    >>>
    >>> service = RuleService()
    >>> await service.initialize()
    >>> rules = await service.get_rules_by_platform(
    ...     "rhel", "8", framework="nist"
    ... )
"""

import logging
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from app.services.platform_capability_service import PlatformCapabilityService
from app.services.rules.cache import RuleCacheService

logger = logging.getLogger(__name__)


class QueryPriority(Enum):
    """Query priority levels for performance optimization."""

    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


class ParameterResolution(Enum):
    """Parameter conflict resolution strategies."""

    MOST_RESTRICTIVE = "most_restrictive"
    FRAMEWORK_SPECIFIC = "framework_specific"
    PLATFORM_DEFAULT = "platform_default"
    EXPLICIT_OVERRIDE = "explicit_override"


class RuleService:
    """
    Enhanced Rule Service with advanced query capabilities.

    Provides comprehensive rule management including:
        - Platform-based filtering
        - Inheritance resolution
        - Dependency management
        - Capability detection
        - Full-text search
    """

    def __init__(self, cache_service: Optional[RuleCacheService] = None):
        """
        Initialize the rule service.

        Args:
            cache_service: Optional cache service instance
        """
        self.cache_service = cache_service or RuleCacheService()
        self.platform_service = PlatformCapabilityService()
        self.query_stats = {
            "total_queries": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "avg_response_time": 0.0,
        }

    async def initialize(self):
        """Initialize the rule service and dependencies."""
        await self.cache_service.initialize()
        await self.platform_service.initialize()
        logger.info("RuleService initialized successfully")

    async def get_rules_by_platform(
        self,
        platform: str,
        platform_version: Optional[str] = None,
        framework: Optional[str] = None,
        framework_version: Optional[str] = None,
        severity_filter: Optional[List[str]] = None,
        category_filter: Optional[List[str]] = None,
        priority: QueryPriority = QueryPriority.NORMAL,
    ) -> List[Dict[str, Any]]:
        """
        Get rules filtered by platform with comprehensive filtering.

        Args:
            platform: Target platform (rhel, ubuntu, windows, etc.)
            platform_version: Specific platform version
            framework: Compliance framework (nist, cis, stig, etc.)
            framework_version: Specific framework version
            severity_filter: List of severities to include
            category_filter: List of categories to include
            priority: Query priority for caching strategy

        Returns:
            List of rule dictionaries
        """
        start_time = datetime.utcnow()

        try:
            # Build cache key
            cache_key = self._build_cache_key(
                "platform_rules",
                platform=platform,
                version=platform_version,
                framework=framework,
                fw_version=framework_version,
                severities=severity_filter,
                categories=category_filter,
            )

            # Try cache first (unless critical priority)
            if priority != QueryPriority.CRITICAL:
                cached_result = await self.cache_service.get(cache_key)
                if cached_result:
                    self._update_query_stats(start_time, cache_hit=True)
                    return cached_result

            # MongoDB rule storage has been removed. Use Kensa Rule Reference
            # service for rule queries instead.
            logger.warning(
                "RuleService.get_rules_by_platform: MongoDB removed. " "Use Kensa Rule Reference service instead."
            )

            self._update_query_stats(start_time, cache_hit=False)
            return []

        except Exception as e:
            logger.error(f"Failed to retrieve rules for platform {platform}: {str(e)}")
            raise

    async def get_rule_with_dependencies(
        self,
        rule_id: str,
        resolve_depth: int = 3,
        include_conflicts: bool = True,
    ) -> Dict[str, Any]:
        """
        Get a rule with its complete dependency chain.

        Args:
            rule_id: Target rule identifier
            resolve_depth: Maximum dependency resolution depth
            include_conflicts: Whether to include conflicting rules

        Returns:
            Dictionary with rule and dependencies
        """
        cache_key = f"rule_deps:{rule_id}:{resolve_depth}:{include_conflicts}"

        # Check cache
        cached = await self.cache_service.get(cache_key)
        if cached:
            return cached

        # MongoDB rule storage has been removed. Use Kensa Rule Reference
        # service for rule queries instead.
        raise NotImplementedError(
            "Rule dependency resolution requires MongoDB (removed). " "Use Kensa Rule Reference service instead."
        )

    async def detect_platform_capabilities(
        self,
        platform: str,
        platform_version: str,
        target_host: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Detect platform capabilities for rule applicability.

        Args:
            platform: Platform name (rhel, ubuntu, etc.)
            platform_version: Platform version
            target_host: Optional target host for remote capability detection

        Returns:
            Dictionary of detected capabilities
        """
        return await self.platform_service.detect_capabilities(platform, platform_version, target_host)

    async def get_applicable_rules(
        self,
        platform: str,
        platform_version: str,
        detected_capabilities: Dict[str, Any],
        framework: Optional[str] = None,
        minimum_severity: str = "low",
    ) -> List[Dict[str, Any]]:
        """
        Get rules applicable to specific platform capabilities.

        Args:
            platform: Target platform
            platform_version: Platform version
            detected_capabilities: Capabilities detected on target system
            framework: Compliance framework filter
            minimum_severity: Minimum rule severity

        Returns:
            List of applicable rules
        """
        # Get all potential rules
        severity_levels = ["info", "low", "medium", "high", "critical"]
        severity_filter = severity_levels[severity_levels.index(minimum_severity) :]

        candidate_rules = await self.get_rules_by_platform(
            platform=platform,
            platform_version=platform_version,
            framework=framework,
            severity_filter=severity_filter,
        )

        # Filter by capabilities
        applicable_rules = []
        for rule in candidate_rules:
            if await self._is_rule_applicable(rule, detected_capabilities):
                applicable_rules.append(rule)

        return applicable_rules

    async def search_rules(
        self,
        search_query: str,
        platform_filter: Optional[str] = None,
        framework_filter: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """
        Full-text search across rules with advanced filtering.

        Args:
            search_query: Text to search for
            platform_filter: Platform to filter by
            framework_filter: Framework to filter by
            limit: Maximum results to return
            offset: Results offset for pagination

        Returns:
            Search results with pagination metadata
        """
        # MongoDB rule storage has been removed. Use Kensa Rule Reference
        # service (/api/rules/reference) for rule search instead.
        logger.warning("RuleService.search_rules: MongoDB removed. Use Kensa Rule Reference API.")
        return {
            "results": [],
            "total_count": 0,
            "offset": offset,
            "limit": limit,
            "has_next": False,
            "has_prev": False,
        }

    async def get_rule_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive rule statistics.

        Returns:
            Statistics dictionary with counts and distributions
        """
        # MongoDB rule storage has been removed. Use Kensa Rule Reference
        # service (/api/rules/reference/stats) for rule statistics instead.
        logger.warning("RuleService.get_rule_statistics: MongoDB removed. Use Kensa Rule Reference API.")
        return {
            "totals": {
                "rules": 0,
                "intelligence_records": 0,
                "remediation_scripts": 0,
            },
            "severity_distribution": {},
            "platform_coverage": {},
            "framework_coverage": {},
            "query_performance": self.query_stats,
            "last_updated": datetime.utcnow().isoformat(),
        }

    # Private helper methods

    def _build_cache_key(self, prefix: str, **kwargs) -> str:
        """Build cache key from parameters."""
        key_parts = [prefix]
        for k, v in sorted(kwargs.items()):
            if v is not None:
                if isinstance(v, list):
                    v = ",".join(sorted(v))
                key_parts.append(f"{k}:{v}")
        return ":".join(key_parts)

    async def _apply_parameter_overrides(
        self,
        rule_data: Dict[str, Any],
        platform: str,
        platform_version: Optional[str],
        framework: Optional[str],
        framework_version: Optional[str],
    ) -> Dict[str, Any]:
        """Apply parameter overrides based on context."""
        if not rule_data.get("parameter_overrides"):
            return rule_data

        # Build context key
        context_keys = []
        if platform and platform_version:
            context_keys.append(f"{platform}:{platform_version}")
        if platform:
            context_keys.append(platform)
        if framework and framework_version:
            context_keys.append(f"{framework}:{framework_version}")
        if framework:
            context_keys.append(framework)

        # Apply overrides in order of specificity (most specific last)
        overrides = rule_data.get("parameter_overrides", {})
        for context_key in reversed(context_keys):  # Apply in reverse order
            if context_key in overrides:
                rule_data = self._apply_override_values(rule_data, overrides[context_key])

        return rule_data

    def _apply_override_values(self, rule_data: Dict[str, Any], overrides: Dict[str, Any]) -> Dict[str, Any]:
        """Apply specific override values to rule data."""
        result = rule_data.copy()

        for key, value in overrides.items():
            if "." in key:
                # Nested key (e.g., "check_content.expected_value")
                self._set_nested_value(result, key, value)
            else:
                # Direct key
                result[key] = value

        return result

    def _set_nested_value(self, data: Dict[str, Any], key_path: str, value: Any):
        """Set nested dictionary value using dot notation."""
        keys = key_path.split(".")
        current = data

        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]

        current[keys[-1]] = value

    async def _is_rule_applicable(self, rule: Dict[str, Any], capabilities: Dict[str, Any]) -> bool:
        """Check if rule is applicable to detected capabilities."""
        rule_requirements = rule.get("platform_requirements", {})

        # Check required capabilities
        required = rule_requirements.get("required", {})
        for capability, expected in required.items():
            if capability not in capabilities:
                return False

            actual = capabilities[capability]
            if not self._capability_matches(actual, expected):
                return False

        # Check optional capabilities don't conflict
        optional = rule_requirements.get("optional", {})
        for capability, expected in optional.items():
            if capability in capabilities:
                actual = capabilities[capability]
                if not self._capability_matches(actual, expected):
                    return False

        return True

    def _capability_matches(self, actual: Any, expected: Any) -> bool:
        """Check if actual capability matches expected."""
        if isinstance(expected, dict):
            if "min_version" in expected:
                return self._version_compare(actual, expected["min_version"]) >= 0
            if "max_version" in expected:
                return self._version_compare(actual, expected["max_version"]) <= 0
            if "exact_version" in expected:
                return actual == expected["exact_version"]

        return actual == expected

    def _version_compare(self, version1: str, version2: str) -> int:
        """Compare version strings (simplified)."""
        try:
            v1_parts = [int(x) for x in version1.split(".")]
            v2_parts = [int(x) for x in version2.split(".")]

            # Pad shorter version with zeros
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))

            for v1, v2 in zip(v1_parts, v2_parts):
                if v1 < v2:
                    return -1
                elif v1 > v2:
                    return 1

            return 0
        except Exception:
            # Fall back to string comparison
            return -1 if version1 < version2 else (1 if version1 > version2 else 0)

    def _get_cache_ttl(self, priority: QueryPriority) -> int:
        """Get cache TTL based on query priority."""
        ttl_map = {
            QueryPriority.LOW: 3600,  # 1 hour
            QueryPriority.NORMAL: 1800,  # 30 minutes
            QueryPriority.HIGH: 600,  # 10 minutes
            QueryPriority.CRITICAL: 0,  # No cache
        }
        return ttl_map[priority]

    def _update_query_stats(self, start_time: datetime, cache_hit: bool):
        """Update query performance statistics."""
        duration = (datetime.utcnow() - start_time).total_seconds() * 1000  # ms

        self.query_stats["total_queries"] += 1
        if cache_hit:
            self.query_stats["cache_hits"] += 1
        else:
            self.query_stats["cache_misses"] += 1

        # Update rolling average response time
        total = self.query_stats["total_queries"]
        current_avg = self.query_stats["avg_response_time"]
        self.query_stats["avg_response_time"] = ((current_avg * (total - 1)) + duration) / total
