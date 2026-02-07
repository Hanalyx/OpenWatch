"""
Plugin Repository
OW-REFACTOR-002: MongoDB Repository Pattern

Provides plugin-specific query methods for InstalledPlugin collection.
Centralizes all plugin query logic in one place.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..models.plugin_models import InstalledPlugin, PluginStatus, PluginTrustLevel
from .base_repository import BaseRepository

logger = logging.getLogger(__name__)


class InstalledPluginRepository(BaseRepository[InstalledPlugin]):
    """
    Repository for InstalledPlugin operations.

    Provides plugin-specific query methods:
    - Find by plugin_id
    - Find active/inactive plugins
    - Find by status and trust level
    - Plugin activation/deactivation

    Example:
        repo = InstalledPluginRepository()
        active = await repo.find_active()
    """

    def __init__(self) -> None:
        """Initialize the installed plugin repository."""
        super().__init__(InstalledPlugin)

    async def find_by_plugin_id(self, plugin_id: str) -> Optional[InstalledPlugin]:
        """
        Find plugin by unique plugin_id.

        Args:
            plugin_id: Unique plugin identifier (e.g., "aegis-ssh@1.2.0")

        Returns:
            InstalledPlugin if found, None otherwise

        Example:
            plugin = await repo.find_by_plugin_id("aegis-ssh@1.2.0")
        """
        query = {"plugin_id": plugin_id}
        return await self.find_one(query)

    async def find_by_name_and_version(self, name: str, version: str) -> Optional[InstalledPlugin]:
        """
        Find plugin by name and version.

        Args:
            name: Plugin name
            version: Plugin version

        Returns:
            InstalledPlugin if found, None otherwise

        Example:
            plugin = await repo.find_by_name_and_version("aegis-ssh", "1.2.0")
        """
        query = {
            "manifest.name": name,
            "manifest.version": version,
        }
        return await self.find_one(query)

    async def find_active(self) -> List[InstalledPlugin]:
        """
        Find all active plugins.

        Returns:
            List of active InstalledPlugin documents

        Example:
            active = await repo.find_active()
        """
        query = {"status": PluginStatus.ACTIVE.value}
        return await self.find_many(query)

    async def find_by_status(self, status: str) -> List[InstalledPlugin]:
        """
        Find plugins by status.

        Args:
            status: Plugin status (pending_validation, validating, active, disabled, quarantined, deprecated)

        Returns:
            List of InstalledPlugin documents with specified status

        Example:
            pending = await repo.find_by_status("pending_validation")
        """
        query = {"status": status}
        return await self.find_many(query)

    async def find_by_trust_level(self, trust_level: str) -> List[InstalledPlugin]:
        """
        Find plugins by trust level.

        Args:
            trust_level: Trust level (verified, community, internal, untrusted)

        Returns:
            List of InstalledPlugin documents with specified trust level

        Example:
            verified = await repo.find_by_trust_level("verified")
        """
        query = {"trust_level": trust_level}
        return await self.find_many(query)

    async def count_by_status(self, status: str) -> int:
        """
        Count plugins by status.

        Args:
            status: Plugin status to count

        Returns:
            Number of plugins with specified status

        Example:
            active_count = await repo.count_by_status("active")
        """
        query = {"status": status}
        return await self.count(query)

    async def deactivate(self, plugin_id: str) -> bool:
        """
        Deactivate a plugin.

        Args:
            plugin_id: Plugin identifier to deactivate

        Returns:
            True if plugin was deactivated, False if not found

        Example:
            success = await repo.deactivate("aegis-ssh@1.2.0")
        """
        result = await self.update_one(
            {"plugin_id": plugin_id},
            {"$set": {"status": PluginStatus.DISABLED.value, "updated_at": datetime.utcnow()}},
        )
        return result is not None

    async def activate(self, plugin_id: str) -> bool:
        """
        Activate a plugin.

        Args:
            plugin_id: Plugin identifier to activate

        Returns:
            True if plugin was activated, False if not found

        Example:
            success = await repo.activate("aegis-ssh@1.2.0")
        """
        result = await self.update_one(
            {"plugin_id": plugin_id},
            {"$set": {"status": PluginStatus.ACTIVE.value, "updated_at": datetime.utcnow()}},
        )
        return result is not None

    async def quarantine(self, plugin_id: str, reason: str) -> bool:
        """
        Quarantine a plugin due to security concerns.

        Args:
            plugin_id: Plugin identifier to quarantine
            reason: Reason for quarantine

        Returns:
            True if plugin was quarantined, False if not found

        Example:
            success = await repo.quarantine("malicious-plugin@1.0.0", "Failed security scan")
        """
        result = await self.update_one(
            {"plugin_id": plugin_id},
            {
                "$set": {
                    "status": PluginStatus.QUARANTINED.value,
                    "updated_at": datetime.utcnow(),
                },
                "$push": {
                    "security_checks": {
                        "check_name": "quarantine",
                        "passed": False,
                        "severity": "critical",
                        "message": reason,
                        "timestamp": datetime.utcnow(),
                    }
                },
            },
        )
        return result is not None

    async def find_by_platform(self, platform: str) -> List[InstalledPlugin]:
        """
        Find plugins that support a specific platform.

        Args:
            platform: Platform name (rhel, ubuntu, windows, etc.)

        Returns:
            List of InstalledPlugin documents supporting the platform

        Example:
            rhel_plugins = await repo.find_by_platform("rhel")
        """
        query = {"manifest.platforms": platform}
        return await self.find_many(query)

    async def find_by_type(self, plugin_type: str) -> List[InstalledPlugin]:
        """
        Find plugins by type.

        Args:
            plugin_type: Plugin type (remediation, validation, scanner, reporter)

        Returns:
            List of InstalledPlugin documents of specified type

        Example:
            remediation_plugins = await repo.find_by_type("remediation")
        """
        query = {"manifest.type": plugin_type}
        return await self.find_many(query)

    async def update_usage(self, plugin_id: str, rule_id: Optional[str] = None) -> Optional[InstalledPlugin]:
        """
        Update plugin usage statistics.

        Args:
            plugin_id: Plugin identifier
            rule_id: Optional rule ID that used the plugin

        Returns:
            Updated InstalledPlugin if found, None otherwise

        Example:
            updated = await repo.update_usage("aegis-ssh@1.2.0", "ow-ssh-disable-root")
        """
        update: Dict[str, Any] = {
            "$inc": {"usage_count": 1},
            "$set": {"last_used": datetime.utcnow(), "updated_at": datetime.utcnow()},
        }

        if rule_id:
            update["$addToSet"] = {"applied_to_rules": rule_id}

        return await self.update_one({"plugin_id": plugin_id}, update)

    async def find_by_imported_by(self, username: str) -> List[InstalledPlugin]:
        """
        Find plugins imported by a specific user.

        Args:
            username: Username who imported the plugins

        Returns:
            List of InstalledPlugin documents imported by the user

        Example:
            user_plugins = await repo.find_by_imported_by("admin")
        """
        query = {"imported_by": username}
        return await self.find_many(query, sort=[("imported_at", -1)])

    async def find_untrusted_active(self) -> List[InstalledPlugin]:
        """
        Find active plugins with untrusted trust level (security risk).

        Returns:
            List of active but untrusted InstalledPlugin documents

        Example:
            risky = await repo.find_untrusted_active()
        """
        query = {
            "status": PluginStatus.ACTIVE.value,
            "trust_level": PluginTrustLevel.UNTRUSTED.value,
        }
        return await self.find_many(query)

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get plugin statistics.

        Returns:
            Dictionary with statistics:
            - total_plugins: Total plugin count
            - by_status: Count by status
            - by_trust_level: Count by trust level
            - by_type: Count by plugin type
            - by_platform: Count by platform

        Example:
            stats = await repo.get_statistics()
        """
        try:
            total = await self.count()

            # Count by status
            status_pipeline: List[Dict[str, Any]] = [
                {"$group": {"_id": "$status", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
            ]
            status_results = await self.aggregate(status_pipeline)
            status_counts = {item["_id"]: item["count"] for item in status_results}

            # Count by trust level
            trust_pipeline: List[Dict[str, Any]] = [
                {"$group": {"_id": "$trust_level", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
            ]
            trust_results = await self.aggregate(trust_pipeline)
            trust_counts = {item["_id"]: item["count"] for item in trust_results}

            # Count by type
            type_pipeline: List[Dict[str, Any]] = [
                {"$group": {"_id": "$manifest.type", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
            ]
            type_results = await self.aggregate(type_pipeline)
            type_counts = {item["_id"]: item["count"] for item in type_results}

            # Count by platform
            platform_pipeline: List[Dict[str, Any]] = [
                {"$unwind": "$manifest.platforms"},
                {"$group": {"_id": "$manifest.platforms", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
            ]
            platform_results = await self.aggregate(platform_pipeline)
            platform_counts = {item["_id"]: item["count"] for item in platform_results}

            return {
                "total_plugins": total,
                "by_status": status_counts,
                "by_trust_level": trust_counts,
                "by_type": type_counts,
                "by_platform": platform_counts,
            }

        except Exception as e:
            logger.error(f"Error getting plugin statistics: {e}")
            raise
