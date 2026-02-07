"""
Remediation Script Repository
OW-REFACTOR-002: MongoDB Repository Pattern

Provides remediation script-specific query methods for RemediationScript collection.
Centralizes all remediation script query logic in one place.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..models.mongo_models import RemediationScript
from .base_repository import BaseRepository

logger = logging.getLogger(__name__)


class RemediationScriptRepository(BaseRepository[RemediationScript]):
    """
    Repository for RemediationScript operations.

    Provides remediation-specific query methods:
    - Find by rule_id
    - Find by platform
    - Find approved scripts
    - Create and update scripts

    Example:
        repo = RemediationScriptRepository()
        scripts = await repo.find_by_rule_id("ow-ssh-disable-root")
    """

    def __init__(self) -> None:
        """Initialize the remediation script repository."""
        super().__init__(RemediationScript)

    async def find_by_rule_id(self, rule_id: str, platform: Optional[str] = None) -> List[RemediationScript]:
        """
        Find scripts by rule_id and optional platform.

        Args:
            rule_id: Rule identifier
            platform: Optional platform filter (rhel, ubuntu, windows, etc.)

        Returns:
            List of RemediationScript documents

        Example:
            # All scripts for a rule
            scripts = await repo.find_by_rule_id("ow-ssh-disable-root")

            # Scripts for specific platform
            scripts = await repo.find_by_rule_id("ow-ssh-disable-root", platform="rhel")
        """
        query: Dict[str, Any] = {"rule_id": rule_id}
        if platform:
            query["platform"] = platform
        return await self.find_many(query)

    async def find_by_platform(self, platform: str) -> List[RemediationScript]:
        """
        Find all scripts for a platform.

        Args:
            platform: Platform identifier (rhel, ubuntu, windows, etc.)

        Returns:
            List of RemediationScript documents for the platform

        Example:
            rhel_scripts = await repo.find_by_platform("rhel")
        """
        query = {"platform": platform}
        return await self.find_many(query)

    async def find_by_script_type(self, script_type: str) -> List[RemediationScript]:
        """
        Find scripts by script type.

        Args:
            script_type: Script type (bash, python, ansible, powershell, puppet)

        Returns:
            List of RemediationScript documents of specified type

        Example:
            ansible_scripts = await repo.find_by_script_type("ansible")
        """
        query = {"script_type": script_type}
        return await self.find_many(query)

    async def find_approved(self, platform: Optional[str] = None) -> List[RemediationScript]:
        """
        Find all approved scripts.

        Args:
            platform: Optional platform filter

        Returns:
            List of approved RemediationScript documents

        Example:
            approved = await repo.find_approved()
            approved_rhel = await repo.find_approved(platform="rhel")
        """
        query: Dict[str, Any] = {"approved": True}
        if platform:
            query["platform"] = platform
        return await self.find_many(query)

    async def find_pending_approval(self) -> List[RemediationScript]:
        """
        Find scripts pending approval.

        Returns:
            List of unapproved RemediationScript documents

        Example:
            pending = await repo.find_pending_approval()
        """
        query = {"approved": False}
        return await self.find_many(query, sort=[("rule_id", 1)])

    async def find_for_rule_and_platform(self, rule_id: str, platform: str) -> Optional[RemediationScript]:
        """
        Find single script for rule and platform combination.

        Args:
            rule_id: Rule identifier
            platform: Platform identifier

        Returns:
            RemediationScript if found, None otherwise

        Example:
            script = await repo.find_for_rule_and_platform(
                "ow-ssh-disable-root", "rhel"
            )
        """
        query = {"rule_id": rule_id, "platform": platform}
        return await self.find_one(query)

    async def approve_script(self, rule_id: str, platform: str) -> Optional[RemediationScript]:
        """
        Approve a remediation script.

        Args:
            rule_id: Rule identifier
            platform: Platform identifier

        Returns:
            Updated RemediationScript if found, None otherwise

        Example:
            approved = await repo.approve_script("ow-ssh-disable-root", "rhel")
        """
        query = {"rule_id": rule_id, "platform": platform}
        update = {
            "$set": {
                "approved": True,
                "approval_date": datetime.utcnow(),
            }
        }
        return await self.update_one(query, update)

    async def upsert_script(
        self,
        rule_id: str,
        platform: str,
        script_type: str,
        script_content: str,
        **kwargs: Any,
    ) -> RemediationScript:
        """
        Upsert a remediation script.

        Creates new script if not exists, updates if exists.

        Args:
            rule_id: Rule identifier
            platform: Platform identifier
            script_type: Script type (bash, ansible, etc.)
            script_content: Script content
            **kwargs: Additional script fields

        Returns:
            Created or updated RemediationScript

        Example:
            script = await repo.upsert_script(
                rule_id="ow-ssh-disable-root",
                platform="rhel",
                script_type="bash",
                script_content="#!/bin/bash\\necho 'PermitRootLogin no' >> /etc/ssh/sshd_config",
                estimated_duration_seconds=30,
            )
        """
        existing = await self.find_for_rule_and_platform(rule_id, platform)

        if existing:
            # Update existing
            update_data = {
                "script_type": script_type,
                "script_content": script_content,
                **kwargs,
            }
            await self.update_one(
                {"rule_id": rule_id, "platform": platform},
                {"$set": update_data},
            )
            updated = await self.find_for_rule_and_platform(rule_id, platform)
            if updated:
                return updated
            raise ValueError(f"Failed to fetch updated script for {rule_id}/{platform}")
        else:
            # Create new
            script_data = {
                "rule_id": rule_id,
                "platform": platform,
                "script_type": script_type,
                "script_content": script_content,
                **kwargs,
            }
            # Set defaults for required fields
            if "estimated_duration_seconds" not in script_data:
                script_data["estimated_duration_seconds"] = 60
            script = RemediationScript(**script_data)
            return await self.create(script)

    async def find_tested_on_version(self, platform: str, version: str) -> List[RemediationScript]:
        """
        Find scripts tested on a specific platform version.

        Args:
            platform: Platform identifier
            version: Version string to search in tested_on array

        Returns:
            List of RemediationScript documents tested on the version

        Example:
            scripts = await repo.find_tested_on_version("rhel", "8.9")
        """
        query = {
            "platform": platform,
            "tested_on": {"$regex": version, "$options": "i"},
        }
        return await self.find_many(query)

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get remediation script statistics.

        Returns:
            Dictionary with statistics:
            - total_scripts: Total script count
            - approved: Count of approved scripts
            - pending: Count of pending scripts
            - by_platform: Script count by platform
            - by_script_type: Script count by type

        Example:
            stats = await repo.get_statistics()
        """
        try:
            total = await self.count()
            approved = await self.count({"approved": True})
            pending = await self.count({"approved": False})

            # Count by platform
            platform_pipeline: List[Dict[str, Any]] = [
                {"$group": {"_id": "$platform", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
            ]
            platform_results = await self.aggregate(platform_pipeline)
            platform_counts = {item["_id"]: item["count"] for item in platform_results}

            # Count by script type
            type_pipeline: List[Dict[str, Any]] = [
                {"$group": {"_id": "$script_type", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
            ]
            type_results = await self.aggregate(type_pipeline)
            type_counts = {item["_id"]: item["count"] for item in type_results}

            return {
                "total_scripts": total,
                "approved": approved,
                "pending": pending,
                "by_platform": platform_counts,
                "by_script_type": type_counts,
            }

        except Exception as e:
            logger.error(f"Error getting remediation script statistics: {e}")
            raise
