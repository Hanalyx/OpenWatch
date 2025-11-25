"""
Plugin Registry Service
Manages plugin lifecycle, dependencies, and storage operations
"""

import json
import logging
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import get_settings
from ..models.plugin_models import InstalledPlugin, PluginStatus, PluginTrustLevel, PluginType

logger = logging.getLogger(__name__)
settings = get_settings()


class PluginRegistryService:
    """Centralized plugin registry and lifecycle management"""

    def __init__(self):
        self.plugin_storage_path = Path("/app/data/plugins")
        self.plugin_storage_path.mkdir(parents=True, exist_ok=True)
        self._plugin_cache = {}
        self._dependency_graph = {}

    async def register_plugin(self, plugin: InstalledPlugin) -> Dict[str, Any]:
        """
        Register a new plugin in the system

        Args:
            plugin: Installed plugin to register

        Returns:
            Registration result with status
        """
        try:
            # Validate plugin before registration
            validation_result = await self._validate_plugin_registration(plugin)
            if not validation_result["valid"]:
                return {
                    "success": False,
                    "error": validation_result["error"],
                    "plugin_id": plugin.plugin_id,
                }

            # Store plugin files to filesystem
            await self._store_plugin_files(plugin)

            # Update dependency graph
            await self._update_dependency_graph(plugin)

            # Cache plugin for quick access
            self._plugin_cache[plugin.plugin_id] = plugin

            logger.info(f"Plugin registered: {plugin.plugin_id}")

            return {
                "success": True,
                "plugin_id": plugin.plugin_id,
                "message": "Plugin registered successfully",
            }

        except Exception as e:
            logger.error(f"Plugin registration failed: {e}")
            return {"success": False, "error": str(e), "plugin_id": plugin.plugin_id}

    async def unregister_plugin(
        self, plugin_id: str, cleanup_files: bool = True, force: bool = False
    ) -> Dict[str, Any]:
        """
        Unregister a plugin from the system

        Args:
            plugin_id: Plugin ID to unregister
            cleanup_files: Whether to remove plugin files
            force: Force removal even if plugin has dependencies

        Returns:
            Unregistration result
        """
        try:
            plugin = await self.get_plugin(plugin_id)
            if not plugin:
                return {
                    "success": False,
                    "error": "Plugin not found",
                    "plugin_id": plugin_id,
                }

            # Check for dependencies
            dependents = await self._get_plugin_dependents(plugin_id)
            if dependents and not force:
                return {
                    "success": False,
                    "error": "Plugin has dependents",
                    "dependents": dependents,
                    "suggestion": "Use force=true to remove anyway",
                }

            # Remove from dependency graph
            await self._remove_from_dependency_graph(plugin_id)

            # Cleanup files if requested
            if cleanup_files:
                await self._cleanup_plugin_files(plugin_id)

            # Remove from cache
            self._plugin_cache.pop(plugin_id, None)

            # Delete from database
            await plugin.delete()

            logger.info(f"Plugin unregistered: {plugin_id}")

            return {
                "success": True,
                "plugin_id": plugin_id,
                "message": "Plugin unregistered successfully",
            }

        except Exception as e:
            logger.error(f"Plugin unregistration failed: {e}")
            return {"success": False, "error": str(e), "plugin_id": plugin_id}

    async def get_plugin(self, plugin_id: str) -> Optional[InstalledPlugin]:
        """Get plugin by ID with caching"""
        # Check cache first
        if plugin_id in self._plugin_cache:
            return self._plugin_cache[plugin_id]

        # Query database
        plugin = await InstalledPlugin.find_one(InstalledPlugin.plugin_id == plugin_id)

        if plugin:
            self._plugin_cache[plugin_id] = plugin

        return plugin

    async def find_plugins(
        self,
        filters: Optional[Dict[str, Any]] = None,
        sort_by: str = "imported_at",
        limit: Optional[int] = None,
    ) -> List[InstalledPlugin]:
        """
        Find plugins with filtering and sorting

        Args:
            filters: Search filters (status, trust_level, platform, etc.)
            sort_by: Sort field
            limit: Maximum number of results

        Returns:
            List of matching plugins
        """
        query = {}

        if filters:
            # Status filter
            if "status" in filters:
                query["status"] = filters["status"]

            # Trust level filter
            if "trust_level" in filters:
                query["trust_level"] = filters["trust_level"]

            # Platform filter
            if "platform" in filters:
                query["enabled_platforms"] = {"$in": [filters["platform"]]}

            # Type filter
            if "type" in filters:
                query["manifest.type"] = filters["type"]

            # Capability filter
            if "capability" in filters:
                query["manifest.capabilities"] = {"$in": [filters["capability"]]}

            # Search in name/description
            if "search" in filters:
                search_term = filters["search"]
                query["$or"] = [
                    {"manifest.name": {"$regex": search_term, "$options": "i"}},
                    {"manifest.description": {"$regex": search_term, "$options": "i"}},
                    {"manifest.author": {"$regex": search_term, "$options": "i"}},
                ]

        # Build query
        cursor = InstalledPlugin.find(query)

        # Apply sorting
        if sort_by == "name":
            cursor = cursor.sort("manifest.name")
        elif sort_by == "version":
            cursor = cursor.sort("manifest.version")
        elif sort_by == "imported_at":
            cursor = cursor.sort(-InstalledPlugin.imported_at)  # Descending
        elif sort_by == "usage":
            cursor = cursor.sort(-InstalledPlugin.usage_count)

        # Apply limit
        if limit:
            cursor = cursor.limit(limit)

        return await cursor.to_list()

    async def get_plugins_for_rule(
        self,
        rule_id: str,
        platform: Optional[str] = None,
        capability_filter: Optional[List[str]] = None,
    ) -> List[InstalledPlugin]:
        """
        Get plugins applicable to a specific rule

        Args:
            rule_id: Rule ID to find plugins for
            platform: Target platform to filter by
            capability_filter: Required capabilities

        Returns:
            List of applicable plugins
        """
        query_filters = {"status": PluginStatus.ACTIVE}

        if platform:
            query_filters["platform"] = platform

        if capability_filter:
            query_filters["capability"] = {"$in": capability_filter}

        plugins = await self.find_plugins(query_filters)

        # Filter by rule association or compatibility
        applicable_plugins = []
        for plugin in plugins:
            # Check if plugin is explicitly associated with rule
            if rule_id in plugin.applied_to_rules:
                applicable_plugins.append(plugin)
                continue

            # Check if plugin can be applied to rule based on type/capabilities
            # This would involve checking rule metadata and plugin capabilities
            # For now, include all active plugins
            applicable_plugins.append(plugin)

        return applicable_plugins

    async def update_plugin_status(
        self, plugin_id: str, new_status: PluginStatus, reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """Update plugin status with logging"""
        try:
            plugin = await self.get_plugin(plugin_id)
            if not plugin:
                return {"success": False, "error": "Plugin not found"}

            old_status = plugin.status
            plugin.status = new_status
            plugin.updated_at = datetime.utcnow()

            await plugin.save()

            # Update cache
            self._plugin_cache[plugin_id] = plugin

            logger.info(
                f"Plugin status updated: {plugin_id} {old_status.value} -> {new_status.value}",
                extra={"reason": reason},
            )

            return {
                "success": True,
                "plugin_id": plugin_id,
                "old_status": old_status.value,
                "new_status": new_status.value,
            }

        except Exception as e:
            logger.error(f"Plugin status update failed: {e}")
            return {"success": False, "error": str(e)}

    async def get_plugin_statistics(self) -> Dict[str, Any]:
        """Get comprehensive plugin statistics"""
        try:
            # Count by status
            status_counts = {}
            # PluginStatus is an Enum (str, Enum) which is iterable
            for status in list(PluginStatus):
                count = await InstalledPlugin.find(InstalledPlugin.status == status).count()
                status_counts[status.value] = count

            # Count by trust level
            trust_counts = {}
            for trust_level in PluginTrustLevel:
                count = await InstalledPlugin.find(InstalledPlugin.trust_level == trust_level).count()
                trust_counts[trust_level.value] = count

            # Count by type
            type_counts = {}
            for plugin_type in PluginType:
                count = await InstalledPlugin.find(InstalledPlugin.manifest.type == plugin_type).count()
                type_counts[plugin_type.value] = count

            # Usage statistics
            total_usage = 0
            most_used_plugins = []

            async for plugin in InstalledPlugin.find().sort(-InstalledPlugin.usage_count).limit(10):
                total_usage += plugin.usage_count
                most_used_plugins.append(
                    {
                        "plugin_id": plugin.plugin_id,
                        "name": plugin.manifest.name,
                        "usage_count": plugin.usage_count,
                    }
                )

            # Recent activity
            recent_imports = await InstalledPlugin.find().sort(-InstalledPlugin.imported_at).limit(5).to_list()

            return {
                "total_plugins": await InstalledPlugin.count(),
                "by_status": status_counts,
                "by_trust_level": trust_counts,
                "by_type": type_counts,
                "usage_stats": {
                    "total_executions": total_usage,
                    "most_used": most_used_plugins,
                },
                "recent_activity": [
                    {
                        "plugin_id": p.plugin_id,
                        "name": p.manifest.name,
                        "imported_at": p.imported_at.isoformat(),
                    }
                    for p in recent_imports
                ],
                "storage_info": await self._get_storage_statistics(),
            }

        except Exception as e:
            logger.error(f"Failed to get plugin statistics: {e}")
            return {"error": str(e)}

    async def cleanup_unused_plugins(self, older_than_days: int = 90, dry_run: bool = True) -> Dict[str, Any]:
        """
        Clean up unused plugins

        Args:
            older_than_days: Remove plugins not used in this many days
            dry_run: If True, only report what would be cleaned up

        Returns:
            Cleanup results
        """
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=older_than_days)

            # Find candidates for cleanup
            cleanup_candidates = []

            async for plugin in InstalledPlugin.find():
                should_cleanup = (
                    len(plugin.applied_to_rules) == 0  # Not applied to any rules
                    and plugin.usage_count == 0  # Never used
                    and plugin.imported_at < cutoff_date  # Old enough
                )

                if should_cleanup:
                    cleanup_candidates.append(
                        {
                            "plugin_id": plugin.plugin_id,
                            "name": plugin.manifest.name,
                            "imported_at": plugin.imported_at.isoformat(),
                            "size_mb": await self._get_plugin_storage_size(plugin.plugin_id),
                        }
                    )

            if dry_run:
                return {
                    "dry_run": True,
                    "candidates_found": len(cleanup_candidates),
                    "candidates": cleanup_candidates,
                    "total_size_mb": sum(c["size_mb"] for c in cleanup_candidates),
                }

            # Perform actual cleanup
            cleaned_up = []
            total_size_freed = 0

            for candidate in cleanup_candidates:
                try:
                    result = await self.unregister_plugin(candidate["plugin_id"], cleanup_files=True, force=True)
                    if result["success"]:
                        cleaned_up.append(candidate)
                        total_size_freed += candidate["size_mb"]
                except Exception as e:
                    logger.error(f"Failed to cleanup plugin {candidate['plugin_id']}: {e}")

            return {
                "dry_run": False,
                "candidates_found": len(cleanup_candidates),
                "cleaned_up": len(cleaned_up),
                "plugins_removed": cleaned_up,
                "size_freed_mb": total_size_freed,
            }

        except Exception as e:
            logger.error(f"Plugin cleanup failed: {e}")
            return {"error": str(e)}

    async def _validate_plugin_registration(self, plugin: InstalledPlugin) -> Dict[str, Any]:
        """Validate plugin before registration"""
        # Check for duplicate plugin ID
        existing = await InstalledPlugin.find_one(InstalledPlugin.plugin_id == plugin.plugin_id)
        if existing:
            return {
                "valid": False,
                "error": f"Plugin with ID {plugin.plugin_id} already exists",
            }

        # Check for name/version conflicts
        existing_name_version = await InstalledPlugin.find_one(
            InstalledPlugin.manifest.name == plugin.manifest.name,
            InstalledPlugin.manifest.version == plugin.manifest.version,
        )
        if existing_name_version:
            return {
                "valid": False,
                "error": f"Plugin {plugin.manifest.name}@{plugin.manifest.version} already exists",
            }

        # Validate executors
        if not plugin.executors:
            return {"valid": False, "error": "Plugin has no executors defined"}

        return {"valid": True}

    async def _store_plugin_files(self, plugin: InstalledPlugin):
        """Store plugin files to filesystem"""
        plugin_dir = self.plugin_storage_path / plugin.plugin_id
        plugin_dir.mkdir(parents=True, exist_ok=True, mode=0o755)

        # Store each file
        for file_path, content in plugin.files.items():
            full_path = plugin_dir / file_path
            full_path.parent.mkdir(parents=True, exist_ok=True)

            # Write file with appropriate permissions
            with open(full_path, "w", encoding="utf-8") as f:
                f.write(content)

            # Set restrictive permissions for executable files
            if file_path.endswith((".sh", ".py", ".pl")):
                full_path.chmod(0o755)
            else:
                full_path.chmod(0o644)

        # Store metadata
        metadata = {
            "plugin_id": plugin.plugin_id,
            "manifest": plugin.manifest.dict(),
            "stored_at": datetime.utcnow().isoformat(),
            "file_count": len(plugin.files),
        }

        metadata_file = plugin_dir / ".plugin_metadata.json"
        with open(metadata_file, "w") as f:
            json.dump(metadata, f, indent=2)

        logger.info(f"Stored {len(plugin.files)} files for plugin {plugin.plugin_id}")

    async def _cleanup_plugin_files(self, plugin_id: str):
        """Remove plugin files from filesystem"""
        plugin_dir = self.plugin_storage_path / plugin_id
        if plugin_dir.exists():
            shutil.rmtree(plugin_dir)
            logger.info(f"Cleaned up files for plugin {plugin_id}")

    async def _update_dependency_graph(self, plugin: InstalledPlugin):
        """Update plugin dependency graph"""
        # Extract dependencies from plugin requirements
        dependencies = []
        for requirement in plugin.manifest.requirements.values():
            # Parse requirement string to extract dependency names
            # This is simplified - real implementation would parse version constraints
            if isinstance(requirement, str):
                dependencies.append(requirement.split()[0])

        self._dependency_graph[plugin.plugin_id] = dependencies

    async def _remove_from_dependency_graph(self, plugin_id: str):
        """Remove plugin from dependency graph"""
        self._dependency_graph.pop(plugin_id, None)

    async def _get_plugin_dependents(self, plugin_id: str) -> List[str]:
        """Get plugins that depend on the given plugin"""
        dependents = []
        plugin_name = plugin_id.split("@")[0] if "@" in plugin_id else plugin_id

        for pid, deps in self._dependency_graph.items():
            if plugin_name in deps:
                dependents.append(pid)

        return dependents

    async def _get_storage_statistics(self) -> Dict[str, Any]:
        """Get plugin storage statistics"""
        try:
            total_size = 0
            file_count = 0

            for plugin_dir in self.plugin_storage_path.iterdir():
                if plugin_dir.is_dir():
                    for file_path in plugin_dir.rglob("*"):
                        if file_path.is_file():
                            total_size += file_path.stat().st_size
                            file_count += 1

            return {
                "total_size_mb": round(total_size / (1024 * 1024), 2),
                "total_files": file_count,
                "plugin_directories": len(list(self.plugin_storage_path.iterdir())),
                "storage_path": str(self.plugin_storage_path),
            }
        except Exception as e:
            logger.error(f"Failed to get storage statistics: {e}")
            return {"error": str(e)}

    async def _get_plugin_storage_size(self, plugin_id: str) -> float:
        """Get storage size for specific plugin in MB"""
        try:
            plugin_dir = self.plugin_storage_path / plugin_id
            if not plugin_dir.exists():
                return 0.0

            total_size = 0
            for file_path in plugin_dir.rglob("*"):
                if file_path.is_file():
                    total_size += file_path.stat().st_size

            return round(total_size / (1024 * 1024), 2)
        except Exception:
            return 0.0
