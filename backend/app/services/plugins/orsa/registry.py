"""
ORSA Plugin Registry

Singleton registry for managing ORSA-compliant plugins at runtime.

The registry provides:
- Plugin registration and unregistration
- Plugin lookup by ID or capability
- Lifecycle management for registered plugins
- Thread-safe singleton access

Usage:
    from app.services.plugins.orsa import ORSAPluginRegistry, Capability

    # Get registry instance (singleton)
    registry = ORSAPluginRegistry.instance()

    # Register a plugin
    await registry.register(kensa_plugin)

    # Get plugin by ID
    plugin = await registry.get("kensa")

    # Get plugins with specific capability
    scanners = await registry.get_by_capability(Capability.COMPLIANCE_CHECK)

    # List all registered plugins
    plugins = await registry.list_all()
"""

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .interface import Capability, ORSAPlugin, PluginInfo

logger = logging.getLogger(__name__)


class PluginAlreadyRegisteredError(Exception):
    """Raised when attempting to register a plugin that is already registered."""

    def __init__(self, plugin_id: str) -> None:
        self.plugin_id = plugin_id
        super().__init__(f"Plugin already registered: {plugin_id}")


class PluginNotRegisteredError(Exception):
    """Raised when attempting to access a plugin that is not registered."""

    def __init__(self, plugin_id: str) -> None:
        self.plugin_id = plugin_id
        super().__init__(f"Plugin not registered: {plugin_id}")


class ORSAPluginRegistry:
    """
    Singleton registry for ORSA-compliant plugins.

    This registry manages in-memory ORSA plugins for quick access during
    scan execution. It is separate from the MongoDB-backed PluginRegistryService
    which manages installed plugin files.

    Thread Safety:
        The singleton pattern uses a class-level instance variable.
        The registry operations are not thread-safe by default.
        For concurrent access, external synchronization is required.

    Example:
        # In application startup
        async def initialize_plugins():
            registry = ORSAPluginRegistry.instance()

            # Register built-in Kensa plugin
            from app.plugins.kensa import KensaORSAPlugin
            kensa = KensaORSAPlugin()
            await registry.register(kensa)

        # In scan execution
        async def execute_scan(host_id: str, plugin_id: str = "kensa"):
            registry = ORSAPluginRegistry.instance()
            plugin = await registry.get(plugin_id)
            if not plugin:
                raise PluginNotRegisteredError(plugin_id)

            results = await plugin.check(host_id)
            return results
    """

    _instance: Optional["ORSAPluginRegistry"] = None
    _plugins: Dict[str, ORSAPlugin]
    _plugin_info_cache: Dict[str, PluginInfo]
    _initialized_at: Optional[datetime]

    def __new__(cls) -> "ORSAPluginRegistry":
        """Create singleton instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._plugins = {}
            cls._instance._plugin_info_cache = {}
            cls._instance._initialized_at = datetime.now(timezone.utc)
        return cls._instance

    @classmethod
    def instance(cls) -> "ORSAPluginRegistry":
        """
        Get the singleton registry instance.

        Returns:
            The global ORSAPluginRegistry instance.
        """
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """
        Reset the singleton instance.

        Used primarily for testing to ensure a clean state.
        """
        cls._instance = None

    async def register(self, plugin: ORSAPlugin) -> PluginInfo:
        """
        Register an ORSA plugin.

        Args:
            plugin: The ORSAPlugin instance to register.

        Returns:
            PluginInfo for the registered plugin.

        Raises:
            PluginAlreadyRegisteredError: If a plugin with the same ID is
                already registered.
        """
        info = await plugin.get_info()

        if info.plugin_id in self._plugins:
            raise PluginAlreadyRegisteredError(info.plugin_id)

        self._plugins[info.plugin_id] = plugin
        self._plugin_info_cache[info.plugin_id] = info

        logger.info(
            "ORSA plugin registered: %s v%s (%d capabilities)",
            info.name,
            info.version,
            len(info.capabilities),
        )

        return info

    async def unregister(self, plugin_id: str) -> None:
        """
        Unregister an ORSA plugin.

        Args:
            plugin_id: The ID of the plugin to unregister.

        Raises:
            PluginNotRegisteredError: If the plugin is not registered.
        """
        if plugin_id not in self._plugins:
            raise PluginNotRegisteredError(plugin_id)

        del self._plugins[plugin_id]
        self._plugin_info_cache.pop(plugin_id, None)

        logger.info("ORSA plugin unregistered: %s", plugin_id)

    async def get(self, plugin_id: str) -> Optional[ORSAPlugin]:
        """
        Get a registered plugin by ID.

        Args:
            plugin_id: The plugin ID to look up.

        Returns:
            The ORSAPlugin instance, or None if not found.
        """
        return self._plugins.get(plugin_id)

    async def get_info(self, plugin_id: str) -> Optional[PluginInfo]:
        """
        Get cached PluginInfo for a registered plugin.

        Args:
            plugin_id: The plugin ID to look up.

        Returns:
            The PluginInfo, or None if not found.
        """
        return self._plugin_info_cache.get(plugin_id)

    async def list_all(self) -> List[PluginInfo]:
        """
        List all registered plugins.

        Returns:
            List of PluginInfo for all registered plugins.
        """
        return list(self._plugin_info_cache.values())

    async def get_by_capability(self, capability: Capability) -> List[ORSAPlugin]:
        """
        Get all plugins with a specific capability.

        Args:
            capability: The capability to filter by.

        Returns:
            List of ORSAPlugin instances with the specified capability.
        """
        result = []
        for plugin_id, info in self._plugin_info_cache.items():
            if capability in info.capabilities:
                plugin = self._plugins.get(plugin_id)
                if plugin:
                    result.append(plugin)
        return result

    async def get_by_platform(self, platform: str) -> List[ORSAPlugin]:
        """
        Get all plugins supporting a specific platform.

        Args:
            platform: The platform to filter by (e.g., "rhel9", "ubuntu22").

        Returns:
            List of ORSAPlugin instances supporting the platform.
        """
        result = []
        for plugin_id, info in self._plugin_info_cache.items():
            if platform in info.supported_platforms:
                plugin = self._plugins.get(plugin_id)
                if plugin:
                    result.append(plugin)
        return result

    async def get_by_framework(self, framework: str) -> List[ORSAPlugin]:
        """
        Get all plugins supporting a specific framework.

        Args:
            framework: The framework to filter by (e.g., "cis", "stig").

        Returns:
            List of ORSAPlugin instances supporting the framework.
        """
        result = []
        for plugin_id, info in self._plugin_info_cache.items():
            if framework in info.supported_frameworks:
                plugin = self._plugins.get(plugin_id)
                if plugin:
                    result.append(plugin)
        return result

    def is_registered(self, plugin_id: str) -> bool:
        """
        Check if a plugin is registered.

        Args:
            plugin_id: The plugin ID to check.

        Returns:
            True if the plugin is registered, False otherwise.
        """
        return plugin_id in self._plugins

    @property
    def plugin_count(self) -> int:
        """Get the number of registered plugins."""
        return len(self._plugins)

    @property
    def initialized_at(self) -> Optional[datetime]:
        """Get the timestamp when the registry was initialized."""
        return self._initialized_at

    async def health_check(self) -> Dict[str, object]:
        """
        Perform health check on the registry and all registered plugins.

        Returns:
            Dict with registry health status and per-plugin health.
        """
        plugin_health: Dict[str, object] = {}
        all_healthy = True

        for plugin_id, plugin in self._plugins.items():
            try:
                health = await plugin.health_check()
                plugin_health[plugin_id] = health
                if not health.get("healthy", False):
                    all_healthy = False
            except Exception as e:
                plugin_health[plugin_id] = {
                    "healthy": False,
                    "error": str(e),
                }
                all_healthy = False

        return {
            "registry_healthy": True,
            "all_plugins_healthy": all_healthy,
            "plugin_count": len(self._plugins),
            "initialized_at": (self._initialized_at.isoformat() if self._initialized_at else None),
            "plugins": plugin_health,
        }


__all__ = [
    "ORSAPluginRegistry",
    "PluginAlreadyRegisteredError",
    "PluginNotRegisteredError",
]
