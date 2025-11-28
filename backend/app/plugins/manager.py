"""
OpenWatch Plugin Manager

Handles plugin discovery, loading, lifecycle management, and hook execution
for OpenWatch's extensible plugin architecture.

This module provides:
- Plugin discovery from filesystem directories
- Safe dynamic plugin loading with validation
- Plugin lifecycle management (init, enable, disable, cleanup)
- Hook-based event system for plugin communication
- Type-safe plugin categorization by functionality

Security Considerations:
- All plugins are validated before loading (OWASP A04:2021)
- Plugin configurations stored separately from code
- Comprehensive error handling prevents plugin failures from affecting core system

Example:
    >>> manager = get_plugin_manager()
    >>> await manager.initialize()
    >>> scanner = await manager.find_compatible_scanner(host_config)
    >>> if scanner:
    ...     results = await scanner.scan(host_config)
"""

import importlib
import importlib.util
import json
import logging
from datetime import datetime
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, List, Optional, Type

from .interface import (
    AuthenticationPlugin,
    ContentPlugin,
    HookablePlugin,
    IntegrationPlugin,
    NotificationPlugin,
    PluginHookContext,
    PluginHooks,
    PluginInterface,
    PluginType,
    RemediationPlugin,
    ReporterPlugin,
    ScannerPlugin,
)

logger = logging.getLogger(__name__)


class PluginLoadError(Exception):
    """Exception raised when plugin loading fails"""


class PluginManager:
    """
    Central plugin manager for OpenWatch
    Handles plugin discovery, loading, configuration, and execution
    """

    def __init__(self, plugins_dir: str = "/app/plugins", config_dir: str = "/app/config/plugins"):
        self.plugins_dir = Path(plugins_dir)
        self.config_dir = Path(config_dir)
        self.loaded_plugins: Dict[str, PluginInterface] = {}
        self.plugin_configs: Dict[str, Dict[str, Any]] = {}
        self.hook_registry: Dict[str, List[HookablePlugin]] = {}
        self.plugin_dependencies: Dict[str, List[str]] = {}

        # Ensure directories exist
        self.plugins_dir.mkdir(parents=True, exist_ok=True)
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # Plugin type mapping - maps PluginType enum to expected plugin interface class
        # Using type: ignore for abstract class assignment (these are ABCs used for isinstance checks)
        self.plugin_type_map: Dict[PluginType, type] = {
            PluginType.SCANNER: ScannerPlugin,
            PluginType.REPORTER: ReporterPlugin,
            PluginType.REMEDIATION: RemediationPlugin,
            PluginType.INTEGRATION: IntegrationPlugin,
            PluginType.CONTENT: ContentPlugin,
            PluginType.AUTH: AuthenticationPlugin,
            PluginType.NOTIFICATION: NotificationPlugin,
        }

    async def initialize(self) -> bool:
        """Initialize the plugin manager and load all plugins"""
        try:
            logger.info("Initializing OpenWatch Plugin Manager")

            # Load plugin configurations
            await self._load_plugin_configs()

            # Discover and load plugins
            await self._discover_plugins()

            # Initialize all loaded plugins
            await self._initialize_plugins()

            # Register plugin hooks
            await self._register_plugin_hooks()

            logger.info(f"Plugin manager initialized with {len(self.loaded_plugins)} plugins")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize plugin manager: {e}")
            return False

    async def shutdown(self) -> bool:
        """Shutdown the plugin manager and cleanup all plugins"""
        try:
            logger.info("Shutting down plugin manager")

            # Execute system shutdown hooks
            await self.execute_hook(PluginHooks.SYSTEM_SHUTDOWN, {})

            # Cleanup all plugins
            for plugin_name, plugin in self.loaded_plugins.items():
                try:
                    await plugin.cleanup()
                    logger.debug(f"Cleaned up plugin: {plugin_name}")
                except Exception as e:
                    logger.error(f"Error cleaning up plugin {plugin_name}: {e}")

            self.loaded_plugins.clear()
            self.hook_registry.clear()

            logger.info("Plugin manager shutdown complete")
            return True

        except Exception as e:
            logger.error(f"Error during plugin manager shutdown: {e}")
            return False

    async def load_plugin(self, plugin_path: str, plugin_name: Optional[str] = None) -> bool:
        """
        Load a single plugin from the specified path.

        Performs dynamic module loading with comprehensive validation to ensure
        plugin safety and compatibility before activation.

        Args:
            plugin_path: Filesystem path to the plugin's main Python file.
            plugin_name: Optional name for the plugin. If not provided,
                        derived from the path stem.

        Returns:
            True if plugin loaded successfully, False otherwise.

        Note:
            Plugin validation includes type checking and interface verification
            to prevent malformed plugins from affecting system stability.
        """
        try:
            if not plugin_name:
                plugin_name = Path(plugin_path).stem

            logger.info(f"Loading plugin: {plugin_name} from {plugin_path}")

            # Load plugin module
            spec = importlib.util.spec_from_file_location(plugin_name, plugin_path)
            if not spec or not spec.loader:
                raise PluginLoadError(f"Cannot load plugin spec from {plugin_path}")

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Find plugin class
            plugin_class = self._find_plugin_class(module)
            if not plugin_class:
                raise PluginLoadError(f"No valid plugin class found in {plugin_path}")

            # Get plugin configuration
            plugin_config = self.plugin_configs.get(plugin_name, {})

            # Instantiate plugin
            plugin = plugin_class(plugin_config)

            # Validate plugin (synchronous validation)
            if not self._validate_plugin(plugin):
                raise PluginLoadError(f"Plugin validation failed: {plugin_name}")

            # Initialize plugin
            if not await plugin.initialize():
                raise PluginLoadError(f"Plugin initialization failed: {plugin_name}")

            # Store plugin
            self.loaded_plugins[plugin_name] = plugin

            # Register hooks if applicable (synchronous operation)
            if isinstance(plugin, HookablePlugin):
                self._register_plugin_hooks_for(plugin)

            logger.info(f"Successfully loaded plugin: {plugin_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to load plugin {plugin_name}: {e}")
            return False

    def get_plugin(self, plugin_name: str) -> Optional[PluginInterface]:
        """Get a loaded plugin by name"""
        return self.loaded_plugins.get(plugin_name)

    def get_plugins_by_type(self, plugin_type: PluginType) -> List[PluginInterface]:
        """Get all loaded plugins of the specified type"""
        plugins = []
        for plugin in self.loaded_plugins.values():
            if plugin.get_metadata().plugin_type == plugin_type:
                plugins.append(plugin)
        return plugins

    def list_plugins(self) -> Dict[str, Dict[str, Any]]:
        """List all loaded plugins with their metadata."""
        plugin_list = {}
        for name, plugin in self.loaded_plugins.items():
            metadata = plugin.get_metadata()
            plugin_list[name] = {
                "name": metadata.name,
                "version": metadata.version,
                "description": metadata.description,
                "author": metadata.author,
                "type": metadata.plugin_type.value,
                "enabled": plugin.is_enabled(),
            }
        return plugin_list

    def enable_plugin(self, plugin_name: str) -> bool:
        """Enable a plugin"""
        plugin = self.get_plugin(plugin_name)
        if plugin:
            plugin.set_enabled(True)
            logger.info(f"Enabled plugin: {plugin_name}")
            return True
        return False

    def disable_plugin(self, plugin_name: str) -> bool:
        """Disable a plugin"""
        plugin = self.get_plugin(plugin_name)
        if plugin:
            plugin.set_enabled(False)
            logger.info(f"Disabled plugin: {plugin_name}")
            return True
        return False

    async def execute_hook(
        self,
        hook_name: str,
        data: Dict[str, Any],
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Execute all registered hooks for the specified event.

        Iterates through all plugins registered for the given hook and executes
        their handlers, collecting results for further processing.

        Args:
            hook_name: The name of the hook/event to execute.
            data: Context data to pass to hook handlers.
            user_id: Optional user identifier for audit context.
            session_id: Optional session identifier for tracking.

        Returns:
            List of result dictionaries from each plugin's hook handler.
        """
        results: List[Dict[str, Any]] = []

        if hook_name not in self.hook_registry:
            return results

        hook_context = PluginHookContext(
            hook_name=hook_name,
            timestamp=datetime.now().isoformat(),
            data=data,
            user_id=user_id,
            session_id=session_id,
        )

        for plugin in self.hook_registry[hook_name]:
            if not plugin.is_enabled():
                continue

            try:
                result = await plugin.handle_hook(hook_context)
                if result:
                    results.append({"plugin": plugin.get_metadata().name, "result": result})
            except Exception as e:
                logger.error(f"Hook execution failed for plugin {plugin.get_metadata().name}: {e}")
                results.append({"plugin": plugin.get_metadata().name, "error": str(e)})

        return results

    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check on all plugins.

        Iterates through all loaded plugins and collects their health status,
        providing an aggregate view of plugin system health.

        Returns:
            Dictionary containing plugin manager health status, plugin counts,
            and individual plugin health information.
        """
        health_status: Dict[str, Any] = {
            "plugin_manager": "healthy",
            "total_plugins": len(self.loaded_plugins),
            "enabled_plugins": 0,
            "disabled_plugins": 0,
            "plugin_health": {},
        }

        for name, plugin in self.loaded_plugins.items():
            try:
                # health_check is synchronous per PluginInterface definition
                plugin_health = plugin.health_check()
                health_status["plugin_health"][name] = plugin_health

                if plugin.is_enabled():
                    health_status["enabled_plugins"] += 1
                else:
                    health_status["disabled_plugins"] += 1

            except Exception as e:
                health_status["plugin_health"][name] = {
                    "status": "error",
                    "error": str(e),
                }

        return health_status

    # Scanner Plugin Helpers
    async def find_compatible_scanner(self, host_config: Dict[str, Any]) -> Optional[ScannerPlugin]:
        """
        Find a scanner plugin that can handle the specified host.

        Iterates through all scanner plugins and returns the first one
        that is enabled and compatible with the host configuration.

        Args:
            host_config: Dictionary containing host configuration details.

        Returns:
            A compatible ScannerPlugin instance, or None if none found.
        """
        scanners = self.get_plugins_by_type(PluginType.SCANNER)

        for scanner in scanners:
            # Type-safe cast: we know these are scanner plugins
            if isinstance(scanner, ScannerPlugin):
                if scanner.is_enabled() and await scanner.can_scan_host(host_config):
                    return scanner

        return None

    # Reporter Plugin Helpers
    async def generate_report(
        self, scan_results: List[Any], format_type: str = "html"
    ) -> Optional[bytes]:
        """
        Generate a report using available reporter plugins.

        Attempts to generate a report in the specified format using the first
        available reporter plugin that supports the format.

        Args:
            scan_results: List of scan result data to include in report.
            format_type: Output format (e.g., 'html', 'pdf', 'json').

        Returns:
            Report content as bytes, or None if no compatible reporter found.
        """
        reporters = self.get_plugins_by_type(PluginType.REPORTER)

        for reporter in reporters:
            # Type-safe cast: we know these are reporter plugins
            if isinstance(reporter, ReporterPlugin):
                if reporter.is_enabled() and format_type in reporter.get_supported_formats():
                    try:
                        return await reporter.generate_report(scan_results, format_type)
                    except Exception as e:
                        logger.error(
                            f"Report generation failed with plugin "
                            f"{reporter.get_metadata().name}: {e}"
                        )

        return None

    # Remediation Plugin Helpers
    async def find_remediation_plugins(
        self, rule_id: str, host_config: Dict[str, Any]
    ) -> List[RemediationPlugin]:
        """
        Find remediation plugins that can handle the specified rule.

        Searches through all remediation plugins to find those capable
        of remediating the given rule on the specified host.

        Args:
            rule_id: The compliance rule identifier to remediate.
            host_config: Dictionary containing host configuration details.

        Returns:
            List of compatible RemediationPlugin instances.
        """
        remediation_plugins = self.get_plugins_by_type(PluginType.REMEDIATION)
        compatible_plugins: List[RemediationPlugin] = []

        for plugin in remediation_plugins:
            # Type-safe cast: we know these are remediation plugins
            if isinstance(plugin, RemediationPlugin):
                if plugin.is_enabled() and await plugin.can_remediate_rule(rule_id, host_config):
                    compatible_plugins.append(plugin)

        return compatible_plugins

    # Private methods
    async def _discover_plugins(self) -> None:
        """
        Discover plugins in the plugins directory.

        Scans the plugins directory for subdirectories containing plugin.py files
        and attempts to load each discovered plugin.
        """
        logger.info(f"Discovering plugins in: {self.plugins_dir}")

        for plugin_dir in self.plugins_dir.iterdir():
            if plugin_dir.is_dir() and not plugin_dir.name.startswith("."):
                plugin_file = plugin_dir / "plugin.py"
                if plugin_file.exists():
                    await self.load_plugin(str(plugin_file), plugin_dir.name)

    async def _load_plugin_configs(self) -> None:
        """
        Load plugin configurations from config directory.

        Reads JSON configuration files for each plugin, storing them in
        plugin_configs dictionary for later use during plugin initialization.
        """
        for config_file in self.config_dir.glob("*.json"):
            try:
                with open(config_file, "r") as f:
                    config: Dict[str, Any] = json.load(f)
                    plugin_name = config_file.stem
                    self.plugin_configs[plugin_name] = config
                    logger.debug(f"Loaded config for plugin: {plugin_name}")
            except Exception as e:
                logger.error(f"Failed to load config for {config_file}: {e}")

    def _find_plugin_class(self, module: ModuleType) -> Optional[Type[PluginInterface]]:
        """
        Find the plugin class in the loaded module.

        Searches the module for a class that inherits from PluginInterface
        (excluding PluginInterface itself).

        Args:
            module: The loaded Python module to search.

        Returns:
            The plugin class if found, None otherwise.
        """
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and issubclass(attr, PluginInterface)
                and attr != PluginInterface
            ):
                return attr
        return None

    def _validate_plugin(self, plugin: PluginInterface) -> bool:
        """
        Validate a plugin meets requirements.

        Performs validation checks including metadata presence and
        interface compliance verification.

        Args:
            plugin: The plugin instance to validate.

        Returns:
            True if plugin passes validation, False otherwise.
        """
        try:
            metadata = plugin.get_metadata()

            # Basic validation
            if not metadata.name or not metadata.version:
                return False

            # Check plugin type
            if metadata.plugin_type not in self.plugin_type_map:
                return False

            # Check if plugin implements required interface
            required_interface = self.plugin_type_map[metadata.plugin_type]
            if not isinstance(plugin, required_interface):
                return False

            return True

        except Exception as e:
            logger.error(f"Plugin validation error: {e}")
            return False

    async def _initialize_plugins(self) -> None:
        """
        Initialize all loaded plugins.

        Iterates through loaded plugins and calls their initialize methods.
        Logs errors for any plugins that fail to initialize.
        """
        # Sort plugins by dependencies (simplified for now)
        for plugin_name, plugin in self.loaded_plugins.items():
            try:
                if not await plugin.initialize():
                    logger.error(f"Failed to initialize plugin: {plugin_name}")
            except Exception as e:
                logger.error(f"Error initializing plugin {plugin_name}: {e}")

    async def _register_plugin_hooks(self) -> None:
        """
        Register hooks for all hookable plugins.

        Iterates through loaded plugins and registers hooks for any
        that implement the HookablePlugin interface.
        """
        for plugin in self.loaded_plugins.values():
            if isinstance(plugin, HookablePlugin):
                self._register_plugin_hooks_for(plugin)

    def _register_plugin_hooks_for(self, plugin: HookablePlugin) -> None:
        """
        Register hooks for a specific plugin.

        Adds the plugin to the hook registry for each hook it declares.

        Args:
            plugin: The hookable plugin to register hooks for.
        """
        for hook_name in plugin.get_registered_hooks():
            if hook_name not in self.hook_registry:
                self.hook_registry[hook_name] = []
            self.hook_registry[hook_name].append(plugin)
            logger.debug(f"Registered hook {hook_name} for plugin {plugin.get_metadata().name}")


# Global plugin manager instance
_plugin_manager: Optional[PluginManager] = None


def get_plugin_manager() -> PluginManager:
    """Get the global plugin manager instance"""
    global _plugin_manager
    if _plugin_manager is None:
        _plugin_manager = PluginManager()
    return _plugin_manager


async def initialize_plugin_system() -> bool:
    """Initialize the global plugin system"""
    manager = get_plugin_manager()
    return await manager.initialize()


async def shutdown_plugin_system() -> bool:
    """Shutdown the global plugin system"""
    manager = get_plugin_manager()
    return await manager.shutdown()
