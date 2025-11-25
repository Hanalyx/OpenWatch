"""
OpenWatch Plugin Manager
Handles plugin discovery, loading, lifecycle management, and hook execution
"""

import importlib
import importlib.util
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Type

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
        self.plugin_configs: Dict[str, Dict] = {}
        self.hook_registry: Dict[str, List[HookablePlugin]] = {}
        self.plugin_dependencies: Dict[str, List[str]] = {}

        # Ensure directories exist
        self.plugins_dir.mkdir(parents=True, exist_ok=True)
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # Plugin type mapping
        self.plugin_type_map = {
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

    async def load_plugin(self, plugin_path: str, plugin_name: str = None) -> bool:
        """Load a single plugin from the specified path"""
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

            # Validate plugin
            if not await self._validate_plugin(plugin):
                raise PluginLoadError(f"Plugin validation failed: {plugin_name}")

            # Initialize plugin
            if not await plugin.initialize():
                raise PluginLoadError(f"Plugin initialization failed: {plugin_name}")

            # Store plugin
            self.loaded_plugins[plugin_name] = plugin

            # Register hooks if applicable
            if isinstance(plugin, HookablePlugin):
                await self._register_plugin_hooks_for(plugin)

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

    def list_plugins(self) -> Dict[str, Dict]:
        """List all loaded plugins with their metadata"""
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
        self, hook_name: str, data: Dict, user_id: str = None, session_id: str = None
    ) -> List[Dict]:
        """Execute all registered hooks for the specified event"""
        results = []

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

    async def health_check(self) -> Dict:
        """Perform health check on all plugins"""
        health_status = {
            "plugin_manager": "healthy",
            "total_plugins": len(self.loaded_plugins),
            "enabled_plugins": 0,
            "disabled_plugins": 0,
            "plugin_health": {},
        }

        for name, plugin in self.loaded_plugins.items():
            try:
                plugin_health = await plugin.health_check()
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
    async def find_compatible_scanner(self, host_config: Dict) -> Optional[ScannerPlugin]:
        """Find a scanner plugin that can handle the specified host"""
        scanners = self.get_plugins_by_type(PluginType.SCANNER)

        for scanner in scanners:
            if scanner.is_enabled() and await scanner.can_scan_host(host_config):
                return scanner

        return None

    # Reporter Plugin Helpers
    async def generate_report(
        self, scan_results: List, format_type: str = "html"
    ) -> Optional[bytes]:
        """Generate a report using available reporter plugins"""
        reporters = self.get_plugins_by_type(PluginType.REPORTER)

        for reporter in reporters:
            if reporter.is_enabled() and format_type in reporter.get_supported_formats():
                try:
                    return await reporter.generate_report(scan_results, format_type)
                except Exception as e:
                    logger.error(
                        f"Report generation failed with plugin {reporter.get_metadata().name}: {e}"
                    )

        return None

    # Remediation Plugin Helpers
    async def find_remediation_plugins(
        self, rule_id: str, host_config: Dict
    ) -> List[RemediationPlugin]:
        """Find remediation plugins that can handle the specified rule"""
        remediation_plugins = self.get_plugins_by_type(PluginType.REMEDIATION)
        compatible_plugins = []

        for plugin in remediation_plugins:
            if plugin.is_enabled() and await plugin.can_remediate_rule(rule_id, host_config):
                compatible_plugins.append(plugin)

        return compatible_plugins

    # Private methods
    async def _discover_plugins(self):
        """Discover plugins in the plugins directory"""
        logger.info(f"Discovering plugins in: {self.plugins_dir}")

        for plugin_dir in self.plugins_dir.iterdir():
            if plugin_dir.is_dir() and not plugin_dir.name.startswith("."):
                plugin_file = plugin_dir / "plugin.py"
                if plugin_file.exists():
                    await self.load_plugin(str(plugin_file), plugin_dir.name)

    def _load_plugin_configs(self):
        """Load plugin configurations from config directory"""
        for config_file in self.config_dir.glob("*.json"):
            try:
                with open(config_file, "r") as f:
                    config = json.load(f)
                    plugin_name = config_file.stem
                    self.plugin_configs[plugin_name] = config
                    logger.debug(f"Loaded config for plugin: {plugin_name}")
            except Exception as e:
                logger.error(f"Failed to load config for {config_file}: {e}")

    def _find_plugin_class(self, module) -> Optional[Type[PluginInterface]]:
        """Find the plugin class in the loaded module"""
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
        """Validate a plugin meets requirements"""
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

    async def _initialize_plugins(self):
        """Initialize all loaded plugins"""
        # Sort plugins by dependencies (simplified for now)
        for plugin_name, plugin in self.loaded_plugins.items():
            try:
                if not await plugin.initialize():
                    logger.error(f"Failed to initialize plugin: {plugin_name}")
            except Exception as e:
                logger.error(f"Error initializing plugin {plugin_name}: {e}")

    async def _register_plugin_hooks(self):
        """Register hooks for all hookable plugins"""
        for plugin in self.loaded_plugins.values():
            if isinstance(plugin, HookablePlugin):
                await self._register_plugin_hooks_for(plugin)

    def _register_plugin_hooks_for(self, plugin: HookablePlugin):
        """Register hooks for a specific plugin"""
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
