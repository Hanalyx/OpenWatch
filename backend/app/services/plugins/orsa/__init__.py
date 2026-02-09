"""
ORSA v2.0 - OpenWatch Remediation System Adapter

The standard interface for compliance scanning and remediation plugins.

This module provides:
- ORSAPlugin: Abstract base class for compliance plugins
- ORSAPluginRegistry: Singleton registry for plugin management
- Capability: Enum of plugin capabilities
- Dataclasses: PluginInfo, CanonicalRule, CheckResult, RemediationResult, etc.

Quick Start:
    from app.services.plugins.orsa import (
        ORSAPlugin,
        ORSAPluginRegistry,
        Capability,
        PluginInfo,
        CheckResult,
    )

    # Get the registry
    registry = ORSAPluginRegistry.instance()

    # Register a plugin
    await registry.register(my_plugin)

    # Execute a scan
    plugin = await registry.get("my-plugin")
    results = await plugin.check(host_id="...")

Version: 2.0.0
"""

from .interface import (
    CanonicalRule,
    Capability,
    CheckResult,
    HostCapabilities,
    HostMetadata,
    ORSAPlugin,
    PluginInfo,
    RemediationResult,
    RemediationStepResult,
    RollbackResult,
)
from .registry import ORSAPluginRegistry, PluginAlreadyRegisteredError, PluginNotRegisteredError

__version__ = "2.0.0"

__all__ = [
    # Version
    "__version__",
    # Abstract class
    "ORSAPlugin",
    # Registry
    "ORSAPluginRegistry",
    "PluginAlreadyRegisteredError",
    "PluginNotRegisteredError",
    # Enums
    "Capability",
    # Dataclasses
    "PluginInfo",
    "CanonicalRule",
    "HostMetadata",
    "CheckResult",
    "RemediationStepResult",
    "RemediationResult",
    "RollbackResult",
    "HostCapabilities",
]
