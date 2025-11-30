"""
Plugin Registry Subpackage

Provides plugin registration, storage, and lifecycle management functionality.
The registry is the central component for tracking all installed plugins and
their metadata.

Components:
    - PluginRegistryService: Main service for plugin CRUD operations

Usage:
    from backend.app.services.plugins.registry import PluginRegistryService

    registry = PluginRegistryService()
    plugin = await registry.get_plugin("my-plugin@1.0.0")
"""

from .service import PluginRegistryService

__all__ = [
    "PluginRegistryService",
]
