"""
Plugin Marketplace Subpackage

Provides comprehensive marketplace integration capabilities for plugin management
including discovery, installation, ratings, and multi-marketplace support.

Components:
    - PluginMarketplaceService: Main service for marketplace operations
    - Models: Marketplaces, plugins, ratings, installations, search

Marketplace Types Supported:
    - OFFICIAL: Official OpenWatch marketplace
    - GITHUB: GitHub repositories
    - DOCKER_HUB: Docker Hub container registry
    - NPM: NPM package registry
    - PYPI: Python Package Index
    - CUSTOM: Custom marketplace/repository
    - FILE_SYSTEM: Local file system

Plugin Sources:
    - MARKETPLACE: From marketplace
    - REPOSITORY: From git repository
    - REGISTRY: From package registry
    - LOCAL: Local installation
    - BUNDLED: Bundled with OpenWatch

Marketplace Capabilities:
    - Multi-marketplace plugin discovery and search
    - Secure plugin installation with verification
    - Automatic dependency resolution
    - Plugin ratings and reviews
    - Marketplace synchronization and caching
    - Governance and compliance integration

Usage:
    from backend.app.services.plugins.marketplace import PluginMarketplaceService

    marketplace = PluginMarketplaceService()
    await marketplace.initialize_marketplace_service()

    # Search for plugins
    results = await marketplace.search_plugins(
        MarketplaceSearchQuery(query="scanner", free_only=True)
    )

    # Install a plugin
    installation = await marketplace.install_plugin(
        marketplace_id="official",
        plugin_id="security-scanner",
        version="1.0.0",
    )

Example:
    >>> from backend.app.services.plugins.marketplace import (
    ...     PluginMarketplaceService,
    ...     MarketplaceType,
    ...     PluginSource,
    ... )
    >>> marketplace = PluginMarketplaceService()
    >>> await marketplace.initialize_marketplace_service()
    >>> stats = await marketplace.get_marketplace_statistics()
    >>> print(f"Total marketplaces: {stats['marketplaces']['total']}")
"""

from .models import (
    MarketplaceConfig,
    MarketplacePlugin,
    MarketplaceSearchQuery,
    MarketplaceSearchResult,
    MarketplaceType,
    PluginInstallationRequest,
    PluginInstallationResult,
    PluginRating,
    PluginSource,
)
from .service import PluginMarketplaceService

__all__ = [
    # Service
    "PluginMarketplaceService",
    # Enums
    "MarketplaceType",
    "PluginSource",
    # Models
    "PluginRating",
    "MarketplacePlugin",
    "MarketplaceConfig",
    "PluginInstallationRequest",
    "PluginInstallationResult",
    "MarketplaceSearchQuery",
    "MarketplaceSearchResult",
]
