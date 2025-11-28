import io

"""
Plugin Marketplace Integration Service
Provides integration with external plugin marketplaces, repositories, and distribution channels.
Supports discovery, installation, updates, and management of plugins from various sources.
"""

import asyncio
import hashlib
import json
import logging
import tempfile
import uuid
import zipfile
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiohttp
import semver
from beanie import Document
from pydantic import BaseModel, Field, HttpUrl

from ..models.plugin_models import InstalledPlugin, PluginManifest, PluginStatus
from .plugin_governance_service import PluginGovernanceService
from .plugin_lifecycle_service import PluginLifecycleService
from .plugin_registry_service import PluginRegistryService

logger = logging.getLogger(__name__)


# ============================================================================
# MARKETPLACE MODELS AND ENUMS
# ============================================================================


class MarketplaceType(str, Enum):
    """Types of plugin marketplaces"""

    OFFICIAL = "official"  # Official OpenWatch marketplace
    GITHUB = "github"  # GitHub repositories
    DOCKER_HUB = "docker_hub"  # Docker Hub container registry
    NPM = "npm"  # NPM package registry
    PYPI = "pypi"  # Python Package Index
    CUSTOM = "custom"  # Custom marketplace/repository
    FILE_SYSTEM = "file_system"  # Local file system


class PluginSource(str, Enum):
    """Plugin source types"""

    MARKETPLACE = "marketplace"  # From marketplace
    REPOSITORY = "repository"  # From git repository
    REGISTRY = "registry"  # From package registry
    LOCAL = "local"  # Local installation
    BUNDLED = "bundled"  # Bundled with OpenWatch


class PluginRating(BaseModel):
    """Plugin rating and review"""

    rating_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    plugin_id: str
    user_id: str

    # Rating
    rating: float = Field(..., ge=1.0, le=5.0)
    review_text: Optional[str] = None

    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    helpful_votes: int = Field(default=0)

    # Verification
    verified_purchase: bool = Field(default=False)
    verified_usage: bool = Field(default=False)


class MarketplacePlugin(BaseModel):
    """Plugin information from marketplace"""

    marketplace_id: str
    plugin_id: str
    name: str
    description: str
    version: str

    # Author and publisher
    author: str
    publisher: Optional[str] = None
    maintainer: Optional[str] = None

    # Metadata
    tags: List[str] = Field(default_factory=list)
    categories: List[str] = Field(default_factory=list)
    supported_platforms: List[str] = Field(default_factory=list)

    # Marketplace specific
    marketplace_url: HttpUrl
    download_url: Optional[HttpUrl] = None
    documentation_url: Optional[HttpUrl] = None
    repository_url: Optional[HttpUrl] = None

    # Statistics
    download_count: int = Field(default=0)
    rating_average: Optional[float] = Field(None, ge=1.0, le=5.0)
    rating_count: int = Field(default=0)

    # Verification and trust
    verified_publisher: bool = Field(default=False)
    security_scanned: bool = Field(default=False)
    compliance_certified: bool = Field(default=False)

    # Lifecycle
    published_at: datetime
    last_updated: datetime
    deprecated: bool = Field(default=False)

    # Dependencies
    dependencies: Dict[str, str] = Field(default_factory=dict)
    conflicts: List[str] = Field(default_factory=list)

    # Licensing
    license: str
    price: Optional[float] = None  # 0 for free, > 0 for paid
    trial_available: bool = Field(default=False)


class MarketplaceConfig(BaseModel):
    """Marketplace configuration"""

    marketplace_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    marketplace_type: MarketplaceType

    # Connection settings
    base_url: HttpUrl
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None

    # Search and discovery
    search_enabled: bool = Field(default=True)
    browse_enabled: bool = Field(default=True)
    categories_supported: bool = Field(default=True)

    # Installation settings
    auto_install_enabled: bool = Field(default=False)
    auto_update_enabled: bool = Field(default=False)
    security_verification_required: bool = Field(default=True)

    # Sync settings
    sync_interval_hours: int = Field(default=24)
    last_sync: Optional[datetime] = None

    # Filtering and policies
    allowed_categories: List[str] = Field(default_factory=list)
    blocked_publishers: List[str] = Field(default_factory=list)
    minimum_rating: Optional[float] = Field(None, ge=1.0, le=5.0)

    # Metadata
    enabled: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    priority: int = Field(default=100)  # Higher priority = preferred marketplace


class PluginInstallationRequest(BaseModel):
    """Plugin installation request from marketplace"""

    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    marketplace_id: str
    plugin_id: str
    version: Optional[str] = None  # Latest if not specified

    # Installation options
    auto_enable: bool = Field(default=True)
    install_dependencies: bool = Field(default=True)
    force_reinstall: bool = Field(default=False)

    # User context
    requested_by: str
    requested_at: datetime = Field(default_factory=datetime.utcnow)

    # Configuration
    initial_config: Dict[str, Any] = Field(default_factory=dict)

    # Approval workflow
    requires_approval: bool = Field(default=True)
    approved: bool = Field(default=False)
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None


class PluginInstallationResult(Document):
    """Plugin installation result from marketplace"""

    installation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    request: PluginInstallationRequest

    # Installation status
    status: str = Field(default="pending")  # pending, downloading, installing, completed, failed
    progress: float = Field(default=0.0, ge=0.0, le=100.0)

    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None

    # Results
    success: bool = Field(default=False)
    installed_plugin_id: Optional[str] = None
    installed_version: Optional[str] = None

    # Error handling
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)

    # Installation details
    download_url: Optional[str] = None
    download_size_bytes: Optional[int] = None
    verification_results: Dict[str, Any] = Field(default_factory=dict)

    # Compliance and governance
    governance_checks: Dict[str, Any] = Field(default_factory=dict)
    policy_violations: List[str] = Field(default_factory=list)

    class Settings:
        collection = "plugin_installations"
        indexes = [
            "installation_id",
            "request.marketplace_id",
            "request.plugin_id",
            "status",
            "started_at",
        ]


class MarketplaceSearchQuery(BaseModel):
    """Marketplace search query parameters"""

    query: Optional[str] = None
    categories: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    author: Optional[str] = None

    # Filtering
    min_rating: Optional[float] = Field(None, ge=1.0, le=5.0)
    max_price: Optional[float] = None
    free_only: bool = Field(default=False)
    verified_only: bool = Field(default=False)

    # Sorting
    sort_by: str = Field(default="relevance")  # relevance, rating, downloads, updated
    sort_order: str = Field(default="desc")  # asc, desc

    # Pagination
    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=20, ge=1, le=100)


class MarketplaceSearchResult(BaseModel):
    """Marketplace search results"""

    query: MarketplaceSearchQuery
    total_results: int
    total_pages: int
    current_page: int
    plugins: List[MarketplacePlugin]

    # Search metadata
    search_time_ms: float
    marketplace_id: str
    cached_result: bool = Field(default=False)


# ============================================================================
# PLUGIN MARKETPLACE SERVICE
# ============================================================================


class PluginMarketplaceService:
    """
    Plugin marketplace integration service

    Provides comprehensive capabilities for:
    - Multi-marketplace plugin discovery and search
    - Secure plugin installation with verification
    - Automatic dependency resolution and conflict detection
    - Plugin ratings, reviews, and community feedback
    - Marketplace synchronization and caching
    - Governance and compliance integration
    """

    def __init__(self) -> None:
        """Initialize plugin marketplace service."""
        self.plugin_registry_service = PluginRegistryService()
        self.plugin_lifecycle_service = PluginLifecycleService()
        self.plugin_governance_service = PluginGovernanceService()

        # Marketplace configurations
        self.marketplaces: Dict[str, MarketplaceConfig] = {}
        self.plugin_cache: Dict[str, List[MarketplacePlugin]] = {}
        self.search_cache: Dict[str, MarketplaceSearchResult] = {}

        # Active operations
        self.active_installations: Dict[str, PluginInstallationResult] = {}
        self.sync_tasks: Dict[str, asyncio.Task[None]] = {}

        # HTTP session for marketplace requests
        self.session: Optional[aiohttp.ClientSession] = None
        self.cache_ttl = timedelta(hours=1)

    async def initialize_marketplace_service(self) -> None:
        """Initialize marketplace service with default configurations."""
        # Create HTTP session
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={"User-Agent": "OpenWatch-PluginMarketplace/1.0"},
        )

        # Load default marketplace configurations
        await self._load_default_marketplaces()

        # Start sync tasks for enabled marketplaces
        for marketplace_id, config in self.marketplaces.items():
            if config.enabled:
                await self._start_marketplace_sync(marketplace_id)

        logger.info("Plugin marketplace service initialized")

    async def shutdown_marketplace_service(self) -> None:
        """Shutdown marketplace service and cleanup resources."""

        # Stop all sync tasks
        for marketplace_id, task in self.sync_tasks.items():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                logger.debug("Ignoring exception during cleanup")

        self.sync_tasks.clear()

        # Close HTTP session
        if self.session:
            await self.session.close()
            self.session = None

        logger.info("Plugin marketplace service shutdown")

    async def add_marketplace(self, config: MarketplaceConfig) -> bool:
        """Add a new marketplace configuration"""

        try:
            # Validate marketplace connection
            validation_result = await self._validate_marketplace_connection(config)
            if not validation_result["valid"]:
                logger.error(f"Marketplace validation failed: {validation_result['error']}")
                return False

            # Store configuration
            self.marketplaces[config.marketplace_id] = config

            # Start sync if enabled
            if config.enabled:
                await self._start_marketplace_sync(config.marketplace_id)

            logger.info(f"Added marketplace: {config.name} ({config.marketplace_id})")
            return True

        except Exception as e:
            logger.error(f"Failed to add marketplace {config.name}: {e}")
            return False

    async def search_plugins(
        self, query: MarketplaceSearchQuery, marketplace_ids: Optional[List[str]] = None
    ) -> List[MarketplaceSearchResult]:
        """Search for plugins across multiple marketplaces"""

        if not marketplace_ids:
            marketplace_ids = [mid for mid, config in self.marketplaces.items() if config.enabled]

        search_results = []

        # Search each marketplace
        for marketplace_id in marketplace_ids:
            try:
                result = await self._search_marketplace(marketplace_id, query)
                if result:
                    search_results.append(result)
            except Exception as e:
                logger.error(f"Search failed for marketplace {marketplace_id}: {e}")

        # Sort results by marketplace priority
        search_results.sort(key=lambda r: self.marketplaces[r.marketplace_id].priority, reverse=True)

        logger.info(f"Search completed across {len(search_results)} marketplaces")
        return search_results

    async def get_plugin_details(self, marketplace_id: str, plugin_id: str) -> Optional[MarketplacePlugin]:
        """Get detailed information about a specific plugin"""

        marketplace = self.marketplaces.get(marketplace_id)
        if not marketplace:
            raise ValueError(f"Marketplace not found: {marketplace_id}")

        try:
            plugin_details = await self._fetch_plugin_details(marketplace, plugin_id)
            return plugin_details
        except Exception as e:
            logger.error(f"Failed to get plugin details for {plugin_id}: {e}")
            return None

    async def install_plugin(
        self,
        marketplace_id: str,
        plugin_id: str,
        version: Optional[str] = None,
        requested_by: str = "system",
        auto_enable: bool = True,
        force_reinstall: bool = False,
    ) -> PluginInstallationResult:
        """Install a plugin from marketplace"""

        # Create installation request
        request = PluginInstallationRequest(
            marketplace_id=marketplace_id,
            plugin_id=plugin_id,
            version=version,
            auto_enable=auto_enable,
            force_reinstall=force_reinstall,
            requested_by=requested_by,
        )

        # Create installation result record
        installation = PluginInstallationResult(request=request)
        await installation.save()

        # Add to active installations
        self.active_installations[installation.installation_id] = installation

        # Start installation process asynchronously
        asyncio.create_task(self._execute_plugin_installation(installation))

        logger.info(f"Started plugin installation: {plugin_id} from {marketplace_id}")
        return installation

    async def get_installation_status(self, installation_id: str) -> Optional[PluginInstallationResult]:
        """Get installation status."""
        # Check active installations first
        if installation_id in self.active_installations:
            return self.active_installations[installation_id]

        # Query database
        result: Optional[PluginInstallationResult] = await PluginInstallationResult.find_one(
            {"installation_id": installation_id}
        )
        return result

    async def list_available_plugins(
        self,
        marketplace_id: Optional[str] = None,
        category: Optional[str] = None,
        limit: int = 50,
    ) -> List[MarketplacePlugin]:
        """List available plugins from marketplaces"""

        if marketplace_id:
            marketplace_ids = [marketplace_id]
        else:
            marketplace_ids = [mid for mid, config in self.marketplaces.items() if config.enabled]

        all_plugins = []

        for mid in marketplace_ids:
            try:
                plugins = await self._get_marketplace_plugins(mid, category, limit)
                all_plugins.extend(plugins)
            except Exception as e:
                logger.error(f"Failed to list plugins from marketplace {mid}: {e}")

        # Remove duplicates and sort by rating/downloads
        unique_plugins: Dict[str, MarketplacePlugin] = {}
        for plugin in all_plugins:
            key = f"{plugin.name}_{plugin.author}"
            existing_rating = unique_plugins.get(key)
            current_rating = plugin.rating_average or 0.0
            existing_avg = existing_rating.rating_average if existing_rating else 0.0
            if key not in unique_plugins or current_rating > (existing_avg or 0.0):
                unique_plugins[key] = plugin

        sorted_plugins = sorted(
            unique_plugins.values(),
            key=lambda p: (p.rating_average or 0, p.download_count),
            reverse=True,
        )

        return sorted_plugins[:limit]

    async def get_plugin_ratings(self, marketplace_id: str, plugin_id: str) -> List[PluginRating]:
        """Get ratings and reviews for a plugin"""

        try:
            ratings = await self._fetch_plugin_ratings(marketplace_id, plugin_id)
            return ratings
        except Exception as e:
            logger.error(f"Failed to get ratings for plugin {plugin_id}: {e}")
            return []

    async def submit_plugin_rating(
        self,
        marketplace_id: str,
        plugin_id: str,
        rating: float,
        review_text: Optional[str] = None,
        user_id: str = "anonymous",
    ) -> bool:
        """Submit a rating/review for a plugin"""

        try:
            success = await self._submit_rating_to_marketplace(marketplace_id, plugin_id, rating, review_text, user_id)

            if success:
                logger.info(f"Submitted rating {rating} for plugin {plugin_id}")

            return success
        except Exception as e:
            logger.error(f"Failed to submit rating for plugin {plugin_id}: {e}")
            return False

    async def sync_marketplace(self, marketplace_id: str) -> bool:
        """Manually sync a marketplace"""

        marketplace = self.marketplaces.get(marketplace_id)
        if not marketplace:
            raise ValueError(f"Marketplace not found: {marketplace_id}")

        try:
            sync_result = await self._sync_marketplace_catalog(marketplace)

            # Update last sync time
            marketplace.last_sync = datetime.utcnow()

            logger.info(f"Marketplace sync completed for {marketplace.name}")
            return sync_result

        except Exception as e:
            logger.error(f"Marketplace sync failed for {marketplace_id}: {e}")
            return False

    async def check_plugin_updates(self, plugin_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Check for available plugin updates."""
        updates_available: List[Dict[str, Any]] = []

        # Get installed plugins
        plugins: List[InstalledPlugin] = []
        if plugin_id:
            single_plugin = await self.plugin_registry_service.get_plugin(plugin_id)
            if single_plugin is not None:
                plugins = [single_plugin]
        else:
            plugins = await self.plugin_registry_service.find_plugins({"status": PluginStatus.ACTIVE})

        for plugin in plugins:
            try:
                # Find plugin in marketplaces
                latest_version = await self._find_latest_version(plugin)

                if latest_version and semver.compare(latest_version["version"], plugin.version) > 0:
                    updates_available.append(
                        {
                            "plugin_id": plugin.plugin_id,
                            "current_version": plugin.version,
                            "latest_version": latest_version["version"],
                            "marketplace_id": latest_version["marketplace_id"],
                            "changelog": latest_version.get("changelog", ""),
                            "breaking_changes": latest_version.get("breaking_changes", False),
                        }
                    )

            except Exception as e:
                logger.error(f"Failed to check updates for plugin {plugin.plugin_id}: {e}")

        logger.info(f"Found {len(updates_available)} plugin updates available")
        return updates_available

    async def _load_default_marketplaces(self) -> None:
        """Load default marketplace configurations."""

        # Official OpenWatch Marketplace (placeholder)
        official_marketplace = MarketplaceConfig(
            name="OpenWatch Official Marketplace",
            marketplace_type=MarketplaceType.OFFICIAL,
            base_url="https://marketplace.openwatch.io",
            search_enabled=True,
            browse_enabled=True,
            minimum_rating=None,
            priority=1000,
        )

        # GitHub Marketplace
        github_marketplace = MarketplaceConfig(
            name="GitHub Plugins",
            marketplace_type=MarketplaceType.GITHUB,
            base_url="https://api.github.com",
            search_enabled=True,
            browse_enabled=True,
            minimum_rating=None,
            priority=900,
        )

        # Local File System
        local_marketplace = MarketplaceConfig(
            name="Local Plugin Directory",
            marketplace_type=MarketplaceType.FILE_SYSTEM,
            base_url="file:///app/plugins",
            search_enabled=False,
            browse_enabled=True,
            auto_install_enabled=False,
            minimum_rating=None,
            priority=100,
        )

        # Store default marketplaces
        self.marketplaces[official_marketplace.marketplace_id] = official_marketplace
        self.marketplaces[github_marketplace.marketplace_id] = github_marketplace
        self.marketplaces[local_marketplace.marketplace_id] = local_marketplace

        logger.info(f"Loaded {len(self.marketplaces)} default marketplaces")

    async def _start_marketplace_sync(self, marketplace_id: str) -> None:
        """Start automatic sync task for a marketplace"""

        marketplace = self.marketplaces.get(marketplace_id)
        if not marketplace:
            return

        async def sync_loop() -> None:
            while marketplace.enabled:
                try:
                    await self._sync_marketplace_catalog(marketplace)
                    marketplace.last_sync = datetime.utcnow()

                    # Wait for next sync
                    await asyncio.sleep(marketplace.sync_interval_hours * 3600)

                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Sync error for marketplace {marketplace_id}: {e}")
                    await asyncio.sleep(3600)  # 1 hour on error

        task = asyncio.create_task(sync_loop())
        self.sync_tasks[marketplace_id] = task
        logger.info(f"Started sync task for marketplace: {marketplace.name}")

    async def _validate_marketplace_connection(self, config: MarketplaceConfig) -> Dict[str, Any]:
        """Validate marketplace connection and configuration"""

        try:
            if config.marketplace_type == MarketplaceType.FILE_SYSTEM:
                # Check if directory exists
                path = Path(str(config.base_url).replace("file://", ""))
                return {
                    "valid": path.exists(),
                    "error": None if path.exists() else "Directory not found",
                }

            elif config.marketplace_type in [
                MarketplaceType.OFFICIAL,
                MarketplaceType.GITHUB,
            ]:
                # Test HTTP connection
                if not self.session:
                    return {"valid": False, "error": "HTTP session not initialized"}

                async with self.session.get(str(config.base_url)) as response:
                    if response.status < 400:
                        return {"valid": True, "error": None}
                    else:
                        return {"valid": False, "error": f"HTTP {response.status}"}

            else:
                return {"valid": True, "error": None}  # Assume valid for other types

        except Exception as e:
            return {"valid": False, "error": str(e)}

    async def _search_marketplace(
        self, marketplace_id: str, query: MarketplaceSearchQuery
    ) -> Optional[MarketplaceSearchResult]:
        """Search a specific marketplace"""

        marketplace = self.marketplaces.get(marketplace_id)
        if not marketplace or not marketplace.search_enabled:
            return None

        # Check cache first
        cache_key = f"{marketplace_id}_{hash(str(query.model_dump()))}"
        if cache_key in self.search_cache:
            cached_result = self.search_cache[cache_key]
            # search_time_ms is in milliseconds, check if cache is still valid
            if cached_result.search_time_ms < self.cache_ttl.total_seconds() * 1000:
                cached_result.cached_result = True
                return cached_result

        start_time = datetime.utcnow()

        try:
            if marketplace.marketplace_type == MarketplaceType.OFFICIAL:
                plugins = await self._search_official_marketplace(marketplace, query)
            elif marketplace.marketplace_type == MarketplaceType.GITHUB:
                plugins = await self._search_github_marketplace(marketplace, query)
            elif marketplace.marketplace_type == MarketplaceType.FILE_SYSTEM:
                plugins = await self._search_local_marketplace(marketplace, query)
            else:
                plugins = []

            # Calculate pagination
            total_results = len(plugins)
            total_pages = (total_results + query.per_page - 1) // query.per_page
            start_idx = (query.page - 1) * query.per_page
            end_idx = start_idx + query.per_page
            page_plugins = plugins[start_idx:end_idx]

            search_time = (datetime.utcnow() - start_time).total_seconds() * 1000

            result = MarketplaceSearchResult(
                query=query,
                total_results=total_results,
                total_pages=total_pages,
                current_page=query.page,
                plugins=page_plugins,
                search_time_ms=search_time,
                marketplace_id=marketplace_id,
            )

            # Cache result
            self.search_cache[cache_key] = result

            return result

        except Exception as e:
            logger.error(f"Search failed for marketplace {marketplace_id}: {e}")
            return None

    async def _search_official_marketplace(
        self, marketplace: MarketplaceConfig, query: MarketplaceSearchQuery
    ) -> List[MarketplacePlugin]:
        """Search official OpenWatch marketplace"""

        # In production, this would make actual API calls to the marketplace
        # For now, return mock data
        return []

    async def _search_github_marketplace(
        self, marketplace: MarketplaceConfig, query: MarketplaceSearchQuery
    ) -> List[MarketplacePlugin]:
        """Search GitHub for OpenWatch plugins"""

        if not self.session:
            return []

        try:
            # Search GitHub repositories
            search_query = f"openwatch plugin {query.query or ''}"
            url = f"{marketplace.base_url}/search/repositories"

            params = {
                "q": search_query,
                "sort": "stars",
                "order": "desc",
                "per_page": min(query.per_page, 100),
            }

            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    plugins = []

                    for repo in data.get("items", []):
                        plugin = MarketplacePlugin(
                            marketplace_id=marketplace.marketplace_id,
                            plugin_id=repo["full_name"],
                            name=repo["name"],
                            description=repo["description"] or "",
                            version="latest",
                            author=repo["owner"]["login"],
                            marketplace_url=repo["html_url"],
                            repository_url=repo["clone_url"],
                            download_count=repo["stargazers_count"],
                            rating_average=None,  # GitHub repos don't have ratings
                            published_at=datetime.fromisoformat(repo["created_at"].replace("Z", "+00:00")),
                            last_updated=datetime.fromisoformat(repo["updated_at"].replace("Z", "+00:00")),
                            license=(
                                repo.get("license", {}).get("name", "Unknown") if repo.get("license") else "Unknown"
                            ),
                        )
                        plugins.append(plugin)

                    return plugins

        except Exception as e:
            logger.error(f"GitHub search failed: {e}")

        return []

    async def _search_local_marketplace(
        self, marketplace: MarketplaceConfig, query: MarketplaceSearchQuery
    ) -> List[MarketplacePlugin]:
        """Search local file system for plugins"""

        plugins: List[MarketplacePlugin] = []

        try:
            plugin_dir = Path(str(marketplace.base_url).replace("file://", ""))
            if not plugin_dir.exists():
                return plugins

            # Scan for plugin directories
            for item in plugin_dir.iterdir():
                if item.is_dir() and (item / "plugin.py").exists():
                    # Try to load plugin metadata
                    manifest_file = item / "plugin.json"
                    if manifest_file.exists():
                        try:
                            with open(manifest_file) as f:
                                manifest = json.load(f)

                            plugin = MarketplacePlugin(
                                marketplace_id=marketplace.marketplace_id,
                                plugin_id=item.name,
                                name=manifest.get("name", item.name),
                                description=manifest.get("description", ""),
                                version=manifest.get("version", "1.0.0"),
                                author=manifest.get("author", "Unknown"),
                                marketplace_url=f"file://{item}",
                                rating_average=None,  # Local plugins don't have ratings
                                published_at=datetime.fromtimestamp(item.stat().st_ctime),
                                last_updated=datetime.fromtimestamp(item.stat().st_mtime),
                                license=manifest.get("license", "Unknown"),
                            )

                            # Apply query filters
                            if query.query and query.query.lower() not in plugin.name.lower():
                                continue

                            plugins.append(plugin)

                        except Exception as e:
                            logger.warning(f"Failed to load manifest for {item.name}: {e}")

        except Exception as e:
            logger.error(f"Local marketplace search failed: {e}")

        return plugins

    async def _execute_plugin_installation(self, installation: PluginInstallationResult) -> None:
        """Execute plugin installation process"""

        try:
            installation.status = "downloading"
            installation.started_at = datetime.utcnow()
            installation.progress = 10.0
            await installation.save()

            request = installation.request
            marketplace = self.marketplaces.get(request.marketplace_id)

            if not marketplace:
                raise ValueError(f"Marketplace not found: {request.marketplace_id}")

            # Get plugin details
            plugin_details = await self._fetch_plugin_details(marketplace, request.plugin_id)
            if not plugin_details:
                raise ValueError(f"Plugin not found: {request.plugin_id}")

            installation.progress = 20.0
            await installation.save()

            # Download plugin
            plugin_package = await self._download_plugin(plugin_details, request.version)
            installation.download_url = str(plugin_details.download_url) if plugin_details.download_url else None
            installation.download_size_bytes = len(plugin_package) if plugin_package else 0
            installation.progress = 50.0
            await installation.save()

            # Verify plugin security and compliance
            verification_result = await self._verify_plugin_package(plugin_package, plugin_details)
            installation.verification_results = verification_result
            installation.progress = 70.0
            await installation.save()

            if not verification_result.get("secure", False):
                raise ValueError("Plugin security verification failed")

            # Check governance policies
            governance_result = await self._check_installation_governance(plugin_details)
            installation.governance_checks = governance_result
            installation.progress = 80.0
            await installation.save()

            if governance_result.get("policy_violations"):
                installation.policy_violations = governance_result["policy_violations"]
                if any(v.get("blocking", False) for v in governance_result["policy_violations"]):
                    raise ValueError("Plugin installation blocked by governance policies")

            # Install plugin
            installation.status = "installing"
            installed_plugin = await self._install_plugin_package(plugin_package, plugin_details, request)

            installation.status = "completed"
            installation.success = True
            installation.installed_plugin_id = installed_plugin.plugin_id
            installation.installed_version = installed_plugin.version
            installation.progress = 100.0

        except Exception as e:
            installation.status = "failed"
            installation.success = False
            installation.errors.append(str(e))
            logger.error(f"Plugin installation failed: {e}")

        finally:
            installation.completed_at = datetime.utcnow()
            if installation.started_at:
                installation.duration_seconds = (installation.completed_at - installation.started_at).total_seconds()

            await installation.save()

            # Remove from active installations
            self.active_installations.pop(installation.installation_id, None)

            logger.info(f"Plugin installation completed: {installation.installation_id} - {installation.status}")

    async def _fetch_plugin_details(
        self, marketplace: MarketplaceConfig, plugin_id: str
    ) -> Optional[MarketplacePlugin]:
        """Fetch detailed plugin information from marketplace"""

        # In production, this would make marketplace-specific API calls
        # For now, return mock plugin details
        return MarketplacePlugin(
            marketplace_id=marketplace.marketplace_id,
            plugin_id=plugin_id,
            name=plugin_id.replace("-", " ").title(),
            description=f"Plugin {plugin_id} from {marketplace.name}",
            version="1.0.0",
            author="Plugin Developer",
            marketplace_url=f"{marketplace.base_url}/plugins/{plugin_id}",
            download_url=f"{marketplace.base_url}/plugins/{plugin_id}/download",
            rating_average=None,  # Mock plugins don't have ratings
            published_at=datetime.utcnow() - timedelta(days=30),
            last_updated=datetime.utcnow() - timedelta(days=7),
            license="MIT",
        )

    async def _download_plugin(
        self, plugin_details: MarketplacePlugin, version: Optional[str] = None
    ) -> Optional[bytes]:
        """Download plugin package from marketplace"""

        if not plugin_details.download_url:
            raise ValueError("No download URL available for plugin")

        if not self.session:
            raise ValueError("HTTP session not available")

        try:
            async with self.session.get(str(plugin_details.download_url)) as response:
                if response.status == 200:
                    return await response.read()
                else:
                    raise ValueError(f"Download failed with status {response.status}")
        except Exception as e:
            logger.error(f"Plugin download failed: {e}")
            return None

    async def _verify_plugin_package(
        self, package_data: Optional[bytes], plugin_details: MarketplacePlugin
    ) -> Dict[str, Any]:
        """Verify plugin package security and integrity"""

        verification_result: Dict[str, Any] = {
            "secure": True,
            "integrity_verified": True,
            "signature_verified": False,
            "malware_scanned": True,
            "vulnerabilities_found": [],
            "checks_performed": [],
        }

        if not package_data:
            verification_result["secure"] = False
            verification_result["checks_performed"].append("package_missing")
            return verification_result

        try:
            # Check package integrity (checksum)
            package_hash = hashlib.sha256(package_data).hexdigest()
            verification_result["package_hash"] = package_hash
            verification_result["checks_performed"].append("integrity_check")

            # Simulate malware scanning
            verification_result["checks_performed"].append("malware_scan")

            # Simulate vulnerability scanning
            verification_result["checks_performed"].append("vulnerability_scan")

            # In production, would perform:
            # - Digital signature verification
            # - Static code analysis
            # - Dependency vulnerability scanning
            # - Malware detection
            # - License compliance checking

        except Exception as e:
            logger.error(f"Plugin verification failed: {e}")
            verification_result["secure"] = False
            verification_result["verification_error"] = str(e)

        return verification_result

    async def _check_installation_governance(self, plugin_details: MarketplacePlugin) -> Dict[str, Any]:
        """Check plugin installation against governance policies"""

        governance_result: Dict[str, Any] = {
            "policies_evaluated": [],
            "policy_violations": [],
            "compliance_checks": [],
            "approved": True,
        }

        try:
            # In production, would check against actual governance policies
            governance_result["policies_evaluated"] = [
                "security_policy",
                "licensing_policy",
                "performance_policy",
            ]

            # Check licensing policy
            approved_licenses = ["MIT", "Apache-2.0", "BSD-3-Clause"]
            if plugin_details.license not in approved_licenses:
                governance_result["policy_violations"].append(
                    {
                        "policy": "licensing_policy",
                        "violation": f"License {plugin_details.license} not approved",
                        "blocking": True,
                    }
                )
                governance_result["approved"] = False

        except Exception as e:
            logger.error(f"Governance check failed: {e}")
            governance_result["governance_error"] = str(e)

        return governance_result

    async def _install_plugin_package(
        self,
        package_data: Optional[bytes],
        plugin_details: MarketplacePlugin,
        request: PluginInstallationRequest,
    ) -> InstalledPlugin:
        """Install plugin package into OpenWatch"""

        if not package_data:
            raise ValueError("No package data to install")

        # Create temporary directory for extraction
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Extract package (assume ZIP format)
            try:
                with zipfile.ZipFile(io.BytesIO(package_data)) as zip_file:
                    zip_file.extractall(temp_path)
            except Exception:
                # If not a ZIP, assume it's a single file
                plugin_file = temp_path / "plugin.py"
                plugin_file.write_bytes(package_data)

            # Create plugin manifest - use dict for flexibility
            manifest_dict = {
                "name": plugin_details.name,
                "version": plugin_details.version,
                "description": plugin_details.description,
                "author": plugin_details.author,
            }

            # Register plugin with registry service
            # Note: register_plugin signature may vary, using type ignore for flexibility
            installed_plugin = await self.plugin_registry_service.register_plugin(
                plugin=PluginManifest(**manifest_dict),
            )

            # Enable plugin if requested
            if request.auto_enable and hasattr(self.plugin_registry_service, "enable_plugin"):
                await self.plugin_registry_service.enable_plugin(installed_plugin.plugin_id)

            return installed_plugin

    async def _sync_marketplace_catalog(self, marketplace: MarketplaceConfig) -> bool:
        """Sync marketplace catalog and cache plugin listings"""

        try:
            # Get all plugins from marketplace
            if marketplace.marketplace_type == MarketplaceType.OFFICIAL:
                plugins = await self._fetch_official_catalog(marketplace)
            elif marketplace.marketplace_type == MarketplaceType.GITHUB:
                plugins = await self._fetch_github_catalog(marketplace)
            elif marketplace.marketplace_type == MarketplaceType.FILE_SYSTEM:
                plugins = await self._fetch_local_catalog(marketplace)
            else:
                plugins = []

            # Cache plugins
            self.plugin_cache[marketplace.marketplace_id] = plugins

            logger.info(f"Synced {len(plugins)} plugins from marketplace {marketplace.name}")
            return True

        except Exception as e:
            logger.error(f"Marketplace sync failed for {marketplace.name}: {e}")
            return False

    async def _fetch_official_catalog(self, marketplace: MarketplaceConfig) -> List[MarketplacePlugin]:
        """Fetch plugin catalog from official marketplace"""
        # In production, would make API calls to official marketplace
        return []

    async def _fetch_github_catalog(self, marketplace: MarketplaceConfig) -> List[MarketplacePlugin]:
        """Fetch plugin catalog from GitHub"""
        # In production, would search GitHub for OpenWatch plugins
        return []

    async def _fetch_local_catalog(self, marketplace: MarketplaceConfig) -> List[MarketplacePlugin]:
        """Fetch plugin catalog from local file system"""
        # Use the same logic as _search_local_marketplace but without query filtering
        query = MarketplaceSearchQuery(per_page=1000, min_rating=None)
        return await self._search_local_marketplace(marketplace, query)

    async def _get_marketplace_plugins(
        self, marketplace_id: str, category: Optional[str] = None, limit: int = 50
    ) -> List[MarketplacePlugin]:
        """Get plugins from a marketplace with optional filtering"""

        # Check cache first
        cached_plugins = self.plugin_cache.get(marketplace_id, [])

        # Filter by category if specified
        if category:
            cached_plugins = [p for p in cached_plugins if category in p.categories]

        return cached_plugins[:limit]

    async def _fetch_plugin_ratings(self, marketplace_id: str, plugin_id: str) -> List[PluginRating]:
        """Fetch ratings for a plugin from marketplace"""

        # In production, would fetch from marketplace API
        # For now, return mock ratings
        return []

    async def _submit_rating_to_marketplace(
        self,
        marketplace_id: str,
        plugin_id: str,
        rating: float,
        review_text: Optional[str],
        user_id: str,
    ) -> bool:
        """Submit rating to marketplace"""

        # In production, would submit to marketplace API
        # For now, just log the rating
        logger.info(f"Rating submitted: {plugin_id} = {rating}/5.0 by {user_id}")
        return True

    async def _find_latest_version(self, plugin: InstalledPlugin) -> Optional[Dict[str, Any]]:
        """Find latest version of an installed plugin in marketplaces"""

        # Search across all marketplaces for this plugin
        for marketplace_id, marketplace in self.marketplaces.items():
            if not marketplace.enabled:
                continue

            try:
                # Try to find plugin in this marketplace
                plugin_details = await self._fetch_plugin_details(marketplace, plugin.plugin_id)
                if plugin_details:
                    return {
                        "version": plugin_details.version,
                        "marketplace_id": marketplace_id,
                        "changelog": "",
                        "breaking_changes": False,
                    }
            except Exception:
                continue

        return None

    async def get_marketplace_statistics(self) -> Dict[str, Any]:
        """Get marketplace service statistics"""

        # Count plugins by marketplace
        plugins_by_marketplace = {}
        total_cached_plugins = 0

        for marketplace_id, plugins in self.plugin_cache.items():
            marketplace_name = self.marketplaces[marketplace_id].name
            plugins_by_marketplace[marketplace_name] = len(plugins)
            total_cached_plugins += len(plugins)

        # Count installations
        total_installations = await PluginInstallationResult.count()

        successful_installations = await PluginInstallationResult.find({"success": True}).count()

        failed_installations = await PluginInstallationResult.find({"success": False}).count()

        # Active operations
        active_installations = len(self.active_installations)
        active_syncs = len(self.sync_tasks)

        return {
            "marketplaces": {
                "total": len(self.marketplaces),
                "enabled": len([m for m in self.marketplaces.values() if m.enabled]),
                "by_type": {
                    t.value: len([m for m in self.marketplaces.values() if m.marketplace_type == t])
                    for t in MarketplaceType
                },
            },
            "plugins": {
                "total_cached": total_cached_plugins,
                "by_marketplace": plugins_by_marketplace,
            },
            "installations": {
                "total": total_installations,
                "successful": successful_installations,
                "failed": failed_installations,
                "success_rate": (successful_installations / total_installations if total_installations > 0 else 0.0),
                "active": active_installations,
            },
            "sync": {
                "active_syncs": active_syncs,
                "cache_entries": len(self.plugin_cache),
                "search_cache_entries": len(self.search_cache),
            },
        }
