"""
Plugin Marketplace Models

Defines data models, enumerations, and schemas for the plugin marketplace
integration system including marketplace configurations, plugin metadata,
installation tracking, and search functionality.

This module follows OpenWatch security and documentation standards:
- All models use Pydantic for validation and serialization
- Beanie Documents for MongoDB persistence where needed
- Comprehensive type hints for IDE support
- Defensive validation with constraints

Security Considerations:
- HttpUrl validation prevents malformed URLs
- Rating constraints (1.0-5.0) prevent data manipulation
- Installation tracking enables audit trails
- Governance checks integrate with security policies
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl

# ============================================================================
# MARKETPLACE ENUMERATIONS
# ============================================================================


class MarketplaceType(str, Enum):
    """
    Types of plugin marketplaces supported by OpenWatch.

    Each marketplace type has different discovery mechanisms,
    authentication requirements, and installation workflows.

    Attributes:
        OFFICIAL: Official OpenWatch marketplace with verified plugins
        GITHUB: GitHub repositories containing plugin code
        DOCKER_HUB: Docker Hub container registry for containerized plugins
        NPM: NPM package registry for JavaScript/TypeScript plugins
        PYPI: Python Package Index for Python-based plugins
        CUSTOM: Custom marketplace/repository with API compatibility
        FILE_SYSTEM: Local file system directory for development/testing
    """

    OFFICIAL = "official"
    GITHUB = "github"
    DOCKER_HUB = "docker_hub"
    NPM = "npm"
    PYPI = "pypi"
    CUSTOM = "custom"
    FILE_SYSTEM = "file_system"


class PluginSource(str, Enum):
    """
    Plugin source types indicating where a plugin was obtained.

    Used for tracking plugin provenance and applying appropriate
    security policies based on source trust level.

    Attributes:
        MARKETPLACE: Obtained from a registered marketplace
        REPOSITORY: Cloned from a git repository
        REGISTRY: Downloaded from a package registry
        LOCAL: Installed from local file system
        BUNDLED: Bundled with OpenWatch installation
    """

    MARKETPLACE = "marketplace"
    REPOSITORY = "repository"
    REGISTRY = "registry"
    LOCAL = "local"
    BUNDLED = "bundled"


# ============================================================================
# RATING AND REVIEW MODELS
# ============================================================================


class PluginRating(BaseModel):
    """
    Plugin rating and review submitted by users.

    Captures user feedback for plugins including numeric ratings,
    text reviews, and verification status to ensure authentic feedback.

    Attributes:
        rating_id: Unique identifier for this rating
        plugin_id: ID of the rated plugin
        user_id: ID of the user who submitted the rating
        rating: Numeric rating from 1.0 to 5.0
        review_text: Optional text review accompanying the rating
        created_at: Timestamp when rating was submitted
        updated_at: Timestamp when rating was last modified
        helpful_votes: Count of users who found this review helpful
        verified_purchase: Whether user obtained plugin through purchase
        verified_usage: Whether user has actually used the plugin
    """

    rating_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this rating",
    )
    plugin_id: str = Field(
        ...,
        description="ID of the plugin being rated",
    )
    user_id: str = Field(
        ...,
        description="ID of the user submitting the rating",
    )

    # Rating value with strict bounds to prevent manipulation
    rating: float = Field(
        ...,
        ge=1.0,
        le=5.0,
        description="Numeric rating from 1.0 (worst) to 5.0 (best)",
    )
    review_text: Optional[str] = Field(
        default=None,
        description="Optional text review accompanying the rating",
    )

    # Metadata for tracking and display
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Timestamp when rating was submitted",
    )
    updated_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Timestamp when rating was last modified",
    )
    helpful_votes: int = Field(
        default=0,
        ge=0,
        description="Count of users who found this review helpful",
    )

    # Verification flags for authenticity
    verified_purchase: bool = Field(
        default=False,
        description="Whether user obtained plugin through purchase",
    )
    verified_usage: bool = Field(
        default=False,
        description="Whether user has actually used the plugin",
    )


# ============================================================================
# MARKETPLACE PLUGIN MODELS
# ============================================================================


class MarketplacePlugin(BaseModel):
    """
    Plugin information from marketplace listing.

    Comprehensive representation of a plugin as listed in a marketplace,
    including metadata, statistics, verification status, and licensing.

    Attributes:
        marketplace_id: ID of the source marketplace
        plugin_id: Unique plugin identifier within marketplace
        name: Human-readable plugin name
        description: Plugin description and purpose
        version: Current version string (semver)
        author: Plugin author name or organization
        publisher: Publisher if different from author
        maintainer: Current maintainer if different from author
        tags: Searchable tags for discovery
        categories: Plugin categories for browsing
        supported_platforms: List of supported platforms
        marketplace_url: URL to plugin page on marketplace
        download_url: Direct download URL for plugin package
        documentation_url: URL to plugin documentation
        repository_url: URL to source code repository
        download_count: Total download count
        rating_average: Average user rating (1.0-5.0)
        rating_count: Total number of ratings
        verified_publisher: Whether publisher is verified
        security_scanned: Whether plugin passed security scanning
        compliance_certified: Whether plugin is compliance certified
        published_at: Initial publication timestamp
        last_updated: Last update timestamp
        deprecated: Whether plugin is deprecated
        dependencies: Required plugin dependencies (id -> version)
        conflicts: List of conflicting plugin IDs
        license: License identifier (e.g., MIT, Apache-2.0)
        price: Price in USD (0 for free, None for not applicable)
        trial_available: Whether a trial version is available
    """

    marketplace_id: str = Field(
        ...,
        description="ID of the source marketplace",
    )
    plugin_id: str = Field(
        ...,
        description="Unique plugin identifier within marketplace",
    )
    name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Human-readable plugin name",
    )
    description: str = Field(
        ...,
        description="Plugin description and purpose",
    )
    version: str = Field(
        ...,
        description="Current version string (semver format preferred)",
    )

    # Author and publisher information
    author: str = Field(
        ...,
        description="Plugin author name or organization",
    )
    publisher: Optional[str] = Field(
        default=None,
        description="Publisher if different from author",
    )
    maintainer: Optional[str] = Field(
        default=None,
        description="Current maintainer if different from author",
    )

    # Discovery metadata
    tags: List[str] = Field(
        default_factory=list,
        description="Searchable tags for discovery",
    )
    categories: List[str] = Field(
        default_factory=list,
        description="Plugin categories for browsing",
    )
    supported_platforms: List[str] = Field(
        default_factory=list,
        description="List of supported platforms (e.g., linux, windows)",
    )

    # URLs for marketplace integration
    marketplace_url: HttpUrl = Field(
        ...,
        description="URL to plugin page on marketplace",
    )
    download_url: Optional[HttpUrl] = Field(
        default=None,
        description="Direct download URL for plugin package",
    )
    documentation_url: Optional[HttpUrl] = Field(
        default=None,
        description="URL to plugin documentation",
    )
    repository_url: Optional[HttpUrl] = Field(
        default=None,
        description="URL to source code repository",
    )

    # Statistics for popularity and quality assessment
    download_count: int = Field(
        default=0,
        ge=0,
        description="Total download count",
    )
    rating_average: Optional[float] = Field(
        default=None,
        ge=1.0,
        le=5.0,
        description="Average user rating (1.0-5.0)",
    )
    rating_count: int = Field(
        default=0,
        ge=0,
        description="Total number of ratings",
    )

    # Verification and trust indicators
    verified_publisher: bool = Field(
        default=False,
        description="Whether publisher is verified by marketplace",
    )
    security_scanned: bool = Field(
        default=False,
        description="Whether plugin passed security scanning",
    )
    compliance_certified: bool = Field(
        default=False,
        description="Whether plugin is compliance certified",
    )

    # Lifecycle information
    published_at: datetime = Field(
        ...,
        description="Initial publication timestamp",
    )
    last_updated: datetime = Field(
        ...,
        description="Last update timestamp",
    )
    deprecated: bool = Field(
        default=False,
        description="Whether plugin is deprecated",
    )

    # Dependency management
    dependencies: Dict[str, str] = Field(
        default_factory=dict,
        description="Required plugin dependencies (plugin_id -> version_constraint)",
    )
    conflicts: List[str] = Field(
        default_factory=list,
        description="List of conflicting plugin IDs",
    )

    # Licensing and pricing
    license: str = Field(
        ...,
        description="License identifier (e.g., MIT, Apache-2.0)",
    )
    price: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Price in USD (0 for free, None for not applicable)",
    )
    trial_available: bool = Field(
        default=False,
        description="Whether a trial version is available",
    )


# ============================================================================
# MARKETPLACE CONFIGURATION
# ============================================================================


class MarketplaceConfig(BaseModel):
    """
    Marketplace configuration for connecting to plugin sources.

    Defines connection settings, authentication, capabilities,
    and policies for a registered marketplace.

    Attributes:
        marketplace_id: Unique marketplace identifier
        name: Human-readable marketplace name
        marketplace_type: Type of marketplace (official, github, etc.)
        base_url: Base URL for marketplace API
        api_key: Optional API key for authentication
        username: Optional username for authentication
        password: Optional password for authentication
        search_enabled: Whether search is supported
        browse_enabled: Whether browsing is supported
        categories_supported: Whether categories are supported
        auto_install_enabled: Whether automatic installation is enabled
        auto_update_enabled: Whether automatic updates are enabled
        security_verification_required: Whether security verification is required
        sync_interval_hours: Hours between automatic syncs
        last_sync: Timestamp of last sync
        allowed_categories: Whitelist of allowed categories
        blocked_publishers: Blacklist of blocked publishers
        minimum_rating: Minimum rating for plugin visibility
        enabled: Whether marketplace is active
        created_at: Timestamp when marketplace was added
        priority: Priority for marketplace ordering (higher = preferred)
    """

    marketplace_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique marketplace identifier",
    )
    name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Human-readable marketplace name",
    )
    marketplace_type: MarketplaceType = Field(
        ...,
        description="Type of marketplace (official, github, etc.)",
    )

    # Connection settings
    base_url: HttpUrl = Field(
        ...,
        description="Base URL for marketplace API",
    )
    api_key: Optional[str] = Field(
        default=None,
        description="Optional API key for authentication",
    )
    username: Optional[str] = Field(
        default=None,
        description="Optional username for authentication",
    )
    password: Optional[str] = Field(
        default=None,
        description="Optional password for authentication",
    )

    # Capability flags
    search_enabled: bool = Field(
        default=True,
        description="Whether search is supported",
    )
    browse_enabled: bool = Field(
        default=True,
        description="Whether browsing is supported",
    )
    categories_supported: bool = Field(
        default=True,
        description="Whether categories are supported",
    )

    # Installation settings
    auto_install_enabled: bool = Field(
        default=False,
        description="Whether automatic installation is enabled",
    )
    auto_update_enabled: bool = Field(
        default=False,
        description="Whether automatic updates are enabled",
    )
    security_verification_required: bool = Field(
        default=True,
        description="Whether security verification is required before installation",
    )

    # Sync settings
    sync_interval_hours: int = Field(
        default=24,
        ge=1,
        le=168,
        description="Hours between automatic syncs (1-168)",
    )
    last_sync: Optional[datetime] = Field(
        default=None,
        description="Timestamp of last successful sync",
    )

    # Filtering and policy settings
    allowed_categories: List[str] = Field(
        default_factory=list,
        description="Whitelist of allowed categories (empty = all allowed)",
    )
    blocked_publishers: List[str] = Field(
        default_factory=list,
        description="Blacklist of blocked publishers",
    )
    minimum_rating: Optional[float] = Field(
        default=None,
        ge=1.0,
        le=5.0,
        description="Minimum rating for plugin visibility",
    )

    # State and metadata
    enabled: bool = Field(
        default=True,
        description="Whether marketplace is active",
    )
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Timestamp when marketplace was added",
    )
    priority: int = Field(
        default=100,
        ge=0,
        description="Priority for marketplace ordering (higher = preferred)",
    )


# ============================================================================
# INSTALLATION MODELS
# ============================================================================


class PluginInstallationRequest(BaseModel):
    """
    Plugin installation request from marketplace.

    Captures all parameters needed to install a plugin from a marketplace,
    including version constraints, installation options, and approval workflow.

    Attributes:
        request_id: Unique identifier for this installation request
        marketplace_id: Source marketplace ID
        plugin_id: ID of the plugin to install
        version: Specific version to install (None = latest)
        auto_enable: Whether to enable plugin after installation
        install_dependencies: Whether to install required dependencies
        force_reinstall: Whether to reinstall if already installed
        requested_by: User ID of requester
        requested_at: Timestamp of request
        initial_config: Initial configuration to apply after installation
        requires_approval: Whether approval workflow is required
        approved: Whether request has been approved
        approved_by: User ID of approver
        approved_at: Timestamp of approval
    """

    request_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this installation request",
    )
    marketplace_id: str = Field(
        ...,
        description="Source marketplace ID",
    )
    plugin_id: str = Field(
        ...,
        description="ID of the plugin to install",
    )
    version: Optional[str] = Field(
        default=None,
        description="Specific version to install (None = latest)",
    )

    # Installation options
    auto_enable: bool = Field(
        default=True,
        description="Whether to enable plugin after installation",
    )
    install_dependencies: bool = Field(
        default=True,
        description="Whether to install required dependencies",
    )
    force_reinstall: bool = Field(
        default=False,
        description="Whether to reinstall if already installed",
    )

    # User context
    requested_by: str = Field(
        ...,
        description="User ID of requester",
    )
    requested_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Timestamp of request",
    )

    # Configuration
    initial_config: Dict[str, Any] = Field(
        default_factory=dict,
        description="Initial configuration to apply after installation",
    )

    # Approval workflow
    requires_approval: bool = Field(
        default=True,
        description="Whether approval workflow is required",
    )
    approved: bool = Field(
        default=False,
        description="Whether request has been approved",
    )
    approved_by: Optional[str] = Field(
        default=None,
        description="User ID of approver",
    )
    approved_at: Optional[datetime] = Field(
        default=None,
        description="Timestamp of approval",
    )


class PluginInstallationResult(BaseModel):
    """
    Plugin installation result tracking.

    Tracks installation history, status, and outcomes
    including verification and governance checks.

    Attributes:
        installation_id: Unique identifier for this installation
        request: Original installation request
        status: Current installation status
        progress: Installation progress percentage (0-100)
        started_at: Timestamp when installation started
        completed_at: Timestamp when installation completed
        duration_seconds: Total duration in seconds
        success: Whether installation succeeded
        installed_plugin_id: ID of installed plugin (if successful)
        installed_version: Version installed (if successful)
        errors: List of error messages encountered
        warnings: List of warning messages generated
        download_url: URL from which plugin was downloaded
        download_size_bytes: Size of downloaded package
        verification_results: Results of security verification
        governance_checks: Results of governance policy checks
        policy_violations: List of policy violations found
    """

    installation_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this installation",
    )
    request: PluginInstallationRequest = Field(
        ...,
        description="Original installation request",
    )

    # Installation status tracking
    status: str = Field(
        default="pending",
        description="Current status: pending, downloading, installing, completed, failed",
    )
    progress: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Installation progress percentage (0-100)",
    )

    # Timing information
    started_at: Optional[datetime] = Field(
        default=None,
        description="Timestamp when installation started",
    )
    completed_at: Optional[datetime] = Field(
        default=None,
        description="Timestamp when installation completed",
    )
    duration_seconds: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Total duration in seconds",
    )

    # Results
    success: bool = Field(
        default=False,
        description="Whether installation succeeded",
    )
    installed_plugin_id: Optional[str] = Field(
        default=None,
        description="ID of installed plugin (if successful)",
    )
    installed_version: Optional[str] = Field(
        default=None,
        description="Version installed (if successful)",
    )

    # Error handling
    errors: List[str] = Field(
        default_factory=list,
        description="List of error messages encountered",
    )
    warnings: List[str] = Field(
        default_factory=list,
        description="List of warning messages generated",
    )

    # Download details
    download_url: Optional[str] = Field(
        default=None,
        description="URL from which plugin was downloaded",
    )
    download_size_bytes: Optional[int] = Field(
        default=None,
        ge=0,
        description="Size of downloaded package in bytes",
    )

    # Verification and governance
    verification_results: Dict[str, Any] = Field(
        default_factory=dict,
        description="Results of security verification checks",
    )
    governance_checks: Dict[str, Any] = Field(
        default_factory=dict,
        description="Results of governance policy checks",
    )
    policy_violations: List[str] = Field(
        default_factory=list,
        description="List of policy violations found",
    )


# ============================================================================
# SEARCH MODELS
# ============================================================================


class MarketplaceSearchQuery(BaseModel):
    """
    Marketplace search query parameters.

    Defines search criteria for discovering plugins across marketplaces,
    including text search, filtering, sorting, and pagination.

    Attributes:
        query: Text search query (searches name and description)
        categories: Filter by category list
        tags: Filter by tag list
        author: Filter by author name
        min_rating: Minimum rating filter
        max_price: Maximum price filter
        free_only: Only show free plugins
        verified_only: Only show verified plugins
        sort_by: Sort field (relevance, rating, downloads, updated)
        sort_order: Sort direction (asc, desc)
        page: Page number (1-based)
        per_page: Results per page (1-100)
    """

    query: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Text search query (searches name and description)",
    )
    categories: List[str] = Field(
        default_factory=list,
        description="Filter by category list",
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Filter by tag list",
    )
    author: Optional[str] = Field(
        default=None,
        max_length=255,
        description="Filter by author name",
    )

    # Filtering options
    min_rating: Optional[float] = Field(
        default=None,
        ge=1.0,
        le=5.0,
        description="Minimum rating filter",
    )
    max_price: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Maximum price filter",
    )
    free_only: bool = Field(
        default=False,
        description="Only show free plugins",
    )
    verified_only: bool = Field(
        default=False,
        description="Only show verified plugins",
    )

    # Sorting
    sort_by: str = Field(
        default="relevance",
        description="Sort field: relevance, rating, downloads, updated",
    )
    sort_order: str = Field(
        default="desc",
        description="Sort direction: asc, desc",
    )

    # Pagination
    page: int = Field(
        default=1,
        ge=1,
        description="Page number (1-based)",
    )
    per_page: int = Field(
        default=20,
        ge=1,
        le=100,
        description="Results per page (1-100)",
    )


class MarketplaceSearchResult(BaseModel):
    """
    Marketplace search results container.

    Encapsulates search results from a marketplace query including
    pagination metadata and performance information.

    Attributes:
        query: Original search query
        total_results: Total number of matching plugins
        total_pages: Total number of pages
        current_page: Current page number
        plugins: List of matching plugins on current page
        search_time_ms: Search execution time in milliseconds
        marketplace_id: ID of the searched marketplace
        cached_result: Whether result was served from cache
    """

    query: MarketplaceSearchQuery = Field(
        ...,
        description="Original search query",
    )
    total_results: int = Field(
        ...,
        ge=0,
        description="Total number of matching plugins",
    )
    total_pages: int = Field(
        ...,
        ge=0,
        description="Total number of pages",
    )
    current_page: int = Field(
        ...,
        ge=1,
        description="Current page number",
    )
    plugins: List[MarketplacePlugin] = Field(
        ...,
        description="List of matching plugins on current page",
    )

    # Search metadata
    search_time_ms: float = Field(
        ...,
        ge=0.0,
        description="Search execution time in milliseconds",
    )
    marketplace_id: str = Field(
        ...,
        description="ID of the searched marketplace",
    )
    cached_result: bool = Field(
        default=False,
        description="Whether result was served from cache",
    )
