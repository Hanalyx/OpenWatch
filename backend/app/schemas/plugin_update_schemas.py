"""
Plugin Update Schemas for Phase 5

Pydantic models for plugin update API endpoints.

Part of Phase 5: Control Plane (Aegis Integration Plan)
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class PluginUpdateStatus(str, Enum):
    """Status of a plugin update operation."""

    PENDING = "pending"
    DOWNLOADING = "downloading"
    VERIFYING = "verifying"
    INSTALLING = "installing"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class ChangeType(str, Enum):
    """Type of change in an update."""

    ADDED = "added"
    UPDATED = "updated"
    FIXED = "fixed"
    REMOVED = "removed"
    SECURITY = "security"
    DEPRECATED = "deprecated"


# =============================================================================
# Update Check Schemas
# =============================================================================


class VersionChange(BaseModel):
    """A single change in a version release."""

    type: ChangeType
    description: str
    rule_ids: Optional[List[str]] = None


class VersionInfo(BaseModel):
    """Information about a specific version."""

    version: str
    released: datetime
    changes: List[VersionChange] = []
    breaking_changes: List[str] = []
    min_openwatch_version: Optional[str] = None
    download_size_mb: Optional[float] = None


class UpdateCheckResponse(BaseModel):
    """Response from checking for updates."""

    update_available: bool
    current_version: str
    latest_version: Optional[str] = None
    latest_stable_version: Optional[str] = None
    versions: List[VersionInfo] = []
    changes: List[VersionChange] = []
    min_openwatch_version: Optional[str] = None
    openwatch_compatible: bool = True
    compatibility_message: Optional[str] = None
    checked_at: datetime
    error: Optional[str] = None


# =============================================================================
# Update Install Schemas
# =============================================================================


class UpdateInstallRequest(BaseModel):
    """Request to install a plugin update."""

    version: str = Field(..., description="Version to install")
    force: bool = Field(default=False, description="Force update even if same version")
    skip_backup: bool = Field(default=False, description="Skip backup (not recommended)")


class UpdateInstallResponse(BaseModel):
    """Response from installing an update."""

    success: bool
    update_id: Optional[UUID] = None
    from_version: str
    to_version: str
    status: PluginUpdateStatus
    stats: Optional[Dict[str, Any]] = None
    changes: List[VersionChange] = []
    backup_path: Optional[str] = None
    error: Optional[str] = None
    started_at: datetime
    completed_at: Optional[datetime] = None


class UpdateProgressResponse(BaseModel):
    """Response with update progress."""

    update_id: UUID
    status: PluginUpdateStatus
    progress: int = Field(..., ge=0, le=100)
    current_step: str
    message: Optional[str] = None
    started_at: datetime
    elapsed_seconds: int


# =============================================================================
# Update History Schemas
# =============================================================================


class UpdateHistoryItem(BaseModel):
    """A single update in history."""

    id: UUID
    from_version: str
    to_version: str
    status: PluginUpdateStatus
    changes: List[VersionChange] = []
    initiated_by: int
    created_at: datetime
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None


class UpdateHistoryResponse(BaseModel):
    """Response with update history."""

    items: List[UpdateHistoryItem]
    total: int
    page: int
    per_page: int


# =============================================================================
# Changelog Schemas
# =============================================================================


class ChangelogResponse(BaseModel):
    """Response with plugin changelog."""

    plugin_id: str
    current_version: str
    changelog_markdown: str
    versions: List[VersionInfo] = []


# =============================================================================
# Notification Schemas
# =============================================================================


class UpdateNotification(BaseModel):
    """Update availability notification."""

    id: UUID
    plugin_id: str
    plugin_name: str
    current_version: str
    available_version: str
    changes: List[VersionChange] = []
    breaking_changes: List[str] = []
    min_openwatch_version: Optional[str] = None
    dismissed: bool = False
    checked_at: datetime
    created_at: datetime


class UpdateNotificationListResponse(BaseModel):
    """Response with update notifications."""

    notifications: List[UpdateNotification]
    total: int


class DismissNotificationRequest(BaseModel):
    """Request to dismiss an update notification."""

    notification_id: UUID


# =============================================================================
# Offline Update Schemas
# =============================================================================


class OfflineUpdateRequest(BaseModel):
    """Request for offline update installation.

    Used when package, signature, and checksum are uploaded manually.
    """

    package_checksum: str = Field(..., description="Expected SHA256 checksum")


class OfflineUpdateResponse(BaseModel):
    """Response from offline update installation."""

    success: bool
    update_id: Optional[UUID] = None
    from_version: str
    to_version: str
    verified: bool
    error: Optional[str] = None


# =============================================================================
# Plugin Registry Schemas
# =============================================================================


class PluginInfo(BaseModel):
    """Information about a registered plugin."""

    plugin_id: str
    name: str
    version: str
    description: Optional[str] = None
    author: Optional[str] = None
    homepage_url: Optional[str] = None
    capabilities: List[str] = []
    is_builtin: bool = False
    is_enabled: bool = True
    health_status: Optional[str] = None
    last_health_check: Optional[datetime] = None
    installed_at: datetime
    updated_at: datetime


class PluginListResponse(BaseModel):
    """Response with list of registered plugins."""

    plugins: List[PluginInfo]
    total: int


class PluginHealthResponse(BaseModel):
    """Health check response for a plugin."""

    plugin_id: str
    healthy: bool
    version: str
    rules_loaded: int
    frameworks_supported: List[str]
    last_check: datetime
    details: Dict[str, Any] = {}
    error: Optional[str] = None
