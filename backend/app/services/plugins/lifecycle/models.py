"""
Plugin Lifecycle Models

Data models for plugin lifecycle management including update strategies,
health status, version information, update plans, and execution records.

These models support:
- Semantic version validation
- Update strategy configuration
- Health check results
- Update execution tracking
- Rollback planning

Security Considerations:
    - Version validation prevents malformed version strings
    - Health scores are bounded (0.0-1.0) to prevent manipulation
    - Update plans include validation steps
    - Rollback conditions are explicitly defined
"""

import logging
import re
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, validator

# Optional semver import - graceful fallback if not installed
try:
    import semver

    SEMVER_AVAILABLE = True
except ImportError:
    semver = None  # type: ignore
    SEMVER_AVAILABLE = False

logger = logging.getLogger(__name__)


# =============================================================================
# LIFECYCLE ENUMS
# =============================================================================


class UpdateStrategy(str, Enum):
    """
    Plugin update deployment strategies.

    Determines how updates are applied to running plugins:
    - IMMEDIATE: Direct update, may cause brief service interruption
    - ROLLING: Gradual deployment, instances updated one at a time
    - BLUE_GREEN: Deploy to new environment, switch traffic
    - CANARY: Gradual traffic shift to test new version
    - MAINTENANCE_WINDOW: Scheduled update during low-traffic periods
    """

    IMMEDIATE = "immediate"
    ROLLING = "rolling"
    BLUE_GREEN = "blue_green"
    CANARY = "canary"
    MAINTENANCE_WINDOW = "maintenance_window"


class PluginHealthStatus(str, Enum):
    """
    Plugin health status levels.

    Status levels from best to worst:
    - HEALTHY: Plugin functioning normally
    - DEGRADED: Some issues but still functional
    - UNHEALTHY: Not functioning properly
    - CRITICAL: Severe issues requiring immediate attention
    - UNKNOWN: Health cannot be determined
    """

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class UpdateStatus(str, Enum):
    """
    Plugin update execution status.

    Status progression for update operations:
    - PENDING: Update is scheduled but not started
    - IN_PROGRESS: Update is currently executing
    - COMPLETED: Update finished successfully
    - FAILED: Update failed to complete
    - ROLLED_BACK: Update was rolled back
    - CANCELLED: Update was cancelled before completion
    """

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    CANCELLED = "cancelled"


# =============================================================================
# VERSION MODELS
# =============================================================================


class PluginVersion(BaseModel):
    """
    Plugin version information.

    Stores comprehensive version metadata including release information,
    compatibility requirements, dependencies, and deprecation status.

    Attributes:
        version: Semantic version string (e.g., "1.2.3").
        release_date: When this version was released.
        changelog: Description of changes in this version.
        min_openwatch_version: Minimum required OpenWatch version.
        max_openwatch_version: Maximum supported OpenWatch version.
        breaking_changes: Whether this version has breaking changes.
        package_url: URL to download the version package.
        package_hash: SHA256 hash of the package for verification.
        package_size: Package size in bytes.
        dependencies: Required dependencies with version constraints.
        conflicts: List of conflicting plugin IDs.
        is_prerelease: Whether this is a pre-release version.
        is_deprecated: Whether this version is deprecated.
        deprecation_date: When deprecation takes effect.

    Example:
        >>> version = PluginVersion(
        ...     version="2.0.0",
        ...     release_date=datetime.utcnow(),
        ...     changelog="Major update with new features",
        ...     breaking_changes=True,
        ... )
    """

    version: str = Field(..., description="Semantic version (e.g., 1.2.3)")
    release_date: datetime
    changelog: str = Field(default="", description="Version changelog")

    # Compatibility requirements
    min_openwatch_version: Optional[str] = None
    max_openwatch_version: Optional[str] = None
    breaking_changes: bool = Field(default=False)

    # Package information
    package_url: Optional[str] = None
    package_hash: Optional[str] = None
    package_size: Optional[int] = None

    # Dependencies and conflicts
    dependencies: Dict[str, str] = Field(default_factory=dict)
    conflicts: List[str] = Field(default_factory=list)

    # Lifecycle metadata
    is_prerelease: bool = Field(default=False)
    is_deprecated: bool = Field(default=False)
    deprecation_date: Optional[datetime] = None

    @validator("version")
    def validate_semver(cls, v: str) -> str:
        """
        Validate semantic versioning format.

        Ensures version string follows semver specification (MAJOR.MINOR.PATCH).
        Pre-release and build metadata are also supported.

        Uses the semver library if available, otherwise falls back to regex
        validation for basic semver format.

        Args:
            v: Version string to validate.

        Returns:
            The validated version string.

        Raises:
            ValueError: If version string is not valid semver.
        """
        if SEMVER_AVAILABLE and semver is not None:
            try:
                semver.VersionInfo.parse(v)
                return v
            except ValueError:
                raise ValueError(f"Invalid semantic version: {v}")
        else:
            # Fallback: Use regex for basic semver validation
            # Pattern: MAJOR.MINOR.PATCH with optional pre-release and build
            semver_pattern = (
                r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
                r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
                r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
                r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
            )
            if not re.match(semver_pattern, v):
                raise ValueError(f"Invalid semantic version: {v}")
            return v


# =============================================================================
# HEALTH CHECK MODELS
# =============================================================================


class PluginHealthCheck(BaseModel):
    """
    Plugin health check result.

    Comprehensive health assessment including connectivity, dependencies,
    resource usage, and performance metrics.

    Attributes:
        plugin_id: ID of the plugin that was checked.
        check_timestamp: When the health check was performed.
        health_status: Overall health status.
        health_score: Numeric health score (0.0-1.0).
        connectivity_check: Whether connectivity check passed.
        dependency_check: Whether dependency check passed.
        resource_check: Whether resource usage is acceptable.
        performance_check: Whether performance is acceptable.
        response_time_ms: Plugin response time in milliseconds.
        memory_usage_mb: Memory usage in megabytes.
        cpu_usage_percent: CPU usage percentage.
        error_rate: Recent error rate (0.0-1.0).
        issues: List of identified issues.
        warnings: List of warnings (non-critical issues).
        remediation_suggestions: Suggested fixes for issues.

    Example:
        >>> health = PluginHealthCheck(
        ...     plugin_id="my-plugin@1.0.0",
        ...     health_status=PluginHealthStatus.HEALTHY,
        ...     health_score=0.95,
        ... )
    """

    plugin_id: str
    check_timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Overall health assessment
    health_status: PluginHealthStatus
    health_score: float = Field(..., ge=0.0, le=1.0, description="Health score 0-1")

    # Individual check results
    connectivity_check: bool = Field(default=True)
    dependency_check: bool = Field(default=True)
    resource_check: bool = Field(default=True)
    performance_check: bool = Field(default=True)

    # Performance metrics
    response_time_ms: Optional[float] = None
    memory_usage_mb: Optional[float] = None
    cpu_usage_percent: Optional[float] = None
    error_rate: Optional[float] = None

    # Issues and recommendations
    issues: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    remediation_suggestions: List[str] = Field(default_factory=list)


# =============================================================================
# UPDATE PLAN MODELS
# =============================================================================


class PluginUpdatePlan(BaseModel):
    """
    Plan for plugin update execution.

    Defines all parameters for updating a plugin including strategy,
    validation steps, rollback conditions, and notifications.

    Attributes:
        update_id: Unique identifier for this update plan.
        plugin_id: ID of the plugin to update.
        current_version: Currently installed version.
        target_version: Version to update to.
        strategy: Deployment strategy to use.
        rollback_enabled: Whether automatic rollback is enabled.
        health_check_enabled: Whether to run health checks.
        scheduled_at: When to execute the update (None = immediate).
        estimated_duration_minutes: Expected update duration.
        maintenance_window_id: Associated maintenance window.
        pre_update_validation: Validation steps before update.
        post_update_validation: Validation steps after update.
        test_cases: Test cases to run after update.
        rollback_conditions: Conditions that trigger rollback.
        rollback_timeout_minutes: Timeout for rollback operation.
        notification_channels: Channels for update notifications.
        notify_on_success: Whether to notify on success.
        notify_on_failure: Whether to notify on failure.

    Example:
        >>> plan = PluginUpdatePlan(
        ...     plugin_id="security-check@1.0.0",
        ...     current_version="1.0.0",
        ...     target_version="1.1.0",
        ...     strategy=UpdateStrategy.ROLLING,
        ... )
    """

    update_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    plugin_id: str

    # Version information
    current_version: str
    target_version: str

    # Update configuration
    strategy: UpdateStrategy
    rollback_enabled: bool = Field(default=True)
    health_check_enabled: bool = Field(default=True)

    # Timing
    scheduled_at: Optional[datetime] = None
    estimated_duration_minutes: int = Field(default=30)
    maintenance_window_id: Optional[str] = None

    # Validation steps
    pre_update_validation: List[str] = Field(default_factory=list)
    post_update_validation: List[str] = Field(default_factory=list)
    test_cases: List[str] = Field(default_factory=list)

    # Rollback configuration
    rollback_conditions: List[str] = Field(default_factory=list)
    rollback_timeout_minutes: int = Field(default=15)

    # Notifications
    notification_channels: List[str] = Field(default_factory=list)
    notify_on_success: bool = Field(default=True)
    notify_on_failure: bool = Field(default=True)


class PluginUpdateExecution(BaseModel):
    """
    Plugin update execution record.

    Stores the complete execution history of a plugin update
    including status, timing, steps, results, and rollback info.

    Attributes:
        execution_id: Unique identifier for this execution.
        update_plan: The update plan being executed.
        status: Current execution status.
        started_at: When execution started.
        completed_at: When execution completed.
        duration_seconds: Total execution duration.
        execution_steps: List of execution step records.
        current_step: Currently executing step.
        success: Whether update was successful.
        rollback_performed: Whether rollback was triggered.
        pre_update_health: Health check before update.
        post_update_health: Health check after update.
        execution_errors: List of errors encountered.
        warnings: List of warnings during execution.
        rollback_version: Version rolled back to (if rolled back).
        rollback_reason: Reason for rollback (if rolled back).
        rollback_completed_at: When rollback completed.
    """

    execution_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    update_plan: PluginUpdatePlan

    # Execution status
    status: UpdateStatus = UpdateStatus.PENDING

    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None

    # Execution steps
    execution_steps: List[Dict[str, Any]] = Field(default_factory=list)
    current_step: Optional[str] = None

    # Results
    success: bool = Field(default=False)
    rollback_performed: bool = Field(default=False)

    # Health checks
    pre_update_health: Optional[PluginHealthCheck] = None
    post_update_health: Optional[PluginHealthCheck] = None

    # Error handling
    execution_errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)

    # Rollback information
    rollback_version: Optional[str] = None
    rollback_reason: Optional[str] = None
    rollback_completed_at: Optional[datetime] = None


# =============================================================================
# ROLLBACK MODELS
# =============================================================================


class PluginRollbackPlan(BaseModel):
    """
    Plan for plugin rollback execution.

    Defines parameters for rolling back a plugin to a previous version
    including validation steps and execution settings.

    Attributes:
        rollback_id: Unique identifier for this rollback plan.
        plugin_id: ID of the plugin to rollback.
        current_version: Currently installed version.
        target_version: Version to rollback to.
        rollback_strategy: Deployment strategy for rollback.
        data_migration_required: Whether data migration is needed.
        pre_rollback_validation: Validation steps before rollback.
        post_rollback_validation: Validation steps after rollback.
        timeout_minutes: Timeout for rollback operation.
        force_rollback: Skip validation checks (emergency only).
        rollback_reason: Reason for initiating rollback.
        triggered_by: User or system that triggered rollback.

    Example:
        >>> rollback = PluginRollbackPlan(
        ...     plugin_id="my-plugin@2.0.0",
        ...     current_version="2.0.0",
        ...     target_version="1.5.0",
        ...     rollback_reason="Health check failed after update",
        ...     triggered_by="system",
        ... )
    """

    rollback_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    plugin_id: str

    # Version information
    current_version: str
    target_version: str

    # Rollback configuration
    rollback_strategy: UpdateStrategy = UpdateStrategy.IMMEDIATE
    data_migration_required: bool = Field(default=False)

    # Validation steps
    pre_rollback_validation: List[str] = Field(default_factory=list)
    post_rollback_validation: List[str] = Field(default_factory=list)

    # Execution settings
    timeout_minutes: int = Field(default=15)
    force_rollback: bool = Field(default=False)

    # Context
    rollback_reason: str
    triggered_by: str
