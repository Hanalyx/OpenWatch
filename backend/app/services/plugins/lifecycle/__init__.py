"""
Plugin Lifecycle Management Subpackage

Provides enterprise-grade plugin lifecycle management including:
- Zero-downtime updates with multiple deployment strategies
- Comprehensive health monitoring and diagnostics
- Automated rollback with configurable conditions
- Version management with semantic versioning
- Update planning and execution tracking

Components:
    - PluginLifecycleService: Main service for plugin lifecycle operations
    - Models: Update strategies, health status, version info, update plans

Update Strategies:
    - IMMEDIATE: Direct update (may cause brief downtime)
    - ROLLING: Gradual deployment across instances
    - BLUE_GREEN: Blue-green deployment pattern
    - CANARY: Gradual traffic shift for risk mitigation
    - MAINTENANCE_WINDOW: Schedule updates for low-traffic periods

Health Monitoring:
    - Connectivity checks
    - Dependency validation
    - Resource usage monitoring (CPU, memory)
    - Performance metrics (response time, error rate)
    - Automatic health score calculation

Usage:
    from app.services.plugins.lifecycle import PluginLifecycleService

    lifecycle = PluginLifecycleService()

    # Check plugin health
    health = await lifecycle.check_plugin_health(plugin_id)

    # Plan an update
    plan = await lifecycle.plan_plugin_update(
        plugin_id, target_version="2.0.0", strategy=UpdateStrategy.ROLLING
    )

    # Execute update
    execution = await lifecycle.execute_plugin_update(plan)

    # Rollback if needed
    rollback = await lifecycle.rollback_plugin(plugin_id, "1.5.0", "Health check failed", "admin")

Example:
    >>> from app.services.plugins.lifecycle import (
    ...     PluginLifecycleService,
    ...     UpdateStrategy,
    ...     PluginHealthStatus,
    ... )
    >>> lifecycle = PluginLifecycleService()
    >>> health = await lifecycle.check_plugin_health("my-plugin@1.0.0")
    >>> print(f"Health: {health.health_status} ({health.health_score:.0%})")
"""

from .models import (
    PluginHealthCheck,
    PluginHealthStatus,
    PluginRollbackPlan,
    PluginUpdateExecution,
    PluginUpdatePlan,
    PluginVersion,
    UpdateStatus,
    UpdateStrategy,
)
from .service import PluginLifecycleService

__all__ = [
    # Service
    "PluginLifecycleService",
    # Models
    "UpdateStrategy",
    "PluginHealthStatus",
    "UpdateStatus",
    "PluginVersion",
    "PluginHealthCheck",
    "PluginUpdatePlan",
    "PluginUpdateExecution",
    "PluginRollbackPlan",
]
