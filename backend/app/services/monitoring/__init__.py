"""
Monitoring services module.

Provides health monitoring, host monitoring, drift detection,
integration metrics, and adaptive scheduling services.

Usage:
    from app.services.monitoring import (
        get_host_monitor,
        get_health_monitoring_service,
        adaptive_scheduler_service,
        metrics_collector,
    )
"""

from .drift import DriftDetectionService
from .health import HealthMonitoringService, get_health_monitoring_service
from .host import HostMonitor, get_host_monitor
from .metrics import (
    IntegrationMetricsCollector,
    metrics_collector,
    record_api_call,
    record_remediation_job,
    record_webhook_delivery,
    time_api_call,
    time_remediation,
    time_webhook_delivery,
)
from .scheduler import AdaptiveSchedulerService, adaptive_scheduler_service
from .state import HostMonitoringStateMachine

__all__ = [
    # Health monitoring
    "HealthMonitoringService",
    "get_health_monitoring_service",
    # Host monitoring
    "HostMonitor",
    "get_host_monitor",
    # State machine
    "HostMonitoringStateMachine",
    # Drift detection
    "DriftDetectionService",
    # Integration metrics
    "IntegrationMetricsCollector",
    "metrics_collector",
    "record_webhook_delivery",
    "record_api_call",
    "record_remediation_job",
    "time_webhook_delivery",
    "time_api_call",
    "time_remediation",
    # Adaptive scheduler
    "AdaptiveSchedulerService",
    "adaptive_scheduler_service",
]
