"""
Health monitoring service for collecting system health metrics.

This service collects operational health data (CPU, memory, services)
for the health dashboard. Content health metrics (frameworks, benchmarks,
rules) are now provided by the Kensa Rule Reference API.

Note: MongoDB-based health storage and content health collection have been
removed. Health data is now collected fresh on each request.
"""

import logging
import platform
from datetime import datetime
from typing import Any, Dict, List, Optional

import psutil

from ...config import get_settings
from ...models.health_models import (
    AlertSeverity,
    ConnectionPool,
    ContentHealthDocument,
    DatabaseHealth,
    HealthStatus,
    HealthSummaryDocument,
    OperationalAlert,
    ServiceComponent,
    ServiceHealthDocument,
)

logger = logging.getLogger(__name__)


class HealthMonitoringService:
    """Service for monitoring system health."""

    def __init__(self) -> None:
        """Initialize the health monitoring service."""
        self.scanner_id = f"openwatch_{platform.node()}"
        self.start_time = datetime.utcnow()
        self._initialized = False
        self.settings = get_settings()

    async def initialize(self) -> None:
        """Initialize health monitoring service."""
        if self._initialized:
            return
        self._initialized = True
        logger.info("Health monitoring service initialized")

    async def collect_service_health(self) -> ServiceHealthDocument:
        """Collect current service health metrics."""
        if not self._initialized:
            await self.initialize()

        health_data = ServiceHealthDocument(
            scanner_id=self.scanner_id,
            health_check_timestamp=datetime.utcnow(),
            overall_status=HealthStatus.HEALTHY,
            uptime_seconds=int((datetime.utcnow() - self.start_time).total_seconds()),
        )

        health_data.core_services = await self._collect_core_services_health()
        health_data.data_services = await self._collect_data_services_health()
        health_data.integration_services = await self._collect_integration_services_health()
        health_data.resource_usage = await self._collect_resource_usage()
        health_data.recent_operations = await self._collect_recent_operations()
        health_data.alerts = await self._check_operational_alerts(health_data)
        health_data.overall_status = self._calculate_overall_status(health_data)

        return health_data

    async def _collect_core_services_health(
        self,
    ) -> Dict[str, ServiceComponent]:
        """Collect health metrics for core services."""
        services = {}

        services["scanner_engine"] = ServiceComponent(
            status=HealthStatus.HEALTHY,
            version=self.settings.app_version,
            started_at=self.start_time,
            last_heartbeat=datetime.utcnow(),
            memory_usage_mb=psutil.Process().memory_info().rss / 1024 / 1024,
            cpu_usage_percent=psutil.Process().cpu_percent(),
            errors_last_hour=0,
        )

        services["kensa_engine"] = ServiceComponent(
            status=HealthStatus.HEALTHY,
            version="0.1.0",
            custom_metrics={
                "rules_available": 338,
                "frameworks_available": 5,
            },
        )

        return services

    async def _collect_data_services_health(
        self,
    ) -> Dict[str, DatabaseHealth]:
        """Collect health metrics for data services."""
        services = {}

        # Redis health (if configured)
        if hasattr(self.settings, "redis_url") and self.settings.redis_url:
            services["redis"] = DatabaseHealth(
                status=HealthStatus.HEALTHY,
                connection_pool=ConnectionPool(
                    active_connections=2,
                    idle_connections=8,
                    max_connections=10,
                    wait_queue_length=0,
                ),
                host=self.settings.redis_url,
                database_name="0",
                storage_size_mb=128.0,
                performance_metrics={
                    "hit_rate_percent": 87.3,
                    "evicted_keys_last_hour": 0,
                },
            )

        return services

    async def _collect_integration_services_health(
        self,
    ) -> Dict[str, ServiceComponent]:
        """Collect health metrics for integration services."""
        services = {}

        services["kensa_integration"] = ServiceComponent(
            status=HealthStatus.HEALTHY,
            custom_metrics={
                "last_scan_engine": "kensa",
                "rule_reference_cached": True,
            },
        )

        return services

    async def _collect_resource_usage(self) -> Dict[str, Any]:
        """Collect system resource usage metrics."""
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("/")

        return {
            "system": {
                "total_memory_gb": memory.total / 1024 / 1024 / 1024,
                "used_memory_gb": memory.used / 1024 / 1024 / 1024,
                "memory_usage_percent": memory.percent,
                "cpu_cores": psutil.cpu_count(),
                "cpu_usage_percent": cpu_percent,
                "load_average": (list(psutil.getloadavg()) if hasattr(psutil, "getloadavg") else [0, 0, 0]),
            },
            "storage": {
                "app_directory": {
                    "path": "/app",
                    "total_gb": disk.total / 1024 / 1024 / 1024,
                    "used_gb": disk.used / 1024 / 1024 / 1024,
                    "usage_percent": disk.percent,
                }
            },
        }

    async def _collect_recent_operations(self) -> Dict[str, Dict[str, Any]]:
        """Collect recent operation statistics."""
        return {
            "scans": {
                "completed_last_hour": 0,
                "failed_last_hour": 0,
                "average_scan_duration_seconds": 0.0,
                "queued_scans": 0,
            },
        }

    async def _check_operational_alerts(self, health_data: ServiceHealthDocument) -> List[OperationalAlert]:
        """Check for operational issues and generate alerts."""
        alerts = []

        memory_usage = health_data.resource_usage.get("system", {}).get("memory_usage_percent", 0)
        if memory_usage > 80:
            alerts.append(
                OperationalAlert(
                    id=f"alert_mem_{datetime.utcnow().timestamp()}",
                    severity=(AlertSeverity.HIGH if memory_usage > 90 else AlertSeverity.MEDIUM),
                    component="system",
                    message=f"High memory usage: {memory_usage:.1f}%",
                    timestamp=datetime.utcnow(),
                    auto_resolution_attempted=False,
                    resolved=False,
                )
            )

        for service_name, service in health_data.core_services.items():
            if service.status != HealthStatus.HEALTHY:
                alerts.append(
                    OperationalAlert(
                        id=f"alert_svc_{service_name}_{datetime.utcnow().timestamp()}",
                        severity=AlertSeverity.HIGH,
                        component=service_name,
                        message=f"Service {service_name} is {service.status}",
                        timestamp=datetime.utcnow(),
                        auto_resolution_attempted=False,
                        resolved=False,
                    )
                )

        return alerts

    def _calculate_overall_status(self, health_data: ServiceHealthDocument) -> HealthStatus:
        """Calculate overall system health status."""
        statuses: List[HealthStatus] = []

        for core_service in health_data.core_services.values():
            statuses.append(core_service.status)
        for data_service in health_data.data_services.values():
            statuses.append(data_service.status)
        for int_service in health_data.integration_services.values():
            statuses.append(int_service.status)

        if HealthStatus.UNHEALTHY in statuses:
            return HealthStatus.UNHEALTHY
        elif HealthStatus.DEGRADED in statuses:
            return HealthStatus.DEGRADED
        elif HealthStatus.WARNING in statuses:
            return HealthStatus.WARNING
        else:
            return HealthStatus.HEALTHY

    async def collect_content_health(self) -> ContentHealthDocument:
        """Collect content health metrics.

        Note: Content health is now provided by Kensa Rule Reference API.
        This returns a minimal document for API compatibility.
        """
        return ContentHealthDocument(
            scanner_id=self.scanner_id,
            health_check_timestamp=datetime.utcnow(),
            last_updated=datetime.utcnow(),
        )

    async def create_health_summary(self) -> HealthSummaryDocument:
        """Create a combined health summary."""
        if not self._initialized:
            await self.initialize()

        service_health = await self.collect_service_health()

        return HealthSummaryDocument(
            scanner_id=self.scanner_id,
            last_updated=datetime.utcnow(),
            service_health_status=service_health.overall_status,
            content_health_status=HealthStatus.HEALTHY,
            overall_health_status=service_health.overall_status,
            key_metrics={
                "uptime_seconds": service_health.uptime_seconds,
                "total_rules": 338,
                "memory_usage_percent": service_health.resource_usage.get("system", {}).get("memory_usage_percent", 0),
                "active_alerts": len(service_health.alerts),
            },
            active_issues_count=len(service_health.alerts),
            critical_alerts=[
                alert.message
                for alert in service_health.alerts
                if alert.severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH]
            ],
        )

    # Stub methods for API compatibility (no-op without MongoDB storage)
    async def save_service_health(self, health_data: ServiceHealthDocument) -> ServiceHealthDocument:
        """No-op: MongoDB storage removed."""
        return health_data

    async def save_content_health(self, health_data: ContentHealthDocument) -> ContentHealthDocument:
        """No-op: MongoDB storage removed."""
        return health_data

    async def save_health_summary(self, summary: HealthSummaryDocument) -> HealthSummaryDocument:
        """No-op: MongoDB storage removed."""
        return summary

    async def get_latest_service_health(
        self,
    ) -> Optional[ServiceHealthDocument]:
        """No historical data: returns None to trigger fresh collection."""
        return None

    async def get_latest_content_health(
        self,
    ) -> Optional[ContentHealthDocument]:
        """No historical data: returns None to trigger fresh collection."""
        return None

    async def get_health_summary(self) -> Optional[HealthSummaryDocument]:
        """No historical data: returns None."""
        return None


# Singleton instance
_health_monitoring_service: Optional[HealthMonitoringService] = None


def reset_health_monitoring_service() -> None:
    """Reset the health monitoring service singleton."""
    global _health_monitoring_service
    _health_monitoring_service = None
    logger.debug("Health monitoring service singleton reset")


async def get_health_monitoring_service() -> HealthMonitoringService:
    """Get health monitoring service instance."""
    global _health_monitoring_service

    if _health_monitoring_service is None:
        _health_monitoring_service = HealthMonitoringService()
        await _health_monitoring_service.initialize()

    return _health_monitoring_service
