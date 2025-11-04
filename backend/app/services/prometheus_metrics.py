"""
Prometheus Metrics Collection for OpenWatch
Comprehensive metrics for monitoring and observability
Author: Noah Chen - nc9010@hanalyx.com
"""

import asyncio
import logging
import time
from typing import Dict, Optional

import psutil
from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    Info,
    generate_latest,
    multiprocess,
    values,
)
from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# Create registry for metrics
registry = CollectorRegistry()

# HTTP Metrics
http_requests_total = Counter(
    "secureops_http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status", "service"],
    registry=registry,
)

http_request_duration_seconds = Histogram(
    "secureops_http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint", "service"],
    buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
    registry=registry,
)

# Service Health Metrics
service_info = Info("secureops_service", "Service information", registry=registry)

service_up = Gauge("secureops_service_up", "Service up status", ["service"], registry=registry)

# SCAP Scanning Metrics
scans_total = Counter(
    "secureops_scans_total",
    "Total SCAP scans performed",
    ["status", "profile", "framework"],
    registry=registry,
)

scans_active = Gauge("secureops_scans_active", "Currently active scans", registry=registry)

scan_duration_seconds = Histogram(
    "secureops_scan_duration_seconds",
    "SCAP scan duration in seconds",
    ["profile", "framework"],
    buckets=[10, 30, 60, 120, 300, 600, 1200, 1800, 3600],
    registry=registry,
)

scan_rules_processed = Counter(
    "secureops_scan_rules_processed_total",
    "Total SCAP rules processed",
    ["status", "severity"],
    registry=registry,
)

# Compliance Metrics
compliance_score = Gauge(
    "secureops_compliance_score",
    "Compliance score for hosts",
    ["host_id", "framework"],
    registry=registry,
)

compliance_rules_failed = Gauge(
    "secureops_compliance_rules_failed",
    "Number of failed compliance rules",
    ["host_id", "severity", "framework"],
    registry=registry,
)

# Host Management Metrics
hosts_total = Gauge(
    "secureops_hosts_total",
    "Total number of managed hosts",
    ["status"],
    registry=registry,
)

host_connectivity_checks = Counter(
    "secureops_host_connectivity_checks_total",
    "Total host connectivity checks",
    ["result"],
    registry=registry,
)

# Integration Metrics
integration_calls_total = Counter(
    "secureops_integration_calls_total",
    "Total integration calls",
    ["target", "endpoint", "status"],
    registry=registry,
)

integration_call_duration_seconds = Histogram(
    "secureops_integration_call_duration_seconds",
    "Integration call duration in seconds",
    ["target", "endpoint"],
    buckets=[0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0],
    registry=registry,
)

# Remediation Metrics (for AEGIS integration)
remediations_total = Counter(
    "secureops_remediations_total",
    "Total remediation attempts",
    ["status", "severity"],
    registry=registry,
)

remediation_duration_seconds = Histogram(
    "secureops_remediation_duration_seconds",
    "Remediation duration in seconds",
    ["severity"],
    buckets=[1, 5, 10, 30, 60, 120, 300, 600],
    registry=registry,
)

# Database Metrics
database_connections_active = Gauge(
    "secureops_database_connections_active",
    "Active database connections",
    registry=registry,
)

database_query_duration_seconds = Histogram(
    "secureops_database_query_duration_seconds",
    "Database query duration in seconds",
    ["operation"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
    registry=registry,
)

# Security Event Metrics
security_events_total = Counter(
    "secureops_security_events_total",
    "Total security events",
    ["event_type", "severity"],
    registry=registry,
)

authentication_attempts_total = Counter(
    "secureops_authentication_attempts_total",
    "Total authentication attempts",
    ["result", "method"],
    registry=registry,
)

# System Resource Metrics
system_cpu_usage_percent = Gauge(
    "secureops_system_cpu_usage_percent",
    "System CPU usage percentage",
    registry=registry,
)

system_memory_usage_bytes = Gauge(
    "secureops_system_memory_usage_bytes",
    "System memory usage in bytes",
    ["type"],  # available, used, total
    registry=registry,
)

system_disk_usage_bytes = Gauge(
    "secureops_system_disk_usage_bytes",
    "System disk usage in bytes",
    ["device", "type"],  # type: free, used, total
    registry=registry,
)

# Business Logic Metrics
workflow_duration_seconds = Histogram(
    "secureops_workflow_duration_seconds",
    "End-to-end workflow duration",
    ["workflow_type"],
    buckets=[60, 300, 600, 1200, 1800, 3600, 7200],
    registry=registry,
)

queue_size = Gauge(
    "secureops_queue_size",
    "Queue size for background tasks",
    ["queue_name"],
    registry=registry,
)

# Error Rate Metrics
error_rate = Gauge(
    "secureops_error_rate",
    "Error rate for various operations",
    ["operation"],
    registry=registry,
)


class PrometheusMetrics:
    """Centralized metrics collection and management"""

    def __init__(self):
        self.start_time = time.time()
        # Initialize service info
        service_info.info({"version": "1.0.0", "service": "openwatch", "environment": "production"})

    def record_http_request(
        self,
        method: str,
        endpoint: str,
        status_code: int,
        duration: float,
        service: str = "openwatch",
    ):
        """Record HTTP request metrics"""
        http_requests_total.labels(
            method=method, endpoint=endpoint, status=str(status_code), service=service
        ).inc()

        http_request_duration_seconds.labels(
            method=method, endpoint=endpoint, service=service
        ).observe(duration)

    def record_scan_metrics(
        self,
        status: str,
        profile: str,
        framework: str,
        duration: Optional[float] = None,
        rules_processed: Dict[str, int] = None,
    ):
        """Record SCAP scan metrics"""
        scans_total.labels(status=status, profile=profile, framework=framework).inc()

        if duration is not None:
            scan_duration_seconds.labels(profile=profile, framework=framework).observe(duration)

        if rules_processed:
            for rule_status, count in rules_processed.items():
                severity = rules_processed.get("severity", "medium")
                scan_rules_processed.labels(status=rule_status, severity=severity).inc(count)

    def update_compliance_score(self, host_id: str, framework: str, score: float):
        """Update compliance score for a host"""
        compliance_score.labels(host_id=host_id, framework=framework).set(score)

    def update_compliance_failures(
        self, host_id: str, framework: str, severity_counts: Dict[str, int]
    ):
        """Update compliance failure counts by severity"""
        for severity, count in severity_counts.items():
            compliance_rules_failed.labels(
                host_id=host_id, severity=severity, framework=framework
            ).set(count)

    def record_host_connectivity(self, result: str):
        """Record host connectivity check result"""
        host_connectivity_checks.labels(result=result).inc()

    def update_host_counts(self, status_counts: Dict[str, int]):
        """Update host count metrics by status"""
        for status, count in status_counts.items():
            hosts_total.labels(status=status).set(count)

    def record_integration_call(self, target: str, endpoint: str, status: str, duration: float):
        """Record integration call metrics"""
        integration_calls_total.labels(target=target, endpoint=endpoint, status=status).inc()

        integration_call_duration_seconds.labels(target=target, endpoint=endpoint).observe(duration)

    def record_remediation(self, status: str, severity: str, duration: Optional[float] = None):
        """Record remediation metrics"""
        remediations_total.labels(status=status, severity=severity).inc()

        if duration is not None:
            remediation_duration_seconds.labels(severity=severity).observe(duration)

    def record_security_event(self, event_type: str, severity: str = "medium"):
        """Record security event"""
        security_events_total.labels(event_type=event_type, severity=severity).inc()

    def record_authentication_attempt(self, result: str, method: str = "jwt"):
        """Record authentication attempt"""
        authentication_attempts_total.labels(result=result, method=method).inc()

    def update_system_metrics(self):
        """Update system resource metrics"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            system_cpu_usage_percent.set(cpu_percent)

            # Memory usage
            memory = psutil.virtual_memory()
            system_memory_usage_bytes.labels(type="total").set(memory.total)
            system_memory_usage_bytes.labels(type="used").set(memory.used)
            system_memory_usage_bytes.labels(type="available").set(memory.available)

            # Disk usage
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    system_disk_usage_bytes.labels(device=partition.device, type="total").set(
                        usage.total
                    )
                    system_disk_usage_bytes.labels(device=partition.device, type="used").set(
                        usage.used
                    )
                    system_disk_usage_bytes.labels(device=partition.device, type="free").set(
                        usage.free
                    )
                except PermissionError:
                    # Skip inaccessible partitions
                    continue

        except Exception as e:
            logger.error(f"Error updating system metrics: {e}")

    async def update_database_metrics(self, db: Session):
        """Update database-related metrics"""
        try:
            # Active connections
            result = db.execute(
                text(
                    """
                SELECT count(*) as active_connections
                FROM pg_stat_activity
                WHERE state = 'active'
            """
                )
            )

            row = result.fetchone()
            if row:
                database_connections_active.set(row.active_connections)

        except Exception as e:
            logger.error(f"Error updating database metrics: {e}")

    def update_queue_metrics(self, queue_name: str, size: int):
        """Update queue size metrics"""
        queue_size.labels(queue_name=queue_name).set(size)

    def record_workflow_duration(self, workflow_type: str, duration: float):
        """Record workflow duration"""
        workflow_duration_seconds.labels(workflow_type=workflow_type).observe(duration)

    def set_active_scans(self, count: int):
        """Set number of active scans"""
        scans_active.set(count)

    def set_service_up(self, service: str, is_up: bool):
        """Set service up status"""
        service_up.labels(service=service).set(1 if is_up else 0)

    def get_metrics(self) -> str:
        """Get all metrics in Prometheus format"""
        try:
            # Update system metrics before generating output
            self.update_system_metrics()
            return generate_latest(registry)
        except Exception as e:
            logger.error(f"Error generating metrics: {e}")
            return ""


# Global metrics instance
metrics = PrometheusMetrics()


def get_metrics_instance() -> PrometheusMetrics:
    """Get the global metrics instance"""
    return metrics
