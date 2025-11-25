"""
Integration Performance Metrics Service
Collects and tracks performance metrics for OpenWatch-AEGIS integration
"""

import json
import logging
import threading
import time
from collections import defaultdict, deque
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class IntegrationMetric:
    """Individual metric data point"""

    timestamp: float
    metric_type: str
    operation: str
    value: float
    labels: Dict[str, str]
    success: bool = True
    error: Optional[str] = None


@dataclass
class MetricsSummary:
    """Aggregated metrics summary"""

    total_requests: int
    successful_requests: int
    failed_requests: int
    average_duration: float
    min_duration: float
    max_duration: float
    p95_duration: float
    error_rate: float


class IntegrationMetricsCollector:
    """Collects and manages integration performance metrics"""

    def __init__(self, retention_hours: int = 24, max_metrics: int = 10000):
        self.retention_hours = retention_hours
        self.max_metrics = max_metrics
        self.metrics: deque = deque(maxlen=max_metrics)
        self.lock = threading.RLock()

        # In-memory counters for quick access
        self.counters = defaultdict(int)
        self.timers = defaultdict(list)

    def record_metric(
        self,
        metric_type: str,
        operation: str,
        value: float,
        success: bool = True,
        error: Optional[str] = None,
        labels: Optional[Dict[str, str]] = None,
    ):
        """Record a new metric"""
        with self.lock:
            metric = IntegrationMetric(
                timestamp=time.time(),
                metric_type=metric_type,
                operation=operation,
                value=value,
                labels=labels or {},
                success=success,
                error=error,
            )

            self.metrics.append(metric)

            # Update counters
            counter_key = f"{metric_type}.{operation}"
            self.counters[f"{counter_key}.total"] += 1

            if success:
                self.counters[f"{counter_key}.success"] += 1
            else:
                self.counters[f"{counter_key}.error"] += 1

            # Store timing data for percentile calculations
            if metric_type == "duration":
                self.timers[counter_key].append(value)
                # Keep only last 1000 values for percentile calculations
                if len(self.timers[counter_key]) > 1000:
                    self.timers[counter_key] = self.timers[counter_key][-1000:]

    @contextmanager
    def time_operation(self, operation: str, labels: Optional[Dict[str, str]] = None):
        """Context manager to time operations"""
        start_time = time.time()
        error = None
        success = True

        try:
            yield
        except Exception as e:
            success = False
            error = str(e)
            raise
        finally:
            duration = time.time() - start_time
            self.record_metric(
                metric_type="duration",
                operation=operation,
                value=duration,
                success=success,
                error=error,
                labels=labels,
            )

    def cleanup_old_metrics(self):
        """Remove metrics older than retention period"""
        with self.lock:
            cutoff_time = time.time() - (self.retention_hours * 3600)

            # Remove old metrics
            while self.metrics and self.metrics[0].timestamp < cutoff_time:
                self.metrics.popleft()

    def get_metrics_summary(self, operation: Optional[str] = None, hours: int = 1) -> Dict[str, MetricsSummary]:
        """Get aggregated metrics summary"""
        with self.lock:
            self.cleanup_old_metrics()

            cutoff_time = time.time() - (hours * 3600)
            relevant_metrics = [m for m in self.metrics if m.timestamp >= cutoff_time]

            if operation:
                relevant_metrics = [m for m in relevant_metrics if m.operation == operation]

            # Group by operation
            grouped_metrics = defaultdict(list)
            for metric in relevant_metrics:
                if metric.metric_type == "duration":
                    grouped_metrics[metric.operation].append(metric)

            summaries = {}
            for op, metrics_list in grouped_metrics.items():
                if not metrics_list:
                    continue

                durations = [m.value for m in metrics_list]
                successful = [m for m in metrics_list if m.success]
                failed = [m for m in metrics_list if not m.success]

                if durations:
                    durations.sort()
                    p95_index = int(len(durations) * 0.95)

                    summaries[op] = MetricsSummary(
                        total_requests=len(metrics_list),
                        successful_requests=len(successful),
                        failed_requests=len(failed),
                        average_duration=sum(durations) / len(durations),
                        min_duration=min(durations),
                        max_duration=max(durations),
                        p95_duration=(durations[p95_index] if p95_index < len(durations) else max(durations)),
                        error_rate=(len(failed) / len(metrics_list)) * 100,
                    )

            return summaries

    def get_current_stats(self) -> Dict[str, Any]:
        """Get current performance statistics"""
        with self.lock:
            self.cleanup_old_metrics()

            stats = {
                "total_metrics": len(self.metrics),
                "counters": dict(self.counters),
                "recent_errors": [],
                "top_operations": {},
            }

            # Recent errors (last hour)
            cutoff_time = time.time() - 3600
            recent_errors = [
                {
                    "timestamp": datetime.fromtimestamp(m.timestamp).isoformat(),
                    "operation": m.operation,
                    "error": m.error,
                }
                for m in self.metrics
                if m.timestamp >= cutoff_time and not m.success and m.error
            ]

            stats["recent_errors"] = recent_errors[-10:]  # Last 10 errors

            # Top operations by volume
            operation_counts = defaultdict(int)
            for metric in self.metrics:
                if metric.timestamp >= cutoff_time:
                    operation_counts[metric.operation] += 1

            stats["top_operations"] = dict(sorted(operation_counts.items(), key=lambda x: x[1], reverse=True)[:10])

            return stats

    def export_metrics(self, format: str = "json") -> str:
        """Export metrics in specified format"""
        if format == "json":
            return json.dumps([asdict(m) for m in self.metrics], indent=2)
        elif format == "prometheus":
            # Basic Prometheus format
            lines = []
            summaries = self.get_metrics_summary()

            for operation, summary in summaries.items():
                safe_op = operation.replace("-", "_").replace(".", "_")
                lines.append(f"# HELP integration_{safe_op}_duration_seconds Operation duration")
                lines.append(f"# TYPE integration_{safe_op}_duration_seconds histogram")
                lines.append(
                    f"integration_{safe_op}_duration_seconds_sum {summary.average_duration * summary.total_requests}"
                )
                lines.append(f"integration_{safe_op}_duration_seconds_count {summary.total_requests}")

                lines.append(f"# HELP integration_{safe_op}_error_rate Error rate percentage")
                lines.append(f"# TYPE integration_{safe_op}_error_rate gauge")
                lines.append(f"integration_{safe_op}_error_rate {summary.error_rate}")

            return "\n".join(lines)

        raise ValueError(f"Unsupported export format: {format}")


# Global metrics collector instance
metrics_collector = IntegrationMetricsCollector()


# Convenience functions for common operations
def record_webhook_delivery(success: bool, duration: float, target_service: str, error: str = None):
    """Record webhook delivery metrics"""
    metrics_collector.record_metric(
        metric_type="duration",
        operation="webhook_delivery",
        value=duration,
        success=success,
        error=error,
        labels={"target_service": target_service},
    )


def record_api_call(operation: str, success: bool, duration: float, service: str, error: str = None):
    """Record API call metrics"""
    metrics_collector.record_metric(
        metric_type="duration",
        operation=f"api_call_{operation}",
        value=duration,
        success=success,
        error=error,
        labels={"service": service},
    )


def record_remediation_job(job_id: str, status: str, duration: float, rules_count: int, success_count: int):
    """Record remediation job metrics"""
    metrics_collector.record_metric(
        metric_type="duration",
        operation="remediation_job",
        value=duration,
        success=(status == "completed"),
        labels={
            "job_id": job_id,
            "status": status,
            "rules_count": str(rules_count),
            "success_count": str(success_count),
        },
    )


# Context managers for easy timing
def time_webhook_delivery(target):
    """Create context manager for timing webhook delivery."""
    return metrics_collector.time_operation("webhook_delivery", {"target": target})


def time_api_call(operation, service):
    """Create context manager for timing API calls."""
    return metrics_collector.time_operation(f"api_call_{operation}", {"service": service})


def time_remediation(job_id):
    """Create context manager for timing remediation execution."""
    return metrics_collector.time_operation("remediation_execution", {"job_id": job_id})
