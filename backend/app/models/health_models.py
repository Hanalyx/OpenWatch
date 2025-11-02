"""
MongoDB models for health monitoring data.

This module defines the schema for both service health (operational monitoring)
and content health (compliance rule effectiveness) data structures.
"""

from beanie import Document, Indexed
from pydantic import BaseModel, Field, validator
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum


class HealthStatus(str, Enum):
    """Health status enumeration"""

    HEALTHY = "healthy"
    WARNING = "warning"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class ServiceStatus(str, Enum):
    """Service operational status"""

    RUNNING = "running"
    STOPPED = "stopped"
    STARTING = "starting"
    STOPPING = "stopping"
    ERROR = "error"
    MAINTENANCE = "maintenance"


class FreshnessStatus(str, Enum):
    """Content freshness status"""

    CURRENT = "current"
    STALE = "stale"
    OUTDATED = "outdated"
    DEPRECATED = "deprecated"


class AlertSeverity(str, Enum):
    """Alert severity levels"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Service Health Models
class ServiceComponent(BaseModel):
    """Individual service component health"""

    status: HealthStatus = Field(description="Component health status")
    version: Optional[str] = Field(None, description="Component version")
    started_at: Optional[datetime] = Field(None, description="Component start time")
    last_heartbeat: Optional[datetime] = Field(
        None, description="Last heartbeat timestamp"
    )
    memory_usage_mb: Optional[float] = Field(None, description="Memory usage in MB")
    cpu_usage_percent: Optional[float] = Field(None, description="CPU usage percentage")
    errors_last_hour: int = Field(0, description="Error count in last hour")
    custom_metrics: Dict[str, Any] = Field(
        default_factory=dict, description="Component-specific metrics"
    )


class ConnectionPool(BaseModel):
    """Database connection pool statistics"""

    active_connections: int = Field(description="Active connection count")
    idle_connections: int = Field(description="Idle connection count")
    max_connections: int = Field(description="Maximum connections allowed")
    wait_queue_length: int = Field(0, description="Connection wait queue length")


class DatabaseHealth(BaseModel):
    """Database service health metrics"""

    status: HealthStatus = Field(description="Database health status")
    connection_pool: ConnectionPool = Field(description="Connection pool stats")
    host: str = Field(description="Database host")
    database_name: str = Field(description="Database name")
    storage_size_mb: float = Field(description="Storage size in MB")
    performance_metrics: Dict[str, float] = Field(
        default_factory=dict, description="Performance metrics"
    )


class ResourceUsage(BaseModel):
    """System resource usage metrics"""

    total_memory_gb: float = Field(description="Total system memory")
    used_memory_gb: float = Field(description="Used memory")
    memory_usage_percent: float = Field(description="Memory usage percentage")
    cpu_cores: int = Field(description="CPU core count")
    cpu_usage_percent: float = Field(description="CPU usage percentage")
    load_average: List[float] = Field(description="System load averages")

    @validator("memory_usage_percent", "cpu_usage_percent")
    def validate_percentage(cls, v):
        if not 0 <= v <= 100:
            raise ValueError("Percentage must be between 0 and 100")
        return v


class StorageUsage(BaseModel):
    """Storage usage metrics"""

    path: str = Field(description="Storage path")
    total_gb: float = Field(description="Total storage in GB")
    used_gb: float = Field(description="Used storage in GB")
    usage_percent: float = Field(description="Storage usage percentage")

    @validator("usage_percent")
    def validate_percentage(cls, v):
        if not 0 <= v <= 100:
            raise ValueError("Percentage must be between 0 and 100")
        return v


class OperationalAlert(BaseModel):
    """Operational alert information"""

    id: str = Field(description="Alert ID")
    severity: AlertSeverity = Field(description="Alert severity")
    component: str = Field(description="Affected component")
    message: str = Field(description="Alert message")
    timestamp: datetime = Field(description="Alert timestamp")
    auto_resolution_attempted: bool = Field(
        False, description="Auto-resolution attempted flag"
    )
    resolved: bool = Field(False, description="Resolution status")
    resolution_timestamp: Optional[datetime] = Field(
        None, description="Resolution timestamp"
    )


class ServiceHealthDocument(Document):
    """Service health monitoring document"""

    scanner_id: Indexed(str) = Field(description="Scanner instance ID")
    health_check_timestamp: datetime = Field(description="Health check timestamp")
    overall_status: HealthStatus = Field(description="Overall system health")
    uptime_seconds: int = Field(description="System uptime in seconds")

    # Service components
    core_services: Dict[str, ServiceComponent] = Field(
        default_factory=dict, description="Core service components health"
    )
    data_services: Dict[str, DatabaseHealth] = Field(
        default_factory=dict, description="Database services health"
    )
    integration_services: Dict[str, ServiceComponent] = Field(
        default_factory=dict, description="Integration services health"
    )

    # Resource usage
    resource_usage: Dict[str, Any] = Field(
        default_factory=dict, description="System resource usage"
    )

    # Recent operations
    recent_operations: Dict[str, Dict[str, Any]] = Field(
        default_factory=dict, description="Recent operation statistics"
    )

    # Alerts
    alerts: List[OperationalAlert] = Field(
        default_factory=list, description="Active operational alerts"
    )

    class Settings:
        name = "service_health"
        indexes = [
            "scanner_id",
            "health_check_timestamp",
            [("scanner_id", 1), ("health_check_timestamp", -1)],
        ]


# Content Health Models
class FrameworkHealth(BaseModel):
    """Framework compliance health metrics"""

    version: str = Field(description="Framework version")
    status: str = Field(description="Framework status (active/deprecated)")
    last_updated: datetime = Field(description="Last update timestamp")
    total_controls: int = Field(description="Total control count")
    implemented_controls: int = Field(description="Implemented control count")
    coverage_percentage: float = Field(description="Coverage percentage")
    rule_count: int = Field(description="Associated rule count")
    benchmark_dependencies: List[str] = Field(
        default_factory=list, description="Dependent benchmarks"
    )

    @validator("coverage_percentage")
    def validate_percentage(cls, v):
        if not 0 <= v <= 100:
            raise ValueError("Coverage percentage must be between 0 and 100")
        return v


class BenchmarkHealth(BaseModel):
    """Benchmark implementation health metrics"""

    benchmark_version: str = Field(description="Benchmark version")
    source_framework: str = Field(description="Source framework")
    platform: str = Field(description="Target platform")
    status: str = Field(description="Benchmark status")
    last_updated: datetime = Field(description="Last update timestamp")
    total_rules: int = Field(description="Total rule count")
    implemented_rules: int = Field(description="Implemented rule count")
    coverage_percentage: float = Field(description="Coverage percentage")
    satisfies_frameworks: List[str] = Field(
        default_factory=list, description="Satisfied frameworks"
    )
    content_freshness: Dict[str, Any] = Field(
        default_factory=dict, description="Freshness metrics"
    )


class RuleDistribution(BaseModel):
    """Rule distribution statistics"""

    by_severity: Dict[str, int] = Field(
        default_factory=dict, description="Distribution by severity"
    )
    by_category: Dict[str, int] = Field(
        default_factory=dict, description="Distribution by category"
    )
    by_platform: Dict[str, int] = Field(
        default_factory=dict, description="Distribution by platform"
    )


class ContentIntegrity(BaseModel):
    """Content integrity validation results"""

    source_validation: Dict[str, Any] = Field(
        default_factory=dict, description="Source validation results"
    )
    rule_consistency: Dict[str, Any] = Field(
        default_factory=dict, description="Rule consistency metrics"
    )
    cross_references: Dict[str, Any] = Field(
        default_factory=dict, description="Cross-reference validation"
    )


class ContentAlert(BaseModel):
    """Content-related alert"""

    type: str = Field(description="Alert type")
    category: str = Field(description="Alert category")
    message: str = Field(description="Alert message")
    rule_impact: Optional[int] = Field(None, description="Number of rules impacted")
    recommended_action: str = Field(description="Recommended action")
    urgency: str = Field(description="Urgency level")


class ContentHealthDocument(Document):
    """Content health monitoring document"""

    scanner_id: Indexed(str) = Field(description="Scanner instance ID")
    health_check_timestamp: datetime = Field(description="Health check timestamp")
    last_updated: datetime = Field(description="Last update timestamp")

    # Framework health
    frameworks: Dict[str, FrameworkHealth] = Field(
        default_factory=dict, description="Framework health metrics"
    )

    # Benchmark health
    benchmarks: Dict[str, BenchmarkHealth] = Field(
        default_factory=dict, description="Benchmark health metrics"
    )

    # Rule statistics
    rule_statistics: Dict[str, Any] = Field(
        default_factory=dict, description="Rule distribution and statistics"
    )

    # Content integrity
    content_integrity: ContentIntegrity = Field(
        default_factory=ContentIntegrity, description="Content integrity metrics"
    )

    # Performance metrics
    performance_metrics: Dict[str, Any] = Field(
        default_factory=dict, description="Content processing performance"
    )

    # Alerts and recommendations
    alerts_and_recommendations: List[ContentAlert] = Field(
        default_factory=list, description="Content alerts and recommendations"
    )

    class Settings:
        name = "content_health"
        indexes = [
            "scanner_id",
            "health_check_timestamp",
            [("scanner_id", 1), ("health_check_timestamp", -1)],
        ]


# Health Summary Model (combines both)
class HealthSummaryDocument(Document):
    """Combined health summary for quick access"""

    scanner_id: Indexed(str, unique=True) = Field(description="Scanner instance ID")
    last_updated: datetime = Field(description="Last update timestamp")

    # Quick status
    service_health_status: HealthStatus = Field(description="Service health status")
    content_health_status: HealthStatus = Field(description="Content health status")
    overall_health_status: HealthStatus = Field(description="Overall health status")

    # Key metrics
    key_metrics: Dict[str, Any] = Field(
        default_factory=dict, description="Key health metrics"
    )

    # Active issues
    active_issues_count: int = Field(0, description="Active issue count")
    critical_alerts: List[str] = Field(
        default_factory=list, description="Critical alert messages"
    )

    class Settings:
        name = "health_summary"
        indexes = ["scanner_id", "last_updated"]
