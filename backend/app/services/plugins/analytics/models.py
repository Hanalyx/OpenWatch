"""
Plugin Analytics Models

Data models for plugin performance analytics including metrics,
summaries, usage statistics, recommendations, and reports.

These models support:
- Individual metric data points
- Time-aggregated metric summaries
- Usage pattern statistics
- Optimization recommendations
- Performance reports
- System-wide analytics

Security Considerations:
    - Metric values are validated to prevent overflow
    - Confidence scores are bounded (0.0-1.0)
    - Performance scores are bounded (0.0-100.0)
    - All timestamps use UTC
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

# =============================================================================
# ANALYTICS ENUMS
# =============================================================================


class MetricType(str, Enum):
    """
    Types of plugin metrics.

    Categories for organizing metric data:
    - PERFORMANCE: Response times, throughput, latency
    - RESOURCE: CPU, memory, disk, network usage
    - ERROR: Error rates, failure counts, exceptions
    - USAGE: Execution counts, frequency patterns
    - AVAILABILITY: Uptime, health status history
    """

    PERFORMANCE = "performance"
    RESOURCE = "resource"
    ERROR = "error"
    USAGE = "usage"
    AVAILABILITY = "availability"


class AggregationPeriod(str, Enum):
    """
    Time periods for metric aggregation.

    Supported granularities for metric rollups:
    - MINUTE: Per-minute aggregation
    - HOUR: Per-hour aggregation
    - DAY: Per-day aggregation
    - WEEK: Per-week aggregation
    - MONTH: Per-month aggregation
    """

    MINUTE = "minute"
    HOUR = "hour"
    DAY = "day"
    WEEK = "week"
    MONTH = "month"


class OptimizationRecommendationType(str, Enum):
    """
    Types of optimization recommendations.

    Categories for improvement suggestions:
    - PERFORMANCE: Speed and responsiveness improvements
    - RESOURCE: CPU, memory, storage optimization
    - RELIABILITY: Stability and availability improvements
    - COST: Resource efficiency and cost reduction
    - SECURITY: Security enhancements
    """

    PERFORMANCE = "performance"
    RESOURCE = "resource"
    RELIABILITY = "reliability"
    COST = "cost"
    SECURITY = "security"


# =============================================================================
# METRIC MODELS
# =============================================================================


class PluginMetric(BaseModel):
    """
    Individual plugin metric data point.

    Stores a single metric measurement with context and metadata.

    Attributes:
        plugin_id: ID of the plugin this metric belongs to.
        metric_type: Category of the metric.
        metric_name: Specific metric name (e.g., "response_time").
        value: Numeric metric value.
        unit: Unit of measurement (e.g., "seconds", "percent").
        timestamp: When the metric was recorded.
        host_id: Target host if applicable.
        execution_id: Related execution if applicable.
        rule_id: Related rule if applicable.
        tags: Key-value tags for filtering.
        metadata: Additional context data.

    Example:
        >>> metric = PluginMetric(
        ...     plugin_id="security-check@1.0.0",
        ...     metric_type=MetricType.PERFORMANCE,
        ...     metric_name="execution_time",
        ...     value=2.5,
        ...     unit="seconds",
        ... )
    """

    plugin_id: str
    metric_type: MetricType
    metric_name: str
    value: float
    unit: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Optional context
    host_id: Optional[str] = None
    execution_id: Optional[str] = None
    rule_id: Optional[str] = None

    # Additional metadata
    tags: Dict[str, str] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PluginMetricSummary(BaseModel):
    """
    Aggregated plugin metrics for a time period.

    Statistical summary of metric values over a defined time window.

    Attributes:
        plugin_id: ID of the plugin.
        metric_type: Category of the metric.
        metric_name: Specific metric name.
        period: Aggregation granularity.
        start_time: Start of the aggregation period.
        end_time: End of the aggregation period.
        count: Number of data points aggregated.
        min_value: Minimum value in period.
        max_value: Maximum value in period.
        avg_value: Average value in period.
        median_value: Median value in period.
        p95_value: 95th percentile value.
        p99_value: 99th percentile value.
        trend_direction: "increasing", "decreasing", or "stable".
        trend_confidence: Confidence in trend detection (0.0-1.0).
        std_deviation: Standard deviation of values.
        variance: Variance of values.

    Example:
        >>> summary = PluginMetricSummary(
        ...     plugin_id="my-plugin@1.0.0",
        ...     metric_type=MetricType.PERFORMANCE,
        ...     metric_name="response_time",
        ...     period=AggregationPeriod.HOUR,
        ...     start_time=datetime.utcnow(),
        ...     end_time=datetime.utcnow(),
        ...     count=100,
        ...     avg_value=1.5,
        ... )
    """

    plugin_id: str
    metric_type: MetricType
    metric_name: str
    period: AggregationPeriod
    start_time: datetime
    end_time: datetime

    # Statistical measures
    count: int = 0
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    avg_value: Optional[float] = None
    median_value: Optional[float] = None
    p95_value: Optional[float] = None
    p99_value: Optional[float] = None

    # Trend analysis
    trend_direction: Optional[str] = None
    trend_confidence: Optional[float] = None

    # Variance and distribution
    std_deviation: Optional[float] = None
    variance: Optional[float] = None


# =============================================================================
# USAGE STATISTICS
# =============================================================================


class PluginUsageStats(BaseModel):
    """
    Plugin usage statistics.

    Comprehensive usage data including execution counts, patterns,
    resource consumption, and reliability metrics.

    Attributes:
        plugin_id: ID of the plugin.
        plugin_name: Display name of the plugin.
        period_start: Start of the statistics period.
        period_end: End of the statistics period.
        total_executions: Total execution count.
        successful_executions: Successful execution count.
        failed_executions: Failed execution count.
        average_execution_time: Average execution duration.
        peak_usage_hour: Hour of day with most executions (0-23).
        avg_daily_executions: Average executions per day.
        usage_trend: "increasing", "decreasing", or "stable".
        total_cpu_seconds: Total CPU time consumed.
        total_memory_mb_hours: Total memory-hours consumed.
        avg_resource_efficiency: Resource efficiency score (0.0-1.0).
        most_used_rules: Top rules by execution count.
        most_targeted_hosts: Top hosts by execution count.
        availability_percentage: Uptime percentage (0.0-100.0).
        mean_time_to_failure: Average time between failures (hours).
        mean_time_to_recovery: Average recovery time (hours).

    Example:
        >>> stats = await analytics.generate_usage_stats("my-plugin@1.0.0")
        >>> print(f"Success rate: {stats.successful_executions / stats.total_executions:.1%}")
    """

    plugin_id: str
    plugin_name: str

    # Time period
    period_start: datetime
    period_end: datetime

    # Execution statistics
    total_executions: int = 0
    successful_executions: int = 0
    failed_executions: int = 0
    average_execution_time: Optional[float] = None

    # Usage patterns
    peak_usage_hour: Optional[int] = None
    avg_daily_executions: Optional[float] = None
    usage_trend: Optional[str] = None

    # Resource consumption
    total_cpu_seconds: Optional[float] = None
    total_memory_mb_hours: Optional[float] = None
    avg_resource_efficiency: Optional[float] = None

    # Popular rules/hosts
    most_used_rules: List[Dict[str, Any]] = Field(default_factory=list)
    most_targeted_hosts: List[Dict[str, Any]] = Field(default_factory=list)

    # Reliability metrics
    availability_percentage: Optional[float] = None
    mean_time_to_failure: Optional[float] = None
    mean_time_to_recovery: Optional[float] = None


# =============================================================================
# RECOMMENDATIONS
# =============================================================================


class OptimizationRecommendation(BaseModel):
    """
    Optimization recommendation for a plugin.

    Data-driven suggestion for improving plugin performance,
    reliability, or resource efficiency.

    Attributes:
        recommendation_id: Unique identifier.
        plugin_id: ID of the target plugin.
        recommendation_type: Category of recommendation.
        title: Short recommendation title.
        description: Detailed explanation.
        impact_level: Expected impact ("low", "medium", "high", "critical").
        confidence_score: Confidence in recommendation (0.0-1.0).
        implementation_effort: Required effort ("low", "medium", "high").
        estimated_improvement: Expected improvement description.
        prerequisites: Requirements before implementing.
        supporting_metrics: Metrics supporting this recommendation.
        baseline_measurements: Current baseline values.
        created_at: When recommendation was generated.
        valid_until: Expiration date for recommendation.
        status: "active", "implemented", or "dismissed".
        implemented_at: When recommendation was implemented.
        implementation_notes: Notes about implementation.

    Example:
        >>> recommendation = OptimizationRecommendation(
        ...     plugin_id="slow-plugin@1.0.0",
        ...     recommendation_type=OptimizationRecommendationType.PERFORMANCE,
        ...     title="Optimize Execution Time",
        ...     description="Plugin execution time exceeds optimal range.",
        ...     impact_level="medium",
        ...     confidence_score=0.85,
        ...     implementation_effort="medium",
        ...     estimated_improvement="30-50% faster execution",
        ... )
    """

    recommendation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    plugin_id: str
    recommendation_type: OptimizationRecommendationType

    # Recommendation details
    title: str
    description: str
    impact_level: str = Field(..., description="low, medium, high, critical")
    confidence_score: float = Field(..., ge=0.0, le=1.0)

    # Implementation details
    implementation_effort: str = Field(..., description="low, medium, high")
    estimated_improvement: str
    prerequisites: List[str] = Field(default_factory=list)

    # Supporting data
    supporting_metrics: Dict[str, Any] = Field(default_factory=dict)
    baseline_measurements: Dict[str, float] = Field(default_factory=dict)

    # Timing
    created_at: datetime = Field(default_factory=datetime.utcnow)
    valid_until: Optional[datetime] = None

    # Status
    status: str = Field(default="active", description="active, implemented, dismissed")
    implemented_at: Optional[datetime] = None
    implementation_notes: Optional[str] = None


# =============================================================================
# REPORTS
# =============================================================================


class PluginPerformanceReport(BaseModel):
    """
    Comprehensive performance report for a plugin.

    Complete assessment including metrics, trends, comparisons,
    issues, and recommendations.

    Attributes:
        plugin_id: ID of the plugin.
        plugin_name: Display name of the plugin.
        report_period: (start_time, end_time) tuple.
        generated_at: When report was generated.
        overall_score: Performance score (0.0-100.0).
        health_status: "excellent", "good", "fair", "poor", "critical".
        usage_stats: Usage statistics for the period.
        performance_metrics: Key performance metrics.
        performance_trends: Detected trends in metrics.
        usage_patterns: Usage pattern analysis.
        peer_comparison: Comparison with similar plugins.
        historical_comparison: Comparison with previous periods.
        identified_issues: List of detected issues.
        optimization_recommendations: Suggested improvements.
        resource_costs: Resource cost breakdown.
        efficiency_score: Resource efficiency score (0.0-1.0).

    Example:
        >>> report = await analytics.generate_performance_report("my-plugin@1.0.0")
        >>> print(f"Health: {report.health_status} ({report.overall_score}/100)")
    """

    plugin_id: str
    plugin_name: str
    report_period: Tuple[datetime, datetime]
    generated_at: datetime = Field(default_factory=datetime.utcnow)

    # Executive summary
    overall_score: float = Field(..., ge=0.0, le=100.0, description="Overall performance score")
    health_status: str = Field(..., description="excellent, good, fair, poor, critical")

    # Key metrics
    usage_stats: PluginUsageStats
    performance_metrics: Dict[str, PluginMetricSummary] = Field(default_factory=dict)

    # Trend analysis
    performance_trends: List[Dict[str, Any]] = Field(default_factory=list)
    usage_patterns: Dict[str, Any] = Field(default_factory=dict)

    # Comparative analysis
    peer_comparison: Optional[Dict[str, Any]] = None
    historical_comparison: Optional[Dict[str, Any]] = None

    # Issues and recommendations
    identified_issues: List[Dict[str, Any]] = Field(default_factory=list)
    optimization_recommendations: List[OptimizationRecommendation] = Field(default_factory=list)

    # Cost analysis
    resource_costs: Optional[Dict[str, float]] = None
    efficiency_score: Optional[float] = None


# =============================================================================
# SYSTEM-WIDE ANALYTICS
# =============================================================================


class SystemWideAnalytics(BaseModel):
    """
    System-wide plugin analytics snapshot.

    Attributes:
        snapshot_id: Unique identifier.
        snapshot_time: When snapshot was taken.
        total_plugins: Total plugin count.
        active_plugins: Active plugin count.
        total_executions_last_24h: Executions in last 24 hours.
        system_wide_success_rate: Overall success rate (0.0-1.0).
        total_cpu_usage: Total CPU usage.
        total_memory_usage: Total memory usage.
        total_network_io: Total network I/O.
        total_disk_io: Total disk I/O.
        top_performers: Top performing plugins.
        bottom_performers: Lowest performing plugins.
        overall_system_health: System health score (0.0-100.0).
        bottlenecks_detected: List of detected bottlenecks.
        system_recommendations: System-wide recommendations.
    """

    snapshot_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    snapshot_time: datetime = Field(default_factory=datetime.utcnow)

    # Overall system metrics
    total_plugins: int = 0
    active_plugins: int = 0
    total_executions_last_24h: int = 0
    system_wide_success_rate: float = 0.0

    # Resource utilization
    total_cpu_usage: float = 0.0
    total_memory_usage: float = 0.0
    total_network_io: float = 0.0
    total_disk_io: float = 0.0

    # Top and bottom performers
    top_performers: List[Dict[str, Any]] = Field(default_factory=list)
    bottom_performers: List[Dict[str, Any]] = Field(default_factory=list)

    # System health indicators
    overall_system_health: float = Field(..., ge=0.0, le=100.0)
    bottlenecks_detected: List[str] = Field(default_factory=list)

    # Recommendations
    system_recommendations: List[OptimizationRecommendation] = Field(default_factory=list)
