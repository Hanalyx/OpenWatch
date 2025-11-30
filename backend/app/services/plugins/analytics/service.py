"""
Plugin Performance Analytics and Monitoring Service
Provides comprehensive analytics, monitoring, and optimization recommendations
for plugin performance, usage patterns, and system efficiency.
"""

import asyncio
import logging
import statistics
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from beanie import Document
from pydantic import BaseModel, Field

from ..models.plugin_models import InstalledPlugin, PluginStatus
from .plugin_registry_service import PluginRegistryService

logger = logging.getLogger(__name__)


# ============================================================================
# ANALYTICS MODELS AND ENUMS
# ============================================================================


class MetricType(str, Enum):
    """Types of plugin metrics"""

    PERFORMANCE = "performance"  # Response times, throughput
    RESOURCE = "resource"  # CPU, memory, disk usage
    ERROR = "error"  # Error rates, failure counts
    USAGE = "usage"  # Execution counts, frequency
    AVAILABILITY = "availability"  # Uptime, health status


class AggregationPeriod(str, Enum):
    """Time periods for metric aggregation"""

    MINUTE = "minute"
    HOUR = "hour"
    DAY = "day"
    WEEK = "week"
    MONTH = "month"


class OptimizationRecommendationType(str, Enum):
    """Types of optimization recommendations"""

    PERFORMANCE = "performance"  # Performance improvements
    RESOURCE = "resource"  # Resource optimization
    RELIABILITY = "reliability"  # Reliability improvements
    COST = "cost"  # Cost optimization
    SECURITY = "security"  # Security enhancements


class PluginMetric(BaseModel):
    """Individual plugin metric data point"""

    plugin_id: str
    metric_type: MetricType
    metric_name: str
    value: float
    unit: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Context
    host_id: Optional[str] = None
    execution_id: Optional[str] = None
    rule_id: Optional[str] = None

    # Additional metadata
    tags: Dict[str, str] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PluginMetricSummary(BaseModel):
    """Aggregated plugin metrics for a time period"""

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
    trend_direction: Optional[str] = None  # "increasing", "decreasing", "stable"
    trend_confidence: Optional[float] = None

    # Variance and distribution
    std_deviation: Optional[float] = None
    variance: Optional[float] = None


class PluginUsageStats(BaseModel):
    """Plugin usage statistics"""

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


class OptimizationRecommendation(BaseModel):
    """Optimization recommendation for a plugin"""

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


class PluginPerformanceReport(BaseModel):
    """Comprehensive performance report for a plugin"""

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


class SystemWideAnalytics(Document):
    """System-wide plugin analytics snapshot"""

    snapshot_id: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True)
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

    # Top performing plugins
    top_performers: List[Dict[str, Any]] = Field(default_factory=list)
    bottom_performers: List[Dict[str, Any]] = Field(default_factory=list)

    # System health indicators
    overall_system_health: float = Field(..., ge=0.0, le=100.0)
    bottlenecks_detected: List[str] = Field(default_factory=list)

    # Recommendations
    system_recommendations: List[OptimizationRecommendation] = Field(default_factory=list)

    class Settings:
        collection = "system_wide_analytics"
        indexes = ["snapshot_id", "snapshot_time"]


# ============================================================================
# PLUGIN ANALYTICS SERVICE
# ============================================================================


class PluginAnalyticsService:
    """
    Comprehensive plugin performance analytics and monitoring service

    Provides:
    - Real-time performance monitoring and metrics collection
    - Usage pattern analysis and trend detection
    - Resource utilization optimization recommendations
    - Comparative analysis and benchmarking
    - System-wide performance insights
    """

    def __init__(self) -> None:
        """Initialize plugin analytics service."""
        self.plugin_registry_service = PluginRegistryService()
        self.metrics_buffer: Dict[str, deque[PluginMetric]] = defaultdict(
            lambda: deque(maxlen=10000)
        )
        self.analytics_cache: Dict[str, Any] = {}
        self.monitoring_enabled = False
        self.collection_task: Optional[asyncio.Task[None]] = None

    async def start_metrics_collection(self) -> None:
        """Start real-time metrics collection."""
        if self.monitoring_enabled:
            logger.warning("Metrics collection is already running")
            return

        self.monitoring_enabled = True
        self.collection_task = asyncio.create_task(self._metrics_collection_loop())
        logger.info("Started plugin metrics collection")

    async def stop_metrics_collection(self) -> None:
        """Stop real-time metrics collection."""
        if not self.monitoring_enabled:
            return

        self.monitoring_enabled = False
        if self.collection_task:
            self.collection_task.cancel()
            try:
                await self.collection_task
            except asyncio.CancelledError:
                logger.debug("Ignoring exception during cleanup")

        logger.info("Stopped plugin metrics collection")

    async def record_plugin_metric(self, metric: PluginMetric) -> None:
        """Record a plugin metric data point."""
        metric_key = f"{metric.plugin_id}:{metric.metric_type.value}:{metric.metric_name}"
        self.metrics_buffer[metric_key].append(metric)

        # Invalidate related cache entries
        cache_keys_to_invalidate = [k for k in self.analytics_cache.keys() if metric.plugin_id in k]
        for key in cache_keys_to_invalidate:
            self.analytics_cache.pop(key, None)

    async def get_plugin_metrics(
        self,
        plugin_id: str,
        metric_type: Optional[MetricType] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[PluginMetric]:
        """Get plugin metrics for a specific time range"""

        if end_time is None:
            end_time = datetime.utcnow()
        if start_time is None:
            start_time = end_time - timedelta(hours=24)

        metrics = []

        # Filter metrics from buffer
        for metric_key, metric_deque in self.metrics_buffer.items():
            if not metric_key.startswith(f"{plugin_id}:"):
                continue

            if metric_type and not metric_key.startswith(f"{plugin_id}:{metric_type.value}:"):
                continue

            for metric in metric_deque:
                if start_time <= metric.timestamp <= end_time:
                    metrics.append(metric)

        # Sort by timestamp and limit
        metrics.sort(key=lambda m: m.timestamp, reverse=True)
        return metrics[:limit]

    async def get_aggregated_metrics(
        self,
        plugin_id: str,
        metric_type: MetricType,
        metric_name: str,
        period: AggregationPeriod,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[PluginMetricSummary]:
        """Get aggregated metrics for a plugin"""

        if end_time is None:
            end_time = datetime.utcnow()
        if start_time is None:
            start_time = end_time - timedelta(days=7)

        # Get raw metrics
        metrics = await self.get_plugin_metrics(
            plugin_id, metric_type, start_time, end_time, limit=10000
        )

        # Filter by metric name
        metrics = [m for m in metrics if m.metric_name == metric_name]

        if not metrics:
            return []

        # Group metrics by time period
        period_groups = self._group_metrics_by_period(metrics, period)

        # Calculate aggregations for each period
        summaries = []
        for period_start, period_metrics in period_groups.items():
            if not period_metrics:
                continue

            values = [m.value for m in period_metrics]

            summary = PluginMetricSummary(
                plugin_id=plugin_id,
                metric_type=metric_type,
                metric_name=metric_name,
                period=period,
                start_time=period_start,
                end_time=period_start + self._get_period_delta(period),
                count=len(values),
                min_value=min(values),
                max_value=max(values),
                avg_value=statistics.mean(values),
                median_value=statistics.median(values),
            )

            # Calculate percentiles
            if len(values) >= 20:  # Need sufficient data for percentiles
                sorted_values = sorted(values)
                summary.p95_value = sorted_values[int(0.95 * len(sorted_values))]
                summary.p99_value = sorted_values[int(0.99 * len(sorted_values))]

            # Calculate variance and standard deviation
            if len(values) > 1:
                summary.variance = statistics.variance(values)
                summary.std_deviation = statistics.stdev(values)

            summaries.append(summary)

        # Analyze trends
        self._analyze_metric_trends(summaries)

        return summaries

    async def generate_usage_stats(
        self,
        plugin_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> PluginUsageStats:
        """Generate comprehensive usage statistics for a plugin"""

        if end_time is None:
            end_time = datetime.utcnow()
        if start_time is None:
            start_time = end_time - timedelta(days=30)

        plugin = await self.plugin_registry_service.get_plugin(plugin_id)
        plugin_name = plugin.name if plugin else plugin_id

        # Get execution metrics
        execution_metrics = await self.get_plugin_metrics(
            plugin_id, MetricType.USAGE, start_time, end_time
        )

        # Get performance metrics
        performance_metrics = await self.get_plugin_metrics(
            plugin_id, MetricType.PERFORMANCE, start_time, end_time
        )

        # Calculate basic statistics
        total_executions = len([m for m in execution_metrics if m.metric_name == "execution_count"])
        successful_executions = len(
            [m for m in execution_metrics if m.metric_name == "successful_execution"]
        )
        failed_executions = total_executions - successful_executions

        # Calculate average execution time
        execution_times = [
            m.value for m in performance_metrics if m.metric_name == "execution_time"
        ]
        avg_execution_time = statistics.mean(execution_times) if execution_times else None

        # Analyze usage patterns
        usage_patterns = self._analyze_usage_patterns(execution_metrics)

        # Get resource metrics
        resource_metrics = await self.get_plugin_metrics(
            plugin_id, MetricType.RESOURCE, start_time, end_time
        )

        # Calculate resource consumption
        cpu_metrics = [m.value for m in resource_metrics if m.metric_name == "cpu_usage"]
        memory_metrics = [m.value for m in resource_metrics if m.metric_name == "memory_usage"]

        total_cpu_seconds = sum(cpu_metrics) if cpu_metrics else None
        total_memory_mb_hours = sum(memory_metrics) if memory_metrics else None

        # Calculate availability
        availability_percentage = self._calculate_availability(plugin_id, start_time, end_time)

        return PluginUsageStats(
            plugin_id=plugin_id,
            plugin_name=plugin_name,
            period_start=start_time,
            period_end=end_time,
            total_executions=total_executions,
            successful_executions=successful_executions,
            failed_executions=failed_executions,
            average_execution_time=avg_execution_time,
            peak_usage_hour=usage_patterns.get("peak_hour"),
            avg_daily_executions=usage_patterns.get("avg_daily"),
            usage_trend=usage_patterns.get("trend"),
            total_cpu_seconds=total_cpu_seconds,
            total_memory_mb_hours=total_memory_mb_hours,
            availability_percentage=availability_percentage,
        )

    async def generate_optimization_recommendations(
        self, plugin_id: str, lookback_days: int = 30
    ) -> List[OptimizationRecommendation]:
        """Generate optimization recommendations for a plugin"""

        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=lookback_days)

        recommendations = []

        # Get usage stats and metrics
        usage_stats = await self.generate_usage_stats(plugin_id, start_time, end_time)

        # Performance recommendations
        if usage_stats.average_execution_time and usage_stats.average_execution_time > 30:
            recommendations.append(
                OptimizationRecommendation(
                    plugin_id=plugin_id,
                    recommendation_type=OptimizationRecommendationType.PERFORMANCE,
                    title="Optimize Execution Time",
                    description=f"Plugin execution time averages {usage_stats.average_execution_time:.1f}s, which is above optimal range (< 30s).",
                    impact_level="medium",
                    confidence_score=0.8,
                    implementation_effort="medium",
                    estimated_improvement="30-50% faster execution times",
                    supporting_metrics={"avg_execution_time": usage_stats.average_execution_time},
                )
            )

        # Reliability recommendations
        if usage_stats.total_executions > 0:
            failure_rate = usage_stats.failed_executions / usage_stats.total_executions
            if failure_rate > 0.05:  # > 5% failure rate
                recommendations.append(
                    OptimizationRecommendation(
                        plugin_id=plugin_id,
                        recommendation_type=OptimizationRecommendationType.RELIABILITY,
                        title="Improve Reliability",
                        description=f"Plugin failure rate is {failure_rate:.1%}, above recommended threshold (< 5%).",
                        impact_level="high",
                        confidence_score=0.9,
                        implementation_effort="high",
                        estimated_improvement="Reduce failure rate to < 2%",
                        supporting_metrics={"failure_rate": failure_rate},
                    )
                )

        # Resource optimization recommendations
        if usage_stats.total_cpu_seconds and usage_stats.total_executions > 0:
            avg_cpu_per_execution = usage_stats.total_cpu_seconds / usage_stats.total_executions
            if avg_cpu_per_execution > 10:  # > 10 CPU seconds per execution
                recommendations.append(
                    OptimizationRecommendation(
                        plugin_id=plugin_id,
                        recommendation_type=OptimizationRecommendationType.RESOURCE,
                        title="Optimize CPU Usage",
                        description=f"High CPU usage per execution ({avg_cpu_per_execution:.1f}s). Consider optimization.",
                        impact_level="medium",
                        confidence_score=0.7,
                        implementation_effort="medium",
                        estimated_improvement="20-40% reduction in CPU usage",
                        supporting_metrics={"avg_cpu_per_execution": avg_cpu_per_execution},
                    )
                )

        return recommendations

    async def generate_performance_report(
        self, plugin_id: str, lookback_days: int = 30
    ) -> PluginPerformanceReport:
        """Generate a comprehensive performance report for a plugin"""

        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=lookback_days)

        plugin = await self.plugin_registry_service.get_plugin(plugin_id)
        plugin_name = plugin.name if plugin else plugin_id

        # Generate usage stats
        usage_stats = await self.generate_usage_stats(plugin_id, start_time, end_time)

        # Get aggregated performance metrics
        performance_metrics = {}
        for metric_name in ["execution_time", "response_time", "throughput"]:
            summaries = await self.get_aggregated_metrics(
                plugin_id,
                MetricType.PERFORMANCE,
                metric_name,
                AggregationPeriod.DAY,
                start_time,
                end_time,
            )
            if summaries:
                performance_metrics[metric_name] = summaries[-1]  # Latest summary

        # Calculate overall performance score
        overall_score = self._calculate_performance_score(usage_stats, performance_metrics)

        # Determine health status
        health_status = self._determine_health_status(overall_score)

        # Generate optimization recommendations
        recommendations = await self.generate_optimization_recommendations(plugin_id, lookback_days)

        # Analyze trends
        performance_trends = self._analyze_performance_trends(performance_metrics)

        # Identify issues
        identified_issues = self._identify_performance_issues(usage_stats, performance_metrics)

        return PluginPerformanceReport(
            plugin_id=plugin_id,
            plugin_name=plugin_name,
            report_period=(start_time, end_time),
            overall_score=overall_score,
            health_status=health_status,
            usage_stats=usage_stats,
            performance_metrics=performance_metrics,
            performance_trends=performance_trends,
            identified_issues=identified_issues,
            optimization_recommendations=recommendations,
        )

    async def get_system_wide_analytics(self) -> SystemWideAnalytics:
        """Generate system-wide analytics snapshot"""

        # Get all plugins
        plugins = await self.plugin_registry_service.find_plugins({})
        active_plugins = [p for p in plugins if p.status == PluginStatus.ACTIVE]

        # Calculate system metrics
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=24)

        total_executions = 0
        total_successes = 0
        system_cpu_usage = 0.0
        system_memory_usage = 0.0

        plugin_scores = []

        for plugin in active_plugins:
            usage_stats = await self.generate_usage_stats(plugin.plugin_id, start_time, end_time)
            total_executions += usage_stats.total_executions
            total_successes += usage_stats.successful_executions

            if usage_stats.total_cpu_seconds:
                system_cpu_usage += usage_stats.total_cpu_seconds
            if usage_stats.total_memory_mb_hours:
                system_memory_usage += usage_stats.total_memory_mb_hours

            # Calculate plugin score for ranking
            score = self._calculate_plugin_score(usage_stats)
            plugin_scores.append(
                {
                    "plugin_id": plugin.plugin_id,
                    "plugin_name": plugin.name,
                    "score": score,
                    "executions": usage_stats.total_executions,
                }
            )

        # Calculate system-wide success rate
        success_rate = (total_successes / total_executions) if total_executions > 0 else 0.0

        # Rank plugins
        plugin_scores.sort(key=lambda x: x["score"], reverse=True)
        top_performers = plugin_scores[:5]
        bottom_performers = plugin_scores[-5:] if len(plugin_scores) > 5 else []

        # Calculate overall system health
        overall_health = min(
            100.0, success_rate * 100 + (1 - min(system_cpu_usage / 1000, 1.0)) * 20
        )

        # Detect bottlenecks
        bottlenecks = []
        if system_cpu_usage > 500:  # High CPU usage
            bottlenecks.append("High system CPU usage detected")
        if system_memory_usage > 10000:  # High memory usage
            bottlenecks.append("High system memory usage detected")
        if success_rate < 0.9:  # Low success rate
            bottlenecks.append("System-wide success rate below threshold")

        analytics = SystemWideAnalytics(
            total_plugins=len(plugins),
            active_plugins=len(active_plugins),
            total_executions_last_24h=total_executions,
            system_wide_success_rate=success_rate,
            total_cpu_usage=system_cpu_usage,
            total_memory_usage=system_memory_usage,
            top_performers=top_performers,
            bottom_performers=bottom_performers,
            overall_system_health=overall_health,
            bottlenecks_detected=bottlenecks,
        )

        await analytics.save()
        return analytics

    async def _metrics_collection_loop(self) -> None:
        """Background metrics collection loop."""
        while self.monitoring_enabled:
            try:
                # Collect metrics from all active plugins
                plugins = await self.plugin_registry_service.find_plugins(
                    {"status": PluginStatus.ACTIVE}
                )

                for plugin in plugins:
                    await self._collect_plugin_metrics(plugin)

                # Wait before next collection
                await asyncio.sleep(60)  # Collect every minute

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in metrics collection loop: {e}")
                await asyncio.sleep(60)

    async def _collect_plugin_metrics(self, plugin: InstalledPlugin) -> None:
        """Collect metrics for a specific plugin."""
        try:
            # This would collect actual metrics from the plugin
            # For now, generate mock metrics

            current_time = datetime.utcnow()

            # Performance metrics
            execution_time_metric = PluginMetric(
                plugin_id=plugin.plugin_id,
                metric_type=MetricType.PERFORMANCE,
                metric_name="execution_time",
                value=30.0 + (hash(plugin.plugin_id) % 100) / 10.0,  # Mock data
                unit="seconds",
                timestamp=current_time,
            )
            await self.record_plugin_metric(execution_time_metric)

            # Resource metrics
            cpu_metric = PluginMetric(
                plugin_id=plugin.plugin_id,
                metric_type=MetricType.RESOURCE,
                metric_name="cpu_usage",
                value=10.0 + (hash(plugin.plugin_id + "cpu") % 50) / 10.0,  # Mock data
                unit="percent",
                timestamp=current_time,
            )
            await self.record_plugin_metric(cpu_metric)

            memory_metric = PluginMetric(
                plugin_id=plugin.plugin_id,
                metric_type=MetricType.RESOURCE,
                metric_name="memory_usage",
                value=100.0 + (hash(plugin.plugin_id + "mem") % 200),  # Mock data
                unit="megabytes",
                timestamp=current_time,
            )
            await self.record_plugin_metric(memory_metric)

        except Exception as e:
            logger.error(f"Failed to collect metrics for plugin {plugin.plugin_id}: {e}")

    def _group_metrics_by_period(
        self, metrics: List[PluginMetric], period: AggregationPeriod
    ) -> Dict[datetime, List[PluginMetric]]:
        """Group metrics by time period"""
        groups = defaultdict(list)

        for metric in metrics:
            # Truncate timestamp to period boundary
            if period == AggregationPeriod.MINUTE:
                period_start = metric.timestamp.replace(second=0, microsecond=0)
            elif period == AggregationPeriod.HOUR:
                period_start = metric.timestamp.replace(minute=0, second=0, microsecond=0)
            elif period == AggregationPeriod.DAY:
                period_start = metric.timestamp.replace(hour=0, minute=0, second=0, microsecond=0)
            elif period == AggregationPeriod.WEEK:
                days_since_monday = metric.timestamp.weekday()
                period_start = (metric.timestamp - timedelta(days=days_since_monday)).replace(
                    hour=0, minute=0, second=0, microsecond=0
                )
            elif period == AggregationPeriod.MONTH:
                period_start = metric.timestamp.replace(
                    day=1, hour=0, minute=0, second=0, microsecond=0
                )
            else:
                period_start = metric.timestamp

            groups[period_start].append(metric)

        return groups

    def _get_period_delta(self, period: AggregationPeriod) -> timedelta:
        """Get time delta for aggregation period"""
        if period == AggregationPeriod.MINUTE:
            return timedelta(minutes=1)
        elif period == AggregationPeriod.HOUR:
            return timedelta(hours=1)
        elif period == AggregationPeriod.DAY:
            return timedelta(days=1)
        elif period == AggregationPeriod.WEEK:
            return timedelta(weeks=1)
        elif period == AggregationPeriod.MONTH:
            return timedelta(days=30)
        else:
            return timedelta(hours=1)

    def _analyze_metric_trends(self, summaries: List[PluginMetricSummary]) -> None:
        """Analyze trends in metric summaries."""
        if len(summaries) < 3:
            return

        # Get recent values
        recent_values = [s.avg_value for s in summaries[-5:] if s.avg_value is not None]

        if len(recent_values) < 3:
            return

        # Simple trend analysis
        first_half = recent_values[: len(recent_values) // 2]
        second_half = recent_values[len(recent_values) // 2 :]

        first_avg = statistics.mean(first_half)
        second_avg = statistics.mean(second_half)

        for summary in summaries:
            if second_avg > first_avg * 1.1:
                summary.trend_direction = "increasing"
                summary.trend_confidence = 0.7
            elif second_avg < first_avg * 0.9:
                summary.trend_direction = "decreasing"
                summary.trend_confidence = 0.7
            else:
                summary.trend_direction = "stable"
                summary.trend_confidence = 0.8

    def _analyze_usage_patterns(self, execution_metrics: List[PluginMetric]) -> Dict[str, Any]:
        """Analyze usage patterns from execution metrics."""
        if not execution_metrics:
            return {}

        # Group by hour of day
        hourly_counts: Dict[int, int] = defaultdict(int)
        daily_counts: Dict[Any, int] = defaultdict(int)

        for metric in execution_metrics:
            if metric.metric_name == "execution_count":
                hour = metric.timestamp.hour
                day = metric.timestamp.date()
                hourly_counts[hour] += 1
                daily_counts[day] += 1

        # Find peak usage hour
        peak_hour = max(hourly_counts.items(), key=lambda x: x[1])[0] if hourly_counts else None

        # Calculate average daily executions
        avg_daily = statistics.mean(daily_counts.values()) if daily_counts else None

        # Determine trend
        if len(daily_counts) >= 7:
            recent_days = list(daily_counts.values())[-7:]
            earlier_days = list(daily_counts.values())[:-7] if len(daily_counts) > 7 else []

            if earlier_days:
                recent_avg = statistics.mean(recent_days)
                earlier_avg = statistics.mean(earlier_days)

                if recent_avg > earlier_avg * 1.2:
                    trend = "increasing"
                elif recent_avg < earlier_avg * 0.8:
                    trend = "decreasing"
                else:
                    trend = "stable"
            else:
                trend = "insufficient_data"
        else:
            trend = "insufficient_data"

        return {"peak_hour": peak_hour, "avg_daily": avg_daily, "trend": trend}

    def _calculate_availability(
        self, plugin_id: str, start_time: datetime, end_time: datetime
    ) -> float:
        """Calculate plugin availability percentage"""
        # This would calculate actual availability based on health checks
        # For now, return mock availability based on plugin ID
        base_availability = 95.0 + (hash(plugin_id) % 5)
        return min(99.9, base_availability)

    def _calculate_performance_score(
        self,
        usage_stats: PluginUsageStats,
        performance_metrics: Dict[str, PluginMetricSummary],
    ) -> float:
        """Calculate overall performance score (0-100)"""

        # Reliability factor (40% of score)
        if usage_stats.total_executions > 0:
            success_rate = usage_stats.successful_executions / usage_stats.total_executions
            reliability_score = success_rate * 40
        else:
            reliability_score = 40  # No executions = neutral

        # Performance factor (30% of score)
        performance_score = 30  # Default
        if (
            "execution_time" in performance_metrics
            and performance_metrics["execution_time"].avg_value
        ):
            avg_time = performance_metrics["execution_time"].avg_value
            if avg_time <= 10:
                performance_score = 30
            elif avg_time <= 30:
                performance_score = 25
            elif avg_time <= 60:
                performance_score = 20
            else:
                performance_score = 10

        # Availability factor (20% of score)
        availability_score = (usage_stats.availability_percentage or 95) * 0.2

        # Resource efficiency factor (10% of score)
        efficiency_score = 10  # Default

        total_score = reliability_score + performance_score + availability_score + efficiency_score
        return min(100.0, max(0.0, total_score))

    def _determine_health_status(self, score: float) -> str:
        """Determine health status from performance score"""
        if score >= 90:
            return "excellent"
        elif score >= 75:
            return "good"
        elif score >= 60:
            return "fair"
        elif score >= 40:
            return "poor"
        else:
            return "critical"

    def _analyze_performance_trends(
        self, performance_metrics: Dict[str, PluginMetricSummary]
    ) -> List[Dict[str, Any]]:
        """Analyze performance trends"""
        trends = []

        for metric_name, summary in performance_metrics.items():
            if summary.trend_direction:
                trends.append(
                    {
                        "metric": metric_name,
                        "trend": summary.trend_direction,
                        "confidence": summary.trend_confidence,
                        "current_value": summary.avg_value,
                    }
                )

        return trends

    def _identify_performance_issues(
        self,
        usage_stats: PluginUsageStats,
        performance_metrics: Dict[str, PluginMetricSummary],
    ) -> List[Dict[str, Any]]:
        """Identify performance issues"""
        issues = []

        # High failure rate
        if usage_stats.total_executions > 0:
            failure_rate = usage_stats.failed_executions / usage_stats.total_executions
            if failure_rate > 0.1:
                issues.append(
                    {
                        "type": "high_failure_rate",
                        "severity": "high",
                        "description": f"Failure rate is {failure_rate:.1%}, above acceptable threshold",
                        "metric_value": failure_rate,
                    }
                )

        # Slow execution times
        if "execution_time" in performance_metrics:
            avg_time = performance_metrics["execution_time"].avg_value
            if avg_time and avg_time > 60:
                issues.append(
                    {
                        "type": "slow_execution",
                        "severity": "medium",
                        "description": f"Average execution time is {avg_time:.1f}s, above optimal range",
                        "metric_value": avg_time,
                    }
                )

        # Low availability
        if usage_stats.availability_percentage and usage_stats.availability_percentage < 95:
            issues.append(
                {
                    "type": "low_availability",
                    "severity": "high",
                    "description": f"Availability is {usage_stats.availability_percentage:.1f}%, below target (95%)",
                    "metric_value": usage_stats.availability_percentage,
                }
            )

        return issues

    def _calculate_plugin_score(self, usage_stats: PluginUsageStats) -> float:
        """Calculate overall plugin score for ranking"""

        # Base score from executions (usage)
        execution_score = min(100, usage_stats.total_executions / 10)  # Normalize to 0-100

        # Success rate score
        if usage_stats.total_executions > 0:
            success_rate = usage_stats.successful_executions / usage_stats.total_executions
            reliability_score = success_rate * 100
        else:
            reliability_score = 50  # Neutral score for no executions

        # Availability score
        availability_score = usage_stats.availability_percentage or 95

        # Weighted average
        overall_score = execution_score * 0.4 + reliability_score * 0.4 + availability_score * 0.2

        return overall_score
