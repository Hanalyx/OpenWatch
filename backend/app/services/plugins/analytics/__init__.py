"""
Plugin Analytics Subpackage

Provides comprehensive analytics, monitoring, and optimization recommendations
for plugin performance, usage patterns, and system efficiency.

Components:
    - PluginAnalyticsService: Main service for plugin analytics operations
    - Models: Metrics, summaries, recommendations, reports

Analytics Capabilities:
    - Real-time performance monitoring
    - Usage pattern analysis and trend detection
    - Resource utilization tracking
    - Comparative analysis and benchmarking
    - Optimization recommendations
    - System-wide analytics snapshots

Metric Types:
    - PERFORMANCE: Response times, throughput, latency
    - RESOURCE: CPU, memory, disk, network usage
    - ERROR: Error rates, failure counts, exceptions
    - USAGE: Execution counts, frequency patterns
    - AVAILABILITY: Uptime, health status history

Usage:
    from backend.app.services.plugins.analytics import PluginAnalyticsService

    analytics = PluginAnalyticsService()

    # Start metrics collection
    await analytics.start_metrics_collection()

    # Generate usage statistics
    stats = await analytics.generate_usage_stats(plugin_id)

    # Generate performance report
    report = await analytics.generate_performance_report(plugin_id)

    # Get optimization recommendations
    recommendations = await analytics.generate_optimization_recommendations(plugin_id)

Example:
    >>> from backend.app.services.plugins.analytics import (
    ...     PluginAnalyticsService,
    ...     MetricType,
    ... )
    >>> analytics = PluginAnalyticsService()
    >>> report = await analytics.generate_performance_report("my-plugin@1.0.0")
    >>> print(f"Overall Score: {report.overall_score}/100")
"""

from .models import (
    AggregationPeriod,
    MetricType,
    OptimizationRecommendation,
    OptimizationRecommendationType,
    PluginMetric,
    PluginMetricSummary,
    PluginPerformanceReport,
    PluginUsageStats,
    SystemWideAnalytics,
)
from .service import PluginAnalyticsService

__all__ = [
    # Service
    "PluginAnalyticsService",
    # Enums
    "MetricType",
    "AggregationPeriod",
    "OptimizationRecommendationType",
    # Models
    "PluginMetric",
    "PluginMetricSummary",
    "PluginUsageStats",
    "OptimizationRecommendation",
    "PluginPerformanceReport",
    "SystemWideAnalytics",
]
