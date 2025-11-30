"""
Plugin Orchestration Subpackage

Provides comprehensive orchestration capabilities for plugin management including
load balancing, auto-scaling, circuit breaking, and performance optimization.

Components:
    - PluginOrchestrationService: Main service for plugin orchestration
    - Models: Clusters, instances, routing, optimization jobs

Orchestration Capabilities:
    - Request routing across plugin instances
    - Load balancing with multiple strategies
    - Auto-scaling based on demand and predictions
    - Circuit breaker fault tolerance
    - Performance optimization and tuning

Load Balancing Strategies:
    - ROUND_ROBIN: Sequential distribution
    - LEAST_CONNECTIONS: Route to least busy instance
    - WEIGHTED_ROUND_ROBIN: Distribution based on instance weights
    - RESOURCE_BASED: Route based on resource availability
    - PERFORMANCE_BASED: Route based on response times
    - INTELLIGENT: ML-based adaptive routing
    - CUSTOM: User-defined routing logic

Auto-Scaling Policies:
    - DISABLED: Manual instance management
    - REACTIVE: Scale based on current metrics
    - PREDICTIVE: Scale based on predicted demand
    - SCHEDULE_BASED: Scale based on time schedules
    - HYBRID: Combine multiple policies

Optimization Targets:
    - THROUGHPUT: Maximize requests per second
    - LATENCY: Minimize response time
    - RESOURCE_EFFICIENCY: Optimize resource usage
    - COST: Minimize operational cost
    - AVAILABILITY: Maximize uptime and reliability
    - BALANCED: Balance all factors

Usage:
    from backend.app.services.plugins.orchestration import PluginOrchestrationService

    orchestrator = PluginOrchestrationService()
    await orchestrator.start()

    # Register a plugin cluster
    cluster = await orchestrator.register_cluster(
        plugin_id="scanner@1.0.0",
        strategy=OrchestrationStrategy.LEAST_CONNECTIONS,
        min_instances=2,
        max_instances=10,
    )

    # Add instances
    await orchestrator.add_instance(
        cluster_id=cluster.cluster_id,
        host="worker-01",
        port=8080,
    )

    # Route a request
    response = await orchestrator.route_request(
        plugin_id="scanner@1.0.0",
        method="POST",
        path="/scan",
    )
    print(f"Routed to {response.instance_host}:{response.instance_port}")

Example:
    >>> from backend.app.services.plugins.orchestration import (
    ...     PluginOrchestrationService,
    ...     OrchestrationStrategy,
    ...     OptimizationTarget,
    ... )
    >>> orchestrator = PluginOrchestrationService()
    >>> await orchestrator.start()
    >>> summary = await orchestrator.get_orchestration_summary()
    >>> print(f"Total clusters: {summary['clusters']['total']}")
"""

from .models import (
    CircuitBreakerConfig,
    CircuitState,
    InstanceStatus,
    OptimizationJob,
    OptimizationTarget,
    OrchestrationStrategy,
    PluginCluster,
    PluginInstance,
    PluginOrchestrationConfig,
    RouteRequest,
    RouteResponse,
    ScalingConfig,
    ScalingPolicy,
)
from .service import PluginOrchestrationService

__all__ = [
    # Service
    "PluginOrchestrationService",
    # Enums
    "OrchestrationStrategy",
    "OptimizationTarget",
    "ScalingPolicy",
    "InstanceStatus",
    "CircuitState",
    # Models
    "PluginInstance",
    "PluginCluster",
    "RouteRequest",
    "RouteResponse",
    "OptimizationJob",
    # Configuration
    "ScalingConfig",
    "CircuitBreakerConfig",
    "PluginOrchestrationConfig",
]
