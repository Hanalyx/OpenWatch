"""
Plugin Orchestration Models

Data models for plugin orchestration including load balancing strategies,
auto-scaling policies, instance management, and optimization jobs.

These models support:
- Multiple load balancing strategies (round-robin, least-connections, etc.)
- Auto-scaling with reactive and predictive policies
- Plugin instance and cluster management
- Request routing and response tracking
- Performance optimization job management

Security Considerations:
    - Instance health scores are bounded (0.0-1.0)
    - Request routing respects plugin security contexts
    - Optimization jobs have resource limits
    - Circuit breaker states protect against cascading failures

Performance Considerations:
    - Load balancer weights are normalized (0.0-1.0)
    - Instance selection algorithms are O(n) or better
    - Cluster statistics are cached for efficiency
    - Optimization models use heuristics for speed
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# =============================================================================
# ORCHESTRATION ENUMS
# =============================================================================


class OrchestrationStrategy(str, Enum):
    """
    Load balancing strategies for plugin orchestration.

    These strategies determine how requests are distributed across
    plugin instances to optimize performance and resource utilization.

    Strategies:
        ROUND_ROBIN: Sequential distribution
            - Simple and predictable
            - Even distribution regardless of load
            - Best for homogeneous instances

        LEAST_CONNECTIONS: Route to least busy instance
            - Tracks active connections per instance
            - Automatically adapts to varying request durations
            - Best for heterogeneous workloads

        WEIGHTED_ROUND_ROBIN: Round-robin with instance weights
            - Assigns weights based on instance capacity
            - Higher weight = more requests
            - Best for instances with different capabilities

        RESOURCE_BASED: Route based on resource availability
            - Considers CPU, memory, and other resources
            - Avoids overloaded instances
            - Best for resource-intensive plugins

        PERFORMANCE_BASED: Route based on response times
            - Tracks historical response times
            - Prefers faster instances
            - Best for latency-sensitive applications

        INTELLIGENT: ML-based adaptive routing
            - Uses multiple factors for routing decisions
            - Learns from historical patterns
            - Best for complex, variable workloads

        CUSTOM: User-defined routing logic
            - Allows custom routing rules
            - Full control over distribution
            - Best for specialized requirements
    """

    ROUND_ROBIN = "round_robin"
    LEAST_CONNECTIONS = "least_connections"
    WEIGHTED_ROUND_ROBIN = "weighted_round_robin"
    RESOURCE_BASED = "resource_based"
    PERFORMANCE_BASED = "performance_based"
    INTELLIGENT = "intelligent"
    CUSTOM = "custom"


class OptimizationTarget(str, Enum):
    """
    Optimization targets for plugin performance.

    These targets define what aspect of plugin performance the
    orchestration service should prioritize when making decisions.

    Targets:
        THROUGHPUT: Maximize requests per second
            - Focus on handling more requests
            - May accept higher latency
            - Best for batch processing

        LATENCY: Minimize response time
            - Focus on fast responses
            - May limit concurrent requests
            - Best for interactive applications

        RESOURCE_EFFICIENCY: Optimize resource usage
            - Balance load across instances
            - Minimize idle resources
            - Best for cost optimization

        COST: Minimize operational cost
            - Consider instance pricing
            - Prefer cheaper instances when possible
            - Best for budget-conscious deployments

        AVAILABILITY: Maximize uptime and reliability
            - Spread load for fault tolerance
            - Maintain capacity reserves
            - Best for critical applications

        BALANCED: Balance all factors
            - Consider all targets equally
            - No single optimization focus
            - Best for general-purpose use
    """

    THROUGHPUT = "throughput"
    LATENCY = "latency"
    RESOURCE_EFFICIENCY = "resource_efficiency"
    COST = "cost"
    AVAILABILITY = "availability"
    BALANCED = "balanced"


class ScalingPolicy(str, Enum):
    """
    Auto-scaling policies for plugin instances.

    These policies control when and how the orchestration service
    adjusts the number of plugin instances based on demand.

    Policies:
        DISABLED: No automatic scaling
            - Manual instance management only
            - Full operator control
            - Best for stable, predictable workloads

        REACTIVE: Scale based on current metrics
            - Responds to threshold breaches
            - Simple and predictable
            - May have lag during traffic spikes

        PREDICTIVE: Scale based on predicted demand
            - Uses historical patterns
            - Proactive scaling before demand
            - Best for predictable traffic patterns

        SCHEDULE_BASED: Scale based on time schedules
            - Pre-defined scaling schedules
            - Scale up before known peaks
            - Best for recurring patterns

        HYBRID: Combine multiple policies
            - Uses reactive + predictive + schedule
            - Comprehensive coverage
            - Best for complex traffic patterns
    """

    DISABLED = "disabled"
    REACTIVE = "reactive"
    PREDICTIVE = "predictive"
    SCHEDULE_BASED = "schedule_based"
    HYBRID = "hybrid"


class InstanceStatus(str, Enum):
    """
    Status of a plugin instance.

    Tracks the lifecycle state of individual plugin instances
    for health monitoring and load balancing decisions.

    Statuses:
        STARTING: Instance is initializing
        RUNNING: Instance is healthy and accepting requests
        STOPPING: Instance is gracefully shutting down
        STOPPED: Instance is not running
        UNHEALTHY: Instance failed health checks
        DRAINING: Instance is finishing existing requests
    """

    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    UNHEALTHY = "unhealthy"
    DRAINING = "draining"


class CircuitState(str, Enum):
    """
    Circuit breaker states for fault tolerance.

    Implements the circuit breaker pattern to prevent cascading
    failures when plugin instances become unhealthy.

    States:
        CLOSED: Normal operation, requests allowed
        OPEN: Failures exceeded threshold, requests blocked
        HALF_OPEN: Testing if instance has recovered
    """

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


# =============================================================================
# INSTANCE MODELS
# =============================================================================


class PluginInstance(BaseModel):
    """
    Plugin instance for orchestration.

    Represents a single running instance of a plugin that can
    receive and process requests. Instances are managed by the
    orchestration service for load balancing and scaling.

    Attributes:
        instance_id: Unique identifier for the instance.
        plugin_id: ID of the plugin this instance runs.
        host: Hostname or IP where the instance is running.
        port: Port number for the instance.
        status: Current instance status.
        weight: Load balancing weight (0.0-1.0).
        health_score: Current health score (0.0-1.0).
        active_connections: Number of active connections.
        total_requests: Total requests processed.
        total_errors: Total errors encountered.
        avg_response_time_ms: Average response time in milliseconds.
        last_health_check: Timestamp of last health check.
        started_at: When the instance was started.
        metadata: Additional instance metadata.
        circuit_state: Circuit breaker state.
        circuit_failures: Consecutive failures for circuit breaker.

    Example:
        >>> instance = PluginInstance(
        ...     plugin_id="scanner@1.0.0",
        ...     host="worker-01",
        ...     port=8080,
        ...     weight=1.0,
        ... )
    """

    instance_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    plugin_id: str
    host: str
    port: int = Field(..., ge=1, le=65535)
    status: InstanceStatus = InstanceStatus.STARTING

    # Load balancing
    weight: float = Field(default=1.0, ge=0.0, le=1.0)
    health_score: float = Field(default=1.0, ge=0.0, le=1.0)

    # Metrics
    active_connections: int = Field(default=0, ge=0)
    total_requests: int = Field(default=0, ge=0)
    total_errors: int = Field(default=0, ge=0)
    avg_response_time_ms: float = Field(default=0.0, ge=0.0)

    # Timestamps
    last_health_check: Optional[datetime] = None
    started_at: datetime = Field(default_factory=datetime.utcnow)

    # Circuit breaker
    circuit_state: CircuitState = CircuitState.CLOSED
    circuit_failures: int = Field(default=0, ge=0)

    # Metadata
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def error_rate(self) -> float:
        """Calculate the error rate for this instance."""
        if self.total_requests == 0:
            return 0.0
        return self.total_errors / self.total_requests

    @property
    def is_available(self) -> bool:
        """Check if instance can accept requests."""
        return (
            self.status == InstanceStatus.RUNNING
            and self.circuit_state != CircuitState.OPEN
            and self.health_score > 0.3
        )


class PluginCluster(BaseModel):
    """
    Cluster of plugin instances for load balancing.

    Represents a group of plugin instances that collectively
    serve requests for a plugin. The cluster manages instance
    lifecycle, load balancing, and scaling decisions.

    Attributes:
        cluster_id: Unique identifier for the cluster.
        plugin_id: ID of the plugin this cluster serves.
        instances: List of instances in the cluster.
        strategy: Load balancing strategy.
        scaling_policy: Auto-scaling policy.
        min_instances: Minimum number of instances.
        max_instances: Maximum number of instances.
        target_instances: Desired number of instances.
        created_at: When the cluster was created.
        updated_at: When the cluster was last updated.
        metadata: Additional cluster metadata.

    Example:
        >>> cluster = PluginCluster(
        ...     plugin_id="scanner@1.0.0",
        ...     strategy=OrchestrationStrategy.LEAST_CONNECTIONS,
        ...     min_instances=2,
        ...     max_instances=10,
        ... )
    """

    cluster_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    plugin_id: str
    instances: List[PluginInstance] = Field(default_factory=list)

    # Load balancing
    strategy: OrchestrationStrategy = OrchestrationStrategy.ROUND_ROBIN

    # Scaling
    scaling_policy: ScalingPolicy = ScalingPolicy.DISABLED
    min_instances: int = Field(default=1, ge=0)
    max_instances: int = Field(default=10, ge=1)
    target_instances: int = Field(default=1, ge=0)

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    # Metadata
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def available_instances(self) -> List[PluginInstance]:
        """Get instances that can accept requests."""
        return [i for i in self.instances if i.is_available]

    @property
    def instance_count(self) -> int:
        """Get total number of instances."""
        return len(self.instances)

    @property
    def healthy_instance_count(self) -> int:
        """Get number of healthy instances."""
        return len(self.available_instances)


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================


class RouteRequest(BaseModel):
    """
    Request routing information.

    Contains all information needed to route a request to an
    appropriate plugin instance based on the configured strategy.

    Attributes:
        request_id: Unique identifier for the request.
        plugin_id: ID of the target plugin.
        method: HTTP method or RPC method name.
        path: Request path or endpoint.
        headers: Request headers.
        body_size: Size of request body in bytes.
        priority: Request priority (higher = more important).
        timeout_ms: Request timeout in milliseconds.
        affinity_key: Key for session affinity routing.
        metadata: Additional request metadata.
        created_at: When the request was created.

    Example:
        >>> request = RouteRequest(
        ...     plugin_id="scanner@1.0.0",
        ...     method="POST",
        ...     path="/scan",
        ...     timeout_ms=30000,
        ... )
    """

    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    plugin_id: str
    method: str = "GET"
    path: str = "/"
    headers: Dict[str, str] = Field(default_factory=dict)
    body_size: int = Field(default=0, ge=0)
    priority: int = Field(default=0, ge=0, le=10)
    timeout_ms: int = Field(default=30000, ge=100, le=600000)
    affinity_key: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class RouteResponse(BaseModel):
    """
    Response from request routing.

    Contains the routing decision and metadata about the
    selected instance and routing process.

    Attributes:
        request_id: ID of the original request.
        instance_id: ID of the selected instance.
        instance_host: Hostname of the selected instance.
        instance_port: Port of the selected instance.
        strategy_used: Load balancing strategy used.
        routing_time_ms: Time taken to make routing decision.
        fallback_used: Whether a fallback was used.
        metadata: Additional response metadata.

    Example:
        >>> response = orchestrator.route_request(request)
        >>> print(f"Routed to {response.instance_host}:{response.instance_port}")
    """

    request_id: str
    instance_id: str
    instance_host: str
    instance_port: int
    strategy_used: OrchestrationStrategy
    routing_time_ms: float = Field(default=0.0, ge=0.0)
    fallback_used: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)


# =============================================================================
# OPTIMIZATION MODELS
# =============================================================================


class OptimizationJob(BaseModel):
    """
    Optimization job for plugin performance.

    Represents a background optimization task that analyzes
    plugin performance and makes recommendations or automatic
    adjustments to improve efficiency.

    Attributes:
        job_id: Unique identifier for the job.
        plugin_id: ID of the plugin to optimize.
        target: Optimization target (throughput, latency, etc.).
        status: Current job status.
        started_at: When the job started.
        completed_at: When the job completed.
        progress: Job progress (0.0-1.0).
        current_metrics: Metrics before optimization.
        target_metrics: Target metrics to achieve.
        recommendations: Generated recommendations.
        actions_taken: Actions automatically taken.
        result_summary: Summary of optimization results.
        error_message: Error message if job failed.
        metadata: Additional job metadata.
    """

    job_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    plugin_id: str
    target: OptimizationTarget = OptimizationTarget.BALANCED
    status: str = Field(default="pending", description="pending, running, completed, failed")

    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    progress: float = Field(default=0.0, ge=0.0, le=1.0)

    # Metrics
    current_metrics: Dict[str, float] = Field(default_factory=dict)
    target_metrics: Dict[str, float] = Field(default_factory=dict)

    # Results
    recommendations: List[Dict[str, Any]] = Field(default_factory=list)
    actions_taken: List[Dict[str, Any]] = Field(default_factory=list)
    result_summary: Optional[str] = None
    error_message: Optional[str] = None

    # Metadata
    metadata: Dict[str, Any] = Field(default_factory=dict)


# =============================================================================
# CONFIGURATION MODELS
# =============================================================================


class ScalingConfig(BaseModel):
    """
    Configuration for auto-scaling behavior.

    Defines thresholds and parameters for automatic scaling
    of plugin instances based on load and performance metrics.

    Attributes:
        enabled: Whether auto-scaling is enabled.
        policy: Scaling policy to use.
        scale_up_threshold: CPU/load threshold to scale up.
        scale_down_threshold: CPU/load threshold to scale down.
        scale_up_cooldown_seconds: Cooldown after scale up.
        scale_down_cooldown_seconds: Cooldown after scale down.
        min_instances: Minimum instance count.
        max_instances: Maximum instance count.
        target_cpu_utilization: Target CPU utilization percentage.
        target_request_rate: Target requests per second per instance.

    Example:
        >>> config = ScalingConfig(
        ...     enabled=True,
        ...     policy=ScalingPolicy.REACTIVE,
        ...     scale_up_threshold=0.8,
        ...     scale_down_threshold=0.3,
        ... )
    """

    enabled: bool = True
    policy: ScalingPolicy = ScalingPolicy.REACTIVE

    # Thresholds
    scale_up_threshold: float = Field(default=0.8, ge=0.0, le=1.0)
    scale_down_threshold: float = Field(default=0.3, ge=0.0, le=1.0)

    # Cooldowns
    scale_up_cooldown_seconds: int = Field(default=60, ge=10, le=3600)
    scale_down_cooldown_seconds: int = Field(default=300, ge=60, le=3600)

    # Limits
    min_instances: int = Field(default=1, ge=0)
    max_instances: int = Field(default=10, ge=1)

    # Targets
    target_cpu_utilization: float = Field(default=0.7, ge=0.1, le=1.0)
    target_request_rate: float = Field(default=100.0, ge=1.0)


class CircuitBreakerConfig(BaseModel):
    """
    Configuration for circuit breaker behavior.

    Defines parameters for the circuit breaker pattern that
    protects against cascading failures from unhealthy instances.

    Attributes:
        enabled: Whether circuit breaker is enabled.
        failure_threshold: Failures before opening circuit.
        success_threshold: Successes to close circuit from half-open.
        timeout_seconds: Time circuit stays open before half-open.
        half_open_max_requests: Requests allowed in half-open state.

    Example:
        >>> config = CircuitBreakerConfig(
        ...     enabled=True,
        ...     failure_threshold=5,
        ...     timeout_seconds=30,
        ... )
    """

    enabled: bool = True
    failure_threshold: int = Field(default=5, ge=1, le=100)
    success_threshold: int = Field(default=3, ge=1, le=20)
    timeout_seconds: int = Field(default=30, ge=5, le=300)
    half_open_max_requests: int = Field(default=3, ge=1, le=10)


class PluginOrchestrationConfig(BaseModel):
    """
    Configuration for plugin orchestration service.

    Defines global settings for load balancing, scaling,
    circuit breaking, and optimization behavior.

    Attributes:
        enabled: Whether orchestration is enabled globally.
        default_strategy: Default load balancing strategy.
        default_optimization_target: Default optimization target.
        scaling: Scaling configuration.
        circuit_breaker: Circuit breaker configuration.
        health_check_interval_seconds: Interval for health checks.
        metrics_retention_hours: Hours to retain metrics.
        max_request_queue_size: Maximum queued requests.
        request_timeout_ms: Default request timeout.
        metadata: Additional configuration metadata.

    Example:
        >>> config = PluginOrchestrationConfig(
        ...     default_strategy=OrchestrationStrategy.INTELLIGENT,
        ...     scaling=ScalingConfig(policy=ScalingPolicy.PREDICTIVE),
        ... )
    """

    enabled: bool = True
    default_strategy: OrchestrationStrategy = OrchestrationStrategy.ROUND_ROBIN
    default_optimization_target: OptimizationTarget = OptimizationTarget.BALANCED

    # Sub-configurations
    scaling: ScalingConfig = Field(default_factory=ScalingConfig)
    circuit_breaker: CircuitBreakerConfig = Field(default_factory=CircuitBreakerConfig)

    # Health checking
    health_check_interval_seconds: int = Field(default=30, ge=5, le=300)

    # Metrics
    metrics_retention_hours: int = Field(default=168, ge=1, le=720)

    # Request handling
    max_request_queue_size: int = Field(default=1000, ge=10, le=100000)
    request_timeout_ms: int = Field(default=30000, ge=1000, le=600000)

    # Metadata
    metadata: Dict[str, Any] = Field(default_factory=dict)
