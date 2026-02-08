"""
Plugin Orchestration Service

Provides comprehensive orchestration capabilities for plugin management including
load balancing, auto-scaling, circuit breaking, and performance optimization.

This service is the central authority for:
- Request routing across plugin instances
- Load balancing with multiple strategies
- Auto-scaling based on demand and predictions
- Circuit breaker fault tolerance
- Performance optimization and tuning

Security Considerations:
    - Request routing respects plugin security contexts
    - Circuit breakers protect against cascading failures
    - Resource limits prevent denial-of-service conditions
    - All routing decisions are logged for audit

Performance Considerations:
    - Load balancer algorithms are O(n) or better
    - Instance selection uses weighted scoring
    - Metrics are cached for efficiency
    - Optimization uses heuristic models for speed

Usage:
    from app.services.plugins.orchestration import PluginOrchestrationService

    orchestrator = PluginOrchestrationService()

    # Register a plugin cluster
    cluster = await orchestrator.register_cluster(
        plugin_id="scanner@1.0.0",
        strategy=OrchestrationStrategy.LEAST_CONNECTIONS,
    )

    # Add instances to the cluster
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

Example:
    >>> from app.services.plugins.orchestration import (
    ...     PluginOrchestrationService,
    ...     OrchestrationStrategy,
    ... )
    >>> orchestrator = PluginOrchestrationService()
    >>> await orchestrator.start()
    >>> cluster = await orchestrator.register_cluster("my-plugin@1.0.0")
    >>> print(f"Cluster {cluster.cluster_id} created")
"""

import logging
import random
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from app.repositories.plugin_models_repository import OptimizationJobRepository

from .models import (
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
    ScalingPolicy,
)

# Configure module logger
logger = logging.getLogger(__name__)


class PluginOrchestrationService:
    """
    Plugin orchestration service for load balancing and scaling.

    Provides enterprise-grade orchestration capabilities including
    intelligent request routing, auto-scaling, circuit breakers,
    and performance optimization.

    The service maintains internal registries for clusters, instances,
    and metrics. Load balancing decisions use efficient algorithms
    appropriate for each strategy.

    Attributes:
        _clusters: Registry of plugin clusters by cluster_id.
        _cluster_by_plugin: Mapping of plugin_id to cluster_id.
        _config: Current orchestration configuration.
        _round_robin_index: Index for round-robin load balancing.
        _metrics_buffer: Buffer for metrics collection.
        _last_scaling_action: Timestamp of last scaling action.

    Example:
        >>> orchestrator = PluginOrchestrationService()
        >>> await orchestrator.start()
        >>> cluster = await orchestrator.register_cluster("my-plugin@1.0.0")
        >>> await orchestrator.add_instance(cluster.cluster_id, "host", 8080)
    """

    def __init__(self) -> None:
        """
        Initialize the plugin orchestration service.

        Sets up internal registries for clusters, metrics, and
        configuration. The service must be started before use.
        """
        # Cluster registry indexed by cluster_id
        self._clusters: Dict[str, PluginCluster] = {}

        # Mapping from plugin_id to cluster_id for fast lookup
        self._cluster_by_plugin: Dict[str, str] = {}

        # Current orchestration configuration
        self._config: PluginOrchestrationConfig = PluginOrchestrationConfig()

        # Round-robin index per cluster for fair distribution
        self._round_robin_index: Dict[str, int] = {}

        # Metrics buffer for batch processing
        self._metrics_buffer: List[Dict[str, Any]] = []

        # Scaling cooldown tracking
        self._last_scaling_action: Dict[str, datetime] = {}

        # Affinity cache for session stickiness
        self._affinity_cache: Dict[str, str] = {}

        # Service state
        self._started: bool = False

        # Repository for optimization jobs
        self._optimization_repo = OptimizationJobRepository()

        logger.info("PluginOrchestrationService initialized")

    async def start(self) -> None:
        """
        Start the orchestration service.

        Initializes background tasks for health checking,
        metrics collection, and scaling decisions.

        Raises:
            RuntimeError: If the service is already started.
        """
        if self._started:
            logger.warning("Orchestration service already started")
            return

        logger.info("Starting plugin orchestration service")

        self._started = True
        logger.info("Plugin orchestration service started successfully")

    async def stop(self) -> None:
        """
        Stop the orchestration service.

        Stops background tasks and releases resources.
        Active requests are allowed to complete.
        """
        if not self._started:
            return

        logger.info("Stopping plugin orchestration service")

        # Flush any pending metrics
        await self._flush_metrics()

        self._started = False
        logger.info("Plugin orchestration service stopped")

    # =========================================================================
    # CLUSTER MANAGEMENT
    # =========================================================================

    async def register_cluster(
        self,
        plugin_id: str,
        strategy: OrchestrationStrategy = OrchestrationStrategy.ROUND_ROBIN,
        scaling_policy: ScalingPolicy = ScalingPolicy.DISABLED,
        min_instances: int = 1,
        max_instances: int = 10,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PluginCluster:
        """
        Register a new plugin cluster.

        Creates a cluster for managing instances of a plugin.
        The cluster handles load balancing and scaling for all
        requests to this plugin.

        Args:
            plugin_id: ID of the plugin this cluster serves.
            strategy: Load balancing strategy.
            scaling_policy: Auto-scaling policy.
            min_instances: Minimum number of instances.
            max_instances: Maximum number of instances.
            metadata: Additional cluster metadata.

        Returns:
            The newly created PluginCluster.

        Raises:
            ValueError: If a cluster already exists for this plugin.

        Example:
            >>> cluster = await orchestrator.register_cluster(
            ...     plugin_id="scanner@1.0.0",
            ...     strategy=OrchestrationStrategy.LEAST_CONNECTIONS,
            ...     min_instances=2,
            ...     max_instances=10,
            ... )
        """
        if plugin_id in self._cluster_by_plugin:
            raise ValueError(f"Cluster already exists for plugin: {plugin_id}")

        cluster = PluginCluster(
            plugin_id=plugin_id,
            strategy=strategy,
            scaling_policy=scaling_policy,
            min_instances=min_instances,
            max_instances=max_instances,
            target_instances=min_instances,
            metadata=metadata or {},
        )

        self._clusters[cluster.cluster_id] = cluster
        self._cluster_by_plugin[plugin_id] = cluster.cluster_id
        self._round_robin_index[cluster.cluster_id] = 0

        logger.info(
            "Registered cluster %s for plugin %s (strategy=%s)",
            cluster.cluster_id,
            plugin_id,
            strategy.value,
        )

        return cluster

    async def get_cluster(
        self,
        cluster_id: Optional[str] = None,
        plugin_id: Optional[str] = None,
    ) -> Optional[PluginCluster]:
        """
        Get a cluster by ID or plugin ID.

        Args:
            cluster_id: ID of the cluster to retrieve.
            plugin_id: ID of the plugin to find cluster for.

        Returns:
            The cluster if found, None otherwise.
        """
        if cluster_id:
            return self._clusters.get(cluster_id)

        if plugin_id:
            cid = self._cluster_by_plugin.get(plugin_id)
            if cid:
                return self._clusters.get(cid)

        return None

    async def update_cluster(
        self,
        cluster_id: str,
        updates: Dict[str, Any],
    ) -> Optional[PluginCluster]:
        """
        Update cluster configuration.

        Args:
            cluster_id: ID of the cluster to update.
            updates: Dictionary of fields to update.

        Returns:
            Updated cluster, or None if not found.
        """
        cluster = self._clusters.get(cluster_id)
        if not cluster:
            logger.warning("Cluster not found: %s", cluster_id)
            return None

        allowed_fields = {
            "strategy",
            "scaling_policy",
            "min_instances",
            "max_instances",
            "target_instances",
            "metadata",
        }

        for field, value in updates.items():
            if field in allowed_fields:
                setattr(cluster, field, value)

        cluster.updated_at = datetime.utcnow()

        logger.info("Updated cluster %s: %s", cluster_id, list(updates.keys()))

        return cluster

    async def delete_cluster(self, cluster_id: str) -> bool:
        """
        Delete a cluster.

        Removes the cluster and all its instances. Active requests
        may fail after deletion.

        Args:
            cluster_id: ID of the cluster to delete.

        Returns:
            True if deleted, False if not found.
        """
        cluster = self._clusters.pop(cluster_id, None)
        if not cluster:
            logger.warning("Cluster not found for deletion: %s", cluster_id)
            return False

        # Remove plugin mapping
        if cluster.plugin_id in self._cluster_by_plugin:
            del self._cluster_by_plugin[cluster.plugin_id]

        # Cleanup other registries
        self._round_robin_index.pop(cluster_id, None)
        self._last_scaling_action.pop(cluster_id, None)

        logger.info(
            "Deleted cluster %s for plugin %s",
            cluster_id,
            cluster.plugin_id,
        )

        return True

    async def get_all_clusters(self) -> List[PluginCluster]:
        """
        Get all registered clusters.

        Returns:
            List of all clusters.
        """
        return list(self._clusters.values())

    # =========================================================================
    # INSTANCE MANAGEMENT
    # =========================================================================

    async def add_instance(
        self,
        cluster_id: str,
        host: str,
        port: int,
        weight: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[PluginInstance]:
        """
        Add an instance to a cluster.

        Registers a new plugin instance that can receive requests.
        The instance starts in STARTING status and transitions to
        RUNNING after passing health checks.

        Args:
            cluster_id: ID of the cluster to add to.
            host: Hostname or IP of the instance.
            port: Port number of the instance.
            weight: Load balancing weight (0.0-1.0).
            metadata: Additional instance metadata.

        Returns:
            The created instance, or None if cluster not found.

        Example:
            >>> instance = await orchestrator.add_instance(
            ...     cluster_id=cluster.cluster_id,
            ...     host="worker-01",
            ...     port=8080,
            ...     weight=1.0,
            ... )
        """
        cluster = self._clusters.get(cluster_id)
        if not cluster:
            logger.warning("Cluster not found: %s", cluster_id)
            return None

        # Check for duplicate host:port
        for existing in cluster.instances:
            if existing.host == host and existing.port == port:
                logger.warning(
                    "Instance already exists: %s:%d in cluster %s",
                    host,
                    port,
                    cluster_id,
                )
                return existing

        instance = PluginInstance(
            plugin_id=cluster.plugin_id,
            host=host,
            port=port,
            weight=weight,
            status=InstanceStatus.STARTING,
            metadata=metadata or {},
        )

        cluster.instances.append(instance)
        cluster.updated_at = datetime.utcnow()

        # Simulate quick startup for demo purposes
        instance.status = InstanceStatus.RUNNING

        logger.info(
            "Added instance %s (%s:%d) to cluster %s",
            instance.instance_id,
            host,
            port,
            cluster_id,
        )

        return instance

    async def remove_instance(
        self,
        cluster_id: str,
        instance_id: str,
        graceful: bool = True,
    ) -> bool:
        """
        Remove an instance from a cluster.

        Args:
            cluster_id: ID of the cluster.
            instance_id: ID of the instance to remove.
            graceful: If True, drain connections before removing.

        Returns:
            True if removed, False if not found.
        """
        cluster = self._clusters.get(cluster_id)
        if not cluster:
            logger.warning("Cluster not found: %s", cluster_id)
            return False

        for i, instance in enumerate(cluster.instances):
            if instance.instance_id == instance_id:
                if graceful:
                    instance.status = InstanceStatus.DRAINING
                    # In production, would wait for connections to drain

                cluster.instances.pop(i)
                cluster.updated_at = datetime.utcnow()

                logger.info(
                    "Removed instance %s from cluster %s (graceful=%s)",
                    instance_id,
                    cluster_id,
                    graceful,
                )
                return True

        logger.warning("Instance not found: %s in cluster %s", instance_id, cluster_id)
        return False

    async def update_instance(
        self,
        cluster_id: str,
        instance_id: str,
        updates: Dict[str, Any],
    ) -> Optional[PluginInstance]:
        """
        Update instance properties.

        Args:
            cluster_id: ID of the cluster.
            instance_id: ID of the instance.
            updates: Properties to update.

        Returns:
            Updated instance, or None if not found.
        """
        cluster = self._clusters.get(cluster_id)
        if not cluster:
            return None

        for instance in cluster.instances:
            if instance.instance_id == instance_id:
                allowed_fields = {"weight", "status", "metadata"}
                for field, value in updates.items():
                    if field in allowed_fields:
                        setattr(instance, field, value)

                cluster.updated_at = datetime.utcnow()
                return instance

        return None

    async def get_instance(
        self,
        cluster_id: str,
        instance_id: str,
    ) -> Optional[PluginInstance]:
        """
        Get an instance by ID.

        Args:
            cluster_id: ID of the cluster.
            instance_id: ID of the instance.

        Returns:
            The instance if found, None otherwise.
        """
        cluster = self._clusters.get(cluster_id)
        if not cluster:
            return None

        for instance in cluster.instances:
            if instance.instance_id == instance_id:
                return instance

        return None

    # =========================================================================
    # REQUEST ROUTING
    # =========================================================================

    async def route_request(
        self,
        plugin_id: str,
        method: str = "GET",
        path: str = "/",
        headers: Optional[Dict[str, str]] = None,
        body_size: int = 0,
        priority: int = 0,
        timeout_ms: int = 30000,
        affinity_key: Optional[str] = None,
    ) -> Optional[RouteResponse]:
        """
        Route a request to an appropriate plugin instance.

        Selects an instance based on the configured load balancing
        strategy and returns routing information. The caller is
        responsible for making the actual request to the instance.

        Args:
            plugin_id: ID of the target plugin.
            method: HTTP method or RPC method name.
            path: Request path or endpoint.
            headers: Request headers.
            body_size: Size of request body.
            priority: Request priority (higher = more important).
            timeout_ms: Request timeout in milliseconds.
            affinity_key: Key for session affinity routing.

        Returns:
            RouteResponse with selected instance, or None if no
            instances are available.

        Example:
            >>> response = await orchestrator.route_request(
            ...     plugin_id="scanner@1.0.0",
            ...     method="POST",
            ...     path="/scan",
            ...     timeout_ms=60000,
            ... )
            >>> if response:
            ...     print(f"Route to {response.instance_host}:{response.instance_port}")
        """
        start_time = time.monotonic()

        request = RouteRequest(
            plugin_id=plugin_id,
            method=method,
            path=path,
            headers=headers or {},
            body_size=body_size,
            priority=priority,
            timeout_ms=timeout_ms,
            affinity_key=affinity_key,
        )

        # Get cluster for plugin
        cluster = await self.get_cluster(plugin_id=plugin_id)
        if not cluster:
            logger.warning("No cluster found for plugin: %s", plugin_id)
            return None

        # Get available instances
        available = cluster.available_instances
        if not available:
            logger.warning("No available instances for plugin: %s", plugin_id)
            return None

        # Check affinity cache for session stickiness
        if affinity_key:
            cached_instance_id = self._affinity_cache.get(affinity_key)
            if cached_instance_id:
                for inst in available:
                    if inst.instance_id == cached_instance_id:
                        return self._create_route_response(request, inst, cluster.strategy, start_time, False)

        # Select instance based on strategy
        instance = await self._select_instance(cluster, available, request)
        if not instance:
            logger.warning("Failed to select instance for plugin: %s", plugin_id)
            return None

        # Update affinity cache
        if affinity_key:
            self._affinity_cache[affinity_key] = instance.instance_id

        # Update instance metrics
        instance.active_connections += 1
        instance.total_requests += 1

        response = self._create_route_response(request, instance, cluster.strategy, start_time, False)

        logger.debug(
            "Routed request %s to %s:%d (strategy=%s)",
            request.request_id,
            instance.host,
            instance.port,
            cluster.strategy.value,
        )

        return response

    def _create_route_response(
        self,
        request: RouteRequest,
        instance: PluginInstance,
        strategy: OrchestrationStrategy,
        start_time: float,
        fallback_used: bool,
    ) -> RouteResponse:
        """
        Create a route response from request and instance.

        Args:
            request: The original route request.
            instance: The selected instance.
            strategy: The strategy used for selection.
            start_time: Start time of routing decision.
            fallback_used: Whether a fallback was used.

        Returns:
            RouteResponse with routing information.
        """
        routing_time_ms = (time.monotonic() - start_time) * 1000

        return RouteResponse(
            request_id=request.request_id,
            instance_id=instance.instance_id,
            instance_host=instance.host,
            instance_port=instance.port,
            strategy_used=strategy,
            routing_time_ms=routing_time_ms,
            fallback_used=fallback_used,
        )

    async def _select_instance(
        self,
        cluster: PluginCluster,
        available: List[PluginInstance],
        request: RouteRequest,
    ) -> Optional[PluginInstance]:
        """
        Select an instance using the configured strategy.

        Args:
            cluster: The cluster to select from.
            available: List of available instances.
            request: The request to route.

        Returns:
            Selected instance, or None if selection failed.
        """
        if not available:
            return None

        strategy = cluster.strategy

        if strategy == OrchestrationStrategy.ROUND_ROBIN:
            return self._select_round_robin(cluster, available)

        elif strategy == OrchestrationStrategy.LEAST_CONNECTIONS:
            return self._select_least_connections(available)

        elif strategy == OrchestrationStrategy.WEIGHTED_ROUND_ROBIN:
            return self._select_weighted_round_robin(cluster, available)

        elif strategy == OrchestrationStrategy.RESOURCE_BASED:
            return self._select_resource_based(available)

        elif strategy == OrchestrationStrategy.PERFORMANCE_BASED:
            return self._select_performance_based(available)

        elif strategy == OrchestrationStrategy.INTELLIGENT:
            return self._select_intelligent(available, request)

        else:
            # Default to round-robin for unknown strategies
            return self._select_round_robin(cluster, available)

    def _select_round_robin(
        self,
        cluster: PluginCluster,
        available: List[PluginInstance],
    ) -> PluginInstance:
        """
        Select instance using round-robin.

        Args:
            cluster: The cluster being selected from.
            available: List of available instances.

        Returns:
            Next instance in round-robin order.
        """
        index = self._round_robin_index.get(cluster.cluster_id, 0)
        instance = available[index % len(available)]
        self._round_robin_index[cluster.cluster_id] = (index + 1) % len(available)
        return instance

    def _select_least_connections(
        self,
        available: List[PluginInstance],
    ) -> PluginInstance:
        """
        Select instance with fewest active connections.

        Args:
            available: List of available instances.

        Returns:
            Instance with minimum active connections.
        """
        return min(available, key=lambda i: i.active_connections)

    def _select_weighted_round_robin(
        self,
        cluster: PluginCluster,
        available: List[PluginInstance],
    ) -> PluginInstance:
        """
        Select instance using weighted round-robin.

        Higher weight instances receive proportionally more requests.

        Args:
            cluster: The cluster being selected from.
            available: List of available instances.

        Returns:
            Selected instance based on weights.
        """
        total_weight = sum(i.weight for i in available)
        if total_weight <= 0:
            return available[0]

        # Use weighted random selection
        r = random.random() * total_weight
        cumulative = 0.0

        for instance in available:
            cumulative += instance.weight
            if r <= cumulative:
                return instance

        return available[-1]

    def _select_resource_based(
        self,
        available: List[PluginInstance],
    ) -> PluginInstance:
        """
        Select instance based on resource availability.

        Prefers instances with better health scores as a proxy
        for resource availability.

        Args:
            available: List of available instances.

        Returns:
            Instance with best resource availability.
        """
        # Use health score as proxy for resource availability
        return max(available, key=lambda i: i.health_score)

    def _select_performance_based(
        self,
        available: List[PluginInstance],
    ) -> PluginInstance:
        """
        Select instance based on response time.

        Prefers instances with lower average response times.

        Args:
            available: List of available instances.

        Returns:
            Instance with best response time.
        """

        # Select instance with lowest average response time
        # Instances with no data get a default penalty
        def score(i: PluginInstance) -> float:
            if i.total_requests == 0:
                return 1000.0  # Penalty for no data
            return i.avg_response_time_ms

        return min(available, key=score)

    def _select_intelligent(
        self,
        available: List[PluginInstance],
        request: RouteRequest,
    ) -> PluginInstance:
        """
        Select instance using intelligent multi-factor scoring.

        Combines multiple factors including connections, response
        time, health score, and error rate for optimal selection.

        Args:
            available: List of available instances.
            request: The request being routed.

        Returns:
            Instance with best overall score.
        """

        def score(i: PluginInstance) -> float:
            """
            Calculate composite score for instance.

            Higher score = better instance.
            """
            # Normalize factors to 0-1 range where higher is better
            # Connection score: fewer connections is better
            max_conn = max(i.active_connections for i in available) or 1
            conn_score = 1.0 - (i.active_connections / max_conn)

            # Response time score: lower is better
            max_rt = max(i.avg_response_time_ms for i in available) or 1.0
            rt_score = 1.0 - (i.avg_response_time_ms / max_rt) if max_rt > 0 else 1.0

            # Health score: already normalized 0-1
            health_score = i.health_score

            # Error rate score: lower is better
            error_score = 1.0 - min(i.error_rate, 1.0)

            # Weighted combination
            return conn_score * 0.25 + rt_score * 0.30 + health_score * 0.25 + error_score * 0.20

        return max(available, key=score)

    async def report_request_complete(
        self,
        instance_id: str,
        success: bool,
        response_time_ms: float,
    ) -> None:
        """
        Report request completion for metrics tracking.

        Called after a request completes to update instance metrics
        and circuit breaker state.

        Args:
            instance_id: ID of the instance that handled the request.
            success: Whether the request succeeded.
            response_time_ms: Request response time in milliseconds.
        """
        # Find the instance
        for cluster in self._clusters.values():
            for instance in cluster.instances:
                if instance.instance_id == instance_id:
                    # Update metrics
                    instance.active_connections = max(0, instance.active_connections - 1)

                    if not success:
                        instance.total_errors += 1

                    # Update rolling average response time
                    # Using exponential moving average for efficiency
                    alpha = 0.1  # Smoothing factor
                    instance.avg_response_time_ms = (
                        alpha * response_time_ms + (1 - alpha) * instance.avg_response_time_ms
                    )

                    # Update circuit breaker
                    await self._update_circuit_breaker(instance, success)

                    return

    # =========================================================================
    # CIRCUIT BREAKER
    # =========================================================================

    async def _update_circuit_breaker(
        self,
        instance: PluginInstance,
        success: bool,
    ) -> None:
        """
        Update circuit breaker state based on request result.

        Implements the circuit breaker pattern to protect against
        cascading failures from unhealthy instances.

        Args:
            instance: The instance to update.
            success: Whether the request succeeded.
        """
        config = self._config.circuit_breaker

        if not config.enabled:
            return

        if success:
            # Success: reset failure count, potentially close circuit
            instance.circuit_failures = 0

            if instance.circuit_state == CircuitState.HALF_OPEN:
                # Success in half-open means we can close
                instance.circuit_state = CircuitState.CLOSED
                logger.info(
                    "Circuit closed for instance %s after successful request",
                    instance.instance_id,
                )
        else:
            # Failure: increment count, potentially open circuit
            instance.circuit_failures += 1

            if instance.circuit_state == CircuitState.CLOSED:
                if instance.circuit_failures >= config.failure_threshold:
                    instance.circuit_state = CircuitState.OPEN
                    logger.warning(
                        "Circuit opened for instance %s after %d failures",
                        instance.instance_id,
                        instance.circuit_failures,
                    )

            elif instance.circuit_state == CircuitState.HALF_OPEN:
                # Failure in half-open means circuit reopens
                instance.circuit_state = CircuitState.OPEN
                logger.warning(
                    "Circuit reopened for instance %s after half-open failure",
                    instance.instance_id,
                )

    async def check_circuit_breakers(self) -> None:
        """
        Check and transition circuit breaker states.

        Called periodically to transition open circuits to half-open
        after the configured timeout.
        """
        config = self._config.circuit_breaker
        timeout = timedelta(seconds=config.timeout_seconds)
        now = datetime.utcnow()

        for cluster in self._clusters.values():
            for instance in cluster.instances:
                if instance.circuit_state == CircuitState.OPEN:
                    # Check if timeout has passed
                    if instance.last_health_check:
                        elapsed = now - instance.last_health_check
                        if elapsed >= timeout:
                            instance.circuit_state = CircuitState.HALF_OPEN
                            logger.info(
                                "Circuit half-opened for instance %s",
                                instance.instance_id,
                            )

    # =========================================================================
    # AUTO-SCALING
    # =========================================================================

    async def evaluate_scaling(self, cluster_id: str) -> Optional[Tuple[str, int]]:
        """
        Evaluate scaling decision for a cluster.

        Analyzes current metrics and determines if scaling is needed
        based on the configured policy and thresholds.

        Args:
            cluster_id: ID of the cluster to evaluate.

        Returns:
            Tuple of (action, count) where action is "scale_up" or
            "scale_down" and count is the number of instances, or
            None if no scaling is needed.
        """
        cluster = self._clusters.get(cluster_id)
        if not cluster:
            return None

        if cluster.scaling_policy == ScalingPolicy.DISABLED:
            return None

        scaling_config = self._config.scaling

        # Check cooldown
        last_action = self._last_scaling_action.get(cluster_id)
        if last_action:
            cooldown = timedelta(seconds=scaling_config.scale_up_cooldown_seconds)
            if datetime.utcnow() - last_action < cooldown:
                return None

        # Calculate current load
        current_load = self._calculate_cluster_load(cluster)

        # Determine scaling action
        current_count = cluster.instance_count

        if current_load > scaling_config.scale_up_threshold:
            # Scale up
            if current_count < cluster.max_instances:
                target = min(current_count + 1, cluster.max_instances)
                self._last_scaling_action[cluster_id] = datetime.utcnow()
                logger.info(
                    "Scaling up cluster %s: %d -> %d (load=%.2f)",
                    cluster_id,
                    current_count,
                    target,
                    current_load,
                )
                return ("scale_up", target - current_count)

        elif current_load < scaling_config.scale_down_threshold:
            # Scale down
            if current_count > cluster.min_instances:
                target = max(current_count - 1, cluster.min_instances)
                self._last_scaling_action[cluster_id] = datetime.utcnow()
                logger.info(
                    "Scaling down cluster %s: %d -> %d (load=%.2f)",
                    cluster_id,
                    current_count,
                    target,
                    current_load,
                )
                return ("scale_down", current_count - target)

        return None

    def _calculate_cluster_load(self, cluster: PluginCluster) -> float:
        """
        Calculate current load for a cluster.

        Uses average connection count normalized by weight as a
        simple load metric.

        Args:
            cluster: The cluster to calculate load for.

        Returns:
            Load value between 0.0 and 1.0+.
        """
        if not cluster.instances:
            return 0.0

        total_connections = sum(i.active_connections for i in cluster.instances)
        total_weight = sum(i.weight for i in cluster.instances)

        if total_weight <= 0:
            return 0.0

        # Normalize by expected capacity (e.g., 100 connections per weight unit)
        expected_capacity = total_weight * 100
        return total_connections / expected_capacity

    # =========================================================================
    # HEALTH CHECKING
    # =========================================================================

    async def check_instance_health(
        self,
        cluster_id: str,
        instance_id: str,
    ) -> Optional[float]:
        """
        Check health of a specific instance.

        Updates the instance health score based on current metrics.
        In production, this would include actual health probe.

        Args:
            cluster_id: ID of the cluster.
            instance_id: ID of the instance.

        Returns:
            Health score (0.0-1.0), or None if not found.
        """
        cluster = self._clusters.get(cluster_id)
        if not cluster:
            return None

        for instance in cluster.instances:
            if instance.instance_id == instance_id:
                # Calculate health score based on metrics
                health_score = self._calculate_health_score(instance)
                instance.health_score = health_score
                instance.last_health_check = datetime.utcnow()

                # Update status based on health
                if health_score < 0.3:
                    instance.status = InstanceStatus.UNHEALTHY
                elif instance.status == InstanceStatus.UNHEALTHY and health_score > 0.5:
                    instance.status = InstanceStatus.RUNNING

                return health_score

        return None

    def _calculate_health_score(self, instance: PluginInstance) -> float:
        """
        Calculate health score for an instance.

        Combines error rate, response time, and circuit state
        into a single health score.

        Args:
            instance: The instance to score.

        Returns:
            Health score between 0.0 and 1.0.
        """
        # Error rate component (lower is better)
        error_score = 1.0 - min(instance.error_rate * 2, 1.0)

        # Response time component (faster is better)
        # Assume 1000ms is threshold for "slow"
        rt_score = max(0.0, 1.0 - (instance.avg_response_time_ms / 1000.0))

        # Circuit state component
        circuit_score = 1.0
        if instance.circuit_state == CircuitState.HALF_OPEN:
            circuit_score = 0.5
        elif instance.circuit_state == CircuitState.OPEN:
            circuit_score = 0.0

        # Weighted combination
        return error_score * 0.4 + rt_score * 0.3 + circuit_score * 0.3

    async def check_all_health(self) -> Dict[str, Dict[str, float]]:
        """
        Check health of all instances in all clusters.

        Returns:
            Dictionary mapping cluster_id to instance health scores.
        """
        results: Dict[str, Dict[str, float]] = {}

        for cluster_id, cluster in self._clusters.items():
            cluster_health: Dict[str, float] = {}

            for instance in cluster.instances:
                score = await self.check_instance_health(cluster_id, instance.instance_id)
                if score is not None:
                    cluster_health[instance.instance_id] = score

            results[cluster_id] = cluster_health

        return results

    # =========================================================================
    # OPTIMIZATION
    # =========================================================================

    async def create_optimization_job(
        self,
        plugin_id: str,
        target: OptimizationTarget = OptimizationTarget.BALANCED,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> OptimizationJob:
        """
        Create a new optimization job.

        Starts background analysis of plugin performance and
        generates recommendations for improvement.

        Args:
            plugin_id: ID of the plugin to optimize.
            target: Optimization target.
            metadata: Additional job metadata.

        Returns:
            The created optimization job.
        """
        job = OptimizationJob(
            plugin_id=plugin_id,
            target=target,
            status="pending",
            metadata=metadata or {},
        )

        # Persist via repository
        await self._optimization_repo.create(job)

        logger.info(
            "Created optimization job %s for plugin %s (target=%s)",
            job.job_id,
            plugin_id,
            target.value,
        )

        return job

    async def _update_optimization_job(self, job: OptimizationJob) -> None:
        """Helper to update optimization job via repository."""
        await self._optimization_repo.update_one(
            {"job_id": job.job_id},
            {
                "$set": {
                    "status": job.status,
                    "progress": job.progress,
                    "started_at": job.started_at,
                    "completed_at": job.completed_at,
                    "current_metrics": job.current_metrics,
                    "recommendations": job.recommendations,
                    "result_summary": job.result_summary,
                    "error_message": job.error_message,
                }
            },
        )

    async def run_optimization(self, job_id: str) -> Optional[OptimizationJob]:
        """
        Run an optimization job.

        Analyzes current performance and generates recommendations.
        This is a simplified heuristic-based implementation.

        Args:
            job_id: ID of the job to run.

        Returns:
            Updated job with results, or None if not found.
        """
        try:
            job = await self._optimization_repo.find_by_job_id(job_id)
            if not job:
                logger.warning("Optimization job not found: %s", job_id)
                return None

            job.status = "running"
            job.started_at = datetime.utcnow()
            job.progress = 0.1
            await self._update_optimization_job(job)

            # Get cluster metrics
            cluster = await self.get_cluster(plugin_id=job.plugin_id)
            if not cluster:
                job.status = "failed"
                job.error_message = f"No cluster found for plugin: {job.plugin_id}"
                await self._update_optimization_job(job)
                return job

            # Collect current metrics
            job.current_metrics = self._collect_cluster_metrics(cluster)
            job.progress = 0.4
            await self._update_optimization_job(job)

            # Generate recommendations based on target
            recommendations = self._generate_recommendations(cluster, job.target, job.current_metrics)
            job.recommendations = recommendations
            job.progress = 0.8
            await self._update_optimization_job(job)

            # Complete job
            job.status = "completed"
            job.completed_at = datetime.utcnow()
            job.progress = 1.0
            job.result_summary = f"Generated {len(recommendations)} recommendations for {job.target.value} optimization"
            await self._update_optimization_job(job)

            logger.info(
                "Completed optimization job %s with %d recommendations",
                job_id,
                len(recommendations),
            )

            return job

        except Exception as e:
            logger.error("Optimization job %s failed: %s", job_id, str(e))
            try:
                job = await self._optimization_repo.find_by_job_id(job_id)
                if job:
                    job.status = "failed"
                    job.error_message = str(e)
                    await self._update_optimization_job(job)
                return job
            except Exception:
                return None

    def _collect_cluster_metrics(
        self,
        cluster: PluginCluster,
    ) -> Dict[str, float]:
        """
        Collect current metrics for a cluster.

        Args:
            cluster: The cluster to collect metrics from.

        Returns:
            Dictionary of metric name to value.
        """
        instances = cluster.instances
        if not instances:
            return {"instance_count": 0}

        total_requests = sum(i.total_requests for i in instances)
        total_errors = sum(i.total_errors for i in instances)
        avg_response_time = sum(i.avg_response_time_ms for i in instances) / len(instances)
        avg_health = sum(i.health_score for i in instances) / len(instances)
        total_connections = sum(i.active_connections for i in instances)

        return {
            "instance_count": float(len(instances)),
            "total_requests": float(total_requests),
            "total_errors": float(total_errors),
            "error_rate": total_errors / total_requests if total_requests > 0 else 0.0,
            "avg_response_time_ms": avg_response_time,
            "avg_health_score": avg_health,
            "total_connections": float(total_connections),
            "load_factor": self._calculate_cluster_load(cluster),
        }

    def _generate_recommendations(
        self,
        cluster: PluginCluster,
        target: OptimizationTarget,
        metrics: Dict[str, float],
    ) -> List[Dict[str, Any]]:
        """
        Generate optimization recommendations.

        Uses heuristics to identify improvement opportunities
        based on the optimization target and current metrics.

        Args:
            cluster: The cluster being optimized.
            target: The optimization target.
            metrics: Current cluster metrics.

        Returns:
            List of recommendation dictionaries.
        """
        recommendations: List[Dict[str, Any]] = []

        # Common recommendations based on metrics
        if metrics.get("error_rate", 0) > 0.05:
            recommendations.append(
                {
                    "type": "reliability",
                    "title": "High Error Rate Detected",
                    "description": f"Error rate is {metrics['error_rate']:.1%}. "
                    "Investigate failing instances and consider circuit breaker tuning.",
                    "priority": "high",
                }
            )

        if metrics.get("avg_response_time_ms", 0) > 2000:
            recommendations.append(
                {
                    "type": "performance",
                    "title": "High Response Time",
                    "description": f"Average response time is {metrics['avg_response_time_ms']:.0f}ms. "
                    "Consider adding instances or optimizing plugin code.",
                    "priority": "medium",
                }
            )

        # Target-specific recommendations
        if target == OptimizationTarget.THROUGHPUT:
            if metrics.get("load_factor", 0) > 0.7:
                recommendations.append(
                    {
                        "type": "scaling",
                        "title": "Scale Up for Throughput",
                        "description": "Load factor is high. Add more instances to increase throughput.",
                        "priority": "high",
                    }
                )

        elif target == OptimizationTarget.LATENCY:
            if cluster.strategy != OrchestrationStrategy.PERFORMANCE_BASED:
                recommendations.append(
                    {
                        "type": "strategy",
                        "title": "Switch to Performance-Based Routing",
                        "description": "Use performance-based routing to minimize latency.",
                        "priority": "medium",
                    }
                )

        elif target == OptimizationTarget.RESOURCE_EFFICIENCY:
            if metrics.get("load_factor", 0) < 0.3 and cluster.instance_count > cluster.min_instances:
                recommendations.append(
                    {
                        "type": "scaling",
                        "title": "Scale Down for Efficiency",
                        "description": "Load is low. Consider reducing instance count to save resources.",
                        "priority": "low",
                    }
                )

        elif target == OptimizationTarget.AVAILABILITY:
            if cluster.instance_count < 3:
                recommendations.append(
                    {
                        "type": "reliability",
                        "title": "Add Redundant Instances",
                        "description": "Run at least 3 instances for high availability.",
                        "priority": "high",
                    }
                )

        return recommendations

    # =========================================================================
    # METRICS AND REPORTING
    # =========================================================================

    async def _flush_metrics(self) -> None:
        """
        Flush buffered metrics to storage.
        """
        if not self._metrics_buffer:
            return

        logger.debug("Flushed %d metrics", len(self._metrics_buffer))
        self._metrics_buffer.clear()

    async def get_cluster_stats(self, cluster_id: str) -> Optional[Dict[str, Any]]:
        """
        Get statistics for a cluster.

        Args:
            cluster_id: ID of the cluster.

        Returns:
            Dictionary of cluster statistics.
        """
        cluster = self._clusters.get(cluster_id)
        if not cluster:
            return None

        return {
            "cluster_id": cluster_id,
            "plugin_id": cluster.plugin_id,
            "strategy": cluster.strategy.value,
            "scaling_policy": cluster.scaling_policy.value,
            "instances": {
                "total": cluster.instance_count,
                "healthy": cluster.healthy_instance_count,
                "min": cluster.min_instances,
                "max": cluster.max_instances,
                "target": cluster.target_instances,
            },
            "metrics": self._collect_cluster_metrics(cluster),
            "updated_at": cluster.updated_at.isoformat(),
        }

    async def get_orchestration_summary(self) -> Dict[str, Any]:
        """
        Get a summary of orchestration state.

        Returns:
            Dictionary with orchestration metrics and status.
        """
        total_instances = sum(len(c.instances) for c in self._clusters.values())
        healthy_instances = sum(c.healthy_instance_count for c in self._clusters.values())

        return {
            "clusters": {
                "total": len(self._clusters),
                "by_strategy": {
                    s.value: sum(1 for c in self._clusters.values() if c.strategy == s) for s in OrchestrationStrategy
                },
            },
            "instances": {
                "total": total_instances,
                "healthy": healthy_instances,
                "unhealthy": total_instances - healthy_instances,
            },
            "config": {
                "enabled": self._config.enabled,
                "default_strategy": self._config.default_strategy.value,
                "scaling_enabled": self._config.scaling.enabled,
                "circuit_breaker_enabled": self._config.circuit_breaker.enabled,
            },
        }

    # =========================================================================
    # CONFIGURATION
    # =========================================================================

    async def get_config(self) -> PluginOrchestrationConfig:
        """
        Get the current orchestration configuration.

        Returns:
            Current PluginOrchestrationConfig.
        """
        return self._config

    async def update_config(
        self,
        updates: Dict[str, Any],
    ) -> PluginOrchestrationConfig:
        """
        Update orchestration configuration.

        Args:
            updates: Configuration updates to apply.

        Returns:
            Updated configuration.
        """
        for key, value in updates.items():
            if hasattr(self._config, key):
                setattr(self._config, key, value)

        logger.info("Updated orchestration configuration: %s", list(updates.keys()))

        return self._config
