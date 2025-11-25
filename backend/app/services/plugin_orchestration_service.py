"""
Advanced Plugin Orchestration and Optimization Service
Provides intelligent plugin orchestration, resource optimization, load balancing,
performance tuning, and automated scaling for enterprise plugin deployments.
"""

import asyncio
import logging
import statistics
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from beanie import Document
from pydantic import BaseModel, Field

from ..models.plugin_models import PluginStatus
from .plugin_analytics_service import PluginAnalyticsService
from .plugin_lifecycle_service import PluginLifecycleService
from .plugin_registry_service import PluginRegistryService

logger = logging.getLogger(__name__)


# ============================================================================
# ORCHESTRATION MODELS AND ENUMS
# ============================================================================


class OrchestrationStrategy(str, Enum):
    """Plugin orchestration strategies"""

    ROUND_ROBIN = "round_robin"  # Simple round-robin distribution
    LEAST_CONNECTIONS = "least_connections"  # Route to least busy plugin
    WEIGHTED_ROUND_ROBIN = "weighted_round_robin"  # Weighted by capacity
    RESOURCE_BASED = "resource_based"  # Based on resource availability
    PERFORMANCE_BASED = "performance_based"  # Based on performance metrics
    INTELLIGENT = "intelligent"  # AI-driven optimization
    CUSTOM = "custom"  # Custom routing logic


class OptimizationTarget(str, Enum):
    """Optimization targets"""

    THROUGHPUT = "throughput"  # Maximize operations per second
    LATENCY = "latency"  # Minimize response time
    RESOURCE_EFFICIENCY = "resource_efficiency"  # Optimize resource usage
    COST = "cost"  # Minimize operational cost
    AVAILABILITY = "availability"  # Maximize uptime
    BALANCED = "balanced"  # Balance all metrics


class ScalingPolicy(str, Enum):
    """Auto-scaling policies"""

    DISABLED = "disabled"  # No auto-scaling
    REACTIVE = "reactive"  # Scale based on current load
    PREDICTIVE = "predictive"  # Scale based on predictions
    SCHEDULE_BASED = "schedule_based"  # Scale based on schedules
    HYBRID = "hybrid"  # Combination of strategies


class PluginInstance(BaseModel):
    """Individual plugin instance in the orchestration system"""

    instance_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    plugin_id: str
    host_id: Optional[str] = None  # Host where instance is running

    # Status and health
    status: str = Field(default="starting")  # starting, running, stopping, stopped, failed
    health_score: float = Field(default=1.0, ge=0.0, le=1.0)
    last_health_check: datetime = Field(default_factory=datetime.utcnow)

    # Load and performance
    current_connections: int = Field(default=0)
    max_connections: int = Field(default=100)
    avg_response_time_ms: float = Field(default=0.0)
    requests_per_second: float = Field(default=0.0)

    # Resource usage
    cpu_usage_percent: float = Field(default=0.0)
    memory_usage_mb: float = Field(default=0.0)
    disk_io_rate: float = Field(default=0.0)
    network_io_rate: float = Field(default=0.0)

    # Configuration
    weight: float = Field(default=1.0, gt=0.0)  # Weight for load balancing
    priority: int = Field(default=100)  # Priority (higher = preferred)
    enabled: bool = Field(default=True)

    # Lifecycle
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    last_activity: datetime = Field(default_factory=datetime.utcnow)


class PluginCluster(BaseModel):
    """Cluster of plugin instances providing the same functionality"""

    cluster_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    plugin_id: str
    name: str
    description: Optional[str] = None

    # Instances
    instances: List[PluginInstance] = Field(default_factory=list)
    target_instance_count: int = Field(default=1, ge=0)
    min_instances: int = Field(default=1, ge=0)
    max_instances: int = Field(default=10, ge=1)

    # Orchestration configuration
    strategy: OrchestrationStrategy = OrchestrationStrategy.ROUND_ROBIN
    optimization_target: OptimizationTarget = OptimizationTarget.BALANCED
    scaling_policy: ScalingPolicy = ScalingPolicy.REACTIVE

    # Load balancing
    sticky_sessions: bool = Field(default=False)
    session_affinity_timeout: int = Field(default=3600)  # seconds
    health_check_interval: int = Field(default=30)  # seconds

    # Auto-scaling thresholds
    scale_up_threshold_cpu: float = Field(default=80.0)
    scale_down_threshold_cpu: float = Field(default=30.0)
    scale_up_threshold_memory: float = Field(default=85.0)
    scale_down_threshold_memory: float = Field(default=40.0)
    scale_up_threshold_requests: float = Field(default=80.0)
    scale_down_threshold_requests: float = Field(default=20.0)

    # Cooldown periods
    scale_up_cooldown_seconds: int = Field(default=300)  # 5 minutes
    scale_down_cooldown_seconds: int = Field(default=600)  # 10 minutes
    last_scale_action: Optional[datetime] = None

    # Circuit breaker
    circuit_breaker_enabled: bool = Field(default=True)
    circuit_breaker_failure_threshold: int = Field(default=5)
    circuit_breaker_timeout_seconds: int = Field(default=60)
    circuit_breaker_status: str = Field(default="closed")  # closed, open, half-open

    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_modified: datetime = Field(default_factory=datetime.utcnow)
    tags: Dict[str, str] = Field(default_factory=dict)


class RouteRequest(BaseModel):
    """Request routing information"""

    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    plugin_id: str

    # Request details
    request_type: str = "execute"
    request_data: Dict[str, Any] = Field(default_factory=dict)

    # Routing preferences
    preferred_instance_id: Optional[str] = None
    session_id: Optional[str] = None
    user_id: Optional[str] = None

    # Quality of service
    max_response_time_ms: Optional[int] = None
    priority: int = Field(default=100)
    retry_count: int = Field(default=0)

    # Context
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source_ip: Optional[str] = None
    correlation_id: Optional[str] = None


class RouteResponse(BaseModel):
    """Request routing response"""

    request_id: str
    routed_to_instance: Optional[str] = None
    routed_to_cluster: Optional[str] = None

    # Route decision
    routing_strategy_used: OrchestrationStrategy
    routing_reason: str
    routing_time_ms: float

    # Load balancing
    instance_load_before: float = Field(default=0.0)
    instance_load_after: float = Field(default=0.0)

    # Performance prediction
    predicted_response_time_ms: Optional[float] = None
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)

    # Status
    success: bool = Field(default=True)
    error_message: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class OptimizationJob(Document):
    """Plugin optimization job record"""

    job_id: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True)
    target: OptimizationTarget

    # Scope
    plugin_ids: List[str] = Field(default_factory=list)
    cluster_ids: List[str] = Field(default_factory=list)

    # Job configuration
    optimization_period_hours: int = Field(default=24)
    analysis_window_days: int = Field(default=7)

    # Status
    status: str = Field(default="pending")  # pending, running, completed, failed
    progress: float = Field(default=0.0, ge=0.0, le=100.0)

    # Results
    baseline_metrics: Dict[str, float] = Field(default_factory=dict)
    optimized_metrics: Dict[str, float] = Field(default_factory=dict)
    improvement_percentage: Dict[str, float] = Field(default_factory=dict)

    # Recommendations
    recommendations: List[Dict[str, Any]] = Field(default_factory=list)
    applied_recommendations: List[str] = Field(default_factory=list)

    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    scheduled_for: datetime = Field(default_factory=datetime.utcnow)

    # Metadata
    created_by: str = Field(default="system")
    tags: Dict[str, str] = Field(default_factory=dict)

    class Settings:
        collection = "plugin_optimization_jobs"
        indexes = ["job_id", "status", "target", "scheduled_for"]


# ============================================================================
# PLUGIN ORCHESTRATION SERVICE
# ============================================================================


class PluginOrchestrationService:
    """
    Advanced plugin orchestration and optimization service

    Provides enterprise-grade capabilities for:
    - Intelligent load balancing with multiple strategies
    - Auto-scaling with predictive and reactive policies
    - Performance optimization with ML-driven recommendations
    - Resource-aware routing and placement
    - Circuit breakers and fault tolerance
    - Multi-objective optimization (throughput, latency, cost, availability)
    """

    def __init__(self):
        self.plugin_registry_service = PluginRegistryService()
        self.plugin_lifecycle_service = PluginLifecycleService()
        self.plugin_analytics_service = PluginAnalyticsService()

        # Orchestration state
        self.clusters: Dict[str, PluginCluster] = {}
        self.instances: Dict[str, PluginInstance] = {}
        self.session_affinity: Dict[str, str] = {}  # session_id -> instance_id

        # Load balancing state
        self.round_robin_counters: Dict[str, int] = defaultdict(int)
        self.request_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))

        # Performance monitoring
        self.performance_metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.optimization_cache: Dict[str, Dict[str, Any]] = {}

        # Circuit breaker state
        self.circuit_breaker_failures: Dict[str, int] = defaultdict(int)
        self.circuit_breaker_timeouts: Dict[str, datetime] = {}

        # Optimization
        self.optimization_jobs: Dict[str, OptimizationJob] = {}
        self.optimization_models: Dict[str, Any] = {}  # ML models for optimization

        # Monitoring and tasks
        self.monitoring_tasks: Dict[str, asyncio.Task] = {}
        self.optimization_tasks: Dict[str, asyncio.Task] = {}
        self.monitoring_enabled = False

    async def initialize_orchestration(self):
        """Initialize orchestration service"""

        # Load existing clusters and instances
        await self._discover_existing_plugins()

        # Initialize optimization models
        await self._initialize_optimization_models()

        # Start monitoring
        await self.start_orchestration_monitoring()

        logger.info("Plugin orchestration service initialized")

    async def start_orchestration_monitoring(self):
        """Start orchestration monitoring and optimization"""
        if self.monitoring_enabled:
            logger.warning("Orchestration monitoring already running")
            return

        self.monitoring_enabled = True

        # Start cluster monitoring
        for cluster_id in self.clusters:
            await self._start_cluster_monitoring(cluster_id)

        # Start optimization scheduler
        await self._start_optimization_scheduler()

        logger.info("Started orchestration monitoring")

    async def stop_orchestration_monitoring(self):
        """Stop orchestration monitoring"""
        if not self.monitoring_enabled:
            return

        self.monitoring_enabled = False

        # Stop all monitoring tasks
        all_tasks = {**self.monitoring_tasks, **self.optimization_tasks}
        for task_id, task in all_tasks.items():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        self.monitoring_tasks.clear()
        self.optimization_tasks.clear()

        logger.info("Stopped orchestration monitoring")

    async def create_plugin_cluster(
        self,
        plugin_id: str,
        name: str,
        target_instances: int = 1,
        strategy: OrchestrationStrategy = OrchestrationStrategy.ROUND_ROBIN,
        optimization_target: OptimizationTarget = OptimizationTarget.BALANCED,
    ) -> PluginCluster:
        """Create a new plugin cluster"""

        # Verify plugin exists
        plugin = await self.plugin_registry_service.get_plugin(plugin_id)
        if not plugin:
            raise ValueError(f"Plugin not found: {plugin_id}")

        cluster = PluginCluster(
            plugin_id=plugin_id,
            name=name,
            target_instance_count=target_instances,
            strategy=strategy,
            optimization_target=optimization_target,
        )

        # Store cluster
        self.clusters[cluster.cluster_id] = cluster

        # Create initial instances
        for i in range(target_instances):
            instance = await self._create_plugin_instance(cluster)
            cluster.instances.append(instance)
            self.instances[instance.instance_id] = instance

        # Start monitoring for this cluster
        if self.monitoring_enabled:
            await self._start_cluster_monitoring(cluster.cluster_id)

        logger.info(f"Created plugin cluster: {name} with {target_instances} instances")
        return cluster

    async def route_request(self, request: RouteRequest) -> RouteResponse:
        """Route a request to the optimal plugin instance"""

        start_time = datetime.utcnow()

        # Find cluster for this plugin
        cluster = self._find_cluster_for_plugin(request.plugin_id)
        if not cluster:
            return RouteResponse(
                request_id=request.request_id,
                routing_strategy_used=OrchestrationStrategy.ROUND_ROBIN,
                routing_reason="No cluster found for plugin",
                routing_time_ms=0.0,
                success=False,
                error_message=f"No cluster configured for plugin {request.plugin_id}",
            )

        # Check circuit breaker
        if cluster.circuit_breaker_enabled and cluster.circuit_breaker_status == "open":
            if cluster.cluster_id in self.circuit_breaker_timeouts:
                if datetime.utcnow() < self.circuit_breaker_timeouts[cluster.cluster_id]:
                    return RouteResponse(
                        request_id=request.request_id,
                        routed_to_cluster=cluster.cluster_id,
                        routing_strategy_used=cluster.strategy,
                        routing_reason="Circuit breaker open",
                        routing_time_ms=0.0,
                        success=False,
                        error_message="Circuit breaker is open",
                    )
                else:
                    # Move to half-open state
                    cluster.circuit_breaker_status = "half-open"

        # Select instance based on strategy
        selected_instance = await self._select_instance(cluster, request)

        if not selected_instance:
            return RouteResponse(
                request_id=request.request_id,
                routed_to_cluster=cluster.cluster_id,
                routing_strategy_used=cluster.strategy,
                routing_reason="No healthy instances available",
                routing_time_ms=0.0,
                success=False,
                error_message="No healthy instances available",
            )

        # Update load tracking
        load_before = self._calculate_instance_load(selected_instance)
        selected_instance.current_connections += 1
        selected_instance.last_activity = datetime.utcnow()
        load_after = self._calculate_instance_load(selected_instance)

        # Record session affinity if enabled
        if cluster.sticky_sessions and request.session_id:
            self.session_affinity[request.session_id] = selected_instance.instance_id

        # Calculate routing time
        routing_time = (datetime.utcnow() - start_time).total_seconds() * 1000

        # Predict response time
        predicted_response_time = await self._predict_response_time(selected_instance, request)

        response = RouteResponse(
            request_id=request.request_id,
            routed_to_instance=selected_instance.instance_id,
            routed_to_cluster=cluster.cluster_id,
            routing_strategy_used=cluster.strategy,
            routing_reason=f"Selected by {cluster.strategy.value} strategy",
            routing_time_ms=routing_time,
            instance_load_before=load_before,
            instance_load_after=load_after,
            predicted_response_time_ms=predicted_response_time["time_ms"],
            confidence_score=predicted_response_time["confidence"],
        )

        # Record routing decision
        await self._record_routing_decision(cluster, selected_instance, request, response)

        return response

    async def scale_cluster(
        self, cluster_id: str, target_instances: int, reason: str = "manual"
    ) -> bool:
        """Scale a plugin cluster to target instance count"""

        cluster = self.clusters.get(cluster_id)
        if not cluster:
            raise ValueError(f"Cluster not found: {cluster_id}")

        if target_instances < cluster.min_instances:
            target_instances = cluster.min_instances
        elif target_instances > cluster.max_instances:
            target_instances = cluster.max_instances

        current_instances = len([i for i in cluster.instances if i.status != "stopped"])

        if target_instances == current_instances:
            logger.info(f"Cluster {cluster_id} already at target size: {target_instances}")
            return True

        try:
            if target_instances > current_instances:
                # Scale up
                instances_to_add = target_instances - current_instances
                for _ in range(instances_to_add):
                    instance = await self._create_plugin_instance(cluster)
                    cluster.instances.append(instance)
                    self.instances[instance.instance_id] = instance
                    await self._start_plugin_instance(instance)

                logger.info(f"Scaled up cluster {cluster_id} by {instances_to_add} instances")

            else:
                # Scale down
                instances_to_remove = current_instances - target_instances
                instances_to_stop = sorted(
                    [i for i in cluster.instances if i.status == "running"],
                    key=lambda x: (x.current_connections, x.last_activity),
                )[:instances_to_remove]

                for instance in instances_to_stop:
                    await self._stop_plugin_instance(instance)
                    cluster.instances = [
                        i for i in cluster.instances if i.instance_id != instance.instance_id
                    ]
                    self.instances.pop(instance.instance_id, None)

                logger.info(f"Scaled down cluster {cluster_id} by {instances_to_remove} instances")

            cluster.target_instance_count = target_instances
            cluster.last_scale_action = datetime.utcnow()
            cluster.last_modified = datetime.utcnow()

            return True

        except Exception as e:
            logger.error(f"Failed to scale cluster {cluster_id}: {e}")
            return False

    async def optimize_cluster_performance(
        self, cluster_id: str, target: OptimizationTarget = OptimizationTarget.BALANCED
    ) -> OptimizationJob:
        """Optimize cluster performance for specific target"""

        cluster = self.clusters.get(cluster_id)
        if not cluster:
            raise ValueError(f"Cluster not found: {cluster_id}")

        # Create optimization job
        job = OptimizationJob(
            target=target, cluster_ids=[cluster_id], plugin_ids=[cluster.plugin_id]
        )

        await job.save()
        self.optimization_jobs[job.job_id] = job

        # Start optimization process
        asyncio.create_task(self._execute_optimization_job(job))

        logger.info(f"Started optimization job for cluster {cluster_id}: {job.job_id}")
        return job

    async def get_cluster_metrics(self, cluster_id: str) -> Dict[str, Any]:
        """Get comprehensive metrics for a cluster"""

        cluster = self.clusters.get(cluster_id)
        if not cluster:
            raise ValueError(f"Cluster not found: {cluster_id}")

        running_instances = [i for i in cluster.instances if i.status == "running"]

        if not running_instances:
            return {
                "cluster_id": cluster_id,
                "instances": {
                    "total": len(cluster.instances),
                    "running": 0,
                    "healthy": 0,
                },
                "performance": {},
                "resources": {},
                "load": {},
            }

        # Calculate aggregate metrics
        total_connections = sum(i.current_connections for i in running_instances)
        max_connections = sum(i.max_connections for i in running_instances)

        avg_response_time = statistics.mean(i.avg_response_time_ms for i in running_instances)
        total_rps = sum(i.requests_per_second for i in running_instances)

        avg_cpu = statistics.mean(i.cpu_usage_percent for i in running_instances)
        avg_memory = statistics.mean(i.memory_usage_mb for i in running_instances)
        total_memory = sum(i.memory_usage_mb for i in running_instances)

        healthy_instances = len([i for i in running_instances if i.health_score >= 0.8])

        return {
            "cluster_id": cluster_id,
            "plugin_id": cluster.plugin_id,
            "strategy": cluster.strategy.value,
            "optimization_target": cluster.optimization_target.value,
            "instances": {
                "total": len(cluster.instances),
                "running": len(running_instances),
                "healthy": healthy_instances,
                "target": cluster.target_instance_count,
                "min": cluster.min_instances,
                "max": cluster.max_instances,
            },
            "performance": {
                "avg_response_time_ms": avg_response_time,
                "total_requests_per_second": total_rps,
                "avg_health_score": statistics.mean(i.health_score for i in running_instances),
            },
            "resources": {
                "avg_cpu_percent": avg_cpu,
                "avg_memory_mb": avg_memory,
                "total_memory_mb": total_memory,
            },
            "load": {
                "total_connections": total_connections,
                "max_connections": max_connections,
                "utilization_percent": (
                    (total_connections / max_connections * 100) if max_connections > 0 else 0.0
                ),
            },
            "circuit_breaker": {
                "enabled": cluster.circuit_breaker_enabled,
                "status": cluster.circuit_breaker_status,
                "failure_count": self.circuit_breaker_failures.get(cluster_id, 0),
            },
        }

    async def _discover_existing_plugins(self):
        """Discover existing plugins and create default clusters"""

        plugins = await self.plugin_registry_service.find_plugins({"status": PluginStatus.ACTIVE})

        for plugin in plugins:
            # Create default single-instance cluster for each plugin
            cluster = PluginCluster(
                plugin_id=plugin.plugin_id,
                name=f"{plugin.name} Cluster",
                target_instance_count=1,
                min_instances=1,
                max_instances=5,
            )

            self.clusters[cluster.cluster_id] = cluster

            # Create initial instance
            instance = await self._create_plugin_instance(cluster)
            cluster.instances.append(instance)
            self.instances[instance.instance_id] = instance

        logger.info(f"Discovered {len(plugins)} plugins and created default clusters")

    async def _initialize_optimization_models(self):
        """Initialize ML models for performance optimization"""

        # In production, would load trained ML models
        # For now, use simple heuristic-based optimization

        self.optimization_models = {
            "response_time_predictor": self._create_response_time_model(),
            "load_predictor": self._create_load_predictor(),
            "resource_optimizer": self._create_resource_optimizer(),
            "scaling_advisor": self._create_scaling_advisor(),
        }

        logger.info("Initialized optimization models")

    def _create_response_time_model(self) -> Callable:
        """Create response time prediction model"""

        def predict_response_time(
            instance: PluginInstance, request: RouteRequest
        ) -> Dict[str, float]:
            # Simple heuristic model
            base_time = instance.avg_response_time_ms or 100.0

            # Factor in current load
            load_factor = instance.current_connections / instance.max_connections
            load_penalty = load_factor * 50.0  # Add up to 50ms for high load

            # Factor in resource usage
            resource_factor = (instance.cpu_usage_percent + instance.memory_usage_mb / 512) / 200
            resource_penalty = resource_factor * 30.0  # Add up to 30ms for high resource usage

            predicted_time = base_time + load_penalty + resource_penalty
            confidence = max(0.1, 1.0 - load_factor - resource_factor)

            return {"time_ms": predicted_time, "confidence": min(1.0, confidence)}

        return predict_response_time

    def _create_load_predictor(self) -> Callable:
        """Create load prediction model"""

        def predict_load(
            cluster: PluginCluster, time_horizon_minutes: int = 30
        ) -> Dict[str, float]:
            # Simple trend-based prediction
            current_load = sum(
                i.current_connections for i in cluster.instances if i.status == "running"
            )

            # Get recent load history
            history = self.request_history.get(cluster.cluster_id, deque())
            if len(history) < 10:
                return {"predicted_load": current_load, "confidence": 0.3}

            # Calculate trend
            recent_loads = list(history)[-10:]
            if len(recent_loads) >= 2:
                trend = (recent_loads[-1] - recent_loads[0]) / len(recent_loads)
                predicted_load = current_load + (trend * time_horizon_minutes)
            else:
                predicted_load = current_load

            confidence = min(1.0, len(history) / 100.0)

            return {"predicted_load": max(0, predicted_load), "confidence": confidence}

        return predict_load

    def _create_resource_optimizer(self) -> Callable:
        """Create resource optimization model"""

        def optimize_resources(cluster: PluginCluster) -> List[Dict[str, Any]]:
            recommendations = []

            running_instances = [i for i in cluster.instances if i.status == "running"]
            if not running_instances:
                return recommendations

            avg_cpu = statistics.mean(i.cpu_usage_percent for i in running_instances)
            avg_memory = statistics.mean(i.memory_usage_mb for i in running_instances)

            # CPU optimization
            if avg_cpu > 80:
                recommendations.append(
                    {
                        "type": "scale_up",
                        "reason": f"High CPU usage: {avg_cpu:.1f}%",
                        "suggested_instances": len(running_instances) + 1,
                        "priority": "high",
                    }
                )
            elif avg_cpu < 30 and len(running_instances) > cluster.min_instances:
                recommendations.append(
                    {
                        "type": "scale_down",
                        "reason": f"Low CPU usage: {avg_cpu:.1f}%",
                        "suggested_instances": len(running_instances) - 1,
                        "priority": "medium",
                    }
                )

            # Memory optimization
            if avg_memory > 400:  # 400MB threshold
                recommendations.append(
                    {
                        "type": "scale_up",
                        "reason": f"High memory usage: {avg_memory:.1f}MB",
                        "suggested_instances": len(running_instances) + 1,
                        "priority": "high",
                    }
                )

            # Load balancing optimization
            if len(running_instances) > 1:
                connection_variance = statistics.variance(
                    i.current_connections for i in running_instances
                )
                if connection_variance > 10:
                    recommendations.append(
                        {
                            "type": "rebalance",
                            "reason": f"Uneven load distribution (variance: {connection_variance:.1f})",
                            "suggested_action": "drain_overloaded_instances",
                            "priority": "medium",
                        }
                    )

            return recommendations

        return optimize_resources

    def _create_scaling_advisor(self) -> Callable:
        """Create scaling advisory model"""

        def advise_scaling(cluster: PluginCluster, metrics_history: List[Dict]) -> Dict[str, Any]:
            if not metrics_history:
                return {"action": "maintain", "confidence": 0.0}

            recent_metrics = metrics_history[-5:]  # Last 5 measurements

            # Calculate trends
            cpu_trend = sum(m.get("avg_cpu", 0) for m in recent_metrics) / len(recent_metrics)
            memory_trend = sum(m.get("avg_memory", 0) for m in recent_metrics) / len(recent_metrics)
            sum(m.get("total_connections", 0) for m in recent_metrics) / len(recent_metrics)

            running_instances = len([i for i in cluster.instances if i.status == "running"])

            # Scaling decision logic
            if (
                cpu_trend > cluster.scale_up_threshold_cpu
                or memory_trend > cluster.scale_up_threshold_memory
            ):
                if running_instances < cluster.max_instances:
                    return {
                        "action": "scale_up",
                        "target_instances": min(cluster.max_instances, running_instances + 1),
                        "reason": f"High resource usage (CPU: {cpu_trend:.1f}%, Memory: {memory_trend:.1f}MB)",
                        "confidence": 0.8,
                    }

            elif (
                cpu_trend < cluster.scale_down_threshold_cpu
                and memory_trend < cluster.scale_down_threshold_memory
            ):
                if running_instances > cluster.min_instances:
                    return {
                        "action": "scale_down",
                        "target_instances": max(cluster.min_instances, running_instances - 1),
                        "reason": f"Low resource usage (CPU: {cpu_trend:.1f}%, Memory: {memory_trend:.1f}MB)",
                        "confidence": 0.7,
                    }

            return {
                "action": "maintain",
                "reason": "Resource usage within normal thresholds",
                "confidence": 0.6,
            }

        return advise_scaling

    async def _start_cluster_monitoring(self, cluster_id: str):
        """Start monitoring for a specific cluster"""

        if cluster_id in self.monitoring_tasks:
            return  # Already monitoring

        async def monitor_loop():
            while self.monitoring_enabled:
                try:
                    cluster = self.clusters.get(cluster_id)
                    if not cluster:
                        break

                    # Update instance health and metrics
                    await self._update_cluster_health(cluster)

                    # Check auto-scaling conditions
                    await self._check_autoscaling(cluster)

                    # Update circuit breaker status
                    await self._update_circuit_breaker(cluster)

                    # Record metrics
                    await self._record_cluster_metrics(cluster)

                    # Wait before next check
                    await asyncio.sleep(cluster.health_check_interval)

                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Cluster monitoring error for {cluster_id}: {e}")
                    await asyncio.sleep(30)

        task = asyncio.create_task(monitor_loop())
        self.monitoring_tasks[cluster_id] = task
        logger.info(f"Started monitoring for cluster: {cluster_id}")

    async def _start_optimization_scheduler(self):
        """Start optimization scheduler"""

        async def optimization_loop():
            while self.monitoring_enabled:
                try:
                    # Run optimization for all clusters periodically
                    for cluster_id, cluster in self.clusters.items():
                        if cluster.optimization_target != OptimizationTarget.BALANCED:
                            # Skip if already being optimized
                            if not any(
                                job.status == "running" and cluster_id in job.cluster_ids
                                for job in self.optimization_jobs.values()
                            ):
                                await self.optimize_cluster_performance(
                                    cluster_id, cluster.optimization_target
                                )

                    # Wait 1 hour before next optimization cycle
                    await asyncio.sleep(3600)

                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Optimization scheduler error: {e}")
                    await asyncio.sleep(600)  # 10 minutes on error

        task = asyncio.create_task(optimization_loop())
        self.optimization_tasks["scheduler"] = task
        logger.info("Started optimization scheduler")

    async def _create_plugin_instance(self, cluster: PluginCluster) -> PluginInstance:
        """Create a new plugin instance"""

        instance = PluginInstance(
            plugin_id=cluster.plugin_id,
            max_connections=100,  # Default, could be configured per plugin
            weight=1.0,
            priority=100,
        )

        return instance

    async def _start_plugin_instance(self, instance: PluginInstance):
        """Start a plugin instance"""

        try:
            instance.status = "starting"
            instance.started_at = datetime.utcnow()

            # In production, would actually start the plugin instance
            # For now, just simulate startup
            await asyncio.sleep(1)

            instance.status = "running"
            instance.health_score = 1.0

            logger.info(f"Started plugin instance: {instance.instance_id}")

        except Exception as e:
            instance.status = "failed"
            instance.health_score = 0.0
            logger.error(f"Failed to start plugin instance {instance.instance_id}: {e}")

    async def _stop_plugin_instance(self, instance: PluginInstance):
        """Stop a plugin instance"""

        try:
            instance.status = "stopping"

            # Wait for active connections to drain
            while instance.current_connections > 0:
                await asyncio.sleep(1)
                instance.current_connections = max(0, instance.current_connections - 1)

            # In production, would actually stop the plugin instance
            await asyncio.sleep(1)

            instance.status = "stopped"
            instance.health_score = 0.0

            logger.info(f"Stopped plugin instance: {instance.instance_id}")

        except Exception as e:
            instance.status = "failed"
            logger.error(f"Failed to stop plugin instance {instance.instance_id}: {e}")

    def _find_cluster_for_plugin(self, plugin_id: str) -> Optional[PluginCluster]:
        """Find cluster for a plugin"""

        for cluster in self.clusters.values():
            if cluster.plugin_id == plugin_id:
                return cluster
        return None

    async def _select_instance(
        self, cluster: PluginCluster, request: RouteRequest
    ) -> Optional[PluginInstance]:
        """Select optimal instance for request based on strategy"""

        # Get healthy instances
        healthy_instances = [
            i
            for i in cluster.instances
            if i.status == "running" and i.enabled and i.health_score >= 0.5
        ]

        if not healthy_instances:
            return None

        # Check session affinity first
        if cluster.sticky_sessions and request.session_id:
            affinity_instance_id = self.session_affinity.get(request.session_id)
            if affinity_instance_id:
                affinity_instance = next(
                    (i for i in healthy_instances if i.instance_id == affinity_instance_id),
                    None,
                )
                if affinity_instance:
                    return affinity_instance

        # Check preferred instance
        if request.preferred_instance_id:
            preferred_instance = next(
                (i for i in healthy_instances if i.instance_id == request.preferred_instance_id),
                None,
            )
            if preferred_instance:
                return preferred_instance

        # Select based on strategy
        if cluster.strategy == OrchestrationStrategy.ROUND_ROBIN:
            return self._select_round_robin(cluster, healthy_instances)

        elif cluster.strategy == OrchestrationStrategy.LEAST_CONNECTIONS:
            return self._select_least_connections(healthy_instances)

        elif cluster.strategy == OrchestrationStrategy.WEIGHTED_ROUND_ROBIN:
            return self._select_weighted_round_robin(cluster, healthy_instances)

        elif cluster.strategy == OrchestrationStrategy.RESOURCE_BASED:
            return self._select_resource_based(healthy_instances)

        elif cluster.strategy == OrchestrationStrategy.PERFORMANCE_BASED:
            return self._select_performance_based(healthy_instances)

        elif cluster.strategy == OrchestrationStrategy.INTELLIGENT:
            return await self._select_intelligent(cluster, healthy_instances, request)

        else:
            # Default to round robin
            return self._select_round_robin(cluster, healthy_instances)

    def _select_round_robin(
        self, cluster: PluginCluster, instances: List[PluginInstance]
    ) -> PluginInstance:
        """Round-robin selection"""

        counter = self.round_robin_counters[cluster.cluster_id]
        selected = instances[counter % len(instances)]
        self.round_robin_counters[cluster.cluster_id] = counter + 1
        return selected

    def _select_least_connections(self, instances: List[PluginInstance]) -> PluginInstance:
        """Least connections selection"""

        return min(instances, key=lambda x: x.current_connections)

    def _select_weighted_round_robin(
        self, cluster: PluginCluster, instances: List[PluginInstance]
    ) -> PluginInstance:
        """Weighted round-robin selection"""

        # Create weighted list
        weighted_instances = []
        for instance in instances:
            weight = int(instance.weight * 10)  # Scale weights
            weighted_instances.extend([instance] * weight)

        if not weighted_instances:
            return instances[0]

        counter = self.round_robin_counters[cluster.cluster_id]
        selected = weighted_instances[counter % len(weighted_instances)]
        self.round_robin_counters[cluster.cluster_id] = counter + 1
        return selected

    def _select_resource_based(self, instances: List[PluginInstance]) -> PluginInstance:
        """Resource-based selection (lowest resource usage)"""

        def resource_score(instance: PluginInstance) -> float:
            cpu_score = instance.cpu_usage_percent / 100.0
            memory_score = min(1.0, instance.memory_usage_mb / 512.0)  # Normalize to 512MB
            return cpu_score + memory_score

        return min(instances, key=resource_score)

    def _select_performance_based(self, instances: List[PluginInstance]) -> PluginInstance:
        """Performance-based selection (best performance metrics)"""

        def performance_score(instance: PluginInstance) -> float:
            response_score = instance.avg_response_time_ms / 1000.0  # Normalize to seconds
            health_score = 1.0 - instance.health_score  # Lower is better
            return response_score + health_score

        return min(instances, key=performance_score)

    async def _select_intelligent(
        self,
        cluster: PluginCluster,
        instances: List[PluginInstance],
        request: RouteRequest,
    ) -> PluginInstance:
        """AI-driven intelligent selection"""

        # Score each instance using multiple factors
        best_instance = None
        best_score = float("inf")

        for instance in instances:
            # Predict response time
            prediction = await self._predict_response_time(instance, request)

            # Calculate composite score
            load_factor = instance.current_connections / instance.max_connections
            resource_factor = (instance.cpu_usage_percent + instance.memory_usage_mb / 512) / 200
            health_factor = 1.0 - instance.health_score
            response_factor = prediction["time_ms"] / 1000.0

            # Weight factors based on optimization target
            if cluster.optimization_target == OptimizationTarget.LATENCY:
                score = response_factor * 0.5 + load_factor * 0.3 + resource_factor * 0.2
            elif cluster.optimization_target == OptimizationTarget.THROUGHPUT:
                score = load_factor * 0.4 + resource_factor * 0.3 + response_factor * 0.3
            elif cluster.optimization_target == OptimizationTarget.RESOURCE_EFFICIENCY:
                score = resource_factor * 0.5 + load_factor * 0.3 + response_factor * 0.2
            else:  # BALANCED
                score = (load_factor + resource_factor + health_factor + response_factor) / 4

            # Apply confidence weighting
            score *= 2.0 - prediction["confidence"]  # Lower confidence = higher penalty

            if score < best_score:
                best_score = score
                best_instance = instance

        return best_instance

    def _calculate_instance_load(self, instance: PluginInstance) -> float:
        """Calculate current load percentage for an instance"""

        if instance.max_connections == 0:
            return 0.0

        connection_load = instance.current_connections / instance.max_connections
        resource_load = (instance.cpu_usage_percent + instance.memory_usage_mb / 512) / 200

        return min(1.0, max(connection_load, resource_load))

    async def _predict_response_time(
        self, instance: PluginInstance, request: RouteRequest
    ) -> Dict[str, float]:
        """Predict response time for instance"""

        predictor = self.optimization_models.get("response_time_predictor")
        if predictor:
            return predictor(instance, request)

        # Fallback prediction
        return {"time_ms": instance.avg_response_time_ms or 100.0, "confidence": 0.5}

    async def _record_routing_decision(
        self,
        cluster: PluginCluster,
        instance: PluginInstance,
        request: RouteRequest,
        response: RouteResponse,
    ):
        """Record routing decision for analytics"""

        # Record in request history
        self.request_history[cluster.cluster_id].append(
            {
                "timestamp": datetime.utcnow(),
                "instance_id": instance.instance_id,
                "load_before": response.instance_load_before,
                "load_after": response.instance_load_after,
                "predicted_time": response.predicted_response_time_ms,
            }
        )

    async def _update_cluster_health(self, cluster: PluginCluster):
        """Update health metrics for all instances in cluster"""

        for instance in cluster.instances:
            if instance.status == "running":
                # Simulate health check
                # In production, would perform actual health checks
                health_score = await self._perform_instance_health_check(instance)
                instance.health_score = health_score
                instance.last_health_check = datetime.utcnow()

                # Simulate resource metrics update
                await self._update_instance_metrics(instance)

    async def _perform_instance_health_check(self, instance: PluginInstance) -> float:
        """Perform health check for an instance"""

        try:
            # In production, would perform actual health check
            # For now, simulate based on load and resources

            load_factor = instance.current_connections / instance.max_connections
            resource_factor = (instance.cpu_usage_percent + instance.memory_usage_mb / 512) / 200

            # Health decreases with high load and resource usage
            health_score = 1.0 - min(0.8, (load_factor + resource_factor) / 2)

            return max(0.0, health_score)

        except Exception as e:
            logger.error(f"Health check failed for instance {instance.instance_id}: {e}")
            return 0.0

    async def _update_instance_metrics(self, instance: PluginInstance):
        """Update performance and resource metrics for an instance"""

        try:
            # In production, would collect actual metrics
            # For now, simulate with some randomness

            import random

            # Simulate gradual changes in metrics
            instance.cpu_usage_percent = max(
                0, min(100, instance.cpu_usage_percent + random.uniform(-5, 5))
            )
            instance.memory_usage_mb = max(
                0, min(1024, instance.memory_usage_mb + random.uniform(-20, 20))
            )

            # Simulate response time based on load
            load_factor = instance.current_connections / instance.max_connections
            base_response_time = 100 + (load_factor * 200)  # 100-300ms range
            instance.avg_response_time_ms = base_response_time + random.uniform(-20, 20)

            # Simulate RPS based on connections
            instance.requests_per_second = instance.current_connections * random.uniform(0.5, 2.0)

        except Exception as e:
            logger.error(f"Failed to update metrics for instance {instance.instance_id}: {e}")

    async def _check_autoscaling(self, cluster: PluginCluster):
        """Check and execute auto-scaling for cluster"""

        if cluster.scaling_policy == ScalingPolicy.DISABLED:
            return

        # Check cooldown period
        if cluster.last_scale_action:
            time_since_last_scale = (datetime.utcnow() - cluster.last_scale_action).total_seconds()
            if time_since_last_scale < cluster.scale_up_cooldown_seconds:
                return

        running_instances = [i for i in cluster.instances if i.status == "running"]
        if not running_instances:
            return

        # Get current metrics
        avg_cpu = statistics.mean(i.cpu_usage_percent for i in running_instances)
        avg_memory = statistics.mean(i.memory_usage_mb for i in running_instances)
        total_connections = sum(i.current_connections for i in running_instances)
        max_connections = sum(i.max_connections for i in running_instances)
        connection_utilization = (
            (total_connections / max_connections * 100) if max_connections > 0 else 0
        )

        current_count = len(running_instances)

        # Check scale-up conditions
        scale_up = False
        scale_up_reason = ""

        if avg_cpu > cluster.scale_up_threshold_cpu:
            scale_up = True
            scale_up_reason = f"High CPU usage: {avg_cpu:.1f}%"
        elif avg_memory > cluster.scale_up_threshold_memory:
            scale_up = True
            scale_up_reason = f"High memory usage: {avg_memory:.1f}MB"
        elif connection_utilization > cluster.scale_up_threshold_requests:
            scale_up = True
            scale_up_reason = f"High connection utilization: {connection_utilization:.1f}%"

        if scale_up and current_count < cluster.max_instances:
            target_count = min(cluster.max_instances, current_count + 1)
            await self.scale_cluster(
                cluster.cluster_id, target_count, f"Auto-scale up: {scale_up_reason}"
            )
            return

        # Check scale-down conditions (with longer cooldown)
        if cluster.last_scale_action:
            time_since_last_scale = (datetime.utcnow() - cluster.last_scale_action).total_seconds()
            if time_since_last_scale < cluster.scale_down_cooldown_seconds:
                return

        scale_down = False
        scale_down_reason = ""

        if (
            avg_cpu < cluster.scale_down_threshold_cpu
            and avg_memory < cluster.scale_down_threshold_memory
            and connection_utilization < cluster.scale_down_threshold_requests
        ):
            scale_down = True
            scale_down_reason = f"Low resource usage (CPU: {avg_cpu:.1f}%, Memory: {avg_memory:.1f}MB, Connections: {connection_utilization:.1f}%)"

        if scale_down and current_count > cluster.min_instances:
            target_count = max(cluster.min_instances, current_count - 1)
            await self.scale_cluster(
                cluster.cluster_id,
                target_count,
                f"Auto-scale down: {scale_down_reason}",
            )

    async def _update_circuit_breaker(self, cluster: PluginCluster):
        """Update circuit breaker status for cluster"""

        if not cluster.circuit_breaker_enabled:
            return

        failure_count = self.circuit_breaker_failures.get(cluster.cluster_id, 0)

        if cluster.circuit_breaker_status == "closed":
            if failure_count >= cluster.circuit_breaker_failure_threshold:
                cluster.circuit_breaker_status = "open"
                timeout_time = datetime.utcnow() + timedelta(
                    seconds=cluster.circuit_breaker_timeout_seconds
                )
                self.circuit_breaker_timeouts[cluster.cluster_id] = timeout_time
                logger.warning(f"Circuit breaker opened for cluster {cluster.cluster_id}")

        elif cluster.circuit_breaker_status == "half-open":
            # In half-open state, one request is allowed through
            # Success would close the circuit, failure would open it again
            # This is handled in the routing logic
            pass

    async def _record_cluster_metrics(self, cluster: PluginCluster):
        """Record cluster metrics for analytics"""

        metrics = await self.get_cluster_metrics(cluster.cluster_id)

        # Store in performance metrics history
        self.performance_metrics[cluster.cluster_id].append(
            {"timestamp": datetime.utcnow(), "metrics": metrics}
        )

    async def _execute_optimization_job(self, job: OptimizationJob):
        """Execute an optimization job"""

        try:
            job.status = "running"
            job.started_at = datetime.utcnow()
            job.progress = 10.0
            await job.save()

            # Collect baseline metrics
            baseline_metrics = {}
            for cluster_id in job.cluster_ids:
                cluster_metrics = await self.get_cluster_metrics(cluster_id)
                baseline_metrics[cluster_id] = cluster_metrics

            job.baseline_metrics = baseline_metrics
            job.progress = 30.0
            await job.save()

            # Generate optimization recommendations
            recommendations = []
            for cluster_id in job.cluster_ids:
                cluster = self.clusters.get(cluster_id)
                if cluster:
                    cluster_recommendations = await self._generate_optimization_recommendations(
                        cluster, job.target
                    )
                    recommendations.extend(cluster_recommendations)

            job.recommendations = recommendations
            job.progress = 60.0
            await job.save()

            # Apply recommendations (in production, would be more careful about this)
            applied_recommendations = []
            for recommendation in recommendations:
                if recommendation.get("auto_apply", False):
                    success = await self._apply_optimization_recommendation(recommendation)
                    if success:
                        applied_recommendations.append(recommendation["id"])

            job.applied_recommendations = applied_recommendations
            job.progress = 80.0
            await job.save()

            # Wait for changes to take effect
            await asyncio.sleep(60)  # 1 minute

            # Collect post-optimization metrics
            optimized_metrics = {}
            improvement = {}
            for cluster_id in job.cluster_ids:
                cluster_metrics = await self.get_cluster_metrics(cluster_id)
                optimized_metrics[cluster_id] = cluster_metrics

                # Calculate improvement
                baseline = baseline_metrics.get(cluster_id, {}).get("performance", {})
                optimized = cluster_metrics.get("performance", {})

                if baseline and optimized:
                    improvement[cluster_id] = self._calculate_improvement(
                        baseline, optimized, job.target
                    )

            job.optimized_metrics = optimized_metrics
            job.improvement_percentage = improvement
            job.status = "completed"
            job.progress = 100.0

        except Exception as e:
            job.status = "failed"
            logger.error(f"Optimization job failed: {e}")

        finally:
            job.completed_at = datetime.utcnow()
            await job.save()

            logger.info(f"Optimization job completed: {job.job_id} - {job.status}")

    async def _generate_optimization_recommendations(
        self, cluster: PluginCluster, target: OptimizationTarget
    ) -> List[Dict[str, Any]]:
        """Generate optimization recommendations for a cluster"""

        recommendations = []

        # Get resource optimizer recommendations
        resource_optimizer = self.optimization_models.get("resource_optimizer")
        if resource_optimizer:
            resource_recs = resource_optimizer(cluster)
            for rec in resource_recs:
                rec["id"] = str(uuid.uuid4())
                rec["cluster_id"] = cluster.cluster_id
                rec["target"] = target.value
                rec["auto_apply"] = (
                    rec.get("priority") != "high"
                )  # Don't auto-apply high priority changes
                recommendations.append(rec)

        # Add strategy-specific recommendations
        if target == OptimizationTarget.LATENCY:
            recommendations.append(
                {
                    "id": str(uuid.uuid4()),
                    "cluster_id": cluster.cluster_id,
                    "type": "strategy_change",
                    "suggested_strategy": OrchestrationStrategy.PERFORMANCE_BASED.value,
                    "reason": "Performance-based routing optimizes for latency",
                    "priority": "medium",
                    "auto_apply": True,
                }
            )

        elif target == OptimizationTarget.THROUGHPUT:
            recommendations.append(
                {
                    "id": str(uuid.uuid4()),
                    "cluster_id": cluster.cluster_id,
                    "type": "strategy_change",
                    "suggested_strategy": OrchestrationStrategy.LEAST_CONNECTIONS.value,
                    "reason": "Least connections routing optimizes for throughput",
                    "priority": "medium",
                    "auto_apply": True,
                }
            )

        elif target == OptimizationTarget.RESOURCE_EFFICIENCY:
            recommendations.append(
                {
                    "id": str(uuid.uuid4()),
                    "cluster_id": cluster.cluster_id,
                    "type": "strategy_change",
                    "suggested_strategy": OrchestrationStrategy.RESOURCE_BASED.value,
                    "reason": "Resource-based routing optimizes for efficiency",
                    "priority": "medium",
                    "auto_apply": True,
                }
            )

        return recommendations

    async def _apply_optimization_recommendation(self, recommendation: Dict[str, Any]) -> bool:
        """Apply an optimization recommendation"""

        try:
            cluster_id = recommendation.get("cluster_id")
            cluster = self.clusters.get(cluster_id)

            if not cluster:
                return False

            rec_type = recommendation.get("type")

            if rec_type == "scale_up":
                target_instances = recommendation.get(
                    "suggested_instances", cluster.target_instance_count + 1
                )
                return await self.scale_cluster(
                    cluster_id,
                    target_instances,
                    f"Optimization: {recommendation.get('reason')}",
                )

            elif rec_type == "scale_down":
                target_instances = recommendation.get(
                    "suggested_instances", cluster.target_instance_count - 1
                )
                return await self.scale_cluster(
                    cluster_id,
                    target_instances,
                    f"Optimization: {recommendation.get('reason')}",
                )

            elif rec_type == "strategy_change":
                new_strategy = OrchestrationStrategy(recommendation.get("suggested_strategy"))
                cluster.strategy = new_strategy
                cluster.last_modified = datetime.utcnow()
                logger.info(f"Changed strategy for cluster {cluster_id} to {new_strategy.value}")
                return True

            elif rec_type == "rebalance":
                # Trigger load rebalancing
                logger.info(f"Triggered load rebalancing for cluster {cluster_id}")
                return True

            return False

        except Exception as e:
            logger.error(f"Failed to apply recommendation: {e}")
            return False

    def _calculate_improvement(
        self,
        baseline: Dict[str, Any],
        optimized: Dict[str, Any],
        target: OptimizationTarget,
    ) -> Dict[str, float]:
        """Calculate improvement percentage for optimization target"""

        improvement = {}

        # Response time improvement (lower is better)
        baseline_rt = baseline.get("avg_response_time_ms", 0)
        optimized_rt = optimized.get("avg_response_time_ms", 0)

        if baseline_rt > 0:
            rt_improvement = ((baseline_rt - optimized_rt) / baseline_rt) * 100
            improvement["response_time"] = rt_improvement

        # Throughput improvement (higher is better)
        baseline_rps = baseline.get("total_requests_per_second", 0)
        optimized_rps = optimized.get("total_requests_per_second", 0)

        if baseline_rps > 0:
            rps_improvement = ((optimized_rps - baseline_rps) / baseline_rps) * 100
            improvement["throughput"] = rps_improvement

        # Health score improvement
        baseline_health = baseline.get("avg_health_score", 0)
        optimized_health = optimized.get("avg_health_score", 0)

        if baseline_health > 0:
            health_improvement = ((optimized_health - baseline_health) / baseline_health) * 100
            improvement["health"] = health_improvement

        return improvement

    async def get_orchestration_statistics(self) -> Dict[str, Any]:
        """Get orchestration service statistics"""

        # Cluster statistics
        total_clusters = len(self.clusters)
        active_clusters = len(
            [c for c in self.clusters.values() if any(i.status == "running" for i in c.instances)]
        )

        # Instance statistics
        total_instances = len(self.instances)
        running_instances = len([i for i in self.instances.values() if i.status == "running"])
        healthy_instances = len(
            [i for i in self.instances.values() if i.status == "running" and i.health_score >= 0.8]
        )

        # Strategy distribution
        strategy_distribution = {}
        for strategy in OrchestrationStrategy:
            count = len([c for c in self.clusters.values() if c.strategy == strategy])
            strategy_distribution[strategy.value] = count

        # Load balancing statistics
        total_connections = sum(
            i.current_connections for i in self.instances.values() if i.status == "running"
        )
        max_connections = sum(
            i.max_connections for i in self.instances.values() if i.status == "running"
        )

        # Optimization statistics
        total_optimization_jobs = len(self.optimization_jobs)
        completed_optimizations = len(
            [j for j in self.optimization_jobs.values() if j.status == "completed"]
        )

        # Circuit breaker statistics
        open_circuit_breakers = len(
            [c for c in self.clusters.values() if c.circuit_breaker_status == "open"]
        )

        return {
            "clusters": {
                "total": total_clusters,
                "active": active_clusters,
                "strategy_distribution": strategy_distribution,
            },
            "instances": {
                "total": total_instances,
                "running": running_instances,
                "healthy": healthy_instances,
                "health_rate": (
                    healthy_instances / running_instances if running_instances > 0 else 0.0
                ),
            },
            "load_balancing": {
                "total_connections": total_connections,
                "max_connections": max_connections,
                "utilization": (
                    (total_connections / max_connections * 100) if max_connections > 0 else 0.0
                ),
                "session_affinity_entries": len(self.session_affinity),
            },
            "optimization": {
                "total_jobs": total_optimization_jobs,
                "completed_jobs": completed_optimizations,
                "success_rate": (
                    completed_optimizations / total_optimization_jobs
                    if total_optimization_jobs > 0
                    else 0.0
                ),
                "models_loaded": len(self.optimization_models),
            },
            "circuit_breakers": {
                "open": open_circuit_breakers,
                "total_failures": sum(self.circuit_breaker_failures.values()),
            },
            "monitoring": {
                "enabled": self.monitoring_enabled,
                "cluster_monitors": len(self.monitoring_tasks),
                "optimization_tasks": len(self.optimization_tasks),
            },
        }
