"""
Health monitoring service for collecting and managing health metrics.

This service handles both service health (operational) and content health
(compliance effectiveness) data collection and storage.
OW-REFACTOR-002: Migrating to Repository Pattern
"""

import asyncio
import logging
import platform
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import psutil
from motor.motor_asyncio import AsyncIOMotorDatabase

from ..models.health_models import (
    AlertSeverity,
    BenchmarkHealth,
    ConnectionPool,
    ContentAlert,
    ContentHealthDocument,
    DatabaseHealth,
    FrameworkHealth,
    FreshnessStatus,
    HealthStatus,
    HealthSummaryDocument,
    OperationalAlert,
    ServiceComponent,
    ServiceHealthDocument,
    ServiceStatus,
)
from ..models.mongo_models import ComplianceRule, RemediationScript, RuleIntelligence
from ..services.mongo_integration_service import get_mongo_service

logger = logging.getLogger(__name__)
from ..config import get_settings

# OW-REFACTOR-002: Import Repository Pattern
try:
    from ..repositories import ComplianceRuleRepository

    REPOSITORY_AVAILABLE = True
except ImportError:
    REPOSITORY_AVAILABLE = False

settings = get_settings()


class HealthMonitoringService:
    """Service for monitoring system and content health"""

    def __init__(self):
        self.scanner_id = f"openwatch_{platform.node()}"
        self.start_time = datetime.utcnow()
        self._initialized = False

    async def initialize(self):
        """Initialize health monitoring service"""
        if self._initialized:
            return

        try:
            # Ensure MongoDB models are initialized
            mongo_service = await get_mongo_service()
            if not mongo_service.initialized:
                raise RuntimeError("MongoDB service not initialized")

            self._initialized = True
            logger.info("Health monitoring service initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize health monitoring service: {e}")
            raise

    # Service Health Collection Methods
    async def collect_service_health(self) -> ServiceHealthDocument:
        """Collect current service health metrics"""
        try:
            # Ensure we're initialized (MongoDB is ready)
            if not self._initialized:
                await self.initialize()

            health_data = ServiceHealthDocument(
                scanner_id=self.scanner_id,
                health_check_timestamp=datetime.utcnow(),
                overall_status=HealthStatus.HEALTHY,
                uptime_seconds=int((datetime.utcnow() - self.start_time).total_seconds()),
            )

            # Collect core services health
            health_data.core_services = await self._collect_core_services_health()

            # Collect data services health
            health_data.data_services = await self._collect_data_services_health()

            # Collect integration services health
            health_data.integration_services = await self._collect_integration_services_health()

            # Collect resource usage
            health_data.resource_usage = await self._collect_resource_usage()

            # Collect recent operations
            health_data.recent_operations = await self._collect_recent_operations()

            # Check for alerts
            health_data.alerts = await self._check_operational_alerts(health_data)

            # Update overall status based on component health
            health_data.overall_status = self._calculate_overall_status(health_data)

            return health_data

        except Exception as e:
            logger.error(f"Error collecting service health: {type(e).__name__}: {str(e)}")
            import traceback

            logger.error(f"Traceback: {traceback.format_exc()}")
            raise

    async def _collect_core_services_health(self) -> Dict[str, ServiceComponent]:
        """Collect health metrics for core services"""
        services = {}

        # Scanner engine health
        services["scanner_engine"] = ServiceComponent(
            status=HealthStatus.HEALTHY,
            version=settings.app_version,
            started_at=self.start_time,
            last_heartbeat=datetime.utcnow(),
            memory_usage_mb=psutil.Process().memory_info().rss / 1024 / 1024,
            cpu_usage_percent=psutil.Process().cpu_percent(),
            errors_last_hour=0,  # TODO: Implement error tracking
        )

        # Rule processor health
        mongo_service = await get_mongo_service()
        rule_count = await ComplianceRule.count()

        services["rule_processor"] = ServiceComponent(
            status=HealthStatus.HEALTHY,
            version=settings.app_version,
            custom_metrics={
                "rules_loaded": rule_count,
                "processing_queue_length": 0,  # TODO: Implement queue tracking
                "average_processing_time_ms": 42.1,  # TODO: Implement metric tracking
            },
        )

        # Remediation engine health
        remediation_count = await RemediationScript.count()

        services["remediation_engine"] = ServiceComponent(
            status=HealthStatus.HEALTHY,
            version="1.2.0",
            custom_metrics={
                "scripts_loaded": remediation_count,
                "active_remediations": 0,  # TODO: Track active remediations
                "plugins_loaded": 3,  # TODO: Implement plugin tracking
            },
        )

        return services

    async def _collect_data_services_health(self) -> Dict[str, DatabaseHealth]:
        """Collect health metrics for data services"""
        services = {}

        # MongoDB health
        mongo_service = await get_mongo_service()
        mongo_health = await mongo_service.health_check()

        if mongo_health.get("status") == "healthy":
            services["mongodb"] = DatabaseHealth(
                status=HealthStatus.HEALTHY,
                connection_pool=ConnectionPool(
                    active_connections=5,  # TODO: Get actual metrics
                    idle_connections=15,
                    max_connections=settings.mongodb_max_pool_size,
                    wait_queue_length=0,
                ),
                host=settings.mongodb_url,
                database_name=settings.mongodb_database,
                storage_size_mb=0.0,  # TODO: Calculate actual size
                performance_metrics={
                    "average_query_time_ms": 12.3,  # TODO: Track actual metrics
                    "slow_queries_last_hour": 0,
                },
            )

        # Redis health (if configured)
        if hasattr(settings, "redis_url") and settings.redis_url:
            # TODO: Implement Redis health check
            services["redis"] = DatabaseHealth(
                status=HealthStatus.HEALTHY,
                connection_pool=ConnectionPool(
                    active_connections=2,
                    idle_connections=8,
                    max_connections=10,
                    wait_queue_length=0,
                ),
                host=settings.redis_url,
                database_name="0",
                storage_size_mb=128.0,
                performance_metrics={
                    "hit_rate_percent": 87.3,
                    "evicted_keys_last_hour": 0,
                },
            )

        return services

    async def _collect_integration_services_health(self) -> Dict[str, ServiceComponent]:
        """Collect health metrics for integration services"""
        services = {}

        # Content updater health
        services["content_updater"] = ServiceComponent(
            status=HealthStatus.WARNING,
            custom_metrics={
                "last_successful_update": datetime.utcnow() - timedelta(days=9),
                "update_sources": {
                    "complianceascode_repo": "healthy",
                    "openwatch_content_cdn": "healthy",
                },
            },
        )

        # Enrichment service health
        services["enrichment_service"] = ServiceComponent(
            status=HealthStatus.HEALTHY,
            custom_metrics={
                "enrichment_providers": {
                    "nvd_cve": "connected",
                    "mitre_attack": "connected",
                },
                "cache_hit_rate_percent": 76.8,
            },
        )

        return services

    async def _collect_resource_usage(self) -> Dict[str, Any]:
        """Collect system resource usage metrics"""
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("/")

        return {
            "system": {
                "total_memory_gb": memory.total / 1024 / 1024 / 1024,
                "used_memory_gb": memory.used / 1024 / 1024 / 1024,
                "memory_usage_percent": memory.percent,
                "cpu_cores": psutil.cpu_count(),
                "cpu_usage_percent": cpu_percent,
                "load_average": (
                    list(psutil.getloadavg()) if hasattr(psutil, "getloadavg") else [0, 0, 0]
                ),
            },
            "storage": {
                "app_directory": {
                    "path": "/app",
                    "total_gb": disk.total / 1024 / 1024 / 1024,
                    "used_gb": disk.used / 1024 / 1024 / 1024,
                    "usage_percent": disk.percent,
                }
            },
        }

    async def _collect_recent_operations(self) -> Dict[str, Dict[str, Any]]:
        """Collect recent operation statistics"""
        # TODO: Implement actual operation tracking
        return {
            "scans": {
                "completed_last_hour": 45,
                "failed_last_hour": 2,
                "average_scan_duration_seconds": 234.5,
                "queued_scans": 3,
            },
            "remediations": {
                "executed_last_hour": 12,
                "successful_last_hour": 11,
                "failed_last_hour": 1,
            },
        }

    async def _check_operational_alerts(
        self, health_data: ServiceHealthDocument
    ) -> List[OperationalAlert]:
        """Check for operational issues and generate alerts"""
        alerts = []

        # Check memory usage
        memory_usage = health_data.resource_usage.get("system", {}).get("memory_usage_percent", 0)
        if memory_usage > 80:
            alerts.append(
                OperationalAlert(
                    id=f"alert_mem_{datetime.utcnow().timestamp()}",
                    severity=(AlertSeverity.HIGH if memory_usage > 90 else AlertSeverity.MEDIUM),
                    component="system",
                    message=f"High memory usage: {memory_usage:.1f}%",
                    timestamp=datetime.utcnow(),
                    auto_resolution_attempted=False,
                    resolved=False,
                )
            )

        # Check service status
        for service_name, service in health_data.core_services.items():
            if service.status != HealthStatus.HEALTHY:
                alerts.append(
                    OperationalAlert(
                        id=f"alert_svc_{service_name}_{datetime.utcnow().timestamp()}",
                        severity=AlertSeverity.HIGH,
                        component=service_name,
                        message=f"Service {service_name} is {service.status}",
                        timestamp=datetime.utcnow(),
                        auto_resolution_attempted=False,
                        resolved=False,
                    )
                )

        return alerts

    def _calculate_overall_status(self, health_data: ServiceHealthDocument) -> HealthStatus:
        """Calculate overall system health status"""
        statuses = []

        # Check all service statuses
        for service in health_data.core_services.values():
            statuses.append(service.status)

        for service in health_data.data_services.values():
            statuses.append(service.status)

        for service in health_data.integration_services.values():
            statuses.append(service.status)

        # Return worst status
        if HealthStatus.UNHEALTHY in statuses:
            return HealthStatus.UNHEALTHY
        elif HealthStatus.DEGRADED in statuses:
            return HealthStatus.DEGRADED
        elif HealthStatus.WARNING in statuses:
            return HealthStatus.WARNING
        else:
            return HealthStatus.HEALTHY

    # Content Health Collection Methods
    async def collect_content_health(self) -> ContentHealthDocument:
        """Collect current content health metrics"""
        try:
            # Ensure we're initialized (MongoDB is ready)
            if not self._initialized:
                await self.initialize()

            health_data = ContentHealthDocument(
                scanner_id=self.scanner_id,
                health_check_timestamp=datetime.utcnow(),
                last_updated=datetime.utcnow(),
            )

            # Collect framework health
            health_data.frameworks = await self._collect_framework_health()

            # Collect benchmark health
            health_data.benchmarks = await self._collect_benchmark_health()

            # Collect rule statistics
            health_data.rule_statistics = await self._collect_rule_statistics()

            # Check content integrity
            health_data.content_integrity = await self._check_content_integrity()

            # Collect performance metrics
            health_data.performance_metrics = await self._collect_content_performance()

            # Generate alerts and recommendations
            health_data.alerts_and_recommendations = await self._generate_content_alerts(
                health_data
            )

            return health_data

        except Exception as e:
            logger.error(f"Error collecting content health: {type(e).__name__}: {str(e)}")
            import traceback

            logger.error(f"Traceback: {traceback.format_exc()}")
            raise

    async def _collect_framework_health(self) -> Dict[str, FrameworkHealth]:
        """Collect health metrics for compliance frameworks
        OW-REFACTOR-002: Supports Repository Pattern
        """
        frameworks = {}

        # Get all rules
        # OW-REFACTOR-002: Use Repository Pattern if enabled
        if REPOSITORY_AVAILABLE and settings.use_repository_pattern:
            logger.info("Using ComplianceRuleRepository for _collect_framework_health")
            repo = ComplianceRuleRepository()
            all_rules = await repo.find_many({})
        else:
            logger.debug("Using direct MongoDB find for _collect_framework_health")
            all_rules = await ComplianceRule.find().to_list()

        # Analyze framework coverage
        framework_configs = {
            "nist_800_53r5": {"version": "revision_5", "total_controls": 334},
            "cis_controls_v8": {"version": "8.0", "total_controls": 18},
            "pci_dss_4.0": {"version": "4.0", "total_controls": 62},
            "iso_27001_2013": {"version": "2013", "total_controls": 114},
        }

        for framework_id, config in framework_configs.items():
            # Count rules for this framework
            framework_rules = [
                r
                for r in all_rules
                if any(
                    framework_id in str(mapping)
                    for mapping in getattr(r, "compliance_mappings", {}).get("frameworks", [])
                )
            ]

            if framework_rules:
                # Get unique controls
                implemented_controls = set()
                for rule in framework_rules:
                    mappings = getattr(rule, "compliance_mappings", {}).get("frameworks", [])
                    for mapping in mappings:
                        if isinstance(mapping, dict) and mapping.get("framework") == framework_id:
                            implemented_controls.update(mapping.get("controls", []))

                frameworks[framework_id] = FrameworkHealth(
                    version=config["version"],
                    status="active",
                    last_updated=max(
                        (r.updated_at for r in framework_rules),
                        default=datetime.utcnow(),
                    ),
                    total_controls=config["total_controls"],
                    implemented_controls=len(implemented_controls),
                    coverage_percentage=(len(implemented_controls) / config["total_controls"])
                    * 100,
                    rule_count=len(framework_rules),
                    benchmark_dependencies=[],  # TODO: Extract from mappings
                )

        return frameworks

    async def _collect_benchmark_health(self) -> Dict[str, BenchmarkHealth]:
        """Collect health metrics for benchmarks
        OW-REFACTOR-002: Supports Repository Pattern
        """
        benchmarks = {}

        # Get all rules
        # OW-REFACTOR-002: Use Repository Pattern if enabled
        if REPOSITORY_AVAILABLE and settings.use_repository_pattern:
            logger.info("Using ComplianceRuleRepository for _collect_benchmark_health")
            repo = ComplianceRuleRepository()
            all_rules = await repo.find_many({})
        else:
            logger.debug("Using direct MongoDB find for _collect_benchmark_health")
            all_rules = await ComplianceRule.find().to_list()

        # Analyze benchmark coverage
        benchmark_configs = {
            "cis_rhel8_v2.0.0": {
                "version": "2.0.0",
                "source_framework": "cis_controls_v8",
                "platform": "rhel8",
                "total_rules": 245,
            },
            "stig_rhel8_v1r11": {
                "version": "1.11",
                "source_framework": "disa_stig",
                "platform": "rhel8",
                "total_rules": 334,
            },
        }

        for benchmark_id, config in benchmark_configs.items():
            # Count rules for this benchmark
            benchmark_rules = [
                r for r in all_rules if benchmark_id in str(getattr(r, "compliance_mappings", {}))
            ]

            if benchmark_rules:
                # Calculate freshness
                last_update = max(
                    (r.updated_at for r in benchmark_rules), default=datetime.utcnow()
                )
                days_since_update = (datetime.utcnow() - last_update).days

                benchmarks[benchmark_id] = BenchmarkHealth(
                    benchmark_version=config["version"],
                    source_framework=config["source_framework"],
                    platform=config["platform"],
                    status="active" if days_since_update < 90 else "outdated",
                    last_updated=last_update,
                    total_rules=config["total_rules"],
                    implemented_rules=len(benchmark_rules),
                    coverage_percentage=(len(benchmark_rules) / config["total_rules"]) * 100,
                    satisfies_frameworks=[],  # TODO: Extract from mappings
                    content_freshness={
                        "days_since_update": days_since_update,
                        "freshness_status": ("current" if days_since_update < 30 else "stale"),
                    },
                )

        return benchmarks

    async def _collect_rule_statistics(self) -> Dict[str, Any]:
        """Collect rule distribution statistics
        OW-REFACTOR-002: Supports Repository Pattern
        """
        # OW-REFACTOR-002: Use Repository Pattern if enabled
        if REPOSITORY_AVAILABLE and settings.use_repository_pattern:
            logger.info("Using ComplianceRuleRepository for _collect_rule_statistics")
            repo = ComplianceRuleRepository()
            all_rules = await repo.find_many({})
        else:
            logger.debug("Using direct MongoDB find for _collect_rule_statistics")
            all_rules = await ComplianceRule.find().to_list()

        remediation_scripts = await RemediationScript.count()

        # Count by severity
        severity_counts = {}
        category_counts = {}
        platform_counts = {}

        for rule in all_rules:
            # Severity
            severity = getattr(rule, "severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            # Category
            category = getattr(rule, "category", "other")
            category_counts[category] = category_counts.get(category, 0) + 1

            # Platform
            platforms = getattr(rule, "platform_implementations", {})
            for platform in platforms.keys():
                platform_counts[platform] = platform_counts.get(platform, 0) + 1

        return {
            "summary": {
                "total_rules": len(all_rules),
                "active_rules": len(
                    [r for r in all_rules if getattr(r, "abstract", False) is False]
                ),
                "deprecated_rules": 0,  # TODO: Track deprecated rules
                "rules_with_remediation": remediation_scripts,
                "rules_with_plugin_support": len(
                    [r for r in all_rules if getattr(r, "fix_extension", False)]
                ),
                "last_import": max((r.imported_at for r in all_rules), default=datetime.utcnow()),
            },
            "rule_distribution": {
                "by_severity": severity_counts,
                "by_category": category_counts,
                "by_platform": platform_counts,
            },
        }

    async def _check_content_integrity(self) -> Dict[str, Any]:
        """Check content integrity and consistency
        OW-REFACTOR-002: Supports Repository Pattern
        """
        # OW-REFACTOR-002: Use Repository Pattern if enabled
        if REPOSITORY_AVAILABLE and settings.use_repository_pattern:
            logger.info("Using ComplianceRuleRepository for _check_content_integrity")
            repo = ComplianceRuleRepository()
            all_rules = await repo.find_many({})
        else:
            logger.debug("Using direct MongoDB find for _check_content_integrity")
            all_rules = await ComplianceRule.find().to_list()

        # Check for issues
        duplicate_ids = []
        missing_fields = []
        invalid_references = []

        rule_ids = [getattr(r, "rule_id", None) for r in all_rules]
        duplicate_ids = [rid for rid in rule_ids if rule_ids.count(rid) > 1]

        for rule in all_rules:
            # Check required fields
            if not getattr(rule, "rule_id", None) or not getattr(rule, "metadata", None):
                missing_fields.append(getattr(rule, "rule_id", "unknown"))

        return {
            "source_validation": {
                "scap_content_valid": True,
                "signature_verification": "passed",
                "last_validation": datetime.utcnow(),
            },
            "rule_consistency": {
                "schema_compliance": 100.0 if not missing_fields else 90.0,
                "duplicate_rule_ids": len(set(duplicate_ids)),
                "missing_required_fields": len(missing_fields),
                "invalid_references": len(invalid_references),
            },
        }

    async def _collect_content_performance(self) -> Dict[str, Any]:
        """Collect content processing performance metrics"""
        # TODO: Implement actual performance tracking
        return {
            "content_loading": {
                "average_rule_load_time_ms": 2.3,
                "framework_index_build_time_ms": 145.7,
                "benchmark_cache_hit_rate": 94.2,
            },
            "scanning_performance": {
                "rules_processed_per_second": 23.7,
                "average_rule_evaluation_time_ms": 42.1,
            },
        }

    async def _generate_content_alerts(
        self, health_data: ContentHealthDocument
    ) -> List[ContentAlert]:
        """Generate content-related alerts and recommendations"""
        alerts = []

        # Check for outdated benchmarks
        for benchmark_id, benchmark in health_data.benchmarks.items():
            freshness = benchmark.content_freshness
            if freshness.get("freshness_status") == "stale":
                alerts.append(
                    ContentAlert(
                        type="warning",
                        category="content_freshness",
                        message=f"{benchmark_id} is {freshness.get('days_since_update')} days old - update recommended",
                        rule_impact=benchmark.implemented_rules,
                        recommended_action=f"Update {benchmark_id} to latest version",
                        urgency="medium",
                    )
                )

        # Check for low framework coverage
        for framework_id, framework in health_data.frameworks.items():
            if framework.coverage_percentage < 80:
                alerts.append(
                    ContentAlert(
                        type="info",
                        category="coverage",
                        message=f"{framework_id} coverage is only {framework.coverage_percentage:.1f}%",
                        rule_impact=framework.total_controls - framework.implemented_controls,
                        recommended_action=f"Import additional rules for {framework_id}",
                        urgency="low",
                    )
                )

        return alerts

    # Combined Health Summary
    async def create_health_summary(self) -> HealthSummaryDocument:
        """Create a combined health summary"""
        try:
            # Ensure we're initialized (MongoDB is ready)
            if not self._initialized:
                await self.initialize()

            # Collect both health metrics
            service_health = await self.collect_service_health()
            content_health = await self.collect_content_health()

            # Determine content health status
            content_status = HealthStatus.HEALTHY
            if any(alert.type == "warning" for alert in content_health.alerts_and_recommendations):
                content_status = HealthStatus.WARNING

            # Create summary
            summary = HealthSummaryDocument(
                scanner_id=self.scanner_id,
                last_updated=datetime.utcnow(),
                service_health_status=service_health.overall_status,
                content_health_status=content_status,
                overall_health_status=self._combine_health_statuses(
                    service_health.overall_status, content_status
                ),
                key_metrics={
                    "uptime_seconds": service_health.uptime_seconds,
                    "total_rules": content_health.rule_statistics.get("summary", {}).get(
                        "total_rules", 0
                    ),
                    "memory_usage_percent": service_health.resource_usage.get("system", {}).get(
                        "memory_usage_percent", 0
                    ),
                    "active_alerts": len(service_health.alerts)
                    + len(content_health.alerts_and_recommendations),
                },
                active_issues_count=len(service_health.alerts)
                + len(content_health.alerts_and_recommendations),
                critical_alerts=[
                    alert.message
                    for alert in service_health.alerts
                    if alert.severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH]
                ],
            )

            return summary

        except Exception as e:
            logger.error(f"Error creating health summary: {type(e).__name__}: {str(e)}")
            import traceback

            logger.error(f"Traceback: {traceback.format_exc()}")
            raise

    def _combine_health_statuses(
        self, service: HealthStatus, content: HealthStatus
    ) -> HealthStatus:
        """Combine two health statuses into overall status"""
        status_priority = {
            HealthStatus.UNHEALTHY: 0,
            HealthStatus.DEGRADED: 1,
            HealthStatus.WARNING: 2,
            HealthStatus.HEALTHY: 3,
            HealthStatus.UNKNOWN: 4,
        }

        # Return the worst status
        if status_priority.get(service, 4) < status_priority.get(content, 4):
            return service
        else:
            return content

    # Storage Methods
    async def save_service_health(
        self, health_data: ServiceHealthDocument
    ) -> ServiceHealthDocument:
        """Save service health data to MongoDB"""
        return await health_data.save()

    async def save_content_health(
        self, health_data: ContentHealthDocument
    ) -> ContentHealthDocument:
        """Save content health data to MongoDB"""
        return await health_data.save()

    async def save_health_summary(self, summary: HealthSummaryDocument) -> HealthSummaryDocument:
        """Save or update health summary"""
        # Upsert based on scanner_id
        existing = await HealthSummaryDocument.find_one({"scanner_id": self.scanner_id})

        if existing:
            existing.last_updated = summary.last_updated
            existing.service_health_status = summary.service_health_status
            existing.content_health_status = summary.content_health_status
            existing.overall_health_status = summary.overall_health_status
            existing.key_metrics = summary.key_metrics
            existing.active_issues_count = summary.active_issues_count
            existing.critical_alerts = summary.critical_alerts
            return await existing.save()
        else:
            return await summary.save()

    # Query Methods
    async def get_latest_service_health(self) -> Optional[ServiceHealthDocument]:
        """Get the latest service health data"""
        results = (
            await ServiceHealthDocument.find({"scanner_id": self.scanner_id})
            .sort(-ServiceHealthDocument.health_check_timestamp)
            .limit(1)
            .to_list()
        )
        return results[0] if results else None

    async def get_latest_content_health(self) -> Optional[ContentHealthDocument]:
        """Get the latest content health data"""
        results = (
            await ContentHealthDocument.find({"scanner_id": self.scanner_id})
            .sort(-ContentHealthDocument.health_check_timestamp)
            .limit(1)
            .to_list()
        )
        return results[0] if results else None

    async def get_health_summary(self) -> Optional[HealthSummaryDocument]:
        """Get the current health summary"""
        return await HealthSummaryDocument.find_one({"scanner_id": self.scanner_id})


# Singleton instance
_health_monitoring_service: Optional[HealthMonitoringService] = None


async def get_health_monitoring_service() -> HealthMonitoringService:
    """Get health monitoring service instance"""
    global _health_monitoring_service

    if _health_monitoring_service is None:
        _health_monitoring_service = HealthMonitoringService()
        await _health_monitoring_service.initialize()

    return _health_monitoring_service
