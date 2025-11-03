"""
Result Aggregation Service
Aggregates and analyzes compliance scan results across multiple frameworks and hosts
"""

import asyncio
import statistics
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.app.models.unified_rule_models import (
    ComplianceStatus,
    Platform,
    RuleExecution,
)
from backend.app.services.multi_framework_scanner import (
    FrameworkResult,
    HostResult,
    ScanResult,
)


class AggregationLevel(str, Enum):
    """Levels of result aggregation"""

    RULE_LEVEL = "rule_level"
    FRAMEWORK_LEVEL = "framework_level"
    HOST_LEVEL = "host_level"
    ORGANIZATION_LEVEL = "organization_level"
    TIME_SERIES = "time_series"


class TrendDirection(str, Enum):
    """Trend direction indicators"""

    IMPROVING = "improving"
    DECLINING = "declining"
    STABLE = "stable"
    UNKNOWN = "unknown"


@dataclass
class ComplianceMetrics:
    """Comprehensive compliance metrics"""

    total_rules: int
    executed_rules: int
    compliant_rules: int
    non_compliant_rules: int
    error_rules: int
    exceeds_rules: int
    partial_rules: int
    not_applicable_rules: int
    compliance_percentage: float
    exceeds_percentage: float
    error_percentage: float
    execution_success_rate: float

    def __post_init__(self):
        # Calculate derived metrics
        if self.executed_rules > 0:
            self.compliance_percentage = ((self.compliant_rules + self.exceeds_rules) / self.executed_rules) * 100
            self.exceeds_percentage = (self.exceeds_rules / self.executed_rules) * 100
            self.error_percentage = (self.error_rules / self.executed_rules) * 100
            self.execution_success_rate = ((self.executed_rules - self.error_rules) / self.executed_rules) * 100
        else:
            self.compliance_percentage = 0.0
            self.exceeds_percentage = 0.0
            self.error_percentage = 0.0
            self.execution_success_rate = 0.0


@dataclass
class TrendAnalysis:
    """Trend analysis for compliance metrics"""

    metric_name: str
    current_value: float
    previous_value: Optional[float]
    trend_direction: TrendDirection
    change_percentage: Optional[float]
    time_period: str
    data_points: List[Tuple[datetime, float]]

    def __post_init__(self):
        # Calculate trend direction and change percentage
        if self.previous_value is not None and self.previous_value != 0:
            self.change_percentage = ((self.current_value - self.previous_value) / self.previous_value) * 100

            if self.change_percentage > 2:  # Significant improvement
                self.trend_direction = TrendDirection.IMPROVING
            elif self.change_percentage < -2:  # Significant decline
                self.trend_direction = TrendDirection.DECLINING
            else:
                self.trend_direction = TrendDirection.STABLE
        else:
            self.change_percentage = None
            self.trend_direction = TrendDirection.UNKNOWN


@dataclass
class ComplianceGap:
    """Identified compliance gap"""

    gap_id: str
    gap_type: str
    severity: str
    framework_id: str
    control_ids: List[str]
    affected_hosts: List[str]
    description: str
    impact_assessment: str
    remediation_priority: int
    estimated_effort: str
    remediation_guidance: List[str]


@dataclass
class FrameworkComparison:
    """Comparison between frameworks"""

    framework_a: str
    framework_b: str
    common_controls: int
    framework_a_unique: int
    framework_b_unique: int
    overlap_percentage: float
    compliance_correlation: float
    implementation_gaps: List[Dict[str, Any]]


@dataclass
class AggregatedResults:
    """Comprehensive aggregated results"""

    aggregation_level: AggregationLevel
    time_period: str
    generated_at: datetime

    # Core metrics
    overall_metrics: ComplianceMetrics
    framework_metrics: Dict[str, ComplianceMetrics]
    host_metrics: Dict[str, ComplianceMetrics]

    # Analysis
    trend_analysis: List[TrendAnalysis]
    compliance_gaps: List[ComplianceGap]
    framework_comparisons: List[FrameworkComparison]

    # Statistics
    platform_distribution: Dict[str, int]
    execution_statistics: Dict[str, Any]
    performance_metrics: Dict[str, float]

    # Recommendations
    priority_recommendations: List[str]
    strategic_recommendations: List[str]

    def __post_init__(self):
        if self.framework_metrics is None:
            self.framework_metrics = {}
        if self.host_metrics is None:
            self.host_metrics = {}
        if self.trend_analysis is None:
            self.trend_analysis = []
        if self.compliance_gaps is None:
            self.compliance_gaps = []
        if self.framework_comparisons is None:
            self.framework_comparisons = []
        if self.platform_distribution is None:
            self.platform_distribution = {}
        if self.execution_statistics is None:
            self.execution_statistics = {}
        if self.performance_metrics is None:
            self.performance_metrics = {}
        if self.priority_recommendations is None:
            self.priority_recommendations = []
        if self.strategic_recommendations is None:
            self.strategic_recommendations = []


class ResultAggregationService:
    """Service for aggregating and analyzing compliance scan results"""

    def __init__(self):
        """Initialize the result aggregation service"""
        self.aggregation_cache: Dict[str, AggregatedResults] = {}
        self.cache_ttl = 3600  # 1 hour cache TTL

    async def aggregate_scan_results(
        self,
        scan_results: List[ScanResult],
        aggregation_level: AggregationLevel = AggregationLevel.ORGANIZATION_LEVEL,
        time_period: str = "current",
    ) -> AggregatedResults:
        """
        Aggregate multiple scan results into comprehensive metrics

        Args:
            scan_results: List of scan results to aggregate
            aggregation_level: Level of aggregation to perform
            time_period: Time period description for the aggregation

        Returns:
            Comprehensive aggregated results
        """
        # Create cache key
        cache_key = f"{aggregation_level.value}_{time_period}_{hash(tuple(sr.scan_id for sr in scan_results))}"

        # Check cache
        if cache_key in self.aggregation_cache:
            cached_result = self.aggregation_cache[cache_key]
            cache_age = (datetime.utcnow() - cached_result.generated_at).total_seconds()
            if cache_age < self.cache_ttl:
                return cached_result

        # Perform aggregation
        aggregated_results = AggregatedResults(
            aggregation_level=aggregation_level,
            time_period=time_period,
            generated_at=datetime.utcnow(),
            overall_metrics=ComplianceMetrics(0, 0, 0, 0, 0, 0, 0, 0, 0.0, 0.0, 0.0, 0.0),
            framework_metrics={},
            host_metrics={},
            trend_analysis=[],
            compliance_gaps=[],
            framework_comparisons=[],
            platform_distribution={},
            execution_statistics={},
            performance_metrics={},
            priority_recommendations=[],
            strategic_recommendations=[],
        )

        # Aggregate based on level
        if aggregation_level == AggregationLevel.ORGANIZATION_LEVEL:
            await self._aggregate_organization_level(scan_results, aggregated_results)
        elif aggregation_level == AggregationLevel.FRAMEWORK_LEVEL:
            await self._aggregate_framework_level(scan_results, aggregated_results)
        elif aggregation_level == AggregationLevel.HOST_LEVEL:
            await self._aggregate_host_level(scan_results, aggregated_results)
        elif aggregation_level == AggregationLevel.TIME_SERIES:
            await self._aggregate_time_series(scan_results, aggregated_results)

        # Perform analysis
        await self._analyze_compliance_gaps(scan_results, aggregated_results)
        await self._analyze_framework_comparisons(scan_results, aggregated_results)
        await self._generate_recommendations(aggregated_results)

        # Cache results
        self.aggregation_cache[cache_key] = aggregated_results

        return aggregated_results

    async def _aggregate_organization_level(
        self, scan_results: List[ScanResult], aggregated_results: AggregatedResults
    ):
        """Aggregate results at organization level"""
        # Collect all rule executions
        all_executions = []
        framework_executions = defaultdict(list)
        host_executions = defaultdict(list)
        platform_counts = defaultdict(int)

        for scan_result in scan_results:
            for host_result in scan_result.host_results:
                # Platform distribution
                platform = host_result.platform_info.get("platform", "unknown")
                platform_counts[platform] += 1

                # Collect executions by framework and host
                for framework_result in host_result.framework_results:
                    framework_id = framework_result.framework_id

                    for execution in framework_result.rule_executions:
                        all_executions.append(execution)
                        framework_executions[framework_id].append(execution)
                        host_executions[host_result.host_id].append(execution)

        # Calculate overall metrics
        aggregated_results.overall_metrics = self._calculate_metrics_from_executions(all_executions)

        # Calculate framework metrics
        for framework_id, executions in framework_executions.items():
            aggregated_results.framework_metrics[framework_id] = self._calculate_metrics_from_executions(executions)

        # Calculate host metrics
        for host_id, executions in host_executions.items():
            aggregated_results.host_metrics[host_id] = self._calculate_metrics_from_executions(executions)

        # Store platform distribution
        aggregated_results.platform_distribution = dict(platform_counts)

        # Calculate execution statistics
        aggregated_results.execution_statistics = {
            "total_scans": len(scan_results),
            "total_hosts": sum(len(sr.host_results) for sr in scan_results),
            "total_frameworks": len(framework_executions),
            "total_executions": len(all_executions),
            "average_execution_time": (
                statistics.mean([e.execution_time for e in all_executions]) if all_executions else 0.0
            ),
            "median_execution_time": (
                statistics.median([e.execution_time for e in all_executions]) if all_executions else 0.0
            ),
        }

        # Calculate performance metrics
        if all_executions:
            aggregated_results.performance_metrics = {
                "rules_per_second": (
                    len(all_executions) / sum(sr.total_execution_time for sr in scan_results)
                    if sum(sr.total_execution_time for sr in scan_results) > 0
                    else 0.0
                ),
                "average_scan_duration": statistics.mean([sr.total_execution_time for sr in scan_results]),
                "success_rate": len([e for e in all_executions if e.execution_success]) / len(all_executions) * 100,
                "compliance_rate": len(
                    [
                        e
                        for e in all_executions
                        if e.compliance_status in [ComplianceStatus.COMPLIANT, ComplianceStatus.EXCEEDS]
                    ]
                )
                / len(all_executions)
                * 100,
            }

    async def _aggregate_framework_level(self, scan_results: List[ScanResult], aggregated_results: AggregatedResults):
        """Aggregate results at framework level"""
        framework_data = defaultdict(list)

        # Group executions by framework
        for scan_result in scan_results:
            for host_result in scan_result.host_results:
                for framework_result in host_result.framework_results:
                    framework_id = framework_result.framework_id
                    framework_data[framework_id].extend(framework_result.rule_executions)

        # Calculate metrics for each framework
        for framework_id, executions in framework_data.items():
            aggregated_results.framework_metrics[framework_id] = self._calculate_metrics_from_executions(executions)

        # Calculate overall metrics as average of frameworks
        if aggregated_results.framework_metrics:
            framework_metrics = list(aggregated_results.framework_metrics.values())
            aggregated_results.overall_metrics = ComplianceMetrics(
                total_rules=sum(fm.total_rules for fm in framework_metrics),
                executed_rules=sum(fm.executed_rules for fm in framework_metrics),
                compliant_rules=sum(fm.compliant_rules for fm in framework_metrics),
                non_compliant_rules=sum(fm.non_compliant_rules for fm in framework_metrics),
                error_rules=sum(fm.error_rules for fm in framework_metrics),
                exceeds_rules=sum(fm.exceeds_rules for fm in framework_metrics),
                partial_rules=sum(fm.partial_rules for fm in framework_metrics),
                not_applicable_rules=sum(fm.not_applicable_rules for fm in framework_metrics),
                compliance_percentage=0.0,  # Will be calculated in __post_init__
                exceeds_percentage=0.0,
                error_percentage=0.0,
                execution_success_rate=0.0,
            )

    async def _aggregate_host_level(self, scan_results: List[ScanResult], aggregated_results: AggregatedResults):
        """Aggregate results at host level"""
        host_data = defaultdict(list)

        # Group executions by host
        for scan_result in scan_results:
            for host_result in scan_result.host_results:
                host_id = host_result.host_id
                for framework_result in host_result.framework_results:
                    host_data[host_id].extend(framework_result.rule_executions)

        # Calculate metrics for each host
        for host_id, executions in host_data.items():
            aggregated_results.host_metrics[host_id] = self._calculate_metrics_from_executions(executions)

        # Calculate overall metrics as average of hosts
        if aggregated_results.host_metrics:
            host_metrics = list(aggregated_results.host_metrics.values())
            aggregated_results.overall_metrics = ComplianceMetrics(
                total_rules=sum(hm.total_rules for hm in host_metrics),
                executed_rules=sum(hm.executed_rules for hm in host_metrics),
                compliant_rules=sum(hm.compliant_rules for hm in host_metrics),
                non_compliant_rules=sum(hm.non_compliant_rules for hm in host_metrics),
                error_rules=sum(hm.error_rules for hm in host_metrics),
                exceeds_rules=sum(hm.exceeds_rules for hm in host_metrics),
                partial_rules=sum(hm.partial_rules for hm in host_metrics),
                not_applicable_rules=sum(hm.not_applicable_rules for hm in host_metrics),
                compliance_percentage=0.0,  # Will be calculated in __post_init__
                exceeds_percentage=0.0,
                error_percentage=0.0,
                execution_success_rate=0.0,
            )

    async def _aggregate_time_series(self, scan_results: List[ScanResult], aggregated_results: AggregatedResults):
        """Aggregate results for time series analysis"""
        # Sort scan results by time
        sorted_scans = sorted(scan_results, key=lambda sr: sr.started_at)

        # Create time series data points
        time_series_data = []
        for scan_result in sorted_scans:
            # Calculate overall compliance for this scan
            all_executions = []
            for host_result in scan_result.host_results:
                for framework_result in host_result.framework_results:
                    all_executions.extend(framework_result.rule_executions)

            metrics = self._calculate_metrics_from_executions(all_executions)
            time_series_data.append((scan_result.started_at, metrics.compliance_percentage))

        # Generate trend analysis
        if len(time_series_data) >= 2:
            current_value = time_series_data[-1][1]
            previous_value = time_series_data[-2][1] if len(time_series_data) >= 2 else None

            trend = TrendAnalysis(
                metric_name="Overall Compliance",
                current_value=current_value,
                previous_value=previous_value,
                trend_direction=TrendDirection.UNKNOWN,  # Will be calculated in __post_init__
                change_percentage=None,
                time_period=aggregated_results.time_period,
                data_points=time_series_data,
            )
            aggregated_results.trend_analysis.append(trend)

    def _calculate_metrics_from_executions(self, executions: List[RuleExecution]) -> ComplianceMetrics:
        """Calculate compliance metrics from rule executions"""
        if not executions:
            return ComplianceMetrics(0, 0, 0, 0, 0, 0, 0, 0, 0.0, 0.0, 0.0, 0.0)

        total_rules = len(executions)
        executed_rules = sum(1 for e in executions if e.execution_success)
        compliant_rules = sum(1 for e in executions if e.compliance_status == ComplianceStatus.COMPLIANT)
        non_compliant_rules = sum(1 for e in executions if e.compliance_status == ComplianceStatus.NON_COMPLIANT)
        error_rules = sum(1 for e in executions if e.compliance_status == ComplianceStatus.ERROR)
        exceeds_rules = sum(1 for e in executions if e.compliance_status == ComplianceStatus.EXCEEDS)
        partial_rules = sum(1 for e in executions if e.compliance_status == ComplianceStatus.PARTIAL)
        not_applicable_rules = sum(1 for e in executions if e.compliance_status == ComplianceStatus.NOT_APPLICABLE)

        return ComplianceMetrics(
            total_rules=total_rules,
            executed_rules=executed_rules,
            compliant_rules=compliant_rules,
            non_compliant_rules=non_compliant_rules,
            error_rules=error_rules,
            exceeds_rules=exceeds_rules,
            partial_rules=partial_rules,
            not_applicable_rules=not_applicable_rules,
            compliance_percentage=0.0,  # Calculated in __post_init__
            exceeds_percentage=0.0,
            error_percentage=0.0,
            execution_success_rate=0.0,
        )

    async def _analyze_compliance_gaps(self, scan_results: List[ScanResult], aggregated_results: AggregatedResults):
        """Analyze compliance gaps across scan results"""
        gaps = []

        # Identify systematic failures
        failure_patterns = defaultdict(list)

        for scan_result in scan_results:
            for host_result in scan_result.host_results:
                for framework_result in host_result.framework_results:
                    for execution in framework_result.rule_executions:
                        if execution.compliance_status == ComplianceStatus.NON_COMPLIANT:
                            pattern_key = f"{framework_result.framework_id}:{execution.rule_id}"
                            failure_patterns[pattern_key].append(
                                {
                                    "host_id": host_result.host_id,
                                    "scan_id": scan_result.scan_id,
                                    "error_message": execution.error_message,
                                }
                            )

        # Convert patterns to gaps
        gap_id = 1
        for pattern_key, failures in failure_patterns.items():
            if len(failures) >= 2:  # Systematic failure (affects multiple hosts/scans)
                framework_id, rule_id = pattern_key.split(":", 1)

                # Assess severity based on failure rate
                total_hosts = sum(len(sr.host_results) for sr in scan_results)
                failure_rate = len(failures) / total_hosts

                if failure_rate >= 0.75:
                    severity = "critical"
                    priority = 1
                elif failure_rate >= 0.5:
                    severity = "high"
                    priority = 2
                elif failure_rate >= 0.25:
                    severity = "medium"
                    priority = 3
                else:
                    severity = "low"
                    priority = 4

                gap = ComplianceGap(
                    gap_id=f"GAP-{gap_id:03d}",
                    gap_type="systematic_failure",
                    severity=severity,
                    framework_id=framework_id,
                    control_ids=[rule_id],
                    affected_hosts=list(set(f["host_id"] for f in failures)),
                    description=f"Rule {rule_id} fails systematically across {len(failures)} hosts ({failure_rate:.1%} failure rate)",
                    impact_assessment=f"Affects {len(failures)} hosts in {framework_id} compliance",
                    remediation_priority=priority,
                    estimated_effort="Medium" if failure_rate >= 0.5 else "Low",
                    remediation_guidance=[
                        "Review baseline configuration across affected hosts",
                        "Implement automated remediation for common failure pattern",
                        "Update configuration management to prevent recurrence",
                    ],
                )
                gaps.append(gap)
                gap_id += 1

        aggregated_results.compliance_gaps = gaps

    async def _analyze_framework_comparisons(
        self, scan_results: List[ScanResult], aggregated_results: AggregatedResults
    ):
        """Analyze comparisons between frameworks"""
        comparisons = []

        # Get all frameworks
        all_frameworks = set()
        for scan_result in scan_results:
            for host_result in scan_result.host_results:
                for framework_result in host_result.framework_results:
                    all_frameworks.add(framework_result.framework_id)

        frameworks = list(all_frameworks)

        # Compare frameworks pairwise
        for i, framework_a in enumerate(frameworks):
            for j, framework_b in enumerate(frameworks[i + 1 :], i + 1):
                comparison = await self._compare_frameworks(framework_a, framework_b, scan_results)
                if comparison:
                    comparisons.append(comparison)

        aggregated_results.framework_comparisons = comparisons

    async def _compare_frameworks(
        self, framework_a: str, framework_b: str, scan_results: List[ScanResult]
    ) -> Optional[FrameworkComparison]:
        """Compare two frameworks based on scan results"""
        # Collect rules for each framework
        rules_a = set()
        rules_b = set()
        compliance_a = []
        compliance_b = []

        for scan_result in scan_results:
            for host_result in scan_result.host_results:
                for framework_result in host_result.framework_results:
                    if framework_result.framework_id == framework_a:
                        rules_a.update(e.rule_id for e in framework_result.rule_executions)
                        compliance_a.append(framework_result.compliance_percentage)
                    elif framework_result.framework_id == framework_b:
                        rules_b.update(e.rule_id for e in framework_result.rule_executions)
                        compliance_b.append(framework_result.compliance_percentage)

        if not rules_a or not rules_b:
            return None

        # Calculate overlap
        common_rules = rules_a.intersection(rules_b)
        overlap_percentage = len(common_rules) / len(rules_a.union(rules_b)) * 100

        # Calculate compliance correlation
        if compliance_a and compliance_b:
            min_length = min(len(compliance_a), len(compliance_b))
            correlation = (
                statistics.correlation(compliance_a[:min_length], compliance_b[:min_length]) if min_length > 1 else 0.0
            )
        else:
            correlation = 0.0

        return FrameworkComparison(
            framework_a=framework_a,
            framework_b=framework_b,
            common_controls=len(common_rules),
            framework_a_unique=len(rules_a - rules_b),
            framework_b_unique=len(rules_b - rules_a),
            overlap_percentage=overlap_percentage,
            compliance_correlation=correlation,
            implementation_gaps=[],  # Could be expanded to identify specific gaps
        )

    async def _generate_recommendations(self, aggregated_results: AggregatedResults):
        """Generate recommendations based on aggregated results"""
        priority_recommendations = []
        strategic_recommendations = []

        # Priority recommendations based on compliance gaps
        critical_gaps = [gap for gap in aggregated_results.compliance_gaps if gap.severity == "critical"]
        high_gaps = [gap for gap in aggregated_results.compliance_gaps if gap.severity == "high"]

        if critical_gaps:
            priority_recommendations.append(
                f"CRITICAL: Address {len(critical_gaps)} systematic failures affecting multiple hosts immediately"
            )

        if high_gaps:
            priority_recommendations.append(
                f"HIGH: Remediate {len(high_gaps)} high-impact compliance gaps within 30 days"
            )

        # Framework-specific recommendations
        for framework_id, metrics in aggregated_results.framework_metrics.items():
            if metrics.compliance_percentage < 70:
                priority_recommendations.append(
                    f"URGENT: {framework_id} compliance at {metrics.compliance_percentage:.1f}% - below acceptable threshold"
                )
            elif metrics.compliance_percentage >= 95:
                strategic_recommendations.append(
                    f"EXCELLENCE: {framework_id} compliance at {metrics.compliance_percentage:.1f}% - consider advanced security measures"
                )

        # Exceeding compliance opportunities
        total_exceeds = sum(metrics.exceeds_rules for metrics in aggregated_results.framework_metrics.values())
        if total_exceeds > 0:
            strategic_recommendations.append(
                f"OPPORTUNITY: {total_exceeds} rules exceed baseline requirements - leverage for enhanced compliance reporting"
            )

        # Performance recommendations
        if aggregated_results.performance_metrics.get("success_rate", 100) < 95:
            priority_recommendations.append(
                f"RELIABILITY: Execution success rate at {aggregated_results.performance_metrics.get('success_rate', 0):.1f}% - investigate infrastructure issues"
            )

        # Platform diversity recommendations
        if len(aggregated_results.platform_distribution) > 1:
            strategic_recommendations.append(
                f"STANDARDIZATION: Multiple platforms detected - consider standardization for consistent compliance"
            )

        aggregated_results.priority_recommendations = priority_recommendations
        aggregated_results.strategic_recommendations = strategic_recommendations

    async def generate_compliance_dashboard_data(self, scan_results: List[ScanResult]) -> Dict[str, Any]:
        """Generate data for compliance dashboard visualization"""
        # Aggregate at organization level
        org_results = await self.aggregate_scan_results(scan_results, AggregationLevel.ORGANIZATION_LEVEL)

        # Framework-level aggregation
        framework_results = await self.aggregate_scan_results(scan_results, AggregationLevel.FRAMEWORK_LEVEL)

        # Dashboard data
        dashboard_data = {
            "overview": {
                "overall_compliance": org_results.overall_metrics.compliance_percentage,
                "total_hosts": org_results.execution_statistics.get("total_hosts", 0),
                "total_frameworks": org_results.execution_statistics.get("total_frameworks", 0),
                "total_rules": org_results.overall_metrics.total_rules,
                "exceeds_percentage": org_results.overall_metrics.exceeds_percentage,
            },
            "framework_breakdown": {
                framework_id: {
                    "compliance_percentage": metrics.compliance_percentage,
                    "total_rules": metrics.total_rules,
                    "compliant_rules": metrics.compliant_rules,
                    "exceeds_rules": metrics.exceeds_rules,
                    "non_compliant_rules": metrics.non_compliant_rules,
                }
                for framework_id, metrics in framework_results.framework_metrics.items()
            },
            "platform_distribution": org_results.platform_distribution,
            "top_gaps": [
                {
                    "gap_id": gap.gap_id,
                    "description": gap.description,
                    "severity": gap.severity,
                    "affected_hosts": len(gap.affected_hosts),
                }
                for gap in sorted(org_results.compliance_gaps, key=lambda g: g.remediation_priority)[:5]
            ],
            "recommendations": {
                "priority": org_results.priority_recommendations[:3],
                "strategic": org_results.strategic_recommendations[:3],
            },
            "performance_metrics": org_results.performance_metrics,
            "generated_at": org_results.generated_at.isoformat(),
        }

        return dashboard_data

    async def export_aggregated_results(self, aggregated_results: AggregatedResults, format: str = "json") -> str:
        """Export aggregated results in specified format"""
        if format == "json":
            import json

            # Convert to serializable dictionary
            export_data = {
                "aggregation_level": aggregated_results.aggregation_level.value,
                "time_period": aggregated_results.time_period,
                "generated_at": aggregated_results.generated_at.isoformat(),
                "overall_metrics": {
                    "compliance_percentage": aggregated_results.overall_metrics.compliance_percentage,
                    "total_rules": aggregated_results.overall_metrics.total_rules,
                    "compliant_rules": aggregated_results.overall_metrics.compliant_rules,
                    "exceeds_rules": aggregated_results.overall_metrics.exceeds_rules,
                    "non_compliant_rules": aggregated_results.overall_metrics.non_compliant_rules,
                    "error_rules": aggregated_results.overall_metrics.error_rules,
                },
                "framework_metrics": {
                    framework_id: {
                        "compliance_percentage": metrics.compliance_percentage,
                        "total_rules": metrics.total_rules,
                        "compliant_rules": metrics.compliant_rules,
                        "exceeds_rules": metrics.exceeds_rules,
                        "non_compliant_rules": metrics.non_compliant_rules,
                    }
                    for framework_id, metrics in aggregated_results.framework_metrics.items()
                },
                "compliance_gaps": [
                    {
                        "gap_id": gap.gap_id,
                        "severity": gap.severity,
                        "framework_id": gap.framework_id,
                        "description": gap.description,
                        "affected_hosts": gap.affected_hosts,
                        "remediation_priority": gap.remediation_priority,
                    }
                    for gap in aggregated_results.compliance_gaps
                ],
                "recommendations": {
                    "priority": aggregated_results.priority_recommendations,
                    "strategic": aggregated_results.strategic_recommendations,
                },
                "platform_distribution": aggregated_results.platform_distribution,
                "execution_statistics": aggregated_results.execution_statistics,
                "performance_metrics": aggregated_results.performance_metrics,
            }

            return json.dumps(export_data, indent=2)

        elif format == "csv":
            # Generate CSV summary
            lines = ["Framework,Compliance_Percentage,Total_Rules,Compliant_Rules,Non_Compliant_Rules,Exceeds_Rules"]

            for framework_id, metrics in aggregated_results.framework_metrics.items():
                lines.append(
                    f"{framework_id},{metrics.compliance_percentage:.2f},{metrics.total_rules},"
                    f"{metrics.compliant_rules},{metrics.non_compliant_rules},{metrics.exceeds_rules}"
                )

            return "\n".join(lines)

        else:
            raise ValueError(f"Unsupported export format: {format}")

    def clear_cache(self):
        """Clear the aggregation cache"""
        self.aggregation_cache.clear()
