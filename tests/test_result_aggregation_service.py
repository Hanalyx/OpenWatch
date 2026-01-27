"""
Test suite for Result Aggregation Service
Tests aggregation, analysis, and reporting capabilities
"""
import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock
from app.services.result_aggregation_service import (
    ResultAggregationService, AggregationLevel, TrendDirection,
    ComplianceMetrics, TrendAnalysis, ComplianceGap, FrameworkComparison,
    AggregatedResults
)
from app.services.multi_framework_scanner import (
    ScanResult, FrameworkResult, HostResult
)
from app.models.unified_rule_models import (
    RuleExecution, ComplianceStatus, Platform
)


class TestResultAggregationService:
    """Test result aggregation service functionality"""

    @pytest.fixture
    def aggregation_service(self):
        """Create result aggregation service instance"""
        return ResultAggregationService()

    @pytest.fixture
    def mock_rule_execution(self):
        """Create mock rule execution"""
        return RuleExecution(
            execution_id="exec_001",
            rule_id="test_rule_001",
            execution_success=True,
            compliance_status=ComplianceStatus.COMPLIANT,
            execution_time=1.5,
            output_data={"result": "passed"},
            error_message=None,
            executed_at=datetime.utcnow()
        )

    @pytest.fixture
    def mock_framework_result(self, mock_rule_execution):
        """Create mock framework result"""
        return FrameworkResult(
            framework_id="nist_800_53_r5",
            compliance_percentage=85.0,
            total_rules=10,
            compliant_rules=8,
            non_compliant_rules=1,
            error_rules=1,
            rule_executions=[mock_rule_execution]
        )

    @pytest.fixture
    def mock_host_result(self, mock_framework_result):
        """Create mock host result"""
        return HostResult(
            host_id="host_001",
            platform_info={
                "platform": "rhel_9",
                "version": "9.2",
                "architecture": "x86_64"
            },
            framework_results=[mock_framework_result]
        )

    @pytest.fixture
    def mock_scan_result(self, mock_host_result):
        """Create mock scan result"""
        return ScanResult(
            scan_id="scan_001",
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow() + timedelta(minutes=5),
            total_execution_time=300.0,
            host_results=[mock_host_result]
        )

    def test_compliance_metrics_creation(self):
        """Test creating compliance metrics objects"""
        metrics = ComplianceMetrics(
            total_rules=100,
            executed_rules=95,
            compliant_rules=80,
            non_compliant_rules=10,
            error_rules=5,
            exceeds_rules=15,
            partial_rules=2,
            not_applicable_rules=3,
            compliance_percentage=0.0,  # Calculated in __post_init__
            exceeds_percentage=0.0,
            error_percentage=0.0,
            execution_success_rate=0.0
        )

        # Test calculated percentages
        assert metrics.compliance_percentage == ((80 + 15) / 95) * 100  # ~100%
        assert metrics.exceeds_percentage == (15 / 95) * 100  # ~15.8%
        assert metrics.error_percentage == (5 / 95) * 100  # ~5.3%
        assert metrics.execution_success_rate == ((95 - 5) / 95) * 100  # ~94.7%

    def test_trend_analysis_creation(self):
        """Test creating trend analysis objects"""
        trend = TrendAnalysis(
            metric_name="Overall Compliance",
            current_value=85.0,
            previous_value=80.0,
            trend_direction=TrendDirection.UNKNOWN,  # Calculated in __post_init__
            change_percentage=None,
            time_period="7 days",
            data_points=[(datetime.utcnow(), 85.0)]
        )

        # Test calculated trend
        assert trend.trend_direction == TrendDirection.IMPROVING
        assert trend.change_percentage == 6.25  # (85-80)/80 * 100

    def test_compliance_gap_creation(self):
        """Test creating compliance gap objects"""
        gap = ComplianceGap(
            gap_id="GAP-001",
            gap_type="systematic_failure",
            severity="high",
            framework_id="nist_800_53_r5",
            control_ids=["AC-11", "AC-12"],
            affected_hosts=["host_001", "host_002"],
            description="Session timeout not configured correctly",
            impact_assessment="Affects 2 hosts in NIST compliance",
            remediation_priority=2,
            estimated_effort="Medium",
            remediation_guidance=[
                "Configure session timeout to 15 minutes",
                "Update PAM configuration",
                "Test timeout functionality"
            ]
        )

        assert gap.gap_id == "GAP-001"
        assert gap.severity == "high"
        assert len(gap.affected_hosts) == 2
        assert len(gap.remediation_guidance) == 3

    def test_framework_comparison_creation(self):
        """Test creating framework comparison objects"""
        comparison = FrameworkComparison(
            framework_a="nist_800_53_r5",
            framework_b="cis_v8",
            common_controls=25,
            framework_a_unique=30,
            framework_b_unique=15,
            overlap_percentage=71.4,  # 25/(25+30+15) * 100
            compliance_correlation=0.85,
            implementation_gaps=[]
        )

        assert comparison.framework_a == "nist_800_53_r5"
        assert comparison.framework_b == "cis_v8"
        assert comparison.common_controls == 25
        assert comparison.overlap_percentage == 71.4
        assert comparison.compliance_correlation == 0.85

    @pytest.mark.asyncio
    async def test_organization_level_aggregation(self, aggregation_service, mock_scan_result):
        """Test organization-level aggregation"""
        scan_results = [mock_scan_result]

        aggregated = await aggregation_service.aggregate_scan_results(
            scan_results, AggregationLevel.ORGANIZATION_LEVEL
        )

        assert aggregated.aggregation_level == AggregationLevel.ORGANIZATION_LEVEL
        assert aggregated.overall_metrics.total_rules > 0
        assert "nist_800_53_r5" in aggregated.framework_metrics
        assert "host_001" in aggregated.host_metrics
        assert aggregated.platform_distribution["rhel_9"] == 1
        assert aggregated.execution_statistics["total_scans"] == 1
        assert aggregated.execution_statistics["total_hosts"] == 1

    @pytest.mark.asyncio
    async def test_framework_level_aggregation(self, aggregation_service, mock_scan_result):
        """Test framework-level aggregation"""
        scan_results = [mock_scan_result]

        aggregated = await aggregation_service.aggregate_scan_results(
            scan_results, AggregationLevel.FRAMEWORK_LEVEL
        )

        assert aggregated.aggregation_level == AggregationLevel.FRAMEWORK_LEVEL
        assert "nist_800_53_r5" in aggregated.framework_metrics
        assert aggregated.framework_metrics["nist_800_53_r5"].total_rules > 0
        assert aggregated.overall_metrics.total_rules > 0

    @pytest.mark.asyncio
    async def test_host_level_aggregation(self, aggregation_service, mock_scan_result):
        """Test host-level aggregation"""
        scan_results = [mock_scan_result]

        aggregated = await aggregation_service.aggregate_scan_results(
            scan_results, AggregationLevel.HOST_LEVEL
        )

        assert aggregated.aggregation_level == AggregationLevel.HOST_LEVEL
        assert "host_001" in aggregated.host_metrics
        assert aggregated.host_metrics["host_001"].total_rules > 0
        assert aggregated.overall_metrics.total_rules > 0

    @pytest.mark.asyncio
    async def test_time_series_aggregation(self, aggregation_service):
        """Test time series aggregation"""
        # Create multiple scan results with different timestamps
        scan_results = []
        for i in range(3):
            mock_execution = RuleExecution(
                execution_id=f"exec_{i:03d}",
                rule_id=f"test_rule_{i:03d}",
                execution_success=True,
                compliance_status=ComplianceStatus.COMPLIANT,
                execution_time=1.0,
                output_data={"result": "passed"},
                executed_at=datetime.utcnow()
            )

            mock_framework = FrameworkResult(
                framework_id="nist_800_53_r5",
                compliance_percentage=80.0 + i * 5,  # Improving trend
                total_rules=10,
                compliant_rules=8 + i,
                non_compliant_rules=2 - i,
                error_rules=0,
                rule_executions=[mock_execution]
            )

            mock_host = HostResult(
                host_id="host_001",
                platform_info={"platform": "rhel_9"},
                framework_results=[mock_framework]
            )

            scan_result = ScanResult(
                scan_id=f"scan_{i:03d}",
                started_at=datetime.utcnow() - timedelta(days=i),
                completed_at=datetime.utcnow() - timedelta(days=i) + timedelta(hours=1),
                total_execution_time=3600.0,
                host_results=[mock_host]
            )
            scan_results.append(scan_result)

        aggregated = await aggregation_service.aggregate_scan_results(
            scan_results, AggregationLevel.TIME_SERIES
        )

        assert aggregated.aggregation_level == AggregationLevel.TIME_SERIES
        assert len(aggregated.trend_analysis) > 0

        # Check trend analysis
        trend = aggregated.trend_analysis[0]
        assert trend.metric_name == "Overall Compliance"
        assert trend.trend_direction == TrendDirection.IMPROVING
        assert len(trend.data_points) == 3

    @pytest.mark.asyncio
    async def test_compliance_gap_analysis(self, aggregation_service):
        """Test compliance gap analysis"""
        # Create scan results with systematic failures
        scan_results = []
        for i in range(3):
            # Create failing executions for same rule across multiple hosts
            mock_execution = RuleExecution(
                execution_id=f"exec_{i:03d}",
                rule_id="failing_rule_001",
                execution_success=True,
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                execution_time=1.0,
                output_data={"result": "failed"},
                error_message="Configuration not compliant",
                executed_at=datetime.utcnow()
            )

            mock_framework = FrameworkResult(
                framework_id="nist_800_53_r5",
                compliance_percentage=60.0,
                total_rules=10,
                compliant_rules=6,
                non_compliant_rules=4,
                error_rules=0,
                rule_executions=[mock_execution]
            )

            mock_host = HostResult(
                host_id=f"host_{i:03d}",
                platform_info={"platform": "rhel_9"},
                framework_results=[mock_framework]
            )

            scan_result = ScanResult(
                scan_id=f"scan_{i:03d}",
                started_at=datetime.utcnow(),
                completed_at=datetime.utcnow() + timedelta(hours=1),
                total_execution_time=3600.0,
                host_results=[mock_host]
            )
            scan_results.append(scan_result)

        aggregated = await aggregation_service.aggregate_scan_results(
            scan_results, AggregationLevel.ORGANIZATION_LEVEL
        )

        # Should identify systematic failure
        assert len(aggregated.compliance_gaps) > 0
        gap = aggregated.compliance_gaps[0]
        assert gap.gap_type == "systematic_failure"
        assert "failing_rule_001" in gap.control_ids
        assert len(gap.affected_hosts) == 3
        assert gap.severity in ["critical", "high", "medium", "low"]

    @pytest.mark.asyncio
    async def test_framework_comparison_analysis(self, aggregation_service):
        """Test framework comparison analysis"""
        # Create scan results with multiple frameworks
        mock_execution_1 = RuleExecution(
            execution_id="exec_001",
            rule_id="shared_rule_001",
            execution_success=True,
            compliance_status=ComplianceStatus.COMPLIANT,
            execution_time=1.0,
            executed_at=datetime.utcnow()
        )

        mock_execution_2 = RuleExecution(
            execution_id="exec_002",
            rule_id="shared_rule_001",
            execution_success=True,
            compliance_status=ComplianceStatus.COMPLIANT,
            execution_time=1.0,
            executed_at=datetime.utcnow()
        )

        mock_framework_1 = FrameworkResult(
            framework_id="nist_800_53_r5",
            compliance_percentage=85.0,
            total_rules=10,
            compliant_rules=8,
            non_compliant_rules=2,
            error_rules=0,
            rule_executions=[mock_execution_1]
        )

        mock_framework_2 = FrameworkResult(
            framework_id="cis_v8",
            compliance_percentage=90.0,
            total_rules=8,
            compliant_rules=7,
            non_compliant_rules=1,
            error_rules=0,
            rule_executions=[mock_execution_2]
        )

        mock_host = HostResult(
            host_id="host_001",
            platform_info={"platform": "rhel_9"},
            framework_results=[mock_framework_1, mock_framework_2]
        )

        scan_result = ScanResult(
            scan_id="scan_001",
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow() + timedelta(hours=1),
            total_execution_time=3600.0,
            host_results=[mock_host]
        )

        aggregated = await aggregation_service.aggregate_scan_results(
            [scan_result], AggregationLevel.ORGANIZATION_LEVEL
        )

        # Should have framework comparison
        assert len(aggregated.framework_comparisons) > 0
        comparison = aggregated.framework_comparisons[0]
        assert comparison.framework_a in ["nist_800_53_r5", "cis_v8"]
        assert comparison.framework_b in ["nist_800_53_r5", "cis_v8"]
        assert comparison.framework_a != comparison.framework_b
        assert comparison.common_controls >= 0

    @pytest.mark.asyncio
    async def test_recommendations_generation(self, aggregation_service):
        """Test recommendations generation"""
        # Create scan results with poor compliance
        mock_execution = RuleExecution(
            execution_id="exec_001",
            rule_id="failing_rule_001",
            execution_success=True,
            compliance_status=ComplianceStatus.NON_COMPLIANT,
            execution_time=1.0,
            executed_at=datetime.utcnow()
        )

        mock_framework = FrameworkResult(
            framework_id="nist_800_53_r5",
            compliance_percentage=60.0,  # Below 70% threshold
            total_rules=10,
            compliant_rules=6,
            non_compliant_rules=4,
            error_rules=0,
            rule_executions=[mock_execution]
        )

        mock_host = HostResult(
            host_id="host_001",
            platform_info={"platform": "rhel_9"},
            framework_results=[mock_framework]
        )

        scan_result = ScanResult(
            scan_id="scan_001",
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow() + timedelta(hours=1),
            total_execution_time=3600.0,
            host_results=[mock_host]
        )

        aggregated = await aggregation_service.aggregate_scan_results(
            [scan_result], AggregationLevel.ORGANIZATION_LEVEL
        )

        # Should generate priority recommendations
        assert len(aggregated.priority_recommendations) > 0
        urgent_rec = next((r for r in aggregated.priority_recommendations if "URGENT" in r), None)
        assert urgent_rec is not None
        assert "nist_800_53_r5" in urgent_rec
        assert "60.0%" in urgent_rec

    @pytest.mark.asyncio
    async def test_dashboard_data_generation(self, aggregation_service, mock_scan_result):
        """Test dashboard data generation"""
        scan_results = [mock_scan_result]

        dashboard_data = await aggregation_service.generate_compliance_dashboard_data(scan_results)

        assert "overview" in dashboard_data
        assert "framework_breakdown" in dashboard_data
        assert "platform_distribution" in dashboard_data
        assert "top_gaps" in dashboard_data
        assert "recommendations" in dashboard_data
        assert "performance_metrics" in dashboard_data
        assert "generated_at" in dashboard_data

        # Check overview data
        overview = dashboard_data["overview"]
        assert "overall_compliance" in overview
        assert "total_hosts" in overview
        assert "total_frameworks" in overview
        assert "total_rules" in overview

        # Check framework breakdown
        framework_breakdown = dashboard_data["framework_breakdown"]
        assert "nist_800_53_r5" in framework_breakdown
        assert "compliance_percentage" in framework_breakdown["nist_800_53_r5"]

        # Check recommendations
        recommendations = dashboard_data["recommendations"]
        assert "priority" in recommendations
        assert "strategic" in recommendations

    @pytest.mark.asyncio
    async def test_export_json_format(self, aggregation_service, mock_scan_result):
        """Test exporting aggregated results in JSON format"""
        scan_results = [mock_scan_result]

        aggregated = await aggregation_service.aggregate_scan_results(
            scan_results, AggregationLevel.ORGANIZATION_LEVEL
        )

        json_output = await aggregation_service.export_aggregated_results(aggregated, 'json')

        # Should be valid JSON
        import json
        parsed = json.loads(json_output)

        assert parsed["aggregation_level"] == "organization_level"
        assert "overall_metrics" in parsed
        assert "framework_metrics" in parsed
        assert "compliance_gaps" in parsed
        assert "recommendations" in parsed
        assert "platform_distribution" in parsed

    @pytest.mark.asyncio
    async def test_export_csv_format(self, aggregation_service, mock_scan_result):
        """Test exporting aggregated results in CSV format"""
        scan_results = [mock_scan_result]

        aggregated = await aggregation_service.aggregate_scan_results(
            scan_results, AggregationLevel.ORGANIZATION_LEVEL
        )

        csv_output = await aggregation_service.export_aggregated_results(aggregated, 'csv')

        # Should be valid CSV
        lines = csv_output.strip().split('\n')
        assert len(lines) >= 2  # Header + at least one data row
        assert "Framework,Compliance_Percentage,Total_Rules" in lines[0]
        assert "nist_800_53_r5" in csv_output

    @pytest.mark.asyncio
    async def test_unsupported_export_format(self, aggregation_service, mock_scan_result):
        """Test unsupported export format"""
        scan_results = [mock_scan_result]

        aggregated = await aggregation_service.aggregate_scan_results(
            scan_results, AggregationLevel.ORGANIZATION_LEVEL
        )

        with pytest.raises(ValueError, match="Unsupported export format"):
            await aggregation_service.export_aggregated_results(aggregated, 'xml')

    def test_cache_functionality(self, aggregation_service):
        """Test aggregation cache functionality"""
        # Test cache clearing
        aggregation_service.aggregation_cache["test_key"] = "test_value"
        assert len(aggregation_service.aggregation_cache) == 1

        aggregation_service.clear_cache()
        assert len(aggregation_service.aggregation_cache) == 0

    @pytest.mark.asyncio
    async def test_caching_behavior(self, aggregation_service, mock_scan_result):
        """Test caching behavior during aggregation"""
        scan_results = [mock_scan_result]

        # First call should cache the result
        result1 = await aggregation_service.aggregate_scan_results(
            scan_results, AggregationLevel.ORGANIZATION_LEVEL
        )

        # Second call should return cached result
        result2 = await aggregation_service.aggregate_scan_results(
            scan_results, AggregationLevel.ORGANIZATION_LEVEL
        )

        # Results should be identical (cached)
        assert result1.generated_at == result2.generated_at
        assert len(aggregation_service.aggregation_cache) >= 1

    def test_metrics_calculation_edge_cases(self, aggregation_service):
        """Test edge cases in metrics calculation"""
        # Test with empty executions
        metrics = aggregation_service._calculate_metrics_from_executions([])
        assert metrics.total_rules == 0
        assert metrics.executed_rules == 0
        assert metrics.compliance_percentage == 0.0

        # Test with failed executions
        failed_execution = RuleExecution(
            execution_id="exec_fail",
            rule_id="test_rule_fail",
            execution_success=False,
            compliance_status=ComplianceStatus.ERROR,
            execution_time=0.0,
            error_message="Execution failed",
            executed_at=datetime.utcnow()
        )

        metrics = aggregation_service._calculate_metrics_from_executions([failed_execution])
        assert metrics.total_rules == 1
        assert metrics.executed_rules == 0
        assert metrics.error_rules == 1
        assert metrics.execution_success_rate == 0.0


class TestComplianceScenarios:
    """Test real-world compliance scenarios"""

    @pytest.mark.asyncio
    async def test_exceeding_compliance_scenario(self):
        """Test scenario where implementation exceeds requirements"""
        aggregation_service = ResultAggregationService()

        # Create execution that exceeds requirements (like FIPS > SHA1 prohibition)
        exceeding_execution = RuleExecution(
            execution_id="exec_exceeds",
            rule_id="crypto_policy_001",
            execution_success=True,
            compliance_status=ComplianceStatus.EXCEEDS,
            execution_time=1.0,
            output_data={"enhancement": "FIPS crypto exceeds CIS SHA1 prohibition"},
            executed_at=datetime.utcnow()
        )

        framework_result = FrameworkResult(
            framework_id="cis_v8",
            compliance_percentage=100.0,
            total_rules=1,
            compliant_rules=0,
            non_compliant_rules=0,
            error_rules=0,
            exceeds_rules=1,  # Rule exceeds baseline
            rule_executions=[exceeding_execution]
        )

        host_result = HostResult(
            host_id="fips_host_001",
            platform_info={"platform": "rhel_9"},
            framework_results=[framework_result]
        )

        scan_result = ScanResult(
            scan_id="fips_scan_001",
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow() + timedelta(hours=1),
            total_execution_time=3600.0,
            host_results=[host_result]
        )

        aggregated = await aggregation_service.aggregate_scan_results(
            [scan_result], AggregationLevel.ORGANIZATION_LEVEL
        )

        # Should recognize exceeding compliance
        assert aggregated.overall_metrics.exceeds_rules == 1
        assert aggregated.overall_metrics.exceeds_percentage > 0

        # Should generate strategic recommendation for exceeding compliance
        exceeding_rec = next((r for r in aggregated.strategic_recommendations if "OPPORTUNITY" in r), None)
        assert exceeding_rec is not None
        assert "exceed baseline requirements" in exceeding_rec

    @pytest.mark.asyncio
    async def test_multi_framework_unified_compliance(self):
        """Test unified compliance across multiple frameworks"""
        aggregation_service = ResultAggregationService()

        # Create executions for same logical control across multiple frameworks
        shared_rule_id = "session_timeout_001"

        frameworks = [
            ("nist_800_53_r5", 90.0),
            ("cis_v8", 95.0),
            ("iso_27001_2022", 85.0),
            ("pci_dss_v4", 88.0)
        ]

        framework_results = []
        for framework_id, compliance_pct in frameworks:
            execution = RuleExecution(
                execution_id=f"exec_{framework_id}_{shared_rule_id}",
                rule_id=shared_rule_id,
                execution_success=True,
                compliance_status=ComplianceStatus.COMPLIANT,
                execution_time=1.0,
                executed_at=datetime.utcnow()
            )

            framework_result = FrameworkResult(
                framework_id=framework_id,
                compliance_percentage=compliance_pct,
                total_rules=1,
                compliant_rules=1,
                non_compliant_rules=0,
                error_rules=0,
                rule_executions=[execution]
            )
            framework_results.append(framework_result)

        host_result = HostResult(
            host_id="unified_host_001",
            platform_info={"platform": "rhel_9"},
            framework_results=framework_results
        )

        scan_result = ScanResult(
            scan_id="unified_scan_001",
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow() + timedelta(hours=1),
            total_execution_time=3600.0,
            host_results=[host_result]
        )

        aggregated = await aggregation_service.aggregate_scan_results(
            [scan_result], AggregationLevel.ORGANIZATION_LEVEL
        )

        # Should have all frameworks represented
        assert len(aggregated.framework_metrics) == 4
        for framework_id, _ in frameworks:
            assert framework_id in aggregated.framework_metrics
            assert aggregated.framework_metrics[framework_id].compliance_percentage > 80

        # Should generate framework comparisons
        assert len(aggregated.framework_comparisons) > 0

        # Should identify common control implementation
        for comparison in aggregated.framework_comparisons:
            assert comparison.common_controls >= 1
            assert comparison.overlap_percentage > 0

    @pytest.mark.asyncio
    async def test_compliance_trend_analysis(self):
        """Test compliance trend analysis over time"""
        aggregation_service = ResultAggregationService()

        # Create scan results showing improvement over time
        scan_results = []
        compliance_values = [70.0, 75.0, 80.0, 85.0, 90.0]  # Improving trend

        for i, compliance_pct in enumerate(compliance_values):
            execution = RuleExecution(
                execution_id=f"exec_{i:03d}",
                rule_id="trend_rule_001",
                execution_success=True,
                compliance_status=ComplianceStatus.COMPLIANT,
                execution_time=1.0,
                executed_at=datetime.utcnow()
            )

            framework_result = FrameworkResult(
                framework_id="nist_800_53_r5",
                compliance_percentage=compliance_pct,
                total_rules=10,
                compliant_rules=int(compliance_pct / 10),
                non_compliant_rules=10 - int(compliance_pct / 10),
                error_rules=0,
                rule_executions=[execution]
            )

            host_result = HostResult(
                host_id="trend_host_001",
                platform_info={"platform": "rhel_9"},
                framework_results=[framework_result]
            )

            scan_result = ScanResult(
                scan_id=f"trend_scan_{i:03d}",
                started_at=datetime.utcnow() - timedelta(days=(4-i)),  # Historical order
                completed_at=datetime.utcnow() - timedelta(days=(4-i)) + timedelta(hours=1),
                total_execution_time=3600.0,
                host_results=[host_result]
            )
            scan_results.append(scan_result)

        aggregated = await aggregation_service.aggregate_scan_results(
            scan_results, AggregationLevel.TIME_SERIES
        )

        # Should detect improving trend
        assert len(aggregated.trend_analysis) > 0
        trend = aggregated.trend_analysis[0]
        assert trend.trend_direction == TrendDirection.IMPROVING
        assert trend.change_percentage > 0
        assert len(trend.data_points) == 5


if __name__ == "__main__":
    pytest.main([__file__])
