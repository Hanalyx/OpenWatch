"""
Test suite for Remediation Recommendation Engine
Tests compliance gap analysis and remediation recommendation generation
"""
import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock

from app.services.remediation_recommendation_engine import (
    RemediationRecommendationEngine, ComplianceGap, RemediationRecommendation,
    RemediationProcedure, RemediationPriority, RemediationComplexity,
    RemediationCategory
)
from app.services.remediation_system_adapter import (
    RemediationRule, RemediationSystemCapability
)
from app.models.unified_rule_models import (
    UnifiedComplianceRule, RuleExecution, ComplianceStatus, Platform,
    FrameworkMapping, PlatformImplementation
)
from app.services.multi_framework_scanner import (
    ScanResult, FrameworkResult, HostResult
)


class TestRemediationRecommendationEngine:
    """Test remediation recommendation engine functionality"""

    @pytest.fixture
    def recommendation_engine(self):
        """Create remediation recommendation engine instance"""
        return RemediationRecommendationEngine()

    @pytest.fixture
    def mock_scan_result(self):
        """Create mock scan result with non-compliant rules"""
        non_compliant_execution = RuleExecution(
            execution_id="exec_fail_001",
            rule_id="session_timeout_001",
            execution_success=False,
            compliance_status=ComplianceStatus.NON_COMPLIANT,
            execution_time=1.5,
            output_data={
                "failed_checks": ["TMOUT not configured", "No session timeout set"],
                "current_value": "",
                "expected_value": "TMOUT=900"
            },
            error_message="Session timeout not configured",
            executed_at=datetime.utcnow()
        )

        framework_result = FrameworkResult(
            framework_id="nist_800_53_r5",
            compliance_percentage=85.0,
            total_rules=1,
            compliant_rules=0,
            non_compliant_rules=1,
            error_rules=0,
            rule_executions=[non_compliant_execution]
        )

        host_result = HostResult(
            host_id="test_host_001",
            platform_info={
                "platform": "rhel_9",
                "version": "9.2",
                "architecture": "x86_64"
            },
            framework_results=[framework_result]
        )

        return ScanResult(
            scan_id="test_scan_001",
            started_at=datetime.utcnow() - timedelta(minutes=10),
            completed_at=datetime.utcnow(),
            total_execution_time=600.0,
            host_results=[host_result]
        )

    @pytest.fixture
    def mock_unified_rule(self):
        """Create mock unified compliance rule"""
        return UnifiedComplianceRule(
            rule_id="session_timeout_001",
            title="Session Timeout Configuration",
            description="Configure automatic session timeout to prevent unauthorized access",
            category="access_control",
            security_function="prevention",
            risk_level="medium",
            framework_mappings=[
                FrameworkMapping(
                    framework_id="nist_800_53_r5",
                    control_ids=["AC-11"],
                    implementation_status="non_compliant",
                    justification="Session timeout must be configured for NIST compliance"
                )
            ],
            platform_implementations=[
                PlatformImplementation(
                    platform=Platform.RHEL_9,
                    implementation_type="configuration",
                    commands=[
                        "echo 'TMOUT=900' >> /etc/profile.d/tmout.sh",
                        "chmod 644 /etc/profile.d/tmout.sh"
                    ],
                    files_modified=["/etc/profile.d/tmout.sh"],
                    services_affected=["bash"],
                    validation_commands=["grep TMOUT /etc/profile.d/tmout.sh"]
                )
            ]
        )

    @pytest.fixture
    def mock_critical_rule(self):
        """Create mock critical risk rule for testing priority calculation"""
        critical_execution = RuleExecution(
            execution_id="exec_critical_001",
            rule_id="root_access_001",
            execution_success=False,
            compliance_status=ComplianceStatus.NON_COMPLIANT,
            execution_time=0.8,
            output_data={
                "failed_checks": ["Root SSH access enabled"],
                "current_value": "PermitRootLogin yes",
                "expected_value": "PermitRootLogin no"
            },
            error_message="Root SSH access is enabled",
            executed_at=datetime.utcnow()
        )

        critical_rule = UnifiedComplianceRule(
            rule_id="root_access_001",
            title="Disable Root SSH Access",
            description="Disable direct root SSH access for security",
            category="access_control",
            security_function="prevention",
            risk_level="critical",
            framework_mappings=[
                FrameworkMapping(
                    framework_id="stig_rhel9",
                    control_ids=["RHEL-09-255030"],
                    implementation_status="non_compliant",
                    justification="STIG requires root SSH access to be disabled"
                )
            ],
            platform_implementations=[
                PlatformImplementation(
                    platform=Platform.RHEL_9,
                    implementation_type="configuration",
                    commands=[
                        "sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
                        "systemctl restart sshd"
                    ],
                    files_modified=["/etc/ssh/sshd_config"],
                    services_affected=["sshd"],
                    validation_commands=["grep '^PermitRootLogin no' /etc/ssh/sshd_config"]
                )
            ]
        )

        return critical_execution, critical_rule

    def test_compliance_gap_creation(self):
        """Test creating compliance gap objects"""
        gap = ComplianceGap(
            gap_id="GAP-TEST-001",
            rule_id="session_timeout_001",
            framework_id="nist_800_53_r5",
            control_id="AC-11",
            host_id="test_host",

            title="Session Timeout Configuration",
            description="Configure session timeout",
            current_status=ComplianceStatus.NON_COMPLIANT,
            expected_status=ComplianceStatus.COMPLIANT,

            priority=RemediationPriority.MEDIUM,
            risk_level="medium",
            business_impact="Moderate security risk",
            security_implications=["Unattended session vulnerability"],

            platform="rhel_9",
            failed_checks=["TMOUT not configured"],
            error_details="Session timeout not set"
        )

        assert gap.gap_id == "GAP-TEST-001"
        assert gap.current_status == ComplianceStatus.NON_COMPLIANT
        assert gap.expected_status == ComplianceStatus.COMPLIANT
        assert gap.priority == RemediationPriority.MEDIUM
        assert gap.platform == "rhel_9"
        assert len(gap.failed_checks) == 1
        assert gap.last_scan_time is not None

    def test_remediation_procedure_creation(self):
        """Test creating remediation procedure objects"""
        procedure = RemediationProcedure(
            procedure_id="PROC-TEST-001",
            title="Configure Session Timeout",
            description="Set TMOUT variable for session timeout",
            category=RemediationCategory.CONFIGURATION,
            complexity=RemediationComplexity.SIMPLE,

            platform="rhel_9",
            framework_id="nist_800_53_r5",
            rule_id="session_timeout_001",

            steps=[
                {
                    "step": 1,
                    "action": "create_config",
                    "command": "echo 'TMOUT=900' >> /etc/profile.d/tmout.sh",
                    "description": "Create session timeout configuration"
                }
            ],
            pre_conditions=["Administrative privileges"],
            post_validation=["grep TMOUT /etc/profile.d/tmout.sh"],

            estimated_time_minutes=5,
            requires_reboot=False,
            backup_recommended=True,
            rollback_available=True
        )

        assert procedure.procedure_id == "PROC-TEST-001"
        assert procedure.category == RemediationCategory.CONFIGURATION
        assert procedure.complexity == RemediationComplexity.SIMPLE
        assert procedure.estimated_time_minutes == 5
        assert not procedure.requires_reboot
        assert procedure.rollback_available
        assert len(procedure.steps) == 1

    def test_remediation_recommendation_creation(self):
        """Test creating complete remediation recommendation"""
        gap = ComplianceGap(
            gap_id="GAP-TEST-001",
            rule_id="session_timeout_001",
            framework_id="nist_800_53_r5",
            control_id="AC-11",
            host_id="test_host",
            title="Session Timeout Configuration",
            description="Configure session timeout",
            current_status=ComplianceStatus.NON_COMPLIANT,
            expected_status=ComplianceStatus.COMPLIANT,
            priority=RemediationPriority.MEDIUM,
            risk_level="medium",
            business_impact="Moderate security risk",
            security_implications=["Unattended session vulnerability"],
            platform="rhel_9"
        )

        procedure = RemediationProcedure(
            procedure_id="PROC-TEST-001",
            title="Configure Session Timeout",
            description="Set TMOUT variable",
            category=RemediationCategory.CONFIGURATION,
            complexity=RemediationComplexity.SIMPLE,
            platform="rhel_9",
            framework_id="nist_800_53_r5",
            rule_id="session_timeout_001",
            steps=[{"step": 1, "command": "echo 'TMOUT=900' >> /etc/profile.d/tmout.sh"}]
        )

        recommendation = RemediationRecommendation(
            recommendation_id="REC-TEST-001",
            compliance_gap=gap,
            primary_procedure=procedure,
            root_cause_analysis="Session timeout not configured in system",
            business_justification="Required for NIST compliance",
            compliance_benefit="Meets AC-11 session lock requirement",
            recommended_approach="Configure TMOUT variable in profile.d",
            confidence_score=0.9
        )

        assert recommendation.recommendation_id == "REC-TEST-001"
        assert recommendation.compliance_gap.gap_id == "GAP-TEST-001"
        assert recommendation.primary_procedure.procedure_id == "PROC-TEST-001"
        assert recommendation.confidence_score == 0.9
        assert recommendation.created_at is not None

    @pytest.mark.asyncio
    async def test_analyze_compliance_gaps(self, recommendation_engine, mock_scan_result, mock_unified_rule):
        """Test analyzing compliance gaps from scan results"""
        unified_rules = {"session_timeout_001": mock_unified_rule}

        compliance_gaps = await recommendation_engine.analyze_compliance_gaps(
            mock_scan_result, unified_rules
        )

        assert len(compliance_gaps) == 1
        gap = compliance_gaps[0]

        assert gap.rule_id == "session_timeout_001"
        assert gap.framework_id == "nist_800_53_r5"
        assert gap.control_id == "AC-11"
        assert gap.host_id == "test_host_001"
        assert gap.current_status == ComplianceStatus.NON_COMPLIANT
        assert gap.expected_status == ComplianceStatus.COMPLIANT
        assert gap.platform == "rhel_9"
        assert len(gap.failed_checks) == 2
        assert gap.error_details == "Session timeout not configured"

    @pytest.mark.asyncio
    async def test_priority_calculation(self, recommendation_engine, mock_critical_rule):
        """Test priority calculation for different risk levels"""
        critical_execution, critical_rule = mock_critical_rule

        # Test critical priority calculation
        priority = recommendation_engine._calculate_remediation_priority(
            critical_rule.risk_level,
            critical_execution.compliance_status,
            critical_rule.security_function
        )

        assert priority == RemediationPriority.CRITICAL

        # Test medium priority calculation
        medium_priority = recommendation_engine._calculate_remediation_priority(
            "medium",
            ComplianceStatus.NON_COMPLIANT,
            "prevention"
        )

        assert medium_priority == RemediationPriority.MEDIUM

        # Test low priority calculation
        low_priority = recommendation_engine._calculate_remediation_priority(
            "low",
            ComplianceStatus.PARTIAL,
            "detection"
        )

        assert low_priority == RemediationPriority.LOW

    @pytest.mark.asyncio
    async def test_generate_remediation_recommendations(self, recommendation_engine, mock_scan_result, mock_unified_rule):
        """Test generating remediation recommendations"""
        unified_rules = {"session_timeout_001": mock_unified_rule}

        # First analyze gaps
        compliance_gaps = await recommendation_engine.analyze_compliance_gaps(
            mock_scan_result, unified_rules
        )

        # Then generate recommendations
        recommendations = await recommendation_engine.generate_remediation_recommendations(
            compliance_gaps, unified_rules
        )

        assert len(recommendations) == 1
        recommendation = recommendations[0]

        assert recommendation.compliance_gap.rule_id == "session_timeout_001"
        assert recommendation.primary_procedure is not None
        assert recommendation.primary_procedure.category == RemediationCategory.CONFIGURATION
        assert recommendation.primary_procedure.platform == "rhel_9"
        assert len(recommendation.primary_procedure.steps) == 2  # Two commands from mock
        assert recommendation.confidence_score > 0.0
        assert recommendation.root_cause_analysis != ""
        assert recommendation.business_justification != ""

    @pytest.mark.asyncio
    async def test_create_remediation_procedure(self, recommendation_engine, mock_unified_rule):
        """Test creating detailed remediation procedures"""
        gap = ComplianceGap(
            gap_id="GAP-TEST-001",
            rule_id="session_timeout_001",
            framework_id="nist_800_53_r5",
            control_id="AC-11",
            host_id="test_host",
            title="Session Timeout Configuration",
            description="Configure session timeout",
            current_status=ComplianceStatus.NON_COMPLIANT,
            expected_status=ComplianceStatus.COMPLIANT,
            priority=RemediationPriority.MEDIUM,
            risk_level="medium",
            business_impact="Moderate security risk",
            security_implications=["Unattended session vulnerability"],
            platform="rhel_9"
        )

        procedure = await recommendation_engine._create_remediation_procedure(
            gap, mock_unified_rule
        )

        assert procedure is not None
        assert procedure.platform == "rhel_9"
        assert procedure.framework_id == "nist_800_53_r5"
        assert procedure.rule_id == "session_timeout_001"
        assert procedure.category == RemediationCategory.CONFIGURATION
        assert len(procedure.steps) == 2  # Two commands from mock unified rule
        assert procedure.estimated_time_minutes > 0
        assert procedure.backup_recommended
        assert procedure.rollback_available

        # Check steps content
        assert any("TMOUT=900" in step.get("command", "") for step in procedure.steps)
        assert any("chmod 644" in step.get("command", "") for step in procedure.steps)

        # Check validation
        assert len(procedure.post_validation) == 1
        assert "grep TMOUT" in procedure.post_validation[0]

    @pytest.mark.asyncio
    async def test_complexity_determination(self, recommendation_engine):
        """Test complexity determination for different scenarios"""
        # Test trivial complexity (single command, no services)
        trivial_steps = [{"step": 1, "command": "echo test"}]
        trivial_impl = Mock()
        trivial_impl.services_affected = []

        complexity = recommendation_engine._determine_complexity(
            trivial_steps, "low", trivial_impl
        )
        assert complexity == RemediationComplexity.TRIVIAL

        # Test simple complexity (few steps, medium risk)
        simple_steps = [
            {"step": 1, "command": "echo test1"},
            {"step": 2, "command": "echo test2"}
        ]
        simple_impl = Mock()
        simple_impl.services_affected = []

        complexity = recommendation_engine._determine_complexity(
            simple_steps, "medium", simple_impl
        )
        assert complexity == RemediationComplexity.SIMPLE

        # Test complex complexity (critical risk)
        complex_steps = [{"step": 1, "command": "echo test"}]
        complex_impl = Mock()
        complex_impl.services_affected = ["critical_service"]

        complexity = recommendation_engine._determine_complexity(
            complex_steps, "critical", complex_impl
        )
        assert complexity == RemediationComplexity.COMPLEX

    @pytest.mark.asyncio
    async def test_map_to_orsa_format(self, recommendation_engine, mock_scan_result, mock_unified_rule):
        """Test mapping recommendations to ORSA format"""
        unified_rules = {"session_timeout_001": mock_unified_rule}

        # Generate recommendations
        compliance_gaps = await recommendation_engine.analyze_compliance_gaps(
            mock_scan_result, unified_rules
        )
        recommendations = await recommendation_engine.generate_remediation_recommendations(
            compliance_gaps, unified_rules
        )

        # Map to ORSA format
        orsa_mappings = await recommendation_engine.map_to_orsa_format(recommendations)

        assert "rhel_9" in orsa_mappings
        rhel_rules = orsa_mappings["rhel_9"]
        assert len(rhel_rules) >= 1

        orsa_rule = rhel_rules[0]
        assert orsa_rule.semantic_name.startswith("ow-")
        assert orsa_rule.title == recommendations[0].primary_procedure.title
        assert orsa_rule.category == "configuration"
        assert "nist_800_53_r5" in orsa_rule.framework_mappings
        assert "rhel_9" in orsa_rule.implementations
        assert orsa_rule.reversible == recommendations[0].primary_procedure.rollback_available

    @pytest.mark.asyncio
    async def test_convert_procedure_to_orsa_rule(self, recommendation_engine):
        """Test converting remediation procedure to ORSA rule"""
        gap = ComplianceGap(
            gap_id="GAP-TEST-001",
            rule_id="session_timeout_001",
            framework_id="nist_800_53_r5",
            control_id="AC-11",
            host_id="test_host",
            title="Session Timeout Configuration",
            description="Configure session timeout",
            current_status=ComplianceStatus.NON_COMPLIANT,
            expected_status=ComplianceStatus.COMPLIANT,
            priority=RemediationPriority.MEDIUM,
            risk_level="medium",
            business_impact="Moderate security risk",
            security_implications=["Unattended session vulnerability"],
            platform="rhel_9"
        )

        procedure = RemediationProcedure(
            procedure_id="PROC-TEST-001",
            title="Configure Session Timeout",
            description="Set TMOUT variable",
            category=RemediationCategory.CONFIGURATION,
            complexity=RemediationComplexity.SIMPLE,
            platform="rhel_9",
            framework_id="nist_800_53_r5",
            rule_id="session_timeout_001",
            steps=[{"step": 1, "command": "echo 'TMOUT=900' >> /etc/profile.d/tmout.sh"}],
            estimated_time_minutes=5,
            requires_reboot=False,
            rollback_available=True
        )

        orsa_rule = await recommendation_engine._convert_procedure_to_orsa_rule(
            procedure, gap
        )

        assert orsa_rule is not None
        assert orsa_rule.semantic_name == "ow-session-timeout-001"
        assert orsa_rule.title == "Configure Session Timeout"
        assert orsa_rule.description == "Set TMOUT variable"
        assert orsa_rule.category == "configuration"
        assert orsa_rule.severity == "medium"
        assert orsa_rule.reversible
        assert not orsa_rule.requires_reboot

        # Check framework mappings
        assert "nist_800_53_r5" in orsa_rule.framework_mappings
        assert "rhel_9" in orsa_rule.framework_mappings["nist_800_53_r5"]
        assert orsa_rule.framework_mappings["nist_800_53_r5"]["rhel_9"] == "AC-11"

        # Check implementations
        assert "rhel_9" in orsa_rule.implementations
        rhel_impl = orsa_rule.implementations["rhel_9"]
        assert rhel_impl["category"] == "configuration"
        assert rhel_impl["complexity"] == "simple"
        assert rhel_impl["estimated_time"] == 5
        assert not rhel_impl["requires_reboot"]
        assert rhel_impl["rollback_available"]

    @pytest.mark.asyncio
    async def test_create_remediation_job_template(self, recommendation_engine):
        """Test creating ORSA-compatible remediation job template"""
        gap = ComplianceGap(
            gap_id="GAP-TEST-001",
            rule_id="session_timeout_001",
            framework_id="nist_800_53_r5",
            control_id="AC-11",
            host_id="test_host",
            title="Session Timeout Configuration",
            description="Configure session timeout",
            current_status=ComplianceStatus.NON_COMPLIANT,
            expected_status=ComplianceStatus.COMPLIANT,
            priority=RemediationPriority.MEDIUM,
            risk_level="medium",
            business_impact="Moderate security risk",
            security_implications=["Unattended session vulnerability"],
            platform="rhel_9"
        )

        procedure = RemediationProcedure(
            procedure_id="PROC-TEST-001",
            title="Configure Session Timeout",
            description="Set TMOUT variable",
            category=RemediationCategory.CONFIGURATION,
            complexity=RemediationComplexity.SIMPLE,
            platform="rhel_9",
            framework_id="nist_800_53_r5",
            rule_id="session_timeout_001",
            steps=[{"step": 1, "command": "echo 'TMOUT=900' >> /etc/profile.d/tmout.sh"}],
            estimated_time_minutes=5,
            requires_reboot=False,
            rollback_available=True
        )

        recommendation = RemediationRecommendation(
            recommendation_id="REC-TEST-001",
            compliance_gap=gap,
            primary_procedure=procedure
        )

        job_template = await recommendation_engine.create_remediation_job_template(
            recommendation, "target_host_123"
        )

        assert job_template.target_host_id == "target_host_123"
        assert job_template.platform == "rhel_9"
        assert job_template.rules == ["session_timeout_001"]
        assert job_template.framework == "nist_800_53_r5"
        assert job_template.dry_run  # Default to dry run
        assert job_template.timeout == 300  # 5 minutes * 60 seconds
        assert not job_template.parallel_execution  # Conservative approach

        # Check OpenWatch context
        context = job_template.openwatch_context
        assert context["compliance_gap_id"] == "GAP-TEST-001"
        assert context["recommendation_id"] == "REC-TEST-001"
        assert context["framework_id"] == "nist_800_53_r5"
        assert context["control_id"] == "AC-11"
        assert context["priority"] == "medium"
        assert context["complexity"] == "simple"
        assert not context["requires_reboot"]
        assert context["backup_recommended"]

    @pytest.mark.asyncio
    async def test_framework_specific_procedures(self, recommendation_engine):
        """Test getting framework-specific procedures"""
        # Test with framework that exists in mappings
        procedures = await recommendation_engine.get_framework_specific_procedures(
            "nist_800_53_r5", "AC-11", "rhel_9"
        )

        # Should return empty list for now (placeholder implementation)
        assert isinstance(procedures, list)

        # Test cache behavior
        cached_procedures = await recommendation_engine.get_framework_specific_procedures(
            "nist_800_53_r5", "AC-11", "rhel_9"
        )

        assert isinstance(cached_procedures, list)

    def test_business_impact_assessment(self, recommendation_engine, mock_unified_rule):
        """Test business impact assessment"""
        mock_execution = Mock()

        impact = recommendation_engine._assess_business_impact(
            mock_unified_rule, mock_execution
        )

        assert "Moderate business risk" in impact
        assert "compliance" in impact.lower()

    def test_security_implications_assessment(self, recommendation_engine, mock_unified_rule):
        """Test security implications assessment"""
        mock_execution = Mock()

        implications = recommendation_engine._assess_security_implications(
            mock_unified_rule, mock_execution
        )

        assert isinstance(implications, list)
        assert len(implications) > 0
        assert any("Preventive security controls" in impl for impl in implications)
        assert any("vulnerability" in impl.lower() for impl in implications)

    def test_regulatory_requirements(self, recommendation_engine):
        """Test getting regulatory requirements"""
        nist_reqs = recommendation_engine._get_regulatory_requirements("nist_800_53_r5")
        assert "NIST SP 800-53 Rev 5" in nist_reqs
        assert "FISMA" in nist_reqs

        cis_reqs = recommendation_engine._get_regulatory_requirements("cis_v8")
        assert "CIS Critical Security Controls Version 8" in cis_reqs

        unknown_reqs = recommendation_engine._get_regulatory_requirements("unknown_framework")
        assert unknown_reqs == []

    def test_compliance_deadline_calculation(self, recommendation_engine):
        """Test compliance deadline calculation"""
        # Test critical priority
        critical_deadline = recommendation_engine._calculate_compliance_deadline(
            RemediationPriority.CRITICAL, "critical"
        )
        assert critical_deadline is not None
        assert (critical_deadline - datetime.utcnow()).days <= 3

        # Test high priority
        high_deadline = recommendation_engine._calculate_compliance_deadline(
            RemediationPriority.HIGH, "medium"
        )
        assert high_deadline is not None
        assert (high_deadline - datetime.utcnow()).days <= 30

        # Test low priority
        low_deadline = recommendation_engine._calculate_compliance_deadline(
            RemediationPriority.LOW, "low"
        )
        assert low_deadline is not None
        assert (low_deadline - datetime.utcnow()).days <= 90

    def test_confidence_score_calculation(self, recommendation_engine):
        """Test confidence score calculation"""
        gap = ComplianceGap(
            gap_id="GAP-TEST-001",
            rule_id="test_rule",
            framework_id="test_framework",
            control_id="TEST-001",
            host_id="test_host",
            title="Test Gap",
            description="Test description",
            current_status=ComplianceStatus.NON_COMPLIANT,
            expected_status=ComplianceStatus.COMPLIANT,
            priority=RemediationPriority.HIGH,
            risk_level="high",
            business_impact="Test impact",
            security_implications=["Test implication"],
            platform="rhel_9"
        )

        procedure = RemediationProcedure(
            procedure_id="PROC-TEST-001",
            title="Test Procedure",
            description="Test description",
            category=RemediationCategory.CONFIGURATION,
            complexity=RemediationComplexity.SIMPLE,
            platform="rhel_9",
            framework_id="test_framework",
            rule_id="test_rule",
            rollback_available=True
        )

        score = recommendation_engine._calculate_confidence_score(gap, procedure)

        assert 0.0 <= score <= 1.0
        assert score > 0.5  # Should be above base score due to simple complexity, high priority, and rollback availability

    def test_cache_functionality(self, recommendation_engine):
        """Test recommendation cache functionality"""
        # Test cache clearing
        recommendation_engine.recommendation_cache["test_key"] = "test_value"
        assert len(recommendation_engine.recommendation_cache) == 1

        recommendation_engine.clear_cache()
        assert len(recommendation_engine.recommendation_cache) == 0

    def test_initialization(self, recommendation_engine):
        """Test engine initialization"""
        # Test procedure library initialization
        assert "session_timeout" in recommendation_engine.procedure_library
        session_procs = recommendation_engine.procedure_library["session_timeout"]
        assert "rhel" in session_procs

        rhel_proc = session_procs["rhel"]
        assert rhel_proc.category == RemediationCategory.CONFIGURATION
        assert rhel_proc.complexity == RemediationComplexity.SIMPLE
        assert rhel_proc.platform == "rhel"

        # Test framework mappings initialization
        assert "nist_800_53_r5" in recommendation_engine.framework_mappings
        nist_mapping = recommendation_engine.framework_mappings["nist_800_53_r5"]
        assert "citations" in nist_mapping
        assert "deadline_days" in nist_mapping
        assert "NIST SP 800-53 Rev 5" in nist_mapping["citations"]


class TestRemediationScenarios:
    """Test real-world remediation scenarios"""

    @pytest.mark.asyncio
    async def test_critical_security_gap_scenario(self):
        """Test critical security gap remediation scenario"""
        engine = RemediationRecommendationEngine()

        # Create critical SSH root access gap
        critical_execution = RuleExecution(
            execution_id="critical_exec",
            rule_id="disable_root_ssh",
            execution_success=False,
            compliance_status=ComplianceStatus.NON_COMPLIANT,
            execution_time=0.5,
            output_data={
                "failed_checks": ["Root SSH access enabled"],
                "current_config": "PermitRootLogin yes",
                "expected_config": "PermitRootLogin no"
            },
            error_message="Root SSH access is enabled - critical security risk",
            executed_at=datetime.utcnow()
        )

        critical_rule = UnifiedComplianceRule(
            rule_id="disable_root_ssh",
            title="Disable Root SSH Access",
            description="Disable direct root SSH access for security",
            category="access_control",
            security_function="prevention",
            risk_level="critical",
            framework_mappings=[
                FrameworkMapping(
                    framework_id="stig_rhel9",
                    control_ids=["RHEL-09-255030"],
                    implementation_status="non_compliant",
                    justification="STIG requires root SSH access to be disabled"
                )
            ],
            platform_implementations=[
                PlatformImplementation(
                    platform=Platform.RHEL_9,
                    implementation_type="configuration",
                    commands=[
                        "sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
                        "systemctl restart sshd"
                    ],
                    files_modified=["/etc/ssh/sshd_config"],
                    services_affected=["sshd"],
                    validation_commands=["grep '^PermitRootLogin no' /etc/ssh/sshd_config"]
                )
            ]
        )

        # Create scan result
        framework_result = FrameworkResult(
            framework_id="stig_rhel9",
            compliance_percentage=75.0,
            total_rules=1,
            compliant_rules=0,
            non_compliant_rules=1,
            error_rules=0,
            rule_executions=[critical_execution]
        )

        host_result = HostResult(
            host_id="critical_host",
            platform_info={"platform": "rhel_9", "version": "9.2"},
            framework_results=[framework_result]
        )

        scan_result = ScanResult(
            scan_id="critical_scan",
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            total_execution_time=300.0,
            host_results=[host_result]
        )

        unified_rules = {"disable_root_ssh": critical_rule}

        # Analyze gaps
        gaps = await engine.analyze_compliance_gaps(scan_result, unified_rules)

        assert len(gaps) == 1
        gap = gaps[0]
        assert gap.priority == RemediationPriority.CRITICAL
        assert gap.risk_level == "critical"
        assert "critical security risk" in gap.error_details

        # Generate recommendations
        recommendations = await engine.generate_remediation_recommendations(
            gaps, unified_rules
        )

        assert len(recommendations) == 1
        recommendation = recommendations[0]

        # Should be high priority with complex handling due to service restart
        assert recommendation.compliance_gap.priority == RemediationPriority.CRITICAL
        assert recommendation.primary_procedure.complexity in [
            RemediationComplexity.MODERATE, RemediationComplexity.COMPLEX
        ]
        assert recommendation.primary_procedure.requires_reboot == False  # SSH restart, not system reboot
        assert len(recommendation.primary_procedure.steps) == 2
        assert recommendation.confidence_score > 0.5

        # Check procedure details
        procedure = recommendation.primary_procedure
        assert "sshd_config" in str(procedure.steps)
        assert "systemctl restart sshd" in str(procedure.steps)
        assert "/etc/ssh/sshd_config" in procedure.files_modified
        assert "sshd" in procedure.services_affected

    @pytest.mark.asyncio
    async def test_multi_host_gap_analysis(self):
        """Test compliance gap analysis across multiple hosts"""
        engine = RemediationRecommendationEngine()

        # Create multiple host results with different compliance statuses
        rule_execution_1 = RuleExecution(
            execution_id="exec_host1",
            rule_id="session_timeout_001",
            execution_success=False,
            compliance_status=ComplianceStatus.NON_COMPLIANT,
            execution_time=1.0,
            error_message="TMOUT not configured",
            executed_at=datetime.utcnow()
        )

        rule_execution_2 = RuleExecution(
            execution_id="exec_host2",
            rule_id="session_timeout_001",
            execution_success=True,
            compliance_status=ComplianceStatus.PARTIAL,
            execution_time=1.0,
            output_data={"tmout_value": "1800"},  # Wrong timeout value
            error_message="TMOUT configured but exceeds recommended value",
            executed_at=datetime.utcnow()
        )

        framework_result_1 = FrameworkResult(
            framework_id="nist_800_53_r5",
            compliance_percentage=80.0,
            total_rules=1,
            compliant_rules=0,
            non_compliant_rules=1,
            error_rules=0,
            rule_executions=[rule_execution_1]
        )

        framework_result_2 = FrameworkResult(
            framework_id="nist_800_53_r5",
            compliance_percentage=90.0,
            total_rules=1,
            compliant_rules=0,
            non_compliant_rules=0,
            error_rules=1,
            rule_executions=[rule_execution_2]
        )

        host_result_1 = HostResult(
            host_id="web_server_01",
            platform_info={"platform": "rhel_9", "version": "9.2"},
            framework_results=[framework_result_1]
        )

        host_result_2 = HostResult(
            host_id="web_server_02",
            platform_info={"platform": "rhel_9", "version": "9.3"},
            framework_results=[framework_result_2]
        )

        scan_result = ScanResult(
            scan_id="multi_host_scan",
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            total_execution_time=600.0,
            host_results=[host_result_1, host_result_2]
        )

        # Create unified rule
        unified_rule = UnifiedComplianceRule(
            rule_id="session_timeout_001",
            title="Session Timeout Configuration",
            description="Configure session timeout",
            category="access_control",
            security_function="prevention",
            risk_level="medium",
            framework_mappings=[
                FrameworkMapping(
                    framework_id="nist_800_53_r5",
                    control_ids=["AC-11"],
                    implementation_status="non_compliant"
                )
            ],
            platform_implementations=[
                PlatformImplementation(
                    platform=Platform.RHEL_9,
                    implementation_type="configuration",
                    commands=["echo 'TMOUT=900' >> /etc/profile.d/tmout.sh"],
                    files_modified=["/etc/profile.d/tmout.sh"],
                    validation_commands=["grep TMOUT /etc/profile.d/tmout.sh"]
                )
            ]
        )

        unified_rules = {"session_timeout_001": unified_rule}

        # Analyze gaps
        gaps = await engine.analyze_compliance_gaps(scan_result, unified_rules)

        # Should find gaps for both hosts
        assert len(gaps) == 2

        # First gap (non-compliant)
        gap1 = next(g for g in gaps if g.host_id == "web_server_01")
        assert gap1.current_status == ComplianceStatus.NON_COMPLIANT
        assert gap1.priority == RemediationPriority.MEDIUM

        # Second gap (partial)
        gap2 = next(g for g in gaps if g.host_id == "web_server_02")
        assert gap2.current_status == ComplianceStatus.PARTIAL
        assert gap2.priority == RemediationPriority.LOW  # Partial compliance = lower priority

        # Generate recommendations
        recommendations = await engine.generate_remediation_recommendations(
            gaps, unified_rules
        )

        assert len(recommendations) == 2

        # Both should have same remediation procedure but different host targets
        rec1 = next(r for r in recommendations if r.compliance_gap.host_id == "web_server_01")
        rec2 = next(r for r in recommendations if r.compliance_gap.host_id == "web_server_02")

        assert rec1.primary_procedure.title == rec2.primary_procedure.title
        assert rec1.compliance_gap.host_id != rec2.compliance_gap.host_id


if __name__ == "__main__":
    pytest.main([__file__])
