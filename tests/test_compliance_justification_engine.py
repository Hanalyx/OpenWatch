"""
Test suite for Compliance Justification Engine
Tests compliance justification generation and audit documentation capabilities
"""
import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock

from backend.app.services.compliance_justification_engine import (
    ComplianceJustificationEngine, ComplianceJustification, JustificationEvidence,
    ExceedingComplianceAnalysis, JustificationType, AuditEvidence
)
from backend.app.models.unified_rule_models import (
    UnifiedComplianceRule, RuleExecution, ComplianceStatus, Platform,
    FrameworkMapping, PlatformImplementation
)
from backend.app.services.multi_framework_scanner import ScanResult, FrameworkResult, HostResult


class TestComplianceJustificationEngine:
    """Test compliance justification engine functionality"""

    @pytest.fixture
    def justification_engine(self):
        """Create compliance justification engine instance"""
        return ComplianceJustificationEngine()

    @pytest.fixture
    def mock_rule_execution(self):
        """Create mock rule execution"""
        return RuleExecution(
            execution_id="exec_001",
            rule_id="session_timeout_001",
            execution_success=True,
            compliance_status=ComplianceStatus.COMPLIANT,
            execution_time=1.2,
            output_data={
                "timeout_value": "900",
                "configuration_file": "/etc/profile.d/tmout.sh",
                "verification_result": "TMOUT=900"
            },
            error_message=None,
            executed_at=datetime.utcnow()
        )

    @pytest.fixture
    def mock_exceeding_execution(self):
        """Create mock rule execution that exceeds requirements"""
        return RuleExecution(
            execution_id="exec_exceeds",
            rule_id="fips_crypto_001",
            execution_success=True,
            compliance_status=ComplianceStatus.EXCEEDS,
            execution_time=0.8,
            output_data={
                "fips_enabled": "1",
                "mode": "FIPS 140-2 Level 1",
                "disabled_algorithms": ["MD5", "SHA1", "DES"],
                "verification_command": "cat /proc/sys/crypto/fips_enabled"
            },
            error_message=None,
            executed_at=datetime.utcnow()
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
                    implementation_status="compliant",
                    justification="Implements NIST session lock requirement with 15-minute timeout"
                ),
                FrameworkMapping(
                    framework_id="cis_v8",
                    control_ids=["5.2"],
                    implementation_status="exceeds",
                    enhancement_details="15-minute timeout exceeds CIS 30-minute baseline",
                    justification="Enhanced session management exceeding CIS requirements"
                )
            ],
            platform_implementations=[
                PlatformImplementation(
                    platform=Platform.RHEL_9,
                    implementation_type="configuration",
                    commands=["echo 'TMOUT=900' >> /etc/profile.d/tmout.sh"],
                    files_modified=["/etc/profile.d/tmout.sh"],
                    services_affected=["bash"],
                    validation_commands=["grep TMOUT /etc/profile.d/tmout.sh"]
                )
            ]
        )

    @pytest.fixture
    def mock_fips_rule(self):
        """Create mock FIPS cryptography rule"""
        return UnifiedComplianceRule(
            rule_id="fips_crypto_001",
            title="FIPS Cryptography Mode",
            description="Enable FIPS mode for cryptographic operations",
            category="cryptography",
            security_function="protection",
            risk_level="high",
            framework_mappings=[
                FrameworkMapping(
                    framework_id="stig_rhel9",
                    control_ids=["RHEL-09-672010"],
                    implementation_status="compliant",
                    justification="STIG requires FIPS mode enablement"
                ),
                FrameworkMapping(
                    framework_id="cis_v8",
                    control_ids=["3.11"],
                    implementation_status="exceeds",
                    enhancement_details="FIPS mode automatically disables SHA1 and other weak algorithms",
                    justification="FIPS compliance exceeds CIS SHA1 prohibition requirement"
                )
            ],
            platform_implementations=[
                PlatformImplementation(
                    platform=Platform.RHEL_9,
                    implementation_type="system_configuration",
                    commands=["fips-mode-setup --enable"],
                    files_modified=["/proc/sys/crypto/fips_enabled"],
                    services_affected=["systemd"],
                    validation_commands=["cat /proc/sys/crypto/fips_enabled"]
                )
            ]
        )

    def test_justification_evidence_creation(self):
        """Test creating justification evidence objects"""
        evidence = JustificationEvidence(
            evidence_type=AuditEvidence.TECHNICAL,
            description="Session timeout configuration validation",
            source="OpenWatch Scanner",
            timestamp=datetime.utcnow(),
            evidence_data={
                "config_file": "/etc/profile.d/tmout.sh",
                "timeout_value": "900",
                "verification_result": "TMOUT=900"
            },
            verification_method="Automated technical scanning",
            confidence_level="high",
            evidence_path="/var/log/openwatch/scan_evidence.log"
        )

        assert evidence.evidence_type == AuditEvidence.TECHNICAL
        assert evidence.description == "Session timeout configuration validation"
        assert evidence.source == "OpenWatch Scanner"
        assert evidence.confidence_level == "high"
        assert "config_file" in evidence.evidence_data
        assert evidence.timestamp is not None

    def test_compliance_justification_creation(self):
        """Test creating compliance justification objects"""
        justification = ComplianceJustification(
            justification_id="JUST-NIST-AC11-HOST001-20241001_143022",
            rule_id="session_timeout_001",
            framework_id="nist_800_53_r5",
            control_id="AC-11",
            host_id="host_001",
            justification_type=JustificationType.COMPLIANT,
            compliance_status=ComplianceStatus.COMPLIANT,

            summary="Session timeout configured to 15 minutes on RHEL 9",
            detailed_explanation="Implementation of session timeout for NIST compliance",
            implementation_description="Automated session lock after 15 minutes of inactivity",

            evidence=[],
            technical_details={"execution_time": 1.2, "validation": "passed"},

            risk_assessment="Medium risk control effectively mitigated",
            business_justification="Supports regulatory compliance objectives",
            impact_analysis="Positive security impact with no operational issues",

            regulatory_citations=["NIST SP 800-53 Rev 5", "FISMA"],
            standards_references=["NIST Cybersecurity Framework"]
        )

        assert justification.justification_id.startswith("JUST-NIST-AC11")
        assert justification.compliance_status == ComplianceStatus.COMPLIANT
        assert justification.justification_type == JustificationType.COMPLIANT
        assert justification.created_at is not None
        assert justification.last_updated is not None
        assert len(justification.auditor_notes) == 0
        assert len(justification.regulatory_citations) == 2

    def test_exceeding_compliance_analysis_creation(self):
        """Test creating exceeding compliance analysis"""
        analysis = ExceedingComplianceAnalysis(
            baseline_requirement="CIS 3.11 prohibit SHA1 cryptographic algorithms",
            actual_implementation="FIPS mode enabled with automatic weak algorithm disabling",
            enhancement_level="significant",
            security_benefits=[
                "NIST-approved cryptographic algorithms",
                "Automatic disabling of weak ciphers",
                "Enhanced key management"
            ],
            compliance_value="Exceeds CIS baseline by implementing FIPS cryptographic protection",
            additional_frameworks_satisfied=["nist_800_53_r5", "stig_rhel9"],
            business_value_statement="Single FIPS implementation satisfies 3 framework requirements",
            audit_advantage="Demonstrates security excellence beyond minimum compliance"
        )

        assert analysis.enhancement_level == "significant"
        assert len(analysis.security_benefits) == 3
        assert len(analysis.additional_frameworks_satisfied) == 2
        assert "FIPS" in analysis.compliance_value
        assert "excellence" in analysis.audit_advantage

    @pytest.mark.asyncio
    async def test_generate_justification_compliant(self, justification_engine, mock_rule_execution, mock_unified_rule):
        """Test generating justification for compliant control"""
        platform_info = {
            "platform": "rhel_9",
            "version": "9.2",
            "architecture": "x86_64"
        }

        justification = await justification_engine.generate_justification(
            rule_execution=mock_rule_execution,
            unified_rule=mock_unified_rule,
            framework_id="nist_800_53_r5",
            control_id="AC-11",
            host_id="host_001",
            platform_info=platform_info
        )

        assert justification.justification_type == JustificationType.COMPLIANT
        assert justification.compliance_status == ComplianceStatus.COMPLIANT
        assert justification.framework_id == "nist_800_53_r5"
        assert justification.control_id == "AC-11"
        assert justification.host_id == "host_001"
        assert "Session Timeout Configuration" in justification.summary
        assert "NIST" in justification.detailed_explanation
        assert len(justification.evidence) >= 2  # Technical and platform evidence
        assert "NIST SP 800-53 Rev 5" in justification.regulatory_citations
        assert justification.risk_assessment.startswith("This medium risk control")

    @pytest.mark.asyncio
    async def test_generate_justification_exceeding(self, justification_engine, mock_exceeding_execution, mock_fips_rule):
        """Test generating justification for exceeding compliance"""
        platform_info = {
            "platform": "rhel_9",
            "version": "9.2",
            "architecture": "x86_64"
        }

        justification = await justification_engine.generate_justification(
            rule_execution=mock_exceeding_execution,
            unified_rule=mock_fips_rule,
            framework_id="cis_v8",
            control_id="3.11",
            host_id="host_002",
            platform_info=platform_info
        )

        assert justification.justification_type == JustificationType.EXCEEDS
        assert justification.compliance_status == ComplianceStatus.EXCEEDS
        assert justification.framework_id == "cis_v8"
        assert justification.control_id == "3.11"
        assert justification.enhancement_details is not None
        assert justification.baseline_comparison is not None
        assert justification.exceeding_rationale is not None
        assert "exceeds baseline requirements" in justification.risk_assessment
        assert "FIPS" in justification.summary

    @pytest.mark.asyncio
    async def test_analyze_exceeding_compliance_fips(self, justification_engine, mock_fips_rule):
        """Test analyzing FIPS exceeding compliance scenario"""
        analysis = await justification_engine._analyze_exceeding_compliance(
            unified_rule=mock_fips_rule,
            framework_id="cis_v8",
            control_id="3.11",
            context_data={}
        )

        assert analysis.enhancement_level in ["moderate", "significant"]
        assert len(analysis.security_benefits) > 0
        assert "NIST-approved cryptographic algorithms" in analysis.security_benefits
        assert len(analysis.additional_frameworks_satisfied) > 0
        assert "stig_rhel9" in analysis.additional_frameworks_satisfied
        assert "FIPS" in analysis.compliance_value
        assert "security excellence" in analysis.audit_advantage

    @pytest.mark.asyncio
    async def test_generate_technical_evidence(self, justification_engine, mock_rule_execution, mock_unified_rule):
        """Test generating technical evidence"""
        platform_info = {
            "platform": "rhel_9",
            "version": "9.2",
            "architecture": "x86_64",
            "capabilities": ["systemd", "selinux"]
        }

        evidence = await justification_engine._generate_technical_evidence(
            rule_execution=mock_rule_execution,
            unified_rule=mock_unified_rule,
            platform_info=platform_info
        )

        assert len(evidence) >= 3  # Execution, platform, implementation evidence

        # Check execution evidence
        execution_evidence = next((e for e in evidence if "execution output" in e.description), None)
        assert execution_evidence is not None
        assert execution_evidence.evidence_type == AuditEvidence.TECHNICAL
        assert execution_evidence.confidence_level == "high"
        assert "timeout_value" in execution_evidence.evidence_data["execution_output"]

        # Check platform evidence
        platform_evidence = next((e for e in evidence if "Platform configuration" in e.description), None)
        assert platform_evidence is not None
        assert platform_evidence.evidence_data["platform"] == "rhel_9"

        # Check implementation evidence
        impl_evidence = next((e for e in evidence if "Implementation details" in e.description), None)
        assert impl_evidence is not None
        assert "commands" in impl_evidence.evidence_data

    @pytest.mark.asyncio
    async def test_generate_justification_text(self, justification_engine, mock_unified_rule, mock_rule_execution):
        """Test generating justification text components"""
        platform_info = {"platform": "rhel_9"}

        summary, detailed, implementation = await justification_engine._generate_justification_text(
            unified_rule=mock_unified_rule,
            rule_execution=mock_rule_execution,
            framework_id="nist_800_53_r5",
            platform_info=platform_info,
            context_data={}
        )

        assert "Session Timeout Configuration" in summary
        assert "rhel_9" in summary
        assert "NIST" in detailed
        assert "Session Timeout Configuration" in detailed
        assert "prevention" in detailed
        assert "medium" in detailed
        assert "successfully implemented" in implementation
        assert "1.200 seconds" in implementation
        assert "Compliant" in detailed

    @pytest.mark.asyncio
    async def test_generate_risk_assessment(self, justification_engine, mock_unified_rule):
        """Test generating risk assessments for different statuses"""
        # Test compliant status
        compliant_execution = RuleExecution(
            execution_id="test", rule_id="test", execution_success=True,
            compliance_status=ComplianceStatus.COMPLIANT, execution_time=1.0,
            executed_at=datetime.utcnow()
        )
        risk_assessment = await justification_engine._generate_risk_assessment(
            mock_unified_rule, compliant_execution
        )
        assert "effectively mitigated" in risk_assessment
        assert "medium risk control" in risk_assessment

        # Test exceeding status
        exceeding_execution = RuleExecution(
            execution_id="test", rule_id="test", execution_success=True,
            compliance_status=ComplianceStatus.EXCEEDS, execution_time=1.0,
            executed_at=datetime.utcnow()
        )
        risk_assessment = await justification_engine._generate_risk_assessment(
            mock_unified_rule, exceeding_execution
        )
        assert "exceeds baseline requirements" in risk_assessment
        assert "enhanced protection" in risk_assessment

        # Test non-compliant status
        non_compliant_execution = RuleExecution(
            execution_id="test", rule_id="test", execution_success=False,
            compliance_status=ComplianceStatus.NON_COMPLIANT, execution_time=1.0,
            executed_at=datetime.utcnow()
        )
        risk_assessment = await justification_engine._generate_risk_assessment(
            mock_unified_rule, non_compliant_execution
        )
        assert "immediate attention" in risk_assessment
        assert "security risk" in risk_assessment

    @pytest.mark.asyncio
    async def test_generate_business_justification(self, justification_engine, mock_unified_rule):
        """Test generating business justifications for different frameworks"""
        # Test NIST framework
        nist_justification = await justification_engine._generate_business_justification(
            mock_unified_rule, "nist_800_53_r5"
        )
        assert "federal compliance" in nist_justification
        assert "cybersecurity framework" in nist_justification

        # Test CIS framework
        cis_justification = await justification_engine._generate_business_justification(
            mock_unified_rule, "cis_v8"
        )
        assert "industry best practices" in cis_justification
        assert "cyber defense" in cis_justification

        # Test ISO framework
        iso_justification = await justification_engine._generate_business_justification(
            mock_unified_rule, "iso_27001_2022"
        )
        assert "information security management" in iso_justification
        assert "international standards" in iso_justification

    @pytest.mark.asyncio
    async def test_batch_justifications(self, justification_engine):
        """Test generating batch justifications from scan results"""
        # Create mock scan result
        rule_execution = RuleExecution(
            execution_id="exec_001",
            rule_id="session_timeout_001",
            execution_success=True,
            compliance_status=ComplianceStatus.COMPLIANT,
            execution_time=1.0,
            executed_at=datetime.utcnow()
        )

        framework_result = FrameworkResult(
            framework_id="nist_800_53_r5",
            compliance_percentage=95.0,
            total_rules=1,
            compliant_rules=1,
            non_compliant_rules=0,
            error_rules=0,
            rule_executions=[rule_execution]
        )

        host_result = HostResult(
            host_id="host_001",
            platform_info={"platform": "rhel_9"},
            framework_results=[framework_result]
        )

        scan_result = ScanResult(
            scan_id="scan_001",
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            total_execution_time=10.0,
            host_results=[host_result]
        )

        # Mock unified rule
        unified_rule = UnifiedComplianceRule(
            rule_id="session_timeout_001",
            title="Session Timeout",
            description="Configure session timeout",
            category="access_control",
            security_function="prevention",
            risk_level="medium",
            framework_mappings=[
                FrameworkMapping(
                    framework_id="nist_800_53_r5",
                    control_ids=["AC-11"],
                    implementation_status="compliant"
                )
            ],
            platform_implementations=[]
        )

        unified_rules = {"session_timeout_001": unified_rule}

        batch_justifications = await justification_engine.generate_batch_justifications(
            scan_result, unified_rules
        )

        assert "host_001" in batch_justifications
        assert len(batch_justifications["host_001"]) == 1

        justification = batch_justifications["host_001"][0]
        assert justification.rule_id == "session_timeout_001"
        assert justification.framework_id == "nist_800_53_r5"
        assert justification.control_id == "AC-11"
        assert justification.host_id == "host_001"

    @pytest.mark.asyncio
    async def test_export_audit_package_json(self, justification_engine):
        """Test exporting audit package in JSON format"""
        justifications = [
            ComplianceJustification(
                justification_id="JUST-001",
                rule_id="rule_001",
                framework_id="nist_800_53_r5",
                control_id="AC-11",
                host_id="host_001",
                justification_type=JustificationType.COMPLIANT,
                compliance_status=ComplianceStatus.COMPLIANT,
                summary="Test justification",
                detailed_explanation="Detailed explanation",
                implementation_description="Implementation details",
                evidence=[],
                technical_details={},
                risk_assessment="Low risk",
                business_justification="Business need",
                impact_analysis="Positive impact"
            )
        ]

        json_export = await justification_engine.export_audit_package(
            justifications, "nist_800_53_r5", "json"
        )

        # Should be valid JSON
        parsed = json.loads(json_export)
        assert "audit_package_metadata" in parsed
        assert "compliance_summary" in parsed
        assert "justifications" in parsed

        # Check metadata
        metadata = parsed["audit_package_metadata"]
        assert metadata["framework"] == "nist_800_53_r5"
        assert metadata["total_justifications"] == 1
        assert "NIST SP 800-53 Rev 5" in metadata["regulatory_citations"]

        # Check compliance summary
        summary = parsed["compliance_summary"]
        assert summary["compliant"] == 1
        assert summary["exceeds"] == 0
        assert summary["non_compliant"] == 0

        # Check justifications
        justification_data = parsed["justifications"][0]
        assert justification_data["justification_id"] == "JUST-001"
        assert justification_data["control_id"] == "AC-11"
        assert justification_data["compliance_status"] == "compliant"

    @pytest.mark.asyncio
    async def test_export_audit_package_csv(self, justification_engine):
        """Test exporting audit package in CSV format"""
        justifications = [
            ComplianceJustification(
                justification_id="JUST-001",
                rule_id="rule_001",
                framework_id="nist_800_53_r5",
                control_id="AC-11",
                host_id="host_001",
                justification_type=JustificationType.COMPLIANT,
                compliance_status=ComplianceStatus.COMPLIANT,
                summary="Test summary",
                detailed_explanation="Detailed explanation",
                implementation_description="Implementation details",
                evidence=[],
                technical_details={},
                risk_assessment="Low risk assessment",
                business_justification="Business justification text",
                impact_analysis="Positive impact"
            )
        ]

        csv_export = await justification_engine.export_audit_package(
            justifications, "nist_800_53_r5", "csv"
        )

        # Should be valid CSV
        lines = csv_export.strip().split('\n')
        assert len(lines) == 2  # Header + 1 data row

        # Check header
        header = lines[0]
        assert "Control_ID" in header
        assert "Host_ID" in header
        assert "Compliance_Status" in header
        assert "Summary" in header

        # Check data row
        data_row = lines[1]
        assert "AC-11" in data_row
        assert "host_001" in data_row
        assert "compliant" in data_row
        assert "Test summary" in data_row

    @pytest.mark.asyncio
    async def test_unsupported_export_format(self, justification_engine):
        """Test unsupported export format"""
        with pytest.raises(ValueError, match="Unsupported export format"):
            await justification_engine.export_audit_package([], "nist", "xml")

    def test_template_library_initialization(self, justification_engine):
        """Test template library initialization"""
        templates = justification_engine.template_library

        assert "session_timeout" in templates
        assert "fips_cryptography" in templates
        assert "access_control" in templates
        assert "patch_management" in templates

        # Check session timeout template
        session_template = templates["session_timeout"]
        assert "summary_template" in session_template
        assert "implementation_template" in session_template
        assert "risk_mitigation" in session_template
        assert "{timeout}" in session_template["summary_template"]

        # Check FIPS template
        fips_template = templates["fips_cryptography"]
        assert "exceeding_rationale" in fips_template
        assert "security_enhancement" in fips_template
        assert "{mode}" in fips_template["summary_template"]

    def test_regulatory_mappings_initialization(self, justification_engine):
        """Test regulatory mappings initialization"""
        mappings = justification_engine.regulatory_mappings

        assert "nist_800_53_r5" in mappings
        assert "cis_v8" in mappings
        assert "iso_27001_2022" in mappings
        assert "pci_dss_v4" in mappings
        assert "stig_rhel9" in mappings

        # Check NIST mappings
        nist_mappings = mappings["nist_800_53_r5"]
        assert "NIST SP 800-53 Rev 5" in nist_mappings
        assert "FISMA" in nist_mappings

        # Check CIS mappings
        cis_mappings = mappings["cis_v8"]
        assert "CIS Critical Security Controls Version 8" in cis_mappings

        # Check STIG mappings
        stig_mappings = mappings["stig_rhel9"]
        assert "DISA Security Technical Implementation Guide (STIG)" in stig_mappings

    def test_cache_functionality(self, justification_engine):
        """Test justification cache functionality"""
        # Test cache clearing
        justification_engine.justification_cache["test_key"] = "test_value"
        assert len(justification_engine.justification_cache) == 1

        justification_engine.clear_cache()
        assert len(justification_engine.justification_cache) == 0

    def test_helper_methods(self, justification_engine):
        """Test helper methods for text generation"""
        # Test security purpose descriptions
        assert "prevent security incidents" in justification_engine._get_security_purpose("prevention")
        assert "identify and alert" in justification_engine._get_security_purpose("detection")
        assert "protect assets" in justification_engine._get_security_purpose("protection")

        # Test risk descriptions
        assert "routine operational" in justification_engine._get_risk_description("low")
        assert "moderate business impact" in justification_engine._get_risk_description("medium")
        assert "significant organizational" in justification_engine._get_risk_description("high")
        assert "severe enterprise-wide" in justification_engine._get_risk_description("critical")

        # Test standards references
        mock_rule = Mock()
        mock_rule.category = "access_control"

        references = justification_engine._get_standards_references(mock_rule, "nist_800_53_r5")
        assert "NIST Cybersecurity Framework" in references
        assert "NIST SP 800-162" in references  # access control specific


class TestJustificationScenarios:
    """Test real-world justification scenarios"""

    @pytest.mark.asyncio
    async def test_fips_exceeding_cis_scenario(self):
        """Test FIPS exceeding CIS cryptography scenario"""
        engine = ComplianceJustificationEngine()

        # Create FIPS rule execution
        fips_execution = RuleExecution(
            execution_id="fips_exec",
            rule_id="fips_crypto_001",
            execution_success=True,
            compliance_status=ComplianceStatus.EXCEEDS,
            execution_time=0.5,
            output_data={
                "fips_enabled": "1",
                "disabled_algorithms": ["MD5", "SHA1", "DES", "3DES"],
                "approved_algorithms": ["AES", "SHA-256", "RSA-2048"]
            },
            executed_at=datetime.utcnow()
        )

        # Create FIPS rule
        fips_rule = UnifiedComplianceRule(
            rule_id="fips_crypto_001",
            title="FIPS Cryptographic Mode",
            description="Enable FIPS 140-2 approved cryptographic algorithms",
            category="cryptography",
            security_function="protection",
            risk_level="high",
            framework_mappings=[
                FrameworkMapping(
                    framework_id="cis_v8",
                    control_ids=["3.11"],
                    implementation_status="exceeds",
                    enhancement_details="FIPS mode automatically disables SHA1 and other weak algorithms",
                    justification="FIPS implementation exceeds CIS prohibition of weak cryptographic algorithms"
                ),
                FrameworkMapping(
                    framework_id="stig_rhel9",
                    control_ids=["RHEL-09-672010"],
                    implementation_status="compliant",
                    justification="Meets STIG FIPS requirement"
                )
            ],
            platform_implementations=[]
        )

        justification = await engine.generate_justification(
            rule_execution=fips_execution,
            unified_rule=fips_rule,
            framework_id="cis_v8",
            control_id="3.11",
            host_id="fips_host",
            platform_info={"platform": "rhel_9"},
            context_data={}
        )

        # Should identify exceeding compliance
        assert justification.justification_type == JustificationType.EXCEEDS
        assert justification.compliance_status == ComplianceStatus.EXCEEDS
        assert justification.enhancement_details is not None
        assert "exceeds baseline requirements" in justification.risk_assessment
        assert "FIPS" in justification.summary
        assert "SHA1" in justification.detailed_explanation or "weak algorithms" in justification.detailed_explanation

        # Should have high-confidence technical evidence
        technical_evidence = [e for e in justification.evidence if e.evidence_type == AuditEvidence.TECHNICAL]
        assert len(technical_evidence) >= 2
        assert any(e.confidence_level == "high" for e in technical_evidence)

    @pytest.mark.asyncio
    async def test_partial_compliance_scenario(self):
        """Test partial compliance justification scenario"""
        engine = ComplianceJustificationEngine()

        # Create partial compliance execution
        partial_execution = RuleExecution(
            execution_id="partial_exec",
            rule_id="patch_management_001",
            execution_success=True,
            compliance_status=ComplianceStatus.PARTIAL,
            execution_time=2.0,
            output_data={
                "automated_updates": "enabled",
                "update_schedule": "weekly",
                "missing_patches": 3,
                "critical_patches": 1
            },
            error_message="1 critical patch pending installation",
            executed_at=datetime.utcnow()
        )

        # Create patch management rule
        patch_rule = UnifiedComplianceRule(
            rule_id="patch_management_001",
            title="Automated Patch Management",
            description="Implement automated patch management with timely installation",
            category="system_maintenance",
            security_function="protection",
            risk_level="high",
            framework_mappings=[
                FrameworkMapping(
                    framework_id="nist_800_53_r5",
                    control_ids=["SI-2"],
                    implementation_status="partial",
                    justification="Automated patching enabled but critical patches pending"
                )
            ],
            platform_implementations=[]
        )

        justification = await engine.generate_justification(
            rule_execution=partial_execution,
            unified_rule=patch_rule,
            framework_id="nist_800_53_r5",
            control_id="SI-2",
            host_id="patch_host",
            platform_info={"platform": "rhel_9"},
            context_data={}
        )

        # Should identify partial compliance
        assert justification.justification_type == JustificationType.PARTIAL
        assert justification.compliance_status == ComplianceStatus.PARTIAL
        assert "partial implementation" in justification.risk_assessment.lower()
        assert "requires completion" in justification.risk_assessment.lower()
        assert "critical patch" in justification.implementation_description

        # Should include error information
        technical_details = justification.technical_details
        assert "critical patch pending" in technical_details["error_details"]


if __name__ == "__main__":
    pytest.main([__file__])
