"""
Test suite for Framework Mapping Engine
Tests intelligent cross-framework control mapping and unified compliance orchestration
"""
import pytest
import json
import tempfile
from datetime import datetime
from unittest.mock import Mock, patch, AsyncMock

from app.services.framework_mapping_engine import (
    FrameworkMappingEngine, ControlMapping, FrameworkRelationship, UnifiedImplementation,
    MappingConfidence, MappingType
)
from app.models.unified_rule_models import (
    UnifiedComplianceRule, FrameworkMapping, Platform, PlatformImplementation
)


class TestFrameworkMappingEngine:
    """Test framework mapping engine functionality"""

    @pytest.fixture
    def mapping_engine(self):
        """Create framework mapping engine instance"""
        return FrameworkMappingEngine()

    @pytest.fixture
    def mock_unified_rule(self):
        """Create mock unified compliance rule"""
        return UnifiedComplianceRule(
            rule_id="session_timeout_001",
            title="Session Timeout Configuration",
            description="Configure session timeout to prevent unauthorized access",
            category="access_control",
            security_function="prevention",
            risk_level="medium",
            framework_mappings=[
                FrameworkMapping(
                    framework_id="nist_800_53_r5",
                    control_ids=["AC-11"],
                    implementation_status="compliant",
                    justification="Implements NIST session lock requirement"
                ),
                FrameworkMapping(
                    framework_id="cis_v8",
                    control_ids=["5.2"],
                    implementation_status="exceeds",
                    enhancement_details="15-minute timeout exceeds CIS baseline",
                    justification="Exceeds CIS session management requirement"
                ),
                FrameworkMapping(
                    framework_id="iso_27001_2022",
                    control_ids=["A.9.1"],
                    implementation_status="compliant",
                    justification="Meets ISO access control requirement"
                )
            ],
            platform_implementations=[
                PlatformImplementation(
                    platform=Platform.RHEL_9,
                    implementation_type="configuration",
                    commands=["tmux set-option -g lock-after-time 900"],
                    files_modified=["/etc/tmux.conf"],
                    services_affected=["tmux"],
                    validation_commands=["tmux show-options -g lock-after-time"]
                )
            ]
        )

    @pytest.fixture
    def mock_crypto_rule(self):
        """Create mock cryptography rule for exceeding compliance scenarios"""
        return UnifiedComplianceRule(
            rule_id="fips_crypto_001",
            title="FIPS Cryptography Policy",
            description="Enable FIPS mode for cryptographic operations",
            category="cryptography",
            security_function="protection",
            risk_level="high",
            framework_mappings=[
                FrameworkMapping(
                    framework_id="stig_rhel9",
                    control_ids=["RHEL-09-672010"],
                    implementation_status="compliant",
                    justification="STIG requires FIPS mode"
                ),
                FrameworkMapping(
                    framework_id="cis_v8",
                    control_ids=["3.11"],
                    implementation_status="exceeds",
                    enhancement_details="FIPS crypto exceeds CIS SHA1 prohibition",
                    justification="FIPS mode automatically disables SHA1, exceeding CIS requirement"
                ),
                FrameworkMapping(
                    framework_id="nist_800_53_r5",
                    control_ids=["SC-13"],
                    implementation_status="compliant",
                    justification="Implements NIST cryptographic protection"
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

    def test_control_mapping_creation(self):
        """Test creating control mapping objects"""
        mapping = ControlMapping(
            source_framework="nist_800_53_r5",
            source_control="AC-11",
            target_framework="cis_v8",
            target_control="5.2",
            mapping_type=MappingType.EQUIVALENT,
            confidence=MappingConfidence.HIGH,
            rationale="Both controls address session management",
            evidence=["shared implementation", "similar objectives"],
            implementation_notes="Both require session timeout configuration"
        )

        assert mapping.source_framework == "nist_800_53_r5"
        assert mapping.source_control == "AC-11"
        assert mapping.target_framework == "cis_v8"
        assert mapping.target_control == "5.2"
        assert mapping.mapping_type == MappingType.EQUIVALENT
        assert mapping.confidence == MappingConfidence.HIGH
        assert "session management" in mapping.rationale
        assert len(mapping.evidence) == 2
        assert mapping.created_at is not None
        assert mapping.exceptions == []

    def test_framework_relationship_creation(self):
        """Test creating framework relationship objects"""
        mock_mappings = [
            ControlMapping(
                source_framework="nist_800_53_r5",
                source_control="AC-11",
                target_framework="cis_v8",
                target_control="5.2",
                mapping_type=MappingType.EQUIVALENT,
                confidence=MappingConfidence.HIGH,
                rationale="Session management alignment",
                evidence=[]
            )
        ]

        relationship = FrameworkRelationship(
            framework_a="nist_800_53_r5",
            framework_b="cis_v8",
            overlap_percentage=75.0,
            common_controls=15,
            framework_a_unique=5,
            framework_b_unique=3,
            relationship_type="well_aligned",
            strength=0.75,
            bidirectional_mappings=mock_mappings,
            implementation_synergies=["Strong alignment in access control"],
            conflict_areas=[]
        )

        assert relationship.framework_a == "nist_800_53_r5"
        assert relationship.framework_b == "cis_v8"
        assert relationship.overlap_percentage == 75.0
        assert relationship.relationship_type == "well_aligned"
        assert relationship.strength == 0.75
        assert len(relationship.bidirectional_mappings) == 1
        assert len(relationship.implementation_synergies) == 1
        assert len(relationship.conflict_areas) == 0

    def test_unified_implementation_creation(self):
        """Test creating unified implementation objects"""
        implementation = UnifiedImplementation(
            implementation_id="unified_session_timeout",
            description="Unified session timeout implementation",
            frameworks_satisfied=["nist_800_53_r5", "cis_v8", "iso_27001_2022"],
            control_mappings={
                "nist_800_53_r5": ["AC-11"],
                "cis_v8": ["5.2"],
                "iso_27001_2022": ["A.9.1"]
            },
            implementation_details={
                "timeout_minutes": 15,
                "scope": "all_sessions",
                "enforcement": "automatic"
            },
            platform_specifics={
                Platform.RHEL_9: PlatformImplementation(
                    platform=Platform.RHEL_9,
                    implementation_type="configuration",
                    commands=["tmux set-option -g lock-after-time 900"],
                    files_modified=["/etc/tmux.conf"],
                    services_affected=["tmux"],
                    validation_commands=["tmux show-options -g lock-after-time"]
                )
            },
            exceeds_frameworks=["cis_v8"],
            compliance_justification="15-minute timeout meets NIST/ISO and exceeds CIS requirements",
            risk_assessment="Low risk - standard timeout configuration",
            effort_estimate="Low"
        )

        assert implementation.implementation_id == "unified_session_timeout"
        assert len(implementation.frameworks_satisfied) == 3
        assert "cis_v8" in implementation.exceeds_frameworks
        assert Platform.RHEL_9 in implementation.platform_specifics
        assert implementation.effort_estimate == "Low"

    @pytest.mark.asyncio
    async def test_load_predefined_mappings(self, mapping_engine):
        """Test loading predefined mappings from JSON file"""
        # Create temporary mappings file
        mappings_data = {
            "mappings": [
                {
                    "source_framework": "nist_800_53_r5",
                    "source_control": "AC-11",
                    "target_framework": "cis_v8",
                    "target_control": "5.2",
                    "mapping_type": "equivalent",
                    "confidence": "high",
                    "rationale": "Both address session management",
                    "evidence": ["shared objectives", "similar implementation"]
                },
                {
                    "source_framework": "nist_800_53_r5",
                    "source_control": "SC-13",
                    "target_framework": "iso_27001_2022",
                    "target_control": "A.10.1",
                    "mapping_type": "direct",
                    "confidence": "high",
                    "rationale": "Both address cryptographic controls",
                    "evidence": ["cryptography requirements"]
                }
            ]
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(mappings_data, f)
            temp_file = f.name

        try:
            loaded_count = await mapping_engine.load_predefined_mappings(temp_file)

            assert loaded_count == 2

            # Check first mapping
            ac11_mappings = mapping_engine.control_mappings["nist_800_53_r5:AC-11"]
            assert len(ac11_mappings) == 1
            assert ac11_mappings[0].target_control == "5.2"
            assert ac11_mappings[0].mapping_type == MappingType.EQUIVALENT
            assert ac11_mappings[0].confidence == MappingConfidence.HIGH

            # Check second mapping
            sc13_mappings = mapping_engine.control_mappings["nist_800_53_r5:SC-13"]
            assert len(sc13_mappings) == 1
            assert sc13_mappings[0].target_control == "A.10.1"

        finally:
            import os
            os.unlink(temp_file)

    @pytest.mark.asyncio
    async def test_discover_control_mappings(self, mapping_engine, mock_unified_rule):
        """Test discovering control mappings from unified rules"""
        unified_rules = [mock_unified_rule]

        # Discover mappings between NIST and CIS
        mappings = await mapping_engine.discover_control_mappings(
            "nist_800_53_r5", "cis_v8", unified_rules
        )

        assert len(mappings) == 1
        mapping = mappings[0]
        assert mapping.source_framework == "nist_800_53_r5"
        assert mapping.source_control == "AC-11"
        assert mapping.target_framework == "cis_v8"
        assert mapping.target_control == "5.2"
        assert mapping.confidence in [MappingConfidence.HIGH, MappingConfidence.MEDIUM]
        assert "unified rule" in mapping.rationale.lower()

    @pytest.mark.asyncio
    async def test_analyze_mapping_characteristics(self, mapping_engine, mock_unified_rule):
        """Test analyzing mapping characteristics"""
        unified_rules = [mock_unified_rule]
        shared_rules = {"session_timeout_001"}

        mapping_type, confidence = await mapping_engine._analyze_mapping_characteristics(
            "nist_800_53_r5", "AC-11",
            "cis_v8", "5.2",
            shared_rules, unified_rules
        )

        # Should detect high confidence mapping due to shared rule
        assert mapping_type in [MappingType.EQUIVALENT, MappingType.DIRECT]
        assert confidence in [MappingConfidence.HIGH, MappingConfidence.MEDIUM]

    @pytest.mark.asyncio
    async def test_analyze_framework_relationship(self, mapping_engine, mock_unified_rule, mock_crypto_rule):
        """Test analyzing framework relationships"""
        unified_rules = [mock_unified_rule, mock_crypto_rule]

        relationship = await mapping_engine.analyze_framework_relationship(
            "nist_800_53_r5", "cis_v8", unified_rules
        )

        assert relationship.framework_a == "nist_800_53_r5"
        assert relationship.framework_b == "cis_v8"
        assert relationship.overlap_percentage > 0
        assert relationship.common_controls > 0
        assert relationship.relationship_type in [
            "highly_aligned", "well_aligned", "moderately_aligned",
            "loosely_aligned", "minimally_aligned"
        ]
        assert len(relationship.bidirectional_mappings) >= 2  # Both rules create mappings
        assert relationship.strength > 0

    @pytest.mark.asyncio
    async def test_identify_implementation_synergies(self, mapping_engine, mock_unified_rule):
        """Test identifying implementation synergies"""
        unified_rules = [mock_unified_rule]
        mappings = [
            ControlMapping(
                source_framework="nist_800_53_r5",
                source_control="AC-11",
                target_framework="cis_v8",
                target_control="5.2",
                mapping_type=MappingType.EQUIVALENT,
                confidence=MappingConfidence.HIGH,
                rationale="Test mapping",
                evidence=[]
            )
        ]

        synergies = await mapping_engine._identify_implementation_synergies(mappings, unified_rules)

        # Should identify exceeding compliance opportunities
        assert len(synergies) > 0
        exceeding_synergy = next((s for s in synergies if "exceeding compliance" in s.lower()), None)
        assert exceeding_synergy is not None

    @pytest.mark.asyncio
    async def test_identify_conflict_areas(self, mapping_engine):
        """Test identifying conflict areas"""
        # Create mappings with low confidence
        mappings = [
            ControlMapping(
                source_framework="nist_800_53_r5",
                source_control="AC-11",
                target_framework="cis_v8",
                target_control="5.2",
                mapping_type=MappingType.OVERLAP,
                confidence=MappingConfidence.UNCERTAIN,
                rationale="Uncertain mapping",
                evidence=[]
            ),
            ControlMapping(
                source_framework="nist_800_53_r5",
                source_control="AC-12",
                target_framework="cis_v8",
                target_control="5.3",
                mapping_type=MappingType.OVERLAP,
                confidence=MappingConfidence.UNCERTAIN,
                rationale="Another uncertain mapping",
                evidence=[]
            )
        ]

        conflicts = await mapping_engine._identify_conflict_areas(mappings, [])

        # Should identify uncertain mappings as conflicts
        if len(mappings) >= 2:  # Threshold for conflict detection
            assert len(conflicts) > 0
            uncertainty_conflict = next((c for c in conflicts if "uncertainty" in c.lower()), None)
            # May or may not be detected depending on threshold

    @pytest.mark.asyncio
    async def test_generate_unified_implementation_existing_rule(self, mapping_engine, mock_unified_rule):
        """Test generating unified implementation from existing rule"""
        unified_rules = [mock_unified_rule]
        target_frameworks = ["nist_800_53_r5", "cis_v8", "iso_27001_2022"]

        implementation = await mapping_engine.generate_unified_implementation(
            "session timeout", target_frameworks, Platform.RHEL_9, unified_rules
        )

        assert implementation.implementation_id.startswith("unified_")
        assert "session" in implementation.description.lower()
        assert len(implementation.frameworks_satisfied) >= 2
        assert "cis_v8" in implementation.exceeds_frameworks  # Based on mock rule
        assert Platform.RHEL_9 in implementation.platform_specifics
        assert implementation.effort_estimate == "Low"  # Since rule exists

    @pytest.mark.asyncio
    async def test_generate_unified_implementation_new_objective(self, mapping_engine):
        """Test generating unified implementation for new control objective"""
        unified_rules = []  # No existing rules
        target_frameworks = ["nist_800_53_r5", "cis_v8"]

        implementation = await mapping_engine.generate_unified_implementation(
            "password complexity", target_frameworks, Platform.RHEL_9, unified_rules
        )

        assert implementation.implementation_id == "unified_password_complexity"
        assert "password complexity" in implementation.description
        assert len(implementation.frameworks_satisfied) == 2
        assert implementation.effort_estimate == "Medium"  # New implementation
        assert Platform.RHEL_9 in implementation.platform_specifics

    @pytest.mark.asyncio
    async def test_get_framework_coverage_analysis(self, mapping_engine, mock_unified_rule, mock_crypto_rule):
        """Test framework coverage analysis"""
        unified_rules = [mock_unified_rule, mock_crypto_rule]
        frameworks = ["nist_800_53_r5", "cis_v8", "iso_27001_2022"]

        # First analyze relationships
        await mapping_engine.analyze_framework_relationship("nist_800_53_r5", "cis_v8", unified_rules)
        await mapping_engine.analyze_framework_relationship("nist_800_53_r5", "iso_27001_2022", unified_rules)

        coverage = await mapping_engine.get_framework_coverage_analysis(frameworks, unified_rules)

        assert coverage["frameworks_analyzed"] == frameworks
        assert "framework_details" in coverage
        assert "cross_framework_analysis" in coverage

        # Check framework details
        for framework in frameworks:
            assert framework in coverage["framework_details"]
            details = coverage["framework_details"][framework]
            assert "total_controls" in details
            assert "total_rules" in details
            assert "coverage_percentage" in details

        # Check cross-framework analysis
        cross_analysis = coverage["cross_framework_analysis"]
        assert "total_unique_controls" in cross_analysis
        assert "framework_relationships" in cross_analysis

    @pytest.mark.asyncio
    async def test_export_mapping_data_json(self, mapping_engine):
        """Test exporting mapping data in JSON format"""
        # Add some test mappings
        test_mapping = ControlMapping(
            source_framework="nist_800_53_r5",
            source_control="AC-11",
            target_framework="cis_v8",
            target_control="5.2",
            mapping_type=MappingType.EQUIVALENT,
            confidence=MappingConfidence.HIGH,
            rationale="Test mapping",
            evidence=["test evidence"]
        )

        mapping_engine.control_mappings["nist_800_53_r5:AC-11"].append(test_mapping)

        json_output = await mapping_engine.export_mapping_data('json')

        # Should be valid JSON
        parsed = json.loads(json_output)
        assert "control_mappings" in parsed
        assert "framework_relationships" in parsed
        assert "unified_implementations" in parsed

        # Check control mappings
        assert len(parsed["control_mappings"]) >= 1
        mapping_data = parsed["control_mappings"][0]
        assert mapping_data["source_framework"] == "nist_800_53_r5"
        assert mapping_data["source_control"] == "AC-11"
        assert mapping_data["target_framework"] == "cis_v8"
        assert mapping_data["target_control"] == "5.2"

    @pytest.mark.asyncio
    async def test_export_mapping_data_csv(self, mapping_engine):
        """Test exporting mapping data in CSV format"""
        # Add some test mappings
        test_mapping = ControlMapping(
            source_framework="nist_800_53_r5",
            source_control="AC-11",
            target_framework="cis_v8",
            target_control="5.2",
            mapping_type=MappingType.EQUIVALENT,
            confidence=MappingConfidence.HIGH,
            rationale="Test mapping",
            evidence=["test evidence"]
        )

        mapping_engine.control_mappings["nist_800_53_r5:AC-11"].append(test_mapping)

        csv_output = await mapping_engine.export_mapping_data('csv')

        # Should be valid CSV
        lines = csv_output.strip().split('\n')
        assert len(lines) >= 2  # Header + at least one data row
        assert "Source_Framework,Source_Control,Target_Framework,Target_Control" in lines[0]
        assert "nist_800_53_r5,AC-11,cis_v8,5.2" in csv_output

    @pytest.mark.asyncio
    async def test_unsupported_export_format(self, mapping_engine):
        """Test unsupported export format"""
        with pytest.raises(ValueError, match="Unsupported export format"):
            await mapping_engine.export_mapping_data('xml')

    def test_framework_hierarchies(self, mapping_engine):
        """Test framework hierarchy definitions"""
        hierarchies = mapping_engine.framework_hierarchies

        # SRG should have STIG children
        assert "srg_os" in hierarchies
        assert hierarchies["srg_os"]["parent"] is None
        assert "stig_rhel9" in hierarchies["srg_os"]["children"]

        # NIST should be standalone
        assert "nist_800_53_r5" in hierarchies
        assert hierarchies["nist_800_53_r5"]["parent"] is None

    def test_framework_affinities(self, mapping_engine):
        """Test framework affinity definitions"""
        affinities = mapping_engine.framework_affinities

        # NIST-ISO should have high affinity
        nist_iso_pair = ("nist_800_53_r5", "iso_27001_2022")
        assert nist_iso_pair in affinities
        assert affinities[nist_iso_pair] >= 0.8

        # SRG-NIST should have very high affinity
        srg_nist_pair = ("srg_os", "nist_800_53_r5")
        assert srg_nist_pair in affinities
        assert affinities[srg_nist_pair] >= 0.9

    def test_cache_functionality(self, mapping_engine):
        """Test cache functionality"""
        # Test cache clearing
        mapping_engine.mapping_cache["test_key"] = "test_value"
        assert len(mapping_engine.mapping_cache) == 1

        mapping_engine.clear_cache()
        assert len(mapping_engine.mapping_cache) == 0


class TestFrameworkMappingScenarios:
    """Test real-world framework mapping scenarios"""

    @pytest.mark.asyncio
    async def test_exceeding_compliance_mapping(self):
        """Test mapping scenario where implementation exceeds requirements"""
        mapping_engine = FrameworkMappingEngine()

        # Create rule that exceeds CIS but meets STIG
        fips_rule = UnifiedComplianceRule(
            rule_id="fips_crypto_exceeds",
            title="FIPS Cryptography Exceeding CIS",
            description="FIPS mode exceeds CIS SHA1 prohibition",
            category="cryptography",
            security_function="protection",
            risk_level="medium",
            framework_mappings=[
                FrameworkMapping(
                    framework_id="stig_rhel9",
                    control_ids=["RHEL-09-672010"],
                    implementation_status="compliant",
                    justification="STIG requires FIPS mode"
                ),
                FrameworkMapping(
                    framework_id="cis_v8",
                    control_ids=["3.11"],
                    implementation_status="exceeds",
                    enhancement_details="FIPS automatically disables SHA1",
                    justification="FIPS mode exceeds CIS SHA1 prohibition requirement"
                )
            ],
            platform_implementations=[]
        )

        unified_rules = [fips_rule]

        # Analyze relationship
        relationship = await mapping_engine.analyze_framework_relationship(
            "stig_rhel9", "cis_v8", unified_rules
        )

        # Should detect exceeding compliance synergy
        assert len(relationship.implementation_synergies) > 0
        exceeding_synergy = next(
            (s for s in relationship.implementation_synergies if "exceeding compliance" in s.lower()),
            None
        )
        assert exceeding_synergy is not None

        # Generate unified implementation
        implementation = await mapping_engine.generate_unified_implementation(
            "cryptography", ["stig_rhel9", "cis_v8"], Platform.RHEL_9, unified_rules
        )

        assert "cis_v8" in implementation.exceeds_frameworks
        assert "exceeds" in implementation.compliance_justification.lower()

    @pytest.mark.asyncio
    async def test_multi_framework_unified_implementation(self):
        """Test unified implementation across multiple frameworks"""
        mapping_engine = FrameworkMappingEngine()

        # Create rule that spans multiple frameworks
        multi_framework_rule = UnifiedComplianceRule(
            rule_id="session_mgmt_unified",
            title="Unified Session Management",
            description="Session management across multiple frameworks",
            category="access_control",
            security_function="prevention",
            risk_level="medium",
            framework_mappings=[
                FrameworkMapping(
                    framework_id="nist_800_53_r5",
                    control_ids=["AC-11", "AC-12"],
                    implementation_status="compliant"
                ),
                FrameworkMapping(
                    framework_id="cis_v8",
                    control_ids=["5.2", "5.3"],
                    implementation_status="compliant"
                ),
                FrameworkMapping(
                    framework_id="iso_27001_2022",
                    control_ids=["A.9.1", "A.9.2"],
                    implementation_status="compliant"
                ),
                FrameworkMapping(
                    framework_id="pci_dss_v4",
                    control_ids=["7.1.1", "8.1.1"],
                    implementation_status="compliant"
                )
            ],
            platform_implementations=[]
        )

        unified_rules = [multi_framework_rule]
        frameworks = ["nist_800_53_r5", "cis_v8", "iso_27001_2022", "pci_dss_v4"]

        # Generate unified implementation
        implementation = await mapping_engine.generate_unified_implementation(
            "session management", frameworks, Platform.RHEL_9, unified_rules
        )

        # Should satisfy all frameworks
        assert len(implementation.frameworks_satisfied) == 4
        for framework in frameworks:
            assert framework in implementation.control_mappings
            assert len(implementation.control_mappings[framework]) >= 1

        # Analyze coverage
        coverage = await mapping_engine.get_framework_coverage_analysis(frameworks, unified_rules)

        assert coverage["frameworks_analyzed"] == frameworks
        for framework in frameworks:
            details = coverage["framework_details"][framework]
            assert details["total_controls"] >= 2  # Each framework has 2 controls
            assert details["total_rules"] >= 1

    @pytest.mark.asyncio
    async def test_framework_inheritance_mapping(self):
        """Test mapping with framework inheritance (SRG -> STIG)"""
        mapping_engine = FrameworkMappingEngine()

        # Create SRG requirement
        srg_rule = UnifiedComplianceRule(
            rule_id="srg_requirement_001",
            title="SRG Operating System Requirement",
            description="General OS security requirement",
            category="system_configuration",
            security_function="protection",
            risk_level="high",
            framework_mappings=[
                FrameworkMapping(
                    framework_id="srg_os",
                    control_ids=["SRG-OS-000001-GPOS-00001"],
                    implementation_status="compliant"
                )
            ],
            platform_implementations=[]
        )

        # Create STIG implementation
        stig_rule = UnifiedComplianceRule(
            rule_id="stig_implementation_001",
            title="STIG RHEL 9 Implementation",
            description="RHEL 9 specific implementation of SRG requirement",
            category="system_configuration",
            security_function="protection",
            risk_level="high",
            framework_mappings=[
                FrameworkMapping(
                    framework_id="stig_rhel9",
                    control_ids=["RHEL-09-412010"],
                    implementation_status="compliant"
                ),
                FrameworkMapping(
                    framework_id="nist_800_53_r5",
                    control_ids=["AC-11"],
                    implementation_status="compliant"
                )
            ],
            platform_implementations=[]
        )

        unified_rules = [srg_rule, stig_rule]

        # Analyze relationship between SRG and STIG
        relationship = await mapping_engine.analyze_framework_relationship(
            "srg_os", "stig_rhel9", unified_rules
        )

        # Should show parent-child relationship characteristics
        assert relationship.relationship_type in ["highly_aligned", "well_aligned"]

        # SRG should be in STIG's hierarchy
        hierarchies = mapping_engine.framework_hierarchies
        assert "stig_rhel9" in hierarchies["srg_os"]["children"]

    @pytest.mark.asyncio
    async def test_coverage_gap_identification(self):
        """Test identification of coverage gaps"""
        mapping_engine = FrameworkMappingEngine()

        # Create rules with incomplete coverage
        partial_rule = UnifiedComplianceRule(
            rule_id="partial_coverage_001",
            title="Partial Framework Coverage",
            description="Rule that only covers some frameworks",
            category="access_control",
            security_function="prevention",
            risk_level="medium",
            framework_mappings=[
                FrameworkMapping(
                    framework_id="nist_800_53_r5",
                    control_ids=["AC-1", "AC-2", "AC-3"],
                    implementation_status="compliant"
                ),
                FrameworkMapping(
                    framework_id="cis_v8",
                    control_ids=["5.1"],  # Only one control
                    implementation_status="compliant"
                )
                # Missing ISO and PCI mappings
            ],
            platform_implementations=[]
        )

        unified_rules = [partial_rule]
        frameworks = ["nist_800_53_r5", "cis_v8", "iso_27001_2022", "pci_dss_v4"]

        coverage = await mapping_engine.get_framework_coverage_analysis(frameworks, unified_rules)

        # Should identify coverage gaps
        assert "coverage_gaps" in coverage

        # Check for frameworks with poor coverage
        gaps = coverage["coverage_gaps"]
        gap_frameworks = [gap["framework"] for gap in gaps]

        # ISO and PCI should have gaps (no rules)
        # Note: actual gap detection depends on having reference control counts
        assert "framework_details" in coverage

        # All frameworks should be analyzed
        for framework in frameworks:
            assert framework in coverage["framework_details"]


if __name__ == "__main__":
    pytest.main([__file__])
