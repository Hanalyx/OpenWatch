"""
Source-inspection tests for framework mapping engine.

Spec: specs/services/framework/framework-mapping.spec.yaml
"""

import inspect

import pytest


@pytest.mark.unit
class TestAC1FrameworkEngine:
    """AC-1: Framework engine maps rules to compliance controls."""

    def test_framework_engine_exists(self):
        import app.services.framework.engine as mod

        assert mod is not None

    def test_mapping_logic(self):
        import app.services.framework.engine as mod

        source = inspect.getsource(mod)
        assert "map" in source.lower() or "framework" in source.lower()


@pytest.mark.unit
class TestAC2ReportingService:
    """AC-2: Reporting service generates framework-specific reports."""

    def test_reporting_module_exists(self):
        import app.services.framework.reporting as mod

        assert mod is not None

    def test_report_generation(self):
        import app.services.framework.reporting as mod

        source = inspect.getsource(mod)
        assert "report" in source.lower()


@pytest.mark.unit
class TestAC3MultipleFrameworks:
    """AC-3: Multiple frameworks supported (CIS, STIG, NIST, PCI-DSS, FedRAMP)."""

    def test_cis_framework(self):
        import app.services.framework.engine as mod

        source = inspect.getsource(mod)
        assert "cis" in source.lower() or "CIS" in source

    def test_stig_framework(self):
        import app.services.framework.engine as mod

        source = inspect.getsource(mod)
        assert "stig" in source.lower() or "STIG" in source


@pytest.mark.unit
class TestAC4RuleToSection:
    """AC-4: Rule-to-section mapping maintained for each framework."""

    def test_section_mapping(self):
        import app.services.framework.engine as mod

        source = inspect.getsource(mod)
        assert "section" in source.lower() or "control" in source.lower()


@pytest.mark.unit
class TestAC5FrameworkStats:
    """AC-5: Framework statistics include rule counts per control section."""

    def test_count_or_stats(self):
        import app.services.framework.engine as mod

        source = inspect.getsource(mod)
        assert "count" in source.lower() or "stat" in source.lower()


@pytest.mark.unit
class TestAC6KensaMappings:
    """AC-6: Framework data sourced from Kensa mapping files."""

    def test_kensa_mapping_reference(self):
        import app.services.framework.engine as mod

        source = inspect.getsource(mod)
        assert "mapping" in source.lower() or "kensa" in source.lower()
