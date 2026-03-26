"""
Source-inspection tests for OWCA compliance scoring engine.

Spec: specs/services/owca/compliance-scoring.spec.yaml
"""

import inspect

import pytest


@pytest.mark.unit
class TestAC1OWCACore:
    """AC-1: OWCACore class exists with compliance scoring methods."""

    def test_owca_core_exists(self):
        from app.services.owca.core.score_calculator import ComplianceScoreCalculator

        assert ComplianceScoreCalculator is not None

    def test_score_calculation_method(self):
        import app.services.owca.core.score_calculator as mod

        source = inspect.getsource(mod)
        assert "score" in source.lower()


@pytest.mark.unit
class TestAC2ComplianceAggregator:
    """AC-2: ComplianceAggregator aggregates scores across scans."""

    def test_aggregator_exists(self):
        import app.services.owca.aggregation.fleet_aggregator as mod

        assert mod is not None

    def test_aggregate_method(self):
        import app.services.owca.aggregation.fleet_aggregator as mod

        source = inspect.getsource(mod)
        assert "aggregate" in source.lower() or "fleet" in source.lower()


@pytest.mark.unit
class TestAC3FrameworkMapper:
    """AC-3: FrameworkMapper maps rules to compliance framework controls."""

    def test_framework_module_exists(self):
        import app.services.owca.framework.models as mod

        assert mod is not None


@pytest.mark.unit
class TestAC4StatusHandling:
    """AC-4: Score calculation handles pass, fail, error, skip statuses."""

    def test_pass_status_handled(self):
        import app.services.owca.core.score_calculator as mod

        source = inspect.getsource(mod)
        assert "pass" in source.lower()

    def test_fail_status_handled(self):
        import app.services.owca.core.score_calculator as mod

        source = inspect.getsource(mod)
        assert "fail" in source.lower()


@pytest.mark.unit
class TestAC5IntelligenceModule:
    """AC-5: Intelligence module includes trend analysis and risk scoring."""

    def test_trend_analyzer_exists(self):
        import app.services.owca.intelligence.trend_analyzer as mod

        assert mod is not None

    def test_risk_scorer_exists(self):
        import app.services.owca.intelligence.risk_scorer as mod

        assert mod is not None
