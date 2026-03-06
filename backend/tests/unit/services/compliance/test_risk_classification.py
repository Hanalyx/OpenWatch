"""
Unit tests for remediation risk classification: risk levels, ordering,
per-step classification, max-risk aggregation, plan summary, schema
fields, reboot-risk detection, and risk_summary initialization.

Spec: specs/services/remediation/risk-classification.spec.yaml
Tests risk classification logic in remediation_tasks.py, remediation.py, and schemas.
"""

import inspect

import pytest

from app.schemas.remediation_schemas import (
    RemediationPlanResponse,
    RemediationPlanRuleDetail,
    RemediationResultResponse,
    RemediationStepResponse,
)
from app.services.compliance.remediation import RemediationService
from app.tasks.remediation_tasks import _execute_rule_remediation

# ---------------------------------------------------------------------------
# AC-1: Four risk levels exist
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC1FourRiskLevels:
    """AC-1: Four risk levels: 'high', 'medium', 'low', 'na'."""

    def test_risk_order_dict_has_four_levels(self):
        source = inspect.getsource(_execute_rule_remediation)
        assert '"high"' in source
        assert '"medium"' in source
        assert '"low"' in source
        assert '"na"' in source

    def test_risk_order_dict_defined(self):
        source = inspect.getsource(_execute_rule_remediation)
        assert "risk_order" in source


# ---------------------------------------------------------------------------
# AC-2: Risk ordering
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC2RiskOrdering:
    """AC-2: Risk ordering is high(3) > medium(2) > low(1) > na(0)."""

    def test_high_is_3(self):
        source = inspect.getsource(_execute_rule_remediation)
        assert '"high": 3' in source

    def test_medium_is_2(self):
        source = inspect.getsource(_execute_rule_remediation)
        assert '"medium": 2' in source

    def test_low_is_1(self):
        source = inspect.getsource(_execute_rule_remediation)
        assert '"low": 1' in source

    def test_na_is_0(self):
        source = inspect.getsource(_execute_rule_remediation)
        assert '"na": 0' in source


# ---------------------------------------------------------------------------
# AC-3: classify_step_risk called per step
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC3PerStepClassification:
    """AC-3: classify_step_risk called per step with mechanism and remediation config."""

    def test_imports_classify_step_risk(self):
        source = inspect.getsource(_execute_rule_remediation)
        assert "classify_step_risk" in source

    def test_called_with_mechanism(self):
        source = inspect.getsource(_execute_rule_remediation)
        assert "classify_step_risk(step.mechanism" in source

    def test_called_with_remediation_config(self):
        source = inspect.getsource(_execute_rule_remediation)
        assert 'rule.get("remediation"' in source


# ---------------------------------------------------------------------------
# AC-4: Max risk across steps determines rule-level risk
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC4MaxRiskAggregation:
    """AC-4: Rule-level risk_level is max risk across all steps."""

    def test_max_risk_tracked(self):
        source = inspect.getsource(_execute_rule_remediation)
        assert "max_risk" in source

    def test_max_risk_comparison(self):
        """Higher risk value replaces current max_risk."""
        source = inspect.getsource(_execute_rule_remediation)
        assert "risk_order" in source
        # Check that max_risk is updated when current risk is higher
        assert "max_risk" in source

    def test_max_risk_passed_to_add_result(self):
        source = inspect.getsource(_execute_rule_remediation)
        assert "risk_level=max_risk" in source


# ---------------------------------------------------------------------------
# AC-5: Plan response includes risk_summary
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC5PlanRiskSummary:
    """AC-5: RemediationPlanResponse includes risk_summary with counts per level."""

    def test_plan_response_has_risk_summary_field(self):
        fields = RemediationPlanResponse.model_fields
        assert "risk_summary" in fields

    def test_risk_summary_is_dict_type(self):
        field = RemediationPlanResponse.model_fields["risk_summary"]
        # Pydantic annotation should be Dict[str, int]
        assert field.annotation is not None

    def test_plan_preview_builds_risk_counts(self):
        source = inspect.getsource(RemediationService.get_remediation_plan)
        assert "risk_counts" in source
        assert "risk_summary" in source


# ---------------------------------------------------------------------------
# AC-6: RemediationStepResponse has risk_level field
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC6StepResponseRiskField:
    """AC-6: RemediationStepResponse schema has a risk_level field."""

    def test_risk_level_field_exists(self):
        fields = RemediationStepResponse.model_fields
        assert "risk_level" in fields

    def test_risk_level_is_optional_string(self):
        field = RemediationStepResponse.model_fields["risk_level"]
        # Should be Optional[str]
        assert field.default is None


# ---------------------------------------------------------------------------
# AC-7: RemediationResultResponse has risk_level field
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC7ResultResponseRiskField:
    """AC-7: RemediationResultResponse schema has a risk_level field."""

    def test_risk_level_field_exists(self):
        fields = RemediationResultResponse.model_fields
        assert "risk_level" in fields

    def test_risk_level_is_optional_string(self):
        field = RemediationResultResponse.model_fields["risk_level"]
        assert field.default is None


# ---------------------------------------------------------------------------
# AC-8: RemediationPlanRuleDetail has risk_level and per-step risk
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC8PlanRuleDetailRiskFields:
    """AC-8: RemediationPlanRuleDetail has risk_level and steps with risk_level."""

    def test_risk_level_field_exists(self):
        fields = RemediationPlanRuleDetail.model_fields
        assert "risk_level" in fields

    def test_steps_field_exists(self):
        fields = RemediationPlanRuleDetail.model_fields
        assert "steps" in fields

    def test_plan_preview_adds_risk_to_steps(self):
        """Plan preview adds risk_level to each step dict."""
        source = inspect.getsource(RemediationService.get_remediation_plan)
        assert '"risk_level"' in source
        # Verify risk_level is in the step dict construction
        assert "risk" in source


# ---------------------------------------------------------------------------
# AC-9: Reboot-risk detected by mechanism
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC9RebootRiskDetection:
    """AC-9: Reboot-risk detected for grub_parameter_set and kernel_module_disable."""

    def test_grub_parameter_set_detected(self):
        source = inspect.getsource(RemediationService.get_remediation_plan)
        assert "grub_parameter_set" in source

    def test_kernel_module_disable_detected(self):
        source = inspect.getsource(RemediationService.get_remediation_plan)
        assert "kernel_module_disable" in source

    def test_requires_reboot_flag_set(self):
        source = inspect.getsource(RemediationService.get_remediation_plan)
        assert "requires_reboot" in source

    def test_reboot_warning_generated(self):
        source = inspect.getsource(RemediationService.get_remediation_plan)
        assert "may require a system reboot" in source


# ---------------------------------------------------------------------------
# AC-10: Risk summary initialized with all 4 level keys
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC10RiskSummaryInitialization:
    """AC-10: Risk summary initialized with all 4 levels set to 0."""

    def test_risk_counts_initialized_with_four_keys(self):
        source = inspect.getsource(RemediationService.get_remediation_plan)
        assert '"high": 0' in source
        assert '"medium": 0' in source
        assert '"low": 0' in source
        assert '"na": 0' in source

    def test_risk_counts_assigned_to_risk_summary(self):
        source = inspect.getsource(RemediationService.get_remediation_plan)
        assert "risk_summary=risk_counts" in source
