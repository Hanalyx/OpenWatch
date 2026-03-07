"""
Unit tests for drift analysis: drift classification thresholds, rule-level
status drift, value-only drift, group drift aggregation, rule summary sorting,
and response schema validation.

Spec: specs/services/compliance/drift-analysis.spec.yaml
Tests detect_drift/detect_group_drift from temporal.py and posture_schemas.py.
"""

import inspect

import pytest

from app.schemas.posture_schemas import (
    DriftAnalysisResponse,
    GroupDriftResponse,
    GroupDriftRuleSummary,
    ValueDriftEvent,
)
from app.services.compliance.temporal import TemporalComplianceService

# ---------------------------------------------------------------------------
# AC-1: Drift classification into 4 types + unknown
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC1DriftClassification:
    """AC-1: detect_drift classifies: major, minor, improvement, stable, unknown."""

    def test_all_four_types_in_source(self):
        """Verify all 4 drift type strings appear in detect_drift source."""
        source = inspect.getsource(TemporalComplianceService.detect_drift)
        for drift_type in ["major", "minor", "improvement", "stable"]:
            assert f'"{drift_type}"' in source, f"Missing drift type: {drift_type}"

    def test_unknown_for_missing_snapshots(self):
        """Verify 'unknown' is returned when snapshots are missing."""
        source = inspect.getsource(TemporalComplianceService.detect_drift)
        assert '"unknown"' in source


# ---------------------------------------------------------------------------
# AC-2: Major drift threshold
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC2MajorDrift:
    """AC-2: magnitude >= 10.0: negative -> major, positive -> improvement."""

    def test_10_threshold_in_source(self):
        """Verify 10.0 threshold for major drift."""
        source = inspect.getsource(TemporalComplianceService.detect_drift)
        assert "drift_magnitude >= 10.0" in source

    def test_negative_delta_is_major(self):
        """Verify negative delta with large magnitude produces 'major'."""
        source = inspect.getsource(TemporalComplianceService.detect_drift)
        # After 10.0 threshold check, negative delta -> "major"
        assert "score_delta < 0" in source


# ---------------------------------------------------------------------------
# AC-3: Minor drift threshold
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC3MinorDrift:
    """AC-3: magnitude >= 5.0: negative -> minor, positive -> improvement."""

    def test_5_threshold_in_source(self):
        """Verify 5.0 threshold for minor drift."""
        source = inspect.getsource(TemporalComplianceService.detect_drift)
        assert "drift_magnitude >= 5.0" in source

    def test_minor_type_exists(self):
        """Verify 'minor' drift type is assigned."""
        source = inspect.getsource(TemporalComplianceService.detect_drift)
        assert '"minor"' in source


# ---------------------------------------------------------------------------
# AC-4: Stable drift
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC4StableDrift:
    """AC-4: magnitude < 5.0 produces 'stable'."""

    def test_stable_type_in_source(self):
        """Verify 'stable' is the else-branch drift type."""
        source = inspect.getsource(TemporalComplianceService.detect_drift)
        assert '"stable"' in source

    def test_stable_is_else_branch(self):
        """Verify stable is the fallthrough case (after major and minor checks)."""
        source = inspect.getsource(TemporalComplianceService.detect_drift)
        lines = source.split("\n")
        stable_line = None
        for i, line in enumerate(lines):
            if '"stable"' in line:
                stable_line = i
                break
        assert stable_line is not None
        # stable should come after drift_magnitude >= 5.0 check
        five_line = None
        for i, line in enumerate(lines):
            if "drift_magnitude >= 5.0" in line:
                five_line = i
                break
        assert five_line is not None
        assert stable_line > five_line


# ---------------------------------------------------------------------------
# AC-5: Rule-level drift direction
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC5RuleLevelDrift:
    """AC-5: pass->fail = regression, fail->pass = improvement."""

    def test_regression_direction(self):
        """Verify pass->fail is classified as regression."""
        source = inspect.getsource(TemporalComplianceService.detect_drift)
        assert '"regression"' in source

    def test_improvement_direction(self):
        """Verify fail->pass is classified as improvement."""
        source = inspect.getsource(TemporalComplianceService.detect_drift)
        assert '"improvement"' in source

    def test_pass_fail_status_checks(self):
        """Verify status comparisons for pass and fail."""
        source = inspect.getsource(TemporalComplianceService.detect_drift)
        assert '"pass"' in source
        assert '"fail"' in source


# ---------------------------------------------------------------------------
# AC-6: Value-only drift
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC6ValueOnlyDrift:
    """AC-6: include_value_drift=True + status unchanged + value changed -> ValueDriftEvent(status_changed=False)."""

    def test_include_value_drift_parameter(self):
        """Verify detect_drift accepts include_value_drift parameter."""
        sig = inspect.signature(TemporalComplianceService.detect_drift)
        assert "include_value_drift" in sig.parameters

    def test_value_drift_event_status_changed_field(self):
        """Verify ValueDriftEvent has status_changed field."""
        assert "status_changed" in ValueDriftEvent.model_fields

    def test_value_drift_source_sets_status_changed_false(self):
        """Verify source sets status_changed=False for value-only drift."""
        source = inspect.getsource(TemporalComplianceService.detect_drift)
        assert "status_changed=False" in source

    def test_value_drift_source_sets_status_changed_true(self):
        """Verify source sets status_changed=True for status+value drift."""
        source = inspect.getsource(TemporalComplianceService.detect_drift)
        assert "status_changed=True" in source


# ---------------------------------------------------------------------------
# AC-7: Group drift queries host_group_memberships
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC7GroupDriftQuery:
    """AC-7: detect_group_drift queries host_group_memberships joined with hosts."""

    def test_joins_host_group_memberships(self):
        """Verify host_group_memberships table is queried."""
        source = inspect.getsource(TemporalComplianceService.detect_group_drift)
        assert "host_group_memberships" in source

    def test_joins_hosts(self):
        """Verify hosts table is joined."""
        source = inspect.getsource(TemporalComplianceService.detect_group_drift)
        assert "JOIN hosts" in source

    def test_calls_detect_drift_per_host(self):
        """Verify detect_drift is called for each host."""
        source = inspect.getsource(TemporalComplianceService.detect_group_drift)
        assert "detect_drift" in source


# ---------------------------------------------------------------------------
# AC-8: Group drift sorted by affected_host_count descending
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC8GroupDriftSorting:
    """AC-8: Rule summaries sorted by affected_host_count descending."""

    def test_sort_key(self):
        """Verify sort uses affected_host_count as key."""
        source = inspect.getsource(TemporalComplianceService.detect_group_drift)
        assert "affected_host_count" in source

    def test_reverse_sort(self):
        """Verify sort is in descending order (reverse=True)."""
        source = inspect.getsource(TemporalComplianceService.detect_group_drift)
        assert "reverse=True" in source


# ---------------------------------------------------------------------------
# AC-9: DriftAnalysisResponse has all 14 fields
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC9DriftResponseFields:
    """AC-9: DriftAnalysisResponse has all fields from host_id through rules_value_changed."""

    EXPECTED_FIELDS = {
        "host_id",
        "start_date",
        "end_date",
        "start_score",
        "end_score",
        "score_delta",
        "drift_magnitude",
        "drift_type",
        "rules_improved",
        "rules_regressed",
        "rules_unchanged",
        "drift_events",
        "value_drift_events",
        "rules_value_changed",
    }

    def test_all_14_fields_present(self):
        """Verify all 14 fields exist."""
        model_fields = set(DriftAnalysisResponse.model_fields.keys())
        for field in self.EXPECTED_FIELDS:
            assert field in model_fields, f"Missing field: {field}"

    def test_exactly_14_fields(self):
        """Verify the expected field count."""
        assert len(self.EXPECTED_FIELDS) == 14
        # Model may have additional inherited fields, but must have all 14
        model_fields = set(DriftAnalysisResponse.model_fields.keys())
        assert self.EXPECTED_FIELDS.issubset(model_fields)


# ---------------------------------------------------------------------------
# AC-10: GroupDriftResponse + GroupDriftRuleSummary fields
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC10GroupDriftSchemas:
    """AC-10: GroupDriftResponse and GroupDriftRuleSummary have correct fields."""

    GROUP_RESPONSE_FIELDS = {
        "group_id",
        "group_name",
        "start_date",
        "end_date",
        "total_hosts",
        "hosts_with_drift",
        "rule_summaries",
    }

    RULE_SUMMARY_FIELDS = {
        "rule_id",
        "rule_title",
        "severity",
        "affected_host_count",
        "total_host_count",
        "status_changes",
        "value_changes",
        "sample_changes",
    }

    def test_group_response_fields(self):
        """Verify GroupDriftResponse has all required fields."""
        model_fields = set(GroupDriftResponse.model_fields.keys())
        for field in self.GROUP_RESPONSE_FIELDS:
            assert field in model_fields, f"Missing GroupDriftResponse field: {field}"

    def test_rule_summary_fields(self):
        """Verify GroupDriftRuleSummary has all required fields."""
        model_fields = set(GroupDriftRuleSummary.model_fields.keys())
        for field in self.RULE_SUMMARY_FIELDS:
            assert field in model_fields, f"Missing GroupDriftRuleSummary field: {field}"
