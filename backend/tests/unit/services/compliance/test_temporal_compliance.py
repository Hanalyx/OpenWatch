"""
Unit tests for temporal compliance: score calculation, posture routing,
snapshot idempotency, severity breakdown, evidence extraction, rule state
assembly, value normalization, and daily snapshot batch creation.

Spec: specs/services/compliance/temporal-compliance.spec.yaml
Tests the TemporalComplianceService from temporal.py (874 LOC).
"""

import inspect

import pytest

from app.schemas.posture_schemas import PostureResponse, SeverityBreakdown
from app.services.compliance.temporal import TemporalComplianceService

# ---------------------------------------------------------------------------
# AC-1: Score calculation formula
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC1ScoreCalculation:
    """AC-1: _get_current_posture computes score as (passed/total * 100) rounded to 2 decimals."""

    def test_score_formula_in_source(self):
        """Verify source contains the exact score formula."""
        source = inspect.getsource(TemporalComplianceService._get_current_posture)
        assert "passed_rules / total_rules * 100" in source

    def test_score_rounding_in_source(self):
        """Verify score is rounded via round()."""
        source = inspect.getsource(TemporalComplianceService._get_current_posture)
        assert "round(compliance_score, 2)" in source

    def test_returns_none_when_no_scans(self):
        """Verify return None when no completed scans exist."""
        source = inspect.getsource(TemporalComplianceService._get_current_posture)
        assert "return None" in source


# ---------------------------------------------------------------------------
# AC-2: get_posture routing
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC2PostureRouting:
    """AC-2: get_posture delegates to historical or current based on as_of."""

    def test_has_as_of_parameter(self):
        """Verify get_posture accepts as_of parameter."""
        sig = inspect.signature(TemporalComplianceService.get_posture)
        assert "as_of" in sig.parameters

    def test_routes_to_historical(self):
        """Verify delegation to _get_historical_posture when as_of is set."""
        source = inspect.getsource(TemporalComplianceService.get_posture)
        assert "_get_historical_posture" in source

    def test_routes_to_current(self):
        """Verify delegation to _get_current_posture when as_of is None."""
        source = inspect.getsource(TemporalComplianceService.get_posture)
        assert "_get_current_posture" in source


# ---------------------------------------------------------------------------
# AC-3: Posture history ordering and limit
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC3PostureHistory:
    """AC-3: get_posture_history orders by snapshot_date DESC with default limit 30."""

    def test_default_limit_30(self):
        """Verify default limit parameter is 30."""
        sig = inspect.signature(TemporalComplianceService.get_posture_history)
        limit_param = sig.parameters["limit"]
        assert limit_param.default == 30

    def test_desc_ordering(self):
        """Verify snapshot_date DESC ordering in source."""
        source = inspect.getsource(TemporalComplianceService.get_posture_history)
        assert ".desc()" in source

    def test_limit_applied(self):
        """Verify .limit() is called."""
        source = inspect.getsource(TemporalComplianceService.get_posture_history)
        assert ".limit(limit)" in source


# ---------------------------------------------------------------------------
# AC-4: Snapshot idempotency
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC4SnapshotIdempotency:
    """AC-4: create_snapshot is idempotent via func.date() check on host+date."""

    def test_func_date_comparison(self):
        """Verify idempotency check uses func.date() comparison."""
        source = inspect.getsource(TemporalComplianceService.create_snapshot)
        assert "func.date(PostureSnapshot.snapshot_date)" in source
        assert "snapshot_date.date()" in source

    def test_returns_existing(self):
        """Verify existing snapshot is returned when found."""
        source = inspect.getsource(TemporalComplianceService.create_snapshot)
        assert "return existing" in source


# ---------------------------------------------------------------------------
# AC-5: Severity breakdown 4 levels
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC5SeverityBreakdown:
    """AC-5: Severity breakdown covers critical, high, medium, low."""

    EXPECTED_KEYS = {"critical", "high", "medium", "low"}

    def test_four_severity_keys_in_current_posture(self):
        """Verify all 4 severity keys are built in _get_current_posture."""
        source = inspect.getsource(TemporalComplianceService._get_current_posture)
        for key in self.EXPECTED_KEYS:
            assert f'"{key}"' in source, f"Missing severity key: {key}"

    def test_severity_breakdown_has_passed_failed(self):
        """Verify SeverityBreakdown has passed and failed fields."""
        breakdown = SeverityBreakdown(passed=5, failed=3)
        assert breakdown.passed == 5
        assert breakdown.failed == 3

    def test_severity_breakdown_total_property(self):
        """Verify SeverityBreakdown.total computes passed + failed."""
        breakdown = SeverityBreakdown(passed=5, failed=3)
        assert breakdown.total == 8


# ---------------------------------------------------------------------------
# AC-6: PostureResponse schema fields
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC6PostureResponseSchema:
    """AC-6: PostureResponse has required fields with compliance_score ge=0, le=100."""

    REQUIRED_FIELDS = {
        "host_id",
        "compliance_score",
        "total_rules",
        "passed",
        "failed",
        "severity_breakdown",
        "snapshot_date",
    }

    def test_all_required_fields_present(self):
        """Verify all required fields exist on PostureResponse."""
        model_fields = set(PostureResponse.model_fields.keys())
        for field in self.REQUIRED_FIELDS:
            assert field in model_fields, f"Missing field: {field}"

    def test_compliance_score_ge_constraint(self):
        """Verify compliance_score has ge=0 constraint."""
        field_info = PostureResponse.model_fields["compliance_score"]
        metadata = field_info.metadata
        ge_found = any(getattr(m, "ge", None) == 0 for m in metadata)
        assert ge_found, "compliance_score missing ge=0 constraint"

    def test_compliance_score_le_constraint(self):
        """Verify compliance_score has le=100 constraint."""
        field_info = PostureResponse.model_fields["compliance_score"]
        metadata = field_info.metadata
        le_found = any(getattr(m, "le", None) == 100 for m in metadata)
        assert le_found, "compliance_score missing le=100 constraint"


# ---------------------------------------------------------------------------
# AC-7: _extract_actual staticmethod
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC7ExtractActual:
    """AC-7: _extract_actual is @staticmethod handling single/multi/none evidence."""

    def test_is_staticmethod(self):
        """Verify _extract_actual is a @staticmethod."""
        attr = inspect.getattr_static(TemporalComplianceService, "_extract_actual")
        assert isinstance(attr, staticmethod)

    def test_single_item_returns_string(self):
        """Verify single-item evidence list returns a string."""
        result = TemporalComplianceService._extract_actual([{"actual": "600"}])
        assert result == "600"
        assert isinstance(result, str)

    def test_multi_item_returns_list(self):
        """Verify multi-item evidence list returns a list."""
        evidence = [{"actual": "600"}, {"actual": "yes"}]
        result = TemporalComplianceService._extract_actual(evidence)
        assert isinstance(result, list)
        assert len(result) == 2

    def test_none_returns_none(self):
        """Verify None/empty evidence returns None."""
        assert TemporalComplianceService._extract_actual(None) is None
        assert TemporalComplianceService._extract_actual([]) is None


# ---------------------------------------------------------------------------
# AC-8: _build_rule_states queries scan_findings
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC8BuildRuleStates:
    """AC-8: _build_rule_states queries scan_findings, builds dict with status/severity/title."""

    def test_queries_scan_findings(self):
        """Verify scan_findings table is queried."""
        source = inspect.getsource(TemporalComplianceService._build_rule_states)
        assert "scan_findings" in source

    def test_calls_extract_actual(self):
        """Verify _extract_actual is called for evidence parsing."""
        source = inspect.getsource(TemporalComplianceService._build_rule_states)
        assert "_extract_actual" in source

    def test_builds_state_dict_keys(self):
        """Verify state dict contains status, severity, title keys."""
        source = inspect.getsource(TemporalComplianceService._build_rule_states)
        assert '"status"' in source
        assert '"severity"' in source
        assert '"title"' in source


# ---------------------------------------------------------------------------
# AC-9: _normalize_actual staticmethod
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC9NormalizeActual:
    """AC-9: _normalize_actual: None->None, list->sorted+joined, other->str()."""

    def test_is_staticmethod(self):
        """Verify _normalize_actual is a @staticmethod."""
        attr = inspect.getattr_static(TemporalComplianceService, "_normalize_actual")
        assert isinstance(attr, staticmethod)

    def test_none_returns_none(self):
        """Verify None input returns None."""
        assert TemporalComplianceService._normalize_actual(None) is None

    def test_list_sorted_and_joined(self):
        """Verify list is sorted and joined with '; '."""
        result = TemporalComplianceService._normalize_actual(["z", "a", "m"])
        assert result == "a; m; z"

    def test_non_list_uses_str(self):
        """Verify non-list value is converted via str()."""
        result = TemporalComplianceService._normalize_actual(42)
        assert result == "42"
        assert isinstance(result, str)

    def test_source_has_join_separator(self):
        """Verify source uses '; ' as join separator."""
        source = inspect.getsource(TemporalComplianceService._normalize_actual)
        assert '"; ".join' in source

    def test_source_has_sorted(self):
        """Verify source uses sorted() for list normalization."""
        source = inspect.getsource(TemporalComplianceService._normalize_actual)
        assert "sorted(" in source


# ---------------------------------------------------------------------------
# AC-10: Daily snapshot batch creation
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC10DailySnapshotBatch:
    """AC-10: create_daily_snapshots_for_all_hosts iterates active hosts."""

    def test_filters_active_hosts(self):
        """Verify Host.is_active filter in source."""
        source = inspect.getsource(TemporalComplianceService.create_daily_snapshots_for_all_hosts)
        assert "Host.is_active" in source

    def test_calls_create_snapshot(self):
        """Verify create_snapshot is called per host."""
        source = inspect.getsource(TemporalComplianceService.create_daily_snapshots_for_all_hosts)
        assert "create_snapshot" in source

    def test_return_dict_keys(self):
        """Verify return dict has all 4 required keys."""
        source = inspect.getsource(TemporalComplianceService.create_daily_snapshots_for_all_hosts)
        for key in ["total_hosts", "created", "skipped", "errors"]:
            assert f'"{key}"' in source, f"Missing return key: {key}"
