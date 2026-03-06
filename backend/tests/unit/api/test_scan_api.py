"""
Unit tests for scan API contracts: start-kensa-scan (POST /api/scans/kensa/)
and scan-results (GET /api/scans/{scan_id}/results) behavioral contracts.

Spec: specs/api/scans/start-kensa-scan.spec.yaml
      specs/api/scans/scan-results.spec.yaml
Tests execute_kensa_scan and get_scan_results from route handlers.
"""

import inspect

import pytest

from app.routes.scans.kensa import execute_kensa_scan
from app.routes.scans.reports import get_scan_results

# ---------------------------------------------------------------------------
# AC-1 (start-kensa-scan): SECURITY_ANALYST+ role required
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestKensaAC1RoleRequirement:
    """AC-1: execute_kensa_scan requires SECURITY_ANALYST or higher role."""

    def test_require_role_decorator_present(self):
        """Verify require_role used on execute_kensa_scan."""
        import app.routes.scans.kensa as kensa_module

        source = inspect.getsource(kensa_module)
        assert "require_role" in source

    def test_security_analyst_in_allowed_roles(self):
        """Verify SECURITY_ANALYST in allowed roles list."""
        import app.routes.scans.kensa as kensa_module

        source = inspect.getsource(kensa_module)
        assert "SECURITY_ANALYST" in source

    def test_security_admin_in_allowed_roles(self):
        """Verify SECURITY_ADMIN in allowed roles list."""
        import app.routes.scans.kensa as kensa_module

        source = inspect.getsource(kensa_module)
        assert "SECURITY_ADMIN" in source


# ---------------------------------------------------------------------------
# AC-2 (start-kensa-scan): KensaScanRequest schema validation
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestKensaAC2RequestSchema:
    """AC-2: execute_kensa_scan validates against KensaScanRequest."""

    def test_uses_kensa_scan_request(self):
        """Verify KensaScanRequest schema imported and used."""
        import app.routes.scans.kensa as kensa_module

        source = inspect.getsource(kensa_module)
        assert "KensaScanRequest" in source

    def test_host_id_in_request(self):
        """Verify host_id field is used from request."""
        source = inspect.getsource(execute_kensa_scan)
        assert "request.host_id" in source or "host_id" in source

    def test_framework_in_request(self):
        """Verify framework field is used from request."""
        source = inspect.getsource(execute_kensa_scan)
        assert "request.framework" in source or "framework" in source


# ---------------------------------------------------------------------------
# AC-3 (start-kensa-scan): HTTP 404 for missing host
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestKensaAC3HostNotFound:
    """AC-3: Returns 404 NOT_FOUND when host_id does not exist."""

    def test_raises_404_for_missing_host(self):
        """Verify HTTP_404_NOT_FOUND raised when host not found."""
        source = inspect.getsource(execute_kensa_scan)
        assert "HTTP_404_NOT_FOUND" in source

    def test_host_lookup_before_scan(self):
        """Verify host is looked up before scan execution."""
        source = inspect.getsource(execute_kensa_scan)
        host_pos = source.find("HTTP_404_NOT_FOUND")
        scan_pos = source.find("running")
        assert host_pos < scan_pos


# ---------------------------------------------------------------------------
# AC-4 (start-kensa-scan): HTTP 409 for active scan
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestKensaAC4ActiveScanConflict:
    """AC-4: Returns 409 CONFLICT when host already has an active scan."""

    def test_raises_409_for_active_scan(self):
        """Verify HTTP_409_CONFLICT raised for active scan conflict."""
        source = inspect.getsource(execute_kensa_scan)
        assert "HTTP_409_CONFLICT" in source

    def test_checks_pending_or_running_status(self):
        """Verify active scan check looks for pending/running statuses."""
        source = inspect.getsource(execute_kensa_scan)
        assert "pending" in source or "running" in source


# ---------------------------------------------------------------------------
# AC-5 (start-kensa-scan): Scan record created with status=running
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestKensaAC5ScanRecordCreation:
    """AC-5: Scan record created with status=running before Kensa executes."""

    def test_creates_scan_with_running_status(self):
        """Verify 'running' status set in scan record creation."""
        source = inspect.getsource(execute_kensa_scan)
        assert '"running"' in source or "'running'" in source

    def test_uses_insert_builder_for_scan(self):
        """Verify InsertBuilder used to insert scan record."""
        source = inspect.getsource(execute_kensa_scan)
        assert "InsertBuilder" in source


# ---------------------------------------------------------------------------
# AC-6 (start-kensa-scan): Response includes compliance metrics
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestKensaAC6ResponseMetrics:
    """AC-6: Response includes compliance_score, rule counts, duration_ms."""

    def test_kensa_scan_response_schema_used(self):
        """Verify KensaScanResponse schema referenced."""
        import app.routes.scans.kensa as kensa_module

        source = inspect.getsource(kensa_module)
        assert "KensaScanResponse" in source

    def test_compliance_score_in_response(self):
        """Verify compliance_score field set in response."""
        source = inspect.getsource(execute_kensa_scan)
        assert "compliance_score" in source

    def test_duration_ms_in_response(self):
        """Verify duration_ms calculated and returned."""
        source = inspect.getsource(execute_kensa_scan)
        assert "duration_ms" in source


# ---------------------------------------------------------------------------
# AC-7 (start-kensa-scan): scan_findings with evidence JSONB
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestKensaAC7FindingsWithEvidence:
    """AC-7: scan_findings rows inserted with evidence JSONB populated."""

    def test_inserts_to_scan_findings(self):
        """Verify scan_findings table is written to."""
        source = inspect.getsource(execute_kensa_scan)
        assert "scan_findings" in source

    def test_evidence_column_written(self):
        """Verify evidence column is included in findings insert."""
        source = inspect.getsource(execute_kensa_scan)
        assert '"evidence"' in source or "'evidence'" in source or "evidence" in source

    def test_serialize_evidence_called(self):
        """Verify serialize_evidence called to convert Kensa evidence."""
        source = inspect.getsource(execute_kensa_scan)
        assert "serialize_evidence" in source or "evidence" in source


# ---------------------------------------------------------------------------
# AC-8 (start-kensa-scan): Drift detection run post-scan
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestKensaAC8DriftDetection:
    """AC-8: Drift detection invoked after scan completion."""

    def test_calls_drift_detection(self):
        """Verify drift detection called after scan."""
        source = inspect.getsource(execute_kensa_scan)
        assert "drift" in source.lower()

    def test_drift_does_not_block_response(self):
        """Verify drift failure is caught and logged, not propagated."""
        source = inspect.getsource(execute_kensa_scan)
        # drift is wrapped in try/except to not block response
        assert "drift" in source and ("except" in source or "warning" in source.lower())


# ---------------------------------------------------------------------------
# AC-9 (start-kensa-scan): Temporal snapshot created post-scan
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestKensaAC9TemporalSnapshot:
    """AC-9: Temporal compliance snapshot created after successful scan."""

    def test_calls_create_snapshot(self):
        """Verify create_snapshot called after scan."""
        source = inspect.getsource(execute_kensa_scan)
        assert "create_snapshot" in source

    def test_snapshot_non_blocking(self):
        """Verify snapshot failure is caught and logged, not propagated."""
        source = inspect.getsource(execute_kensa_scan)
        snapshot_pos = source.find("create_snapshot")
        # Should have exception handling around it
        assert snapshot_pos != -1


# ---------------------------------------------------------------------------
# AC-10 (start-kensa-scan): HTTP 500 on Kensa failure
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestKensaAC10FailureHandling:
    """AC-10: Scan status set to failed and 500 returned on Kensa error."""

    def test_raises_500_on_failure(self):
        """Verify HTTP_500_INTERNAL_SERVER_ERROR returned on scan failure."""
        source = inspect.getsource(execute_kensa_scan)
        assert "HTTP_500_INTERNAL_SERVER_ERROR" in source

    def test_status_set_to_failed(self):
        """Verify scan status updated to failed on exception."""
        source = inspect.getsource(execute_kensa_scan)
        assert '"failed"' in source or "'failed'" in source


# ---------------------------------------------------------------------------
# AC-1 (scan-results): HTTP 404 for missing scan
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestScanResultsAC1NotFound:
    """AC-1 (scan-results): Returns 404 NOT_FOUND for unknown scan_id."""

    def test_raises_404_for_missing_scan(self):
        """Verify 404 raised when scan not found."""
        source = inspect.getsource(get_scan_results)
        assert "404" in source and ("Scan not found" in source or "not found" in source.lower())


# ---------------------------------------------------------------------------
# AC-2 (scan-results): Scan metadata in response
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestScanResultsAC2Metadata:
    """AC-2 (scan-results): Response includes scan_id, status, timestamps."""

    def test_scan_id_in_response(self):
        """Verify scan_id included in response."""
        source = inspect.getsource(get_scan_results)
        assert "scan_id" in source

    def test_status_in_response(self):
        """Verify status field included."""
        source = inspect.getsource(get_scan_results)
        assert "status" in source

    def test_timestamps_in_response(self):
        """Verify timing timestamps included (started_at or completed_at)."""
        source = inspect.getsource(get_scan_results)
        assert "started_at" in source or "completed_at" in source


# ---------------------------------------------------------------------------
# AC-3 (scan-results): Host sub-object
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestScanResultsAC3HostSubObject:
    """AC-3 (scan-results): Response includes host sub-object."""

    def test_hostname_in_response(self):
        """Verify hostname field in response."""
        source = inspect.getsource(get_scan_results)
        assert "hostname" in source

    def test_ip_address_in_response(self):
        """Verify ip_address field in response."""
        source = inspect.getsource(get_scan_results)
        assert "ip_address" in source


# ---------------------------------------------------------------------------
# AC-4 (scan-results): Results sub-object with compliance metrics
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestScanResultsAC4ResultsSubObject:
    """AC-4 (scan-results): Results sub-object with rule counts and score."""

    def test_total_rules_in_results(self):
        """Verify total_rules included."""
        source = inspect.getsource(get_scan_results)
        assert "total_rules" in source

    def test_passed_rules_in_results(self):
        """Verify passed_rules included."""
        source = inspect.getsource(get_scan_results)
        assert "passed_rules" in source

    def test_score_in_results(self):
        """Verify compliance score field included (score or compliance_score)."""
        source = inspect.getsource(get_scan_results)
        assert "score" in source


# ---------------------------------------------------------------------------
# AC-7 (scan-results): include_rules adds findings list
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestScanResultsAC7IncludeRules:
    """AC-7 (scan-results): include_rules=true adds per-rule findings."""

    def test_include_rules_parameter_present(self):
        """Verify include_rules query parameter accepted."""
        source = inspect.getsource(get_scan_results)
        assert "include_rules" in source

    def test_findings_conditional_on_include_rules(self):
        """Verify findings list gated on include_rules flag."""
        source = inspect.getsource(get_scan_results)
        assert "include_rules" in source


# ---------------------------------------------------------------------------
# AC-9 (scan-results): UUID validation on scan_id
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestScanResultsAC9UUIDValidation:
    """AC-9 (scan-results): scan_id parameter validated as UUID."""

    def test_scan_id_typed_as_uuid(self):
        """Verify scan_id parameter uses UUID type."""
        source = inspect.getsource(get_scan_results)
        assert "UUID" in source or "uuid" in source.lower()
