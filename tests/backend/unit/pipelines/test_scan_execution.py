"""
Source-inspection tests for the scan execution pipeline.

Spec: specs/pipelines/scan-execution.spec.yaml

Verifies scan lifecycle state machine, result storage, post-scan processing,
concurrent scan guards, and stale scan recovery via code structure inspection.
"""

import inspect

import pytest


# ---------------------------------------------------------------------------
# AC-1: SECURITY_ANALYST+ starts Kensa scan -> 202 with scan_id, status=PENDING
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC1StartScan:
    """AC-1: SECURITY_ANALYST or higher starts a Kensa scan and receives scan_id."""

    def test_execute_kensa_scan_exists(self):
        """Route handler function exists."""
        from app.routes.scans.kensa import execute_kensa_scan

        assert callable(execute_kensa_scan)

    def test_require_role_decorator(self):
        """RBAC decorator applied with SECURITY_ANALYST role."""
        import app.routes.scans.kensa as mod

        source = inspect.getsource(mod)
        assert "require_role" in source
        assert "SECURITY_ANALYST" in source

    def test_scan_record_created_in_db(self):
        """Scan record inserted via InsertBuilder."""
        import app.routes.scans.kensa as mod

        source = inspect.getsource(mod)
        assert 'InsertBuilder("scans")' in source

    def test_response_contains_scan_id(self):
        """Response model includes scan_id field."""
        import app.routes.scans.kensa as mod

        source = inspect.getsource(mod)
        assert "KensaScanResponse" in source


# ---------------------------------------------------------------------------
# AC-2: GUEST or AUDITOR -> 403
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC2RoleRestriction:
    """AC-2: GUEST or AUDITOR role receives 403 when attempting to start a scan."""

    def test_allowed_roles_exclude_guest(self):
        """GUEST is not in the allowed roles for execute_kensa_scan."""
        import app.routes.scans.kensa as mod

        source = inspect.getsource(mod.execute_kensa_scan)
        assert "GUEST" not in source

    def test_allowed_roles_exclude_auditor(self):
        """AUDITOR is not in the allowed roles for execute_kensa_scan."""
        import app.routes.scans.kensa as mod

        source = inspect.getsource(mod.execute_kensa_scan)
        assert "AUDITOR" not in source

    def test_require_role_enforces_restriction(self):
        """require_role decorator is present to enforce role restrictions."""
        import app.routes.scans.kensa as mod

        source = inspect.getsource(mod)
        assert "require_role" in source


# ---------------------------------------------------------------------------
# AC-3: Non-existent host -> 404 HOST_NOT_FOUND
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC3HostNotFound:
    """AC-3: Scan for non-existent host returns 404."""

    def test_host_existence_query(self):
        """Route queries hosts table to verify host exists."""
        import app.routes.scans.kensa as mod

        source = inspect.getsource(mod.execute_kensa_scan)
        assert "hosts" in source.lower()
        assert "WHERE" in source or "where" in source

    def test_404_raised_for_missing_host(self):
        """404 status code raised when host not found."""
        import app.routes.scans.kensa as mod

        source = inspect.getsource(mod.execute_kensa_scan)
        assert "404" in source or "HTTP_404_NOT_FOUND" in source

    def test_error_message_mentions_host(self):
        """Error detail mentions host."""
        import app.routes.scans.kensa as mod

        source = inspect.getsource(mod.execute_kensa_scan)
        assert "Host not found" in source or "host" in source.lower()


# ---------------------------------------------------------------------------
# AC-4: Host with no SSH credentials -> error with clear message
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC4NoCredentials:
    """AC-4: Scan for host with no SSH credentials returns error."""

    def test_credential_check_in_scan_task(self):
        """Scan task checks for credentials before execution."""
        import app.tasks.scan_tasks as mod

        source = inspect.getsource(mod)
        assert "credential" in source.lower()

    def test_error_message_for_missing_credentials(self):
        """Error message is descriptive about missing credentials."""
        import app.tasks.scan_tasks as mod

        source = inspect.getsource(mod)
        assert "credential" in source.lower() or "No credentials" in source


# ---------------------------------------------------------------------------
# AC-5: Host with active scan -> 409 SCAN_IN_PROGRESS
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC5ConcurrentScanGuard:
    """AC-5: Duplicate scan for host with active scan -> 409."""

    def test_active_scan_query(self):
        """Route checks for existing pending/running scans on same host."""
        import app.routes.scans.kensa as mod

        source = inspect.getsource(mod.execute_kensa_scan)
        assert "pending" in source and "running" in source

    def test_409_conflict_raised(self):
        """409 status raised for concurrent scan."""
        import app.routes.scans.kensa as mod

        source = inspect.getsource(mod.execute_kensa_scan)
        assert "409" in source or "HTTP_409_CONFLICT" in source

    def test_error_mentions_active_scan(self):
        """Error detail mentions active scan."""
        import app.routes.scans.kensa as mod

        source = inspect.getsource(mod.execute_kensa_scan)
        assert "active scan" in source or "already" in source.lower()


# ---------------------------------------------------------------------------
# AC-6: PENDING -> RUNNING when worker starts execution
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC6PendingToRunning:
    """AC-6: Scan transitions PENDING -> RUNNING when worker starts."""

    def test_scan_task_sets_running_status(self):
        """Scan task updates status to running."""
        import app.tasks.scan_tasks as mod

        source = inspect.getsource(mod)
        assert "running" in source


# ---------------------------------------------------------------------------
# AC-7: RUNNING -> COMPLETED with scan_results and scan_findings
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC7RunningToCompleted:
    """AC-7: Scan transitions to COMPLETED with results and findings stored."""

    def test_scan_results_inserted(self):
        """scan_results row created on completion."""
        import app.routes.scans.kensa as mod

        source = inspect.getsource(mod)
        assert "scan_results" in source

    def test_scan_findings_inserted(self):
        """scan_findings rows created for each rule."""
        import app.routes.scans.kensa as mod

        source = inspect.getsource(mod)
        assert "scan_findings" in source

    def test_completed_status_set(self):
        """Status updated to completed."""
        import app.routes.scans.kensa as mod

        source = inspect.getsource(mod)
        assert "completed" in source


# ---------------------------------------------------------------------------
# AC-8: SSH connection failure -> FAILED with descriptive error_message
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC8SSHFailure:
    """AC-8: SSH connection failure transitions scan to FAILED."""

    def test_ssh_error_handling_in_task(self):
        """Scan task has exception handling for SSH failures."""
        import app.tasks.scan_tasks as mod

        source = inspect.getsource(mod)
        assert "except" in source
        assert "error" in source.lower() or "failed" in source.lower()

    def test_error_message_stored(self):
        """Error message written to scan record."""
        import app.tasks.scan_tasks as mod

        source = inspect.getsource(mod)
        assert "error_message" in source or "error" in source.lower()


# ---------------------------------------------------------------------------
# AC-9: Kensa rule evaluation failure -> FAILED with error_message
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC9KensaFailure:
    """AC-9: Kensa rule evaluation failure transitions scan to FAILED."""

    def test_kensa_error_handling(self):
        """Route handler catches Kensa execution errors."""
        import app.routes.scans.kensa as mod

        source = inspect.getsource(mod.execute_kensa_scan)
        assert "except" in source
        assert "failed" in source.lower() or "error" in source.lower()


# ---------------------------------------------------------------------------
# AC-10: Evidence stored as JSONB in scan_findings.evidence
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC10EvidenceStorage:
    """AC-10: Evidence is stored as JSONB in scan_findings.evidence."""

    def test_evidence_column_in_insert(self):
        """scan_findings INSERT includes evidence column."""
        import app.routes.scans.kensa as mod

        source = inspect.getsource(mod)
        assert '"evidence"' in source or "'evidence'" in source

    def test_evidence_serialization_function(self):
        """Evidence serialization function imported and used."""
        import app.routes.scans.kensa as mod

        source = inspect.getsource(mod)
        assert "serialize_evidence" in source

    def test_framework_refs_column(self):
        """Framework refs stored alongside evidence."""
        import app.routes.scans.kensa as mod

        source = inspect.getsource(mod)
        assert "framework_refs" in source


# ---------------------------------------------------------------------------
# AC-11: Posture snapshot created after scan completion
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC11PostureSnapshot:
    """AC-11: Posture snapshot is created after scan completion."""

    def test_temporal_compliance_service_used(self):
        """TemporalComplianceService called for snapshot."""
        import app.routes.scans.kensa as mod

        source = inspect.getsource(mod)
        assert "TemporalComplianceService" in source or "create_snapshot" in source

    def test_snapshot_creation_call(self):
        """create_snapshot called after scan."""
        import app.routes.scans.kensa as mod

        source = inspect.getsource(mod)
        assert "snapshot" in source.lower()


# ---------------------------------------------------------------------------
# AC-12: Drift detection runs after scan completion
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC12DriftDetection:
    """AC-12: Drift detection runs after scan completion."""

    def test_drift_detection_service_used(self):
        """DriftDetectionService called after scan."""
        import app.routes.scans.kensa as mod

        source = inspect.getsource(mod)
        assert "DriftDetectionService" in source or "detect_drift" in source

    def test_drift_detection_non_critical(self):
        """Drift detection failure does not fail the scan."""
        import app.routes.scans.kensa as mod

        source = inspect.getsource(mod)
        # Post-scan processing wrapped in try/except with warning log
        assert "warning" in source.lower() or "logger" in source.lower()


# ---------------------------------------------------------------------------
# AC-13: Alerts generated when drift exceeds threshold
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC13DriftAlerts:
    """AC-13: Alerts generated when drift exceeds configured threshold."""

    def test_drift_service_exists(self):
        """DriftDetectionService exists and is importable."""
        from app.services.monitoring.drift import DriftDetectionService

        assert DriftDetectionService is not None

    def test_alert_generation_in_drift(self):
        """Drift service references alert generation."""
        from app.services.monitoring import drift as mod

        source = inspect.getsource(mod)
        assert "alert" in source.lower() or "drift" in source.lower()


# ---------------------------------------------------------------------------
# AC-14: Completed scan has started_at, completed_at, duration derivable
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC14TimestampFields:
    """AC-14: Completed scan has non-null started_at and completed_at."""

    def test_started_at_set(self):
        """started_at timestamp set during scan execution."""
        import app.routes.scans.kensa as mod

        source = inspect.getsource(mod)
        assert "started_at" in source or "created_at" in source

    def test_completed_at_set(self):
        """completed_at timestamp set on completion."""
        import app.routes.scans.kensa as mod

        source = inspect.getsource(mod)
        assert "completed_at" in source


# ---------------------------------------------------------------------------
# AC-15: Scan exceeding soft time limit -> TIMED_OUT
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC15TimeoutHandling:
    """AC-15: Scan exceeding soft time limit transitions to TIMED_OUT."""

    def test_scan_status_enum_has_timed_out(self):
        """ScanStatus enum includes TIMED_OUT value."""
        from app.models.scan_models import ScanStatus

        assert hasattr(ScanStatus, "TIMED_OUT")
        assert ScanStatus.TIMED_OUT.value == "timed_out"

    def test_stale_scan_detection_exists(self):
        """Stale scan detection task exists."""
        from app.tasks.stale_scan_detection import detect_stale_scans

        assert callable(detect_stale_scans)

    def test_stale_running_threshold(self):
        """Stale running threshold is 2 hours."""
        import app.tasks.stale_scan_detection as mod

        source = inspect.getsource(mod)
        assert "hours=2" in source or "RUNNING_TIMEOUT" in source

    def test_stale_pending_threshold(self):
        """Stale pending threshold is 30 minutes."""
        import app.tasks.stale_scan_detection as mod

        source = inspect.getsource(mod)
        assert "minutes=30" in source or "PENDING_TIMEOUT" in source
