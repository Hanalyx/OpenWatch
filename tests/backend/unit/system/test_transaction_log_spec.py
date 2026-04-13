"""
Source-inspection tests for the unified transaction log.

Spec: specs/system/transaction-log.spec.yaml
Status: draft (Q1 — promotion to active scheduled for week 12)

Tests are skip-marked until the corresponding Q1 implementation lands.
Each PR in the transaction log workstream removes skip markers from the
tests it makes passing. At week 12, all tests must pass and the spec
promotes to active.
"""

import pytest

SKIP_REASON = "Q1: transaction log not yet implemented"


@pytest.mark.unit
class TestAC1TransactionsTableExists:
    """AC-1: transactions table exists with specified columns and indexes."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_model_defined(self):
        """Transaction SQLAlchemy model importable from app.models.transaction_models."""
        from app.models.transaction_models import Transaction  # noqa: F401

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_required_columns(self):
        """Model has all required columns per spec."""
        from app.models.transaction_models import Transaction

        required = {
            "id", "host_id", "rule_id", "scan_id", "phase", "status",
            "severity", "initiator_type", "initiator_id", "pre_state",
            "apply_plan", "validate_result", "post_state", "evidence_envelope",
            "framework_refs", "baseline_id", "remediation_job_id",
            "started_at", "completed_at", "duration_ms", "tenant_id",
        }
        actual = {c.name for c in Transaction.__table__.columns}
        assert required.issubset(actual)


@pytest.mark.unit
class TestAC2DualWriteAtomic:
    """AC-2: Kensa scan atomically inserts both transactions and legacy rows."""

    def test_dual_write_in_kensa_scan_tasks(self):
        """kensa_scan_tasks writes scan_findings and delegates transaction writes to state_writer."""
        import inspect

        import app.tasks.kensa_scan_tasks as mod

        source = inspect.getsource(mod)
        assert 'InsertBuilder("scan_findings")' in source
        # Transaction INSERT moved to state_writer; kensa_scan_tasks calls process_rule_result
        assert "process_rule_result" in source or "state_writer" in source


@pytest.mark.unit
class TestAC3EnvelopeSchemaVersion:
    """AC-3: evidence_envelope.schema_version is 1.0 and kensa_version captured."""

    def test_envelope_builder_sets_schema_version(self):
        import inspect

        import app.plugins.kensa.evidence as mod

        source = inspect.getsource(mod)
        assert "ENVELOPE_SCHEMA_VERSION" in source
        assert "kensa_version" in source

    def test_envelope_constants_defined(self):
        from app.plugins.kensa.evidence import (
            ENVELOPE_SCHEMA_VERSION,
            ENVELOPE_SCHEMA_VERSION_BACKFILL,
        )

        assert ENVELOPE_SCHEMA_VERSION == "1.0"
        assert ENVELOPE_SCHEMA_VERSION_BACKFILL == "0.9"


@pytest.mark.unit
class TestAC4ReadOnlyCheckEnvelope:
    """AC-4: read-only checks populate phases.validate and phases.capture."""

    def test_build_evidence_envelope_importable(self):
        from app.plugins.kensa.evidence import build_evidence_envelope

        assert callable(build_evidence_envelope)

    def test_envelope_has_capture_and_validate_phases(self):
        """build_evidence_envelope source populates capture and validate."""
        import inspect

        import app.plugins.kensa.evidence as mod

        source = inspect.getsource(mod.build_evidence_envelope)
        assert '"capture"' in source
        assert '"validate"' in source
        assert '"commit"' in source


@pytest.mark.unit
class TestAC5RemediationFourPhases:
    """AC-5: remediation transactions populate all four phases."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_remediation_envelope_four_phases(self):
        pass  # placeholder — exercises remediation write path


@pytest.mark.unit
class TestAC6BackfillIdempotent:
    """AC-6: backfill_transactions_from_scans is idempotent."""

    def test_backfill_task_exists(self):
        from app.tasks.transaction_backfill_tasks import (  # noqa: F401
            backfill_transactions_from_scans,
        )


@pytest.mark.unit
class TestAC7BackfillSchemaVersion:
    """AC-7: backfilled rows marked schema_version=0.9."""

    def test_backfill_sets_historical_schema_version(self):
        import inspect

        import app.tasks.transaction_backfill_tasks as mod

        source = inspect.getsource(mod)
        assert '"schema_version": "0.9"' in source


@pytest.mark.unit
class TestAC8AuditQueryReadsTransactions:
    """AC-8: AuditQueryService reads from transactions table."""

    def test_audit_query_reads_transactions(self):
        import inspect

        import app.services.compliance.audit_query as mod

        source = inspect.getsource(mod)
        assert "transactions" in source.lower()


@pytest.mark.unit
class TestAC9TemporalQueryPerformance:
    """AC-9: get_posture p95 < 500ms on 1M-row fixture."""

    @pytest.mark.skip(reason=SKIP_REASON)
    @pytest.mark.slow
    def test_get_posture_p95_under_500ms(self):
        pass  # benchmark test — implemented in integration suite


@pytest.mark.unit
class TestAC10DriftFromAggregates:
    """AC-10: DriftDetectionService computes from transaction aggregates."""

    def test_temporal_service_reads_transactions(self):
        import inspect

        import app.services.compliance.temporal as mod

        source = inspect.getsource(mod)
        assert "transactions" in source.lower()


@pytest.mark.unit
class TestAC11AlertGeneratorReadsTransactions:
    """AC-11: AlertGeneratorService queries transactions."""

    def test_alert_generator_reads_transactions(self):
        import inspect

        import app.services.compliance.alert_generator as mod

        source = inspect.getsource(mod)
        assert "transactions" in source.lower()


@pytest.mark.unit
class TestAC12AuditExportParity:
    """AC-12: audit export produces byte-identical output post-migration."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_parity_regression_test_exists(self):
        from pathlib import Path

        test_path = Path("tests/backend/integration/test_audit_export_parity.py")
        assert test_path.exists()


@pytest.mark.unit
class TestAC13AuditExportFallback:
    """AC-13: AUDIT_EXPORT_SOURCE flag falls back to legacy tables."""

    def test_audit_export_source_flag(self):
        import inspect

        import app.services.compliance.audit_export as mod

        source = inspect.getsource(mod)
        assert "AUDIT_EXPORT_SOURCE" in source


@pytest.mark.unit
class TestAC14SQLBuildersUsed:
    """AC-14: All transaction reads use QueryBuilder, writes use InsertBuilder."""

    def test_dual_write_uses_insert_builder(self):
        """kensa_scan_tasks uses InsertBuilder for transactions writes."""
        import inspect

        import app.tasks.kensa_scan_tasks as mod

        source = inspect.getsource(mod)
        assert 'InsertBuilder("transactions")' in source


@pytest.mark.unit
class TestAC15LegacyTablesStillWritten:
    """AC-15: legacy tables remain written during Q1 for rollback safety."""

    def test_legacy_write_path_preserved(self):
        import inspect

        import app.tasks.kensa_scan_tasks as mod

        source = inspect.getsource(mod)
        assert 'InsertBuilder("scans")' in source
        assert 'InsertBuilder("scan_results")' in source
        assert 'InsertBuilder("scan_findings")' in source


@pytest.mark.unit
class TestAC16DualWritePerformance:
    """AC-16: dual-write adds less than 10% overhead."""

    @pytest.mark.skip(reason=SKIP_REASON)
    @pytest.mark.slow
    def test_dual_write_overhead_under_10_percent(self):
        pass  # benchmark — integration suite


@pytest.mark.unit
class TestAC17ScanIdForeignKeyBehavior:
    """AC-17: transactions.scan_id uses ON DELETE SET NULL."""

    def test_scan_id_on_delete_set_null(self):
        from pathlib import Path

        migration = Path("backend/alembic/versions/20260411_2100_044_add_transactions_table.py")
        assert migration.exists(), f"Migration file not found: {migration}"
        content = migration.read_text()
        assert "ondelete='SET NULL'" in content or 'ondelete="SET NULL"' in content
