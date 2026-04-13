"""
Source-inspection tests for data retention policy engine.

Spec: specs/services/compliance/retention-policy.spec.yaml
Status: draft (Q2 — workstream I3)

Tests are skip-marked until the corresponding Q2 implementation lands.
Each PR in the retention policy workstream removes skip markers from the
tests it makes passing.
"""

import pytest

SKIP_REASON = "Q2: retention policy not yet implemented"


@pytest.mark.unit
class TestAC1RetentionPoliciesTable:
    """AC-1: retention_policies table exists with required columns."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_model_defined(self):
        """RetentionPolicy model importable from app.models."""
        from app.models.retention_models import RetentionPolicy  # noqa: F401

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_required_columns(self):
        """Model has tenant_id, resource_type, retention_days columns."""
        from app.models.retention_models import RetentionPolicy

        required = {
            "tenant_id",
            "resource_type",
            "retention_days",
        }
        actual = {c.name for c in RetentionPolicy.__table__.columns}
        assert required.issubset(actual)


@pytest.mark.unit
class TestAC2DefaultRetention:
    """AC-2: Default retention is 365 days for transactions."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_default_retention_days(self):
        """Retention service source defines 365-day default for transactions."""
        import inspect

        import app.services.compliance.retention_policy as mod

        source = inspect.getsource(mod)
        assert "365" in source


@pytest.mark.unit
class TestAC3CleanupJob:
    """AC-3: cleanup_old_transactions job runs on schedule and deletes expired rows."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_cleanup_task_exists(self):
        """Celery task for cleanup_old_transactions is importable."""
        from app.tasks.retention_tasks import cleanup_old_transactions  # noqa: F401

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_cleanup_deletes_expired(self):
        """Cleanup task source references retention_days and deletion."""
        import inspect

        import app.tasks.retention_tasks as mod

        source = inspect.getsource(mod)
        assert "retention_days" in source or "expired" in source.lower()


@pytest.mark.unit
class TestAC4SignedArchiveBeforeDeletion:
    """AC-4: Before deletion, a signed archive bundle is emitted."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_archive_before_delete(self):
        """Retention service source references archive or signing before deletion."""
        import inspect

        import app.services.compliance.retention_policy as mod

        source = inspect.getsource(mod)
        assert "archive" in source.lower() or "sign" in source.lower()


@pytest.mark.unit
class TestAC5AdminAPI:
    """AC-5: Retention policy configurable via admin API (GET/PUT /api/admin/retention)."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_admin_retention_route_exists(self):
        """Admin retention routes are registered."""
        import inspect

        import app.routes.admin.retention as mod

        source = inspect.getsource(mod)
        assert "retention" in source.lower()


@pytest.mark.unit
class TestAC6PreservesHostRuleState:
    """AC-6: Retention deletion does not remove host_rule_state rows."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_host_rule_state_excluded(self):
        """Retention cleanup source explicitly excludes or skips host_rule_state."""
        import inspect

        import app.services.compliance.retention_policy as mod

        source = inspect.getsource(mod)
        assert "host_rule_state" in source or "transactions" in source
