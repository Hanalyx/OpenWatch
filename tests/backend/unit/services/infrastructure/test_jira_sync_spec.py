"""
Source-inspection tests for Jira bidirectional sync.

Spec: specs/services/infrastructure/jira-sync.spec.yaml
Status: draft (Q2 — workstream G3)

Tests are skip-marked until the corresponding Q2 implementation lands.
Each PR in the Jira sync workstream removes skip markers from the
tests it makes passing.
"""

import pytest

SKIP_REASON = "Q2: Jira sync not yet implemented"


@pytest.mark.unit
class TestAC1JiraServiceConnects:
    """AC-1: JiraService connects to Jira API using configured credentials."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_jira_service_importable(self):
        """JiraService importable from app.services.infrastructure."""
        from app.services.infrastructure.jira_service import JiraService  # noqa: F401

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_connect_method_exists(self):
        """JiraService has a connect or client initialization method."""
        from app.services.infrastructure.jira_service import JiraService

        assert callable(getattr(JiraService, "connect", None)) or callable(
            getattr(JiraService, "__init__", None)
        )


@pytest.mark.unit
class TestAC2OutboundDriftEvents:
    """AC-2: Drift events create Jira issues with evidence summary."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_create_issue_from_drift_exists(self):
        """JiraService has a method for creating issues from drift events."""
        from app.services.infrastructure.jira_service import JiraService

        assert callable(
            getattr(JiraService, "create_issue_from_drift", None)
        )


@pytest.mark.unit
class TestAC3OutboundFailedTransactions:
    """AC-3: Failed transactions create Jira issues with rule details."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_create_issue_from_transaction_exists(self):
        """JiraService has a method for creating issues from failed transactions."""
        from app.services.infrastructure.jira_service import JiraService

        assert callable(
            getattr(JiraService, "create_issue_from_transaction", None)
        )


@pytest.mark.unit
class TestAC4InboundWebhook:
    """AC-4: POST /api/integrations/jira/webhook receives Jira state transitions."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_webhook_route_exists(self):
        """Jira webhook route is registered."""
        import inspect

        import app.routes.integrations.jira as mod

        source = inspect.getsource(mod)
        assert "webhook" in source


@pytest.mark.unit
class TestAC5InboundResolvedMapsToException:
    """AC-5: Jira issue resolved maps to OpenWatch exception updated."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_handle_resolution_exists(self):
        """JiraService has a method to handle Jira resolution events."""
        from app.services.infrastructure.jira_service import JiraService

        assert callable(
            getattr(JiraService, "handle_resolution", None)
        )


@pytest.mark.unit
class TestAC6FieldMappingConfigurable:
    """AC-6: Field mapping is configurable per Jira project via admin API."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_field_mapping_admin_route(self):
        """Admin route for Jira field mapping exists."""
        import inspect

        import app.routes.integrations.jira as mod

        source = inspect.getsource(mod)
        assert "field_mapping" in source or "field-mapping" in source


@pytest.mark.unit
class TestAC7CredentialsEncrypted:
    """AC-7: Jira credentials are encrypted at rest."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_encryption_service_used(self):
        """JiraService source references EncryptionService for credential storage."""
        import inspect

        import app.services.infrastructure.jira_service as mod

        source = inspect.getsource(mod)
        assert "EncryptionService" in source or "encrypt" in source.lower()


@pytest.mark.unit
class TestAC8SSRFProtection:
    """AC-8: SSRF protection on outbound Jira API calls."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_ssrf_protection_in_source(self):
        """JiraService source includes SSRF protection measures."""
        import inspect

        import app.services.infrastructure.jira_service as mod

        source = inspect.getsource(mod)
        assert "ssrf" in source.lower() or "allowlist" in source.lower() or "validate_url" in source.lower()
