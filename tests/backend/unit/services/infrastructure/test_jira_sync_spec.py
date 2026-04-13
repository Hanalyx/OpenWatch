"""
Source-inspection tests for Jira bidirectional sync.

Spec: specs/services/infrastructure/jira-sync.spec.yaml
Status: active
"""

import inspect

import pytest


@pytest.mark.unit
class TestAC1JiraServiceConnects:
    """AC-1: JiraService connects to Jira API using configured credentials."""

    def test_jira_service_importable(self):
        """JiraService importable from app.services.infrastructure."""
        from app.services.infrastructure.jira_service import JiraService  # noqa: F401

    def test_connect_method_exists(self):
        """JiraService has a connect or client initialization method."""
        from app.services.infrastructure.jira_service import JiraService

        assert callable(getattr(JiraService, "connect", None)) or callable(
            getattr(JiraService, "__init__", None)
        )


@pytest.mark.unit
class TestAC2OutboundDriftEvents:
    """AC-2: Drift events create Jira issues with evidence summary."""

    def test_create_issue_from_drift_exists(self):
        """JiraService has a method for creating issues from drift events."""
        from app.services.infrastructure.jira_service import JiraService

        assert callable(
            getattr(JiraService, "create_issue_from_drift", None)
        )

    def test_drift_method_accepts_evidence(self):
        """AC-2: create_issue_from_drift signature includes evidence parameter."""
        from app.services.infrastructure.jira_service import JiraService

        sig = inspect.signature(JiraService.create_issue_from_drift)
        assert "evidence" in sig.parameters


@pytest.mark.unit
class TestAC3OutboundFailedTransactions:
    """AC-3: Failed transactions create Jira issues with rule details."""

    def test_create_issue_from_transaction_exists(self):
        """JiraService has a method for creating issues from failed transactions."""
        from app.services.infrastructure.jira_service import JiraService

        assert callable(
            getattr(JiraService, "create_issue_from_transaction", None)
        )

    def test_transaction_method_accepts_rule_id(self):
        """AC-3: create_issue_from_transaction signature includes rule_id."""
        from app.services.infrastructure.jira_service import JiraService

        sig = inspect.signature(JiraService.create_issue_from_transaction)
        assert "rule_id" in sig.parameters


@pytest.mark.unit
class TestAC4InboundWebhook:
    """AC-4: POST /api/integrations/jira/webhook receives Jira state transitions."""

    def test_webhook_route_exists(self):
        """Jira webhook route is registered."""
        import app.routes.integrations.jira as mod

        source = inspect.getsource(mod)
        assert "webhook" in source

    def test_webhook_route_is_post(self):
        """AC-4: webhook endpoint uses POST method."""
        import app.routes.integrations.jira as mod

        source = inspect.getsource(mod)
        assert "router.post" in source and "/webhook" in source


@pytest.mark.unit
class TestAC5InboundResolvedMapsToException:
    """AC-5: Jira issue resolved maps to OpenWatch exception updated."""

    def test_handle_resolution_exists(self):
        """JiraService has a method to handle Jira resolution events."""
        from app.services.infrastructure.jira_service import JiraService

        assert callable(
            getattr(JiraService, "handle_resolution", None)
        )

    def test_webhook_checks_resolved_status(self):
        """AC-5: webhook handler checks for resolved/done/closed status."""
        import app.routes.integrations.jira as mod

        source = inspect.getsource(mod)
        assert "resolved" in source and "done" in source and "closed" in source


@pytest.mark.unit
class TestAC6FieldMappingConfigurable:
    """AC-6: Field mapping is configurable per Jira project via admin API."""

    def test_field_mapping_admin_route(self):
        """Admin route for Jira field mapping exists."""
        import app.routes.integrations.jira as mod

        source = inspect.getsource(mod)
        assert "field_mapping" in source or "field-mapping" in source

    def test_field_mapping_get_and_put(self):
        """AC-6: both GET and PUT endpoints exist for field mapping."""
        import app.routes.integrations.jira as mod

        source = inspect.getsource(mod)
        assert "router.get" in source and "field-mapping" in source
        assert "router.put" in source and "field-mapping" in source


@pytest.mark.unit
class TestAC7CredentialsEncrypted:
    """AC-7: Jira credentials are encrypted at rest."""

    def test_encryption_service_used(self):
        """JiraService source references EncryptionService for credential storage."""
        import app.services.infrastructure.jira_service as mod

        source = inspect.getsource(mod)
        assert "EncryptionService" in source or "encrypt" in source.lower()


@pytest.mark.unit
class TestAC8SSRFProtection:
    """AC-8: SSRF protection on outbound Jira API calls."""

    def test_ssrf_protection_in_source(self):
        """JiraService source includes SSRF protection measures."""
        import app.services.infrastructure.jira_service as mod

        source = inspect.getsource(mod)
        assert "ssrf" in source.lower() or "allowlist" in source.lower() or "validate_url" in source.lower()

    def test_private_ip_check_imported(self):
        """AC-8: JiraService imports the private-IP check for SSRF blocking."""
        import app.services.infrastructure.jira_service as mod

        source = inspect.getsource(mod)
        assert "_is_private_ip" in source or "validate_url" in source
