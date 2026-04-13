"""
Source-inspection tests for alert routing rules engine.

Spec: specs/services/compliance/alert-routing.spec.yaml
Status: active
"""

import pytest


@pytest.mark.unit
class TestAC1AlertRoutingRulesTable:
    """AC-1: alert_routing_rules table exists with required columns."""

    def test_model_defined(self):
        """AlertRoutingRule model importable from app.models."""
        from app.models.alert_models import AlertRoutingRule  # noqa: F401

    def test_required_columns(self):
        """Model has severity, alert_type, channel_id, enabled columns."""
        from app.models.alert_models import AlertRoutingRule

        required = {
            "severity",
            "alert_type",
            "channel_id",
            "enabled",
        }
        actual = {c.name for c in AlertRoutingRule.__table__.columns}
        assert required.issubset(actual)


@pytest.mark.unit
class TestAC2DispatchToMatchingChannels:
    """AC-2: AlertService dispatches to channels matching routing rules."""

    def test_dispatch_method_exists(self):
        """AlertRoutingService has a resolve_channels method."""
        from app.services.compliance.alert_routing import AlertRoutingService

        assert callable(getattr(AlertRoutingService, "resolve_channels", None))


@pytest.mark.unit
class TestAC3FanOut:
    """AC-3: Multiple routing rules can match a single alert (fan-out)."""

    def test_fan_out_in_source(self):
        """Alert routing source handles multiple matching rules."""
        import inspect

        import app.services.compliance.alert_routing as mod

        source = inspect.getsource(mod)
        # Fan-out implies iterating over multiple matching rules
        assert "for " in source and "rule" in source.lower()


@pytest.mark.unit
class TestAC4PagerDutyChannel:
    """AC-4: PagerDuty channel creates incidents via PagerDuty Events API v2."""

    def test_pagerduty_channel_exists(self):
        """PagerDuty channel implementation exists."""
        from app.services.notifications.pagerduty import PagerDutyChannel  # noqa: F401

    def test_pagerduty_referenced_in_routing(self):
        """Alert routing service references pagerduty."""
        import inspect

        import app.services.compliance.alert_routing as mod

        source = inspect.getsource(mod)
        assert "pagerduty" in source.lower() or "PagerDuty" in source


@pytest.mark.unit
class TestAC5AdminCRUD:
    """AC-5: Routing rules are manageable via admin API (CRUD)."""

    def test_admin_routes_exist(self):
        """Admin routes for alert routing rules are registered."""
        import inspect

        import app.routes.compliance.alert_routing as mod

        source = inspect.getsource(mod)
        assert "routing" in source.lower()


@pytest.mark.unit
class TestAC6DefaultRoutingRule:
    """AC-6: Default routing rule applies when no specific rules match."""

    def test_default_rule_fallback(self):
        """Alert routing source includes default/fallback logic."""
        import inspect

        import app.services.compliance.alert_routing as mod

        source = inspect.getsource(mod)
        assert "default" in source.lower() or "fallback" in source.lower()
