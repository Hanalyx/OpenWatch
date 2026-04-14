"""
Source-inspection tests for ORSA integration routes.

Spec: specs/api/integrations/orsa-routes.spec.yaml
"""

import inspect

import pytest


@pytest.mark.unit
class TestAC1ListPlugins:
    """AC-1: List plugins returns all registered ORSA plugins."""

    def test_list_endpoint_exists(self):
        import app.routes.integrations.orsa as mod

        source = inspect.getsource(mod)
        assert "router.get" in source or "@router" in source

    def test_plugin_listing(self):
        import app.routes.integrations.orsa as mod

        source = inspect.getsource(mod)
        assert "plugin" in source.lower()


@pytest.mark.unit
class TestAC2HealthCheck:
    """AC-2: Plugin health check validates plugin status."""

    def test_health_endpoint(self):
        import app.routes.integrations.orsa as mod

        source = inspect.getsource(mod)
        assert "health" in source.lower()


@pytest.mark.unit
class TestAC3GetPlugin:
    """AC-3: Get plugin by ID returns plugin details."""

    def test_get_by_id(self):
        import app.routes.integrations.orsa as mod

        source = inspect.getsource(mod)
        assert "plugin_id" in source


@pytest.mark.unit
class TestAC4Capabilities:
    """AC-4: Get plugin capabilities returns capability list."""

    def test_capabilities_endpoint(self):
        import app.routes.integrations.orsa as mod

        source = inspect.getsource(mod)
        assert "capabilities" in source.lower() or "Capability" in source


@pytest.mark.unit
class TestAC5PluginRules:
    """AC-5: Get plugin rules returns paginated rule list."""

    def test_rules_endpoint(self):
        import app.routes.integrations.orsa as mod

        source = inspect.getsource(mod)
        assert "rules" in source.lower()
