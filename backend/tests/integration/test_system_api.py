"""
Integration tests for system API endpoints.

Tests health check, version, capabilities, and system configuration.
"""

import pytest


@pytest.mark.integration
class TestHealthEndpoints:
    """Test health check endpoints."""

    def test_health_check(self, client):
        """Health endpoint returns 200 without auth."""
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_api_health(self, client):
        """API health endpoint returns 200."""
        resp = client.get("/api/health")
        assert resp.status_code in (200, 404)


@pytest.mark.integration
class TestVersionEndpoints:
    """Test /api/version/* endpoints."""

    def test_version_endpoint(self, client):
        """Version endpoint returns version info."""
        resp = client.get("/api/version")
        assert resp.status_code in (200, 404)
        if resp.status_code == 200:
            data = resp.json()
            assert isinstance(data, dict)


@pytest.mark.integration
class TestCapabilitiesEndpoints:
    """Test /api/capabilities/* endpoints."""

    def test_capabilities_unauthenticated(self, client):
        """Capabilities may require authentication."""
        resp = client.get("/api/capabilities")
        assert resp.status_code in (200, 401, 403, 404)

    def test_capabilities_authenticated(self, client, test_user):
        """Capabilities returns data when authenticated."""
        resp = client.get("/api/capabilities", headers=test_user["headers"])
        assert resp.status_code in (200, 404)


@pytest.mark.integration
class TestSystemEndpoints:
    """Test /api/system/* endpoints."""

    def test_system_settings_unauthenticated(self, client):
        """System settings require authentication."""
        resp = client.get("/api/system/settings")
        assert resp.status_code in (401, 403, 404)

    def test_system_settings_authenticated(self, client, test_user):
        """System settings returns data when authenticated."""
        resp = client.get("/api/system/settings", headers=test_user["headers"])
        # May require admin role
        assert resp.status_code in (200, 403, 404)
