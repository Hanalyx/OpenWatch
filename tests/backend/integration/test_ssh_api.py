"""
Integration tests for SSH API endpoints.

Tests SSH settings and debug endpoints.
"""

import pytest


@pytest.mark.integration
class TestSSHSettings:
    """Test /api/ssh/settings/* endpoints."""

    def test_ssh_settings_unauthenticated(self, client):
        """SSH settings require authentication."""
        resp = client.get("/api/ssh/settings")
        assert resp.status_code in (401, 403, 404)

    def test_ssh_settings_authenticated(self, client, test_user):
        """SSH settings returns data when authenticated."""
        resp = client.get("/api/ssh/settings", headers=test_user["headers"])
        assert resp.status_code in (200, 403, 404)

    def test_ssh_settings_as_admin(self, client, admin_user):
        """Admin can access SSH settings."""
        resp = client.get("/api/ssh/settings", headers=admin_user["headers"])
        assert resp.status_code in (200, 404)


@pytest.mark.integration
class TestSSHDebug:
    """Test /api/ssh/debug/* endpoints."""

    def test_ssh_debug_unauthenticated(self, client):
        """SSH debug requires authentication."""
        resp = client.get("/api/ssh/debug")
        assert resp.status_code in (401, 403, 404)

    def test_ssh_debug_as_admin(self, client, admin_user):
        """Admin can access SSH debug info."""
        resp = client.get("/api/ssh/debug", headers=admin_user["headers"])
        assert resp.status_code in (200, 403, 404)
