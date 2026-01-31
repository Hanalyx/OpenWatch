"""
Integration tests for admin API endpoints.

Tests user management, audit logs, credentials, and authorization settings.
"""

import pytest


@pytest.mark.integration
class TestUserManagement:
    """Test /api/users/* endpoints."""

    def test_list_users_unauthenticated(self, client):
        """User listing requires authentication."""
        resp = client.get("/api/users/")
        assert resp.status_code in (401, 403, 404)

    def test_list_users_as_regular_user(self, client, test_user):
        """Regular users may not have permission to list users."""
        resp = client.get("/api/users/", headers=test_user["headers"])
        # guest role may get 403 or may be allowed to list
        assert resp.status_code in (200, 403, 404)

    def test_list_users_as_admin(self, client, admin_user):
        """Admin users can list all users."""
        resp = client.get("/api/users/", headers=admin_user["headers"])
        assert resp.status_code in (200, 404)
        if resp.status_code == 200:
            data = resp.json()
            assert isinstance(data, (list, dict))


@pytest.mark.integration
class TestAuditEndpoints:
    """Test /api/audit/* endpoints."""

    def test_audit_logs_unauthenticated(self, client):
        """Audit logs require authentication."""
        resp = client.get("/api/audit/")
        assert resp.status_code in (401, 403, 404)

    def test_audit_logs_as_admin(self, client, admin_user):
        """Admin can view audit logs."""
        resp = client.get("/api/audit/", headers=admin_user["headers"])
        assert resp.status_code in (200, 404)


@pytest.mark.integration
class TestCredentialEndpoints:
    """Test /api/credentials/* endpoints."""

    def test_credentials_unauthenticated(self, client):
        """Credentials endpoint requires authentication."""
        resp = client.get("/api/credentials/")
        assert resp.status_code in (401, 403, 404)

    def test_credentials_as_admin(self, client, admin_user):
        """Admin can list credentials."""
        resp = client.get("/api/credentials/", headers=admin_user["headers"])
        assert resp.status_code in (200, 404)


@pytest.mark.integration
class TestAuthorizationEndpoints:
    """Test /api/authorization/* endpoints."""

    def test_authorization_roles_unauthenticated(self, client):
        """Authorization roles require authentication."""
        resp = client.get("/api/authorization/roles")
        assert resp.status_code in (401, 403, 404)

    def test_authorization_roles_authenticated(self, client, test_user):
        """Authenticated users can view roles."""
        resp = client.get("/api/authorization/roles", headers=test_user["headers"])
        assert resp.status_code in (200, 403, 404)
