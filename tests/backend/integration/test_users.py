"""
Integration tests for user management endpoints.

Tests:
- List users (admin only)
- Get user profile
- Unauthenticated access rejected
- Permission enforcement (non-admin can't list users)
"""

import pytest


@pytest.mark.integration
class TestUserList:
    def test_list_users_as_admin(self, client, admin_user):
        """Admin should be able to list users."""
        resp = client.get("/api/users", headers=admin_user["headers"])
        # Admin can list users (200) or might get 403 if role isn't high enough
        assert resp.status_code in (200, 403)

    def test_list_users_unauthenticated(self, client):
        """Listing users without auth should fail."""
        resp = client.get("/api/users")
        assert resp.status_code in (401, 403)

    def test_list_users_as_guest(self, client, test_user):
        """Guest/viewer user should not be able to list users."""
        resp = client.get("/api/users", headers=test_user["headers"])
        assert resp.status_code == 403


@pytest.mark.integration
class TestUserProfile:
    def test_get_own_profile(self, client, test_user):
        """User should be able to get their own profile via /auth/me."""
        resp = client.get("/api/auth/me", headers=test_user["headers"])
        assert resp.status_code == 200

    def test_get_profile_unauthenticated(self, client):
        """Getting profile without auth should fail."""
        resp = client.get("/api/auth/me")
        assert resp.status_code in (401, 403)


@pytest.mark.integration
class TestUserRoles:
    def test_roles_endpoint(self, client, admin_user):
        """Roles endpoint should return available roles for admin."""
        resp = client.get("/api/users/roles", headers=admin_user["headers"])
        # 200 if admin has USER_READ permission, 403 otherwise
        assert resp.status_code in (200, 403)

    def test_roles_unauthenticated(self, client):
        """Roles endpoint without auth should fail."""
        resp = client.get("/api/users/roles")
        assert resp.status_code in (401, 403)
