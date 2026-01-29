"""
Integration tests for authentication endpoints.

Tests:
- User registration
- Login with valid/invalid credentials
- Token refresh
- Access /auth/me with valid token
- Unauthenticated access rejected
"""

import pytest

from tests.conftest import auth_headers, login_user, register_user


@pytest.mark.integration
class TestRegistration:
    def test_register_new_user(self, client, unique_suffix):
        """Registering a new user should return 200 with tokens."""
        resp = register_user(
            client,
            username=f"newuser_{unique_suffix}",
            email=f"newuser_{unique_suffix}@example.com",
            password="SecurePass123!@#",  # pragma: allowlist secret
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    def test_register_duplicate_username(self, client, unique_suffix):
        """Registering with an existing username should fail."""
        username = f"dupuser_{unique_suffix}"
        email_base = f"dupuser_{unique_suffix}"

        # First registration
        resp1 = register_user(
            client,
            username=username,
            email=f"{email_base}_a@example.com",
            password="SecurePass123!@#",  # pragma: allowlist secret
        )
        assert resp1.status_code == 200

        # Duplicate registration
        resp2 = register_user(
            client,
            username=username,
            email=f"{email_base}_b@example.com",
            password="SecurePass123!@#",  # pragma: allowlist secret
        )
        assert resp2.status_code in (400, 409, 422)


@pytest.mark.integration
class TestLogin:
    def test_login_valid_credentials(self, client, test_user):
        """Login with valid credentials should return tokens."""
        resp = login_user(client, test_user["username"], test_user["password"])
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert "user" in data

    def test_login_wrong_password(self, client, test_user):
        """Login with wrong password should fail."""
        resp = login_user(client, test_user["username"], "WrongPassword999!")
        assert resp.status_code == 401

    def test_login_nonexistent_user(self, client):
        """Login with nonexistent username should fail."""
        resp = login_user(client, "nonexistent_user_xyz", "SomePassword123!")
        assert resp.status_code == 401

    def test_login_response_has_user_data(self, client, test_user):
        """Login response should include user data."""
        resp = login_user(client, test_user["username"], test_user["password"])
        data = resp.json()
        user = data.get("user", {})
        assert "username" in user or "id" in user


@pytest.mark.integration
class TestTokenRefresh:
    def test_refresh_valid_token(self, client, test_user):
        """Refreshing with a valid refresh token should return a new access token."""
        # Get refresh token from login
        login_resp = login_user(client, test_user["username"], test_user["password"])
        refresh_token = login_resp.json().get("refresh_token")
        if not refresh_token:
            pytest.skip("Refresh token not returned by login")

        resp = client.post("/api/auth/refresh", json={"refresh_token": refresh_token})
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data

    def test_refresh_invalid_token(self, client):
        """Refreshing with an invalid token should fail."""
        resp = client.post("/api/auth/refresh", json={"refresh_token": "invalid.token.here"})
        assert resp.status_code in (401, 422)


@pytest.mark.integration
class TestAuthMe:
    def test_me_authenticated(self, client, test_user):
        """GET /auth/me with valid token should return user info."""
        resp = client.get("/api/auth/me", headers=test_user["headers"])
        assert resp.status_code == 200
        data = resp.json()
        # Should have user identification
        assert "username" in data or "id" in data or "user" in data

    def test_me_unauthenticated(self, client):
        """GET /auth/me without token should fail."""
        resp = client.get("/api/auth/me")
        assert resp.status_code in (401, 403)

    def test_me_invalid_token(self, client):
        """GET /auth/me with invalid token should fail."""
        resp = client.get("/api/auth/me", headers=auth_headers("invalid.jwt.token"))
        assert resp.status_code in (401, 403)
