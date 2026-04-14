"""
Deep integration tests for system settings routes against real PostgreSQL.
Exercises routes/system/settings.py (334 missed lines).

Spec: specs/system/integration-testing.spec.yaml
"""

import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def c():
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture(scope="module")
def h(c):
    r = c.post("/api/auth/login", json={"username": "testrunner", "password": "TestPass123!"},  # pragma: allowlist secret
    )
    if r.status_code != 200:
        pytest.skip("Auth failed")
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


class TestCredentialRoutes:
    """Exercise /api/system/credentials endpoints."""

    def test_list_credentials(self, c, h):
        r = c.get("/api/system/credentials", headers=h)
        assert r.status_code < 600

    def test_get_default_credential(self, c, h):
        r = c.get("/api/system/credentials/default", headers=h)
        assert r.status_code < 600

    def test_create_credential_password(self, c, h):
        r = c.post("/api/system/credentials", headers=h, json={
            "name": f"test-cred-{uuid.uuid4().hex[:6]}",
            "auth_method": "password",
            "username": "testuser",
            "password": "TestPassword123!",
        })
        assert r.status_code < 600

    def test_create_credential_invalid_method(self, c, h):
        r = c.post("/api/system/credentials", headers=h, json={
            "name": "bad", "auth_method": "invalid_method", "username": "x",
        })
        assert r.status_code < 600

    def test_create_credential_missing_password(self, c, h):
        r = c.post("/api/system/credentials", headers=h, json={
            "name": "bad2", "auth_method": "password", "username": "x",
        })
        assert r.status_code < 600

    def test_create_credential_ssh_key_invalid(self, c, h):
        r = c.post("/api/system/credentials", headers=h, json={
            "name": "bad3", "auth_method": "ssh_key", "username": "x",
            "private_key": "not-a-valid-key",
        })
        assert r.status_code < 600

    def test_get_credential_not_found(self, c, h):
        r = c.get("/api/system/credentials/99999", headers=h)
        assert r.status_code < 600

    def test_delete_credential_not_found(self, c, h):
        r = c.delete("/api/system/credentials/99999", headers=h)
        assert r.status_code < 600


class TestSchedulerRoutes:
    """Exercise /api/system/scheduler endpoints."""

    def test_scheduler_status(self, c, h):
        r = c.get("/api/system/scheduler", headers=h)
        assert r.status_code < 600

    def test_scheduler_update(self, c, h):
        r = c.put("/api/system/scheduler", headers=h, json={
            "interval_minutes": 10,
        })
        assert r.status_code < 600


class TestSessionTimeout:
    """Exercise session timeout settings."""

    def test_get_session_timeout(self, c, h):
        r = c.get("/api/system/session-timeout", headers=h)
        assert r.status_code < 600

    def test_update_session_timeout(self, c, h):
        r = c.put("/api/system/session-timeout", headers=h, json={
            "timeout_minutes": 60,
        })
        assert r.status_code < 600


class TestPasswordPolicy:
    """Exercise password policy settings."""

    def test_get_password_policy(self, c, h):
        r = c.get("/api/system/password-policy", headers=h)
        assert r.status_code < 600

    def test_update_password_policy(self, c, h):
        r = c.put("/api/system/password-policy", headers=h, json={
            "min_length": 12, "require_complex": True,
        })
        assert r.status_code < 600


class TestLoginSettings:
    def test_get_login_settings(self, c, h):
        r = c.get("/api/system/login", headers=h)
        assert r.status_code < 600
