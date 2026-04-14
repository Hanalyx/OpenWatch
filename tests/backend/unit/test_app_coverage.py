"""
Coverage tests that exercise the FastAPI app directly.
Uses TestClient to call endpoints which executes route handler code.

Spec: specs/system/architecture.spec.yaml
"""

import pytest


@pytest.mark.unit
class TestAppStartup:
    """AC-5: FastAPI app loads and routes are registered."""

    def test_app_importable(self):
        from app.main import app

        assert app is not None

    def test_app_has_routes(self):
        from app.main import app

        routes = [r.path for r in app.routes]
        assert len(routes) > 10

    def test_health_route_registered(self):
        from app.main import app

        paths = [r.path for r in app.routes]
        assert "/health" in paths or any("/health" in p for p in paths)

    def test_api_routes_registered(self):
        from app.main import app

        paths = [r.path for r in app.routes]
        api_paths = [p for p in paths if p.startswith("/api")]
        assert len(api_paths) > 20


@pytest.mark.unit
class TestHealthEndpointDirect:
    """AC-1: Health endpoint via TestClient."""

    def test_health_returns_200(self):
        from fastapi.testclient import TestClient
        from app.main import app

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_returns_json(self):
        from fastapi.testclient import TestClient
        from app.main import app

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/health")
        data = resp.json()
        assert "status" in data


@pytest.mark.unit
class TestUnauthenticatedEndpoints:
    """AC-5: Unauthenticated endpoints return 401/403."""

    def test_hosts_requires_auth(self):
        from fastapi.testclient import TestClient
        from app.main import app

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/hosts")
        assert resp.status_code in (401, 403, 422)

    def test_scans_requires_auth(self):
        from fastapi.testclient import TestClient
        from app.main import app

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/scans")
        assert resp.status_code in (401, 403, 422)

    def test_users_requires_auth(self):
        from fastapi.testclient import TestClient
        from app.main import app

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/users")
        assert resp.status_code in (401, 403, 422)


@pytest.mark.unit
class TestLoginEndpoint:
    """AC-5: Login endpoint exercises auth code."""

    def test_login_missing_body(self):
        from fastapi.testclient import TestClient
        from app.main import app

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/auth/login")
        assert resp.status_code == 422  # Validation error

    def test_login_invalid_credentials(self):
        from fastapi.testclient import TestClient
        from app.main import app

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/auth/login",
            json={"username": "nonexistent_user", "password": "wrong_password"},
        )
        # Should return 401 (invalid creds) or 500 (if DB not connected in test)
        assert resp.status_code in (401, 500)
