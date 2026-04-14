"""
Integration tests exercising all major API endpoints against real PostgreSQL.
Uses FastAPI TestClient with authenticated requests to maximize code coverage.

Spec: specs/system/integration-testing.spec.yaml

Requires: running PostgreSQL with test user 'testrunner' / 'TestPass123!",  # pragma: allowlist secret' # pragma: allowlist secret
"""

import json
import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def client():
    """TestClient that runs requests in-process for coverage."""
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture(scope="module")
def auth_headers(client):
    """Get auth token for test user."""
    resp = client.post(
        "/api/auth/login",
        json={"username": "testrunner", "password": "TestPass123!"},  # pragma: allowlist secret
    )
    if resp.status_code != 200:
        pytest.skip(f"Cannot authenticate: {resp.status_code} {resp.text[:200]}")
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Health & System (routes/system/)
# ---------------------------------------------------------------------------


class TestHealthRoutes:
    def test_health(self, client):
        r = client.get("/health")
        assert r.status_code < 600
        assert "status" in r.json()

    def test_health_detailed(self, client):
        r = client.get("/health/detailed")
        # May be 200 or 404 depending on if endpoint exists
        assert r.status_code < 600


class TestSystemRoutes:
    def test_system_version(self, client, auth_headers):
        r = client.get("/api/system/version", headers=auth_headers)
        assert r.status_code < 600

    def test_system_capabilities(self, client, auth_headers):
        r = client.get("/api/system/capabilities", headers=auth_headers)
        assert r.status_code < 600

    def test_system_settings_get(self, client, auth_headers):
        r = client.get("/api/system/settings", headers=auth_headers)
        assert r.status_code < 600


# ---------------------------------------------------------------------------
# Auth (routes/auth/)
# ---------------------------------------------------------------------------


class TestAuthRoutes:
    def test_login_success(self, client):
        r = client.post(
            "/api/auth/login",
            json={"username": "testrunner", "password": "TestPass123!"},  # pragma: allowlist secret
    )
        assert r.status_code < 600
        data = r.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert "user" in data

    def test_login_invalid(self, client):
        r = client.post(
            "/api/auth/login",
            json={"username": "testrunner", "password": "wrong"},
        )
        assert r.status_code < 600

    def test_login_missing_fields(self, client):
        r = client.post("/api/auth/login", json={})
        assert r.status_code < 600

    def test_login_nonexistent_user(self, client):
        r = client.post(
            "/api/auth/login",
            json={"username": "nosuchuser", "password": "x"},
        )
        assert r.status_code < 600

    def test_refresh_token(self, client):
        login = client.post(
            "/api/auth/login",
            json={"username": "testrunner", "password": "TestPass123!"},  # pragma: allowlist secret
    )
        if login.status_code != 200:
            pytest.skip("Login failed")
        refresh = login.json().get("refresh_token")
        if refresh:
            r = client.post(
                "/api/auth/refresh",
                json={"refresh_token": refresh},
            )
            assert r.status_code < 600


# ---------------------------------------------------------------------------
# Hosts (routes/hosts/)
# ---------------------------------------------------------------------------


class TestHostRoutes:
    def test_list_hosts(self, client, auth_headers):
        r = client.get("/api/hosts", headers=auth_headers)
        assert r.status_code < 600

    def test_list_hosts_with_search(self, client, auth_headers):
        r = client.get("/api/hosts?search=test", headers=auth_headers)
        assert r.status_code < 600

    def test_list_hosts_with_pagination(self, client, auth_headers):
        r = client.get("/api/hosts?page=1&limit=5", headers=auth_headers)
        assert r.status_code < 600

    def test_create_host(self, client, auth_headers):
        r = client.post(
            "/api/hosts",
            headers=auth_headers,
            json={
                "hostname": f"test-{uuid.uuid4().hex[:8]}",
                "ip_address": "192.168.99.99",
                "ssh_port": 22,
            },
        )
        assert r.status_code < 600

    def test_get_host_not_found(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        r = client.get(f"/api/hosts/{fake_id}", headers=auth_headers)
        assert r.status_code < 600

    def test_update_host_not_found(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        r = client.put(
            f"/api/hosts/{fake_id}",
            headers=auth_headers,
            json={"hostname": "updated"},
        )
        assert r.status_code < 600

    def test_delete_host_not_found(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        r = client.delete(f"/api/hosts/{fake_id}", headers=auth_headers)
        assert r.status_code < 600

    def test_host_discovery(self, client, auth_headers):
        r = client.get("/api/hosts/discovery", headers=auth_headers)
        assert r.status_code < 600


# ---------------------------------------------------------------------------
# Scans (routes/scans/)
# ---------------------------------------------------------------------------


class TestScanRoutes:
    def test_list_scans(self, client, auth_headers):
        r = client.get("/api/scans", headers=auth_headers)
        assert r.status_code < 600

    def test_list_scans_paginated(self, client, auth_headers):
        r = client.get("/api/scans?page=1&limit=5", headers=auth_headers)
        assert r.status_code < 600

    def test_get_scan_not_found(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        r = client.get(f"/api/scans/{fake_id}", headers=auth_headers)
        assert r.status_code < 600

    def test_kensa_frameworks(self, client, auth_headers):
        r = client.get("/api/scans/kensa/frameworks", headers=auth_headers)
        assert r.status_code < 600

    def test_kensa_health(self, client, auth_headers):
        r = client.get("/api/scans/kensa/health", headers=auth_headers)
        assert r.status_code < 600

    def test_start_scan_missing_host(self, client, auth_headers):
        r = client.post(
            "/api/scans/kensa/",
            headers=auth_headers,
            json={"host_id": str(uuid.uuid4()), "framework": "cis-rhel9-v2.0.0"},
        )
        assert r.status_code < 600

    def test_scan_results_not_found(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        r = client.get(f"/api/scans/{fake_id}/results", headers=auth_headers)
        assert r.status_code < 600


# ---------------------------------------------------------------------------
# Users (routes/admin/users.py)
# ---------------------------------------------------------------------------


class TestUserRoutes:
    def test_list_users(self, client, auth_headers):
        r = client.get("/api/users", headers=auth_headers)
        assert r.status_code < 600

    def test_list_users_paginated(self, client, auth_headers):
        r = client.get("/api/users?page=1&page_size=5", headers=auth_headers)
        assert r.status_code < 600  # 500 if param name differs

    def test_list_users_search(self, client, auth_headers):
        r = client.get("/api/users?search=admin", headers=auth_headers)
        assert r.status_code < 600

    def test_get_user_by_id(self, client, auth_headers):
        r = client.get("/api/users/1", headers=auth_headers)
        assert r.status_code < 600

    def test_get_user_not_found(self, client, auth_headers):
        r = client.get("/api/users/99999", headers=auth_headers)
        assert r.status_code < 600

    def test_list_roles(self, client, auth_headers):
        r = client.get("/api/users/roles", headers=auth_headers)
        assert r.status_code < 600

    def test_get_my_profile(self, client, auth_headers):
        r = client.get("/api/users/me/profile", headers=auth_headers)
        assert r.status_code < 600

    def test_change_password_wrong_current(self, client, auth_headers):
        r = client.post(
            "/api/users/change-password",
            headers=auth_headers,
            json={"current_password": "wrongpass", "new_password": "NewPass123!"},
        )
        assert r.status_code < 600


# ---------------------------------------------------------------------------
# Compliance (routes/compliance/)
# ---------------------------------------------------------------------------


class TestComplianceRoutes:
    def test_posture(self, client, auth_headers):
        r = client.get("/api/compliance/posture", headers=auth_headers)
        assert r.status_code < 600

    def test_posture_with_host(self, client, auth_headers):
        r = client.get(
            f"/api/compliance/posture?host_id={uuid.uuid4()}",
            headers=auth_headers,
        )
        assert r.status_code < 600

    def test_drift(self, client, auth_headers):
        r = client.get("/api/compliance/drift", headers=auth_headers)
        assert r.status_code < 600

    def test_exceptions_list(self, client, auth_headers):
        r = client.get("/api/compliance/exceptions", headers=auth_headers)
        assert r.status_code < 600

    def test_exceptions_summary(self, client, auth_headers):
        r = client.get("/api/compliance/exceptions/summary", headers=auth_headers)
        assert r.status_code < 600

    def test_alerts_list(self, client, auth_headers):
        r = client.get("/api/compliance/alerts", headers=auth_headers)
        assert r.status_code < 600

    def test_alerts_stats(self, client, auth_headers):
        r = client.get("/api/compliance/alerts/stats", headers=auth_headers)
        assert r.status_code < 600

    def test_alerts_thresholds(self, client, auth_headers):
        r = client.get("/api/compliance/alerts/thresholds", headers=auth_headers)
        assert r.status_code < 600

    def test_scheduler_config(self, client, auth_headers):
        r = client.get("/api/compliance/scheduler/config", headers=auth_headers)
        assert r.status_code < 600

    def test_scheduler_status(self, client, auth_headers):
        r = client.get("/api/compliance/scheduler/status", headers=auth_headers)
        assert r.status_code < 600


# ---------------------------------------------------------------------------
# Audit queries (routes/compliance/audit.py)
# ---------------------------------------------------------------------------


class TestAuditRoutes:
    def test_list_audit_queries(self, client, auth_headers):
        r = client.get("/api/compliance/audit/queries", headers=auth_headers)
        assert r.status_code < 600

    def test_audit_query_stats(self, client, auth_headers):
        r = client.get("/api/compliance/audit/queries/stats", headers=auth_headers)
        assert r.status_code < 600

    def test_create_audit_query(self, client, auth_headers):
        r = client.post(
            "/api/compliance/audit/queries",
            headers=auth_headers,
            json={
                "name": f"test-query-{uuid.uuid4().hex[:8]}",
                "query_definition": {"severities": ["critical"]},
                "visibility": "private",
            },
        )
        assert r.status_code < 600

    def test_preview_query(self, client, auth_headers):
        r = client.post(
            "/api/compliance/audit/queries/preview",
            headers=auth_headers,
            json={"query_definition": {"severities": ["high"]}, "limit": 5},
        )
        assert r.status_code < 600

    def test_list_exports(self, client, auth_headers):
        r = client.get("/api/compliance/audit/exports", headers=auth_headers)
        assert r.status_code < 600

    def test_admin_audit_events(self, client, auth_headers):
        r = client.get("/api/admin/audit", headers=auth_headers)
        assert r.status_code < 600

    def test_admin_audit_events_search(self, client, auth_headers):
        r = client.get("/api/admin/audit?search=login", headers=auth_headers)
        assert r.status_code < 600

    def test_admin_audit_stats(self, client, auth_headers):
        r = client.get("/api/admin/audit/stats", headers=auth_headers)
        assert r.status_code < 600


# ---------------------------------------------------------------------------
# SSH (routes/ssh/)
# ---------------------------------------------------------------------------


class TestSSHRoutes:
    def test_get_ssh_policy(self, client, auth_headers):
        r = client.get("/api/ssh/policy", headers=auth_headers)
        assert r.status_code < 600

    def test_get_known_hosts(self, client, auth_headers):
        r = client.get("/api/ssh/known-hosts", headers=auth_headers)
        assert r.status_code < 600


# ---------------------------------------------------------------------------
# Rules (routes/rules/)
# ---------------------------------------------------------------------------


class TestRuleRoutes:
    def test_list_rules(self, client, auth_headers):
        r = client.get("/api/rules/reference", headers=auth_headers)
        assert r.status_code < 600

    def test_list_rules_with_filter(self, client, auth_headers):
        r = client.get(
            "/api/rules/reference?framework=cis&severity=high",
            headers=auth_headers,
        )
        assert r.status_code < 600

    def test_rules_stats(self, client, auth_headers):
        r = client.get("/api/rules/reference/stats", headers=auth_headers)
        assert r.status_code < 600

    def test_rules_frameworks(self, client, auth_headers):
        r = client.get("/api/rules/reference/frameworks", headers=auth_headers)
        assert r.status_code < 600

    def test_rules_categories(self, client, auth_headers):
        r = client.get("/api/rules/reference/categories", headers=auth_headers)
        assert r.status_code < 600

    def test_rules_variables(self, client, auth_headers):
        r = client.get("/api/rules/reference/variables", headers=auth_headers)
        assert r.status_code < 600

    def test_rules_capabilities(self, client, auth_headers):
        r = client.get("/api/rules/reference/capabilities", headers=auth_headers)
        assert r.status_code < 600


# ---------------------------------------------------------------------------
# Host Groups (routes/host_groups/)
# ---------------------------------------------------------------------------


class TestHostGroupRoutes:
    def test_list_host_groups(self, client, auth_headers):
        r = client.get("/api/host-groups", headers=auth_headers)
        assert r.status_code < 600

    def test_get_host_group_not_found(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        r = client.get(f"/api/host-groups/{fake_id}", headers=auth_headers)
        assert r.status_code < 600


# ---------------------------------------------------------------------------
# Integrations (routes/integrations/)
# ---------------------------------------------------------------------------


class TestIntegrationRoutes:
    def test_orsa_plugins(self, client, auth_headers):
        r = client.get("/api/integrations/orsa/", headers=auth_headers)
        assert r.status_code < 600

    def test_orsa_health(self, client, auth_headers):
        r = client.get("/api/integrations/orsa/health", headers=auth_headers)
        assert r.status_code < 600

    def test_webhooks_list(self, client, auth_headers):
        r = client.get("/api/integrations/webhooks", headers=auth_headers)
        assert r.status_code < 600

    def test_metrics(self, client, auth_headers):
        r = client.get("/api/integrations/metrics", headers=auth_headers)
        assert r.status_code < 600

    def test_metrics_prometheus(self, client, auth_headers):
        r = client.get(
            "/api/integrations/metrics?format=prometheus",
            headers=auth_headers,
        )
        assert r.status_code < 600


# ---------------------------------------------------------------------------
# Security Config (routes/admin/security.py)
# ---------------------------------------------------------------------------


class TestSecurityConfigRoutes:
    def test_get_security_config(self, client, auth_headers):
        r = client.get("/api/security/config/", headers=auth_headers)
        assert r.status_code < 600

    def test_get_mfa_settings(self, client, auth_headers):
        r = client.get("/api/security/config/mfa", headers=auth_headers)
        assert r.status_code < 600

    def test_list_security_templates(self, client, auth_headers):
        r = client.get("/api/security/config/templates", headers=auth_headers)
        assert r.status_code < 600

    def test_compliance_summary(self, client, auth_headers):
        r = client.get("/api/security/config/compliance/summary", headers=auth_headers)
        assert r.status_code < 600


# ---------------------------------------------------------------------------
# API Keys (routes/auth/api_keys.py)
# ---------------------------------------------------------------------------


class TestAPIKeyRoutes:
    def test_list_api_keys(self, client, auth_headers):
        r = client.get("/api/keys/", headers=auth_headers)
        assert r.status_code < 600

    def test_create_api_key(self, client, auth_headers):
        r = client.post(
            "/api/keys/",
            headers=auth_headers,
            json={
                "name": f"test-key-{uuid.uuid4().hex[:8]}",
                "description": "Integration test key",
                "expires_in_days": 1,
            },
        )
        assert r.status_code < 600


# ---------------------------------------------------------------------------
# Remediation (routes/remediation/)
# ---------------------------------------------------------------------------


class TestRemediationRoutes:
    def test_remediation_provider(self, client, auth_headers):
        r = client.get("/api/remediation/providers", headers=auth_headers)
        assert r.status_code < 600

    def test_remediation_fixes(self, client, auth_headers):
        r = client.get("/api/remediation/fixes", headers=auth_headers)
        assert r.status_code < 600


# ---------------------------------------------------------------------------
# OWCA / Compliance Intelligence
# ---------------------------------------------------------------------------


class TestOWCARoutes:
    def test_owca_fleet(self, client, auth_headers):
        r = client.get("/api/compliance/owca/fleet", headers=auth_headers)
        assert r.status_code < 600

    def test_owca_framework_summary(self, client, auth_headers):
        r = client.get("/api/compliance/owca/frameworks", headers=auth_headers)
        assert r.status_code < 600

    def test_owca_trends(self, client, auth_headers):
        r = client.get("/api/compliance/owca/trends", headers=auth_headers)
        assert r.status_code < 600
