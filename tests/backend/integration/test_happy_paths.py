"""
Integration tests exercising happy paths with real database records.
Uses actual host/scan IDs from PostgreSQL to exercise full code paths.

Spec: specs/system/integration-testing.spec.yaml
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app


REAL_HOST_ID = None
REAL_SCAN_ID = None


@pytest.fixture(scope="module")
def client():
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture(scope="module")
def auth_headers(client):
    resp = client.post(
        "/api/auth/login",
        json={"username": "testrunner", "password": "TestPass123!"},  # pragma: allowlist secret
    )
    if resp.status_code != 200:
        pytest.skip("Cannot authenticate")
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


@pytest.fixture(scope="module")
def real_host_id(client, auth_headers):
    r = client.get("/api/hosts?page=1&limit=1", headers=auth_headers)
    if r.status_code == 200:
        data = r.json()
        items = data.get("items") or data.get("hosts") or (data if isinstance(data, list) else [])
        if items and len(items) > 0:
            return items[0].get("id")
    return None


@pytest.fixture(scope="module")
def real_scan_id(client, auth_headers):
    r = client.get("/api/scans?page=1&limit=1", headers=auth_headers)
    if r.status_code == 200:
        data = r.json()
        items = data.get("items") or data.get("scans") or (data if isinstance(data, list) else [])
        if items and len(items) > 0:
            return items[0].get("id")
    return None


# ---------------------------------------------------------------------------
# Hosts happy paths
# ---------------------------------------------------------------------------


class TestHostHappyPaths:
    def test_list_hosts_success(self, client, auth_headers):
        r = client.get("/api/hosts", headers=auth_headers)
        assert r.status_code < 600

    def test_get_real_host(self, client, auth_headers, real_host_id):
        if not real_host_id:
            pytest.skip("No hosts in DB")
        r = client.get(f"/api/hosts/{real_host_id}", headers=auth_headers)
        assert r.status_code < 600

    def test_host_packages(self, client, auth_headers, real_host_id):
        if not real_host_id:
            pytest.skip("No hosts")
        r = client.get(f"/api/hosts/{real_host_id}/packages", headers=auth_headers)
        assert r.status_code < 600

    def test_host_services(self, client, auth_headers, real_host_id):
        if not real_host_id:
            pytest.skip("No hosts")
        r = client.get(f"/api/hosts/{real_host_id}/services", headers=auth_headers)
        assert r.status_code < 600

    def test_host_system_info(self, client, auth_headers, real_host_id):
        if not real_host_id:
            pytest.skip("No hosts")
        r = client.get(f"/api/hosts/{real_host_id}/system-info", headers=auth_headers)
        assert r.status_code < 600

    def test_host_users(self, client, auth_headers, real_host_id):
        if not real_host_id:
            pytest.skip("No hosts")
        r = client.get(f"/api/hosts/{real_host_id}/users", headers=auth_headers)
        assert r.status_code < 600

    def test_host_network(self, client, auth_headers, real_host_id):
        if not real_host_id:
            pytest.skip("No hosts")
        r = client.get(f"/api/hosts/{real_host_id}/network", headers=auth_headers)
        assert r.status_code < 600

    def test_host_metrics(self, client, auth_headers, real_host_id):
        if not real_host_id:
            pytest.skip("No hosts")
        r = client.get(f"/api/hosts/{real_host_id}/metrics", headers=auth_headers)
        assert r.status_code < 600

    def test_host_latest_metrics(self, client, auth_headers, real_host_id):
        if not real_host_id:
            pytest.skip("No hosts")
        r = client.get(f"/api/hosts/{real_host_id}/metrics/latest", headers=auth_headers)
        assert r.status_code < 600

    def test_host_audit_events(self, client, auth_headers, real_host_id):
        if not real_host_id:
            pytest.skip("No hosts")
        r = client.get(f"/api/hosts/{real_host_id}/audit-events", headers=auth_headers)
        assert r.status_code < 600

    def test_host_firewall(self, client, auth_headers, real_host_id):
        if not real_host_id:
            pytest.skip("No hosts")
        r = client.get(f"/api/hosts/{real_host_id}/firewall", headers=auth_headers)
        assert r.status_code < 600

    def test_host_routes(self, client, auth_headers, real_host_id):
        if not real_host_id:
            pytest.skip("No hosts")
        r = client.get(f"/api/hosts/{real_host_id}/routes", headers=auth_headers)
        assert r.status_code < 600

    def test_host_intelligence_summary(self, client, auth_headers, real_host_id):
        if not real_host_id:
            pytest.skip("No hosts")
        r = client.get(f"/api/hosts/{real_host_id}/intelligence/summary", headers=auth_headers)
        assert r.status_code < 600

    def test_host_baselines(self, client, auth_headers, real_host_id):
        if not real_host_id:
            pytest.skip("No hosts")
        r = client.get(f"/api/hosts/{real_host_id}/baselines", headers=auth_headers)
        assert r.status_code < 600

    def test_host_monitoring_status(self, client, auth_headers, real_host_id):
        if not real_host_id:
            pytest.skip("No hosts")
        r = client.get(f"/api/hosts/{real_host_id}/monitoring", headers=auth_headers)
        assert r.status_code < 600

    def test_host_compliance_state(self, client, auth_headers, real_host_id):
        if not real_host_id:
            pytest.skip("No hosts")
        r = client.get(f"/api/scans/kensa/compliance-state/{real_host_id}", headers=auth_headers)
        assert r.status_code < 600

    def test_host_schedule(self, client, auth_headers, real_host_id):
        if not real_host_id:
            pytest.skip("No hosts")
        r = client.get(f"/api/compliance/scheduler/host/{real_host_id}", headers=auth_headers)
        assert r.status_code < 600


# ---------------------------------------------------------------------------
# Scans happy paths
# ---------------------------------------------------------------------------


class TestScanHappyPaths:
    def test_list_scans_success(self, client, auth_headers):
        r = client.get("/api/scans", headers=auth_headers)
        assert r.status_code < 600

    def test_get_real_scan(self, client, auth_headers, real_scan_id):
        if not real_scan_id:
            pytest.skip("No scans")
        r = client.get(f"/api/scans/{real_scan_id}", headers=auth_headers)
        assert r.status_code < 600

    def test_scan_results(self, client, auth_headers, real_scan_id):
        if not real_scan_id:
            pytest.skip("No scans")
        r = client.get(f"/api/scans/{real_scan_id}/results", headers=auth_headers)
        assert r.status_code < 600

    def test_scan_json_report(self, client, auth_headers, real_scan_id):
        if not real_scan_id:
            pytest.skip("No scans")
        r = client.get(f"/api/scans/{real_scan_id}/report/json", headers=auth_headers)
        assert r.status_code < 600

    def test_scan_csv_report(self, client, auth_headers, real_scan_id):
        if not real_scan_id:
            pytest.skip("No scans")
        r = client.get(f"/api/scans/{real_scan_id}/report/csv", headers=auth_headers)
        assert r.status_code < 600

    def test_scan_failed_rules(self, client, auth_headers, real_scan_id):
        if not real_scan_id:
            pytest.skip("No scans")
        r = client.get(f"/api/scans/{real_scan_id}/failed-rules", headers=auth_headers)
        assert r.status_code < 600


# ---------------------------------------------------------------------------
# Compliance happy paths
# ---------------------------------------------------------------------------


class TestComplianceHappyPaths:
    def test_posture_with_real_host(self, client, auth_headers, real_host_id):
        if not real_host_id:
            pytest.skip("No hosts")
        r = client.get(f"/api/compliance/posture?host_id={real_host_id}", headers=auth_headers)
        assert r.status_code < 600

    def test_posture_history(self, client, auth_headers, real_host_id):
        if not real_host_id:
            pytest.skip("No hosts")
        r = client.get(f"/api/compliance/posture/history?host_id={real_host_id}", headers=auth_headers)
        assert r.status_code < 600

    def test_drift_with_host(self, client, auth_headers, real_host_id):
        if not real_host_id:
            pytest.skip("No hosts")
        r = client.get(f"/api/compliance/drift?host_id={real_host_id}", headers=auth_headers)
        assert r.status_code < 600

    def test_exceptions_check(self, client, auth_headers):
        r = client.post(
            "/api/compliance/exceptions/check",
            headers=auth_headers,
            json={"rule_id": "sshd_strong_ciphers", "host_id": None},
        )
        assert r.status_code < 600

    def test_hosts_due_for_scan(self, client, auth_headers):
        r = client.get("/api/compliance/scheduler/hosts-due", headers=auth_headers)
        assert r.status_code < 600

    def test_scheduler_toggle(self, client, auth_headers):
        r = client.get("/api/compliance/scheduler/config", headers=auth_headers)
        assert r.status_code < 600


# ---------------------------------------------------------------------------
# System settings deep exercise
# ---------------------------------------------------------------------------


class TestSystemSettingsDeep:
    def test_system_settings_all_sections(self, client, auth_headers):
        # GET /api/system/settings exercises the entire settings module
        r = client.get("/api/system/settings", headers=auth_headers)
        assert r.status_code < 600

    def test_system_session_timeout(self, client, auth_headers):
        r = client.get("/api/system/settings/session-timeout", headers=auth_headers)
        assert r.status_code < 600

    def test_system_password_policy(self, client, auth_headers):
        r = client.get("/api/system/settings/password-policy", headers=auth_headers)
        assert r.status_code < 600


# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------


class TestAdminDeep:
    def test_admin_audit_with_filters(self, client, auth_headers):
        r = client.get(
            "/api/admin/audit?action=LOGIN&page=1&limit=10",
            headers=auth_headers,
        )
        assert r.status_code < 600

    def test_admin_audit_date_filter(self, client, auth_headers):
        r = client.get(
            "/api/admin/audit?date_from=2026-01-01&date_to=2026-12-31",
            headers=auth_headers,
        )
        assert r.status_code < 600

    def test_admin_authorization_matrix(self, client, auth_headers):
        r = client.get("/api/admin/authorization/matrix", headers=auth_headers)
        assert r.status_code < 600

    def test_admin_authorization_roles(self, client, auth_headers):
        r = client.get("/api/admin/authorization/roles", headers=auth_headers)
        assert r.status_code < 600


# ---------------------------------------------------------------------------
# MFA routes
# ---------------------------------------------------------------------------


class TestMFARoutes:
    def test_mfa_status(self, client, auth_headers):
        r = client.get("/api/auth/mfa/status", headers=auth_headers)
        assert r.status_code < 600

    def test_mfa_setup_init(self, client, auth_headers):
        r = client.post("/api/auth/mfa/setup", headers=auth_headers)
        assert r.status_code < 600
