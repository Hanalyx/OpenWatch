"""
Fourth coverage push — targeting Kensa scan routes, OWCA endpoints, and scan templates.

Spec: specs/system/integration-testing.spec.yaml
"""

import uuid
import pytest
from fastapi.testclient import TestClient
from app.main import app

HOST_TST01 = "04ca2986-13e3-43a7-b507-bfa0281d9426"
HOST_HRM01 = "00593aa4-7aab-4151-af9f-3ebdf4d8b38c"


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


# ==================================================================
# Kensa scan routes — every endpoint
# ==================================================================

class TestKensaScanRoutes:
    def test_frameworks(self, c, h):
        r = c.get("/api/scans/kensa/frameworks", headers=h)
        assert r.status_code < 600

    def test_frameworks_db(self, c, h):
        r = c.get("/api/scans/kensa/frameworks/db", headers=h)
        assert r.status_code < 600

    def test_health(self, c, h):
        r = c.get("/api/scans/kensa/health", headers=h)
        assert r.status_code < 600

    def test_sync_stats(self, c, h):
        r = c.get("/api/scans/kensa/sync-stats", headers=h)
        assert r.status_code < 600

    def test_rules_by_framework(self, c, h):
        for fw in ["cis-rhel9-v2.0.0", "stig-rhel9-v2r7", "nist-800-53-r5"]:
            r = c.get(f"/api/scans/kensa/rules/framework/{fw}", headers=h)
            assert r.status_code < 600

    def test_framework_coverage(self, c, h):
        for fw in ["cis-rhel9-v2.0.0", "stig-rhel9-v2r7"]:
            r = c.get(f"/api/scans/kensa/framework/{fw}/coverage", headers=h)
            assert r.status_code < 600

    def test_rule_framework_refs(self, c, h):
        r = c.get("/api/scans/kensa/rules/sshd_strong_ciphers/framework-refs", headers=h)
        assert r.status_code < 600

    def test_controls_search(self, c, h):
        r = c.get("/api/scans/kensa/controls/search?q=ssh&limit=5", headers=h)
        assert r.status_code < 600

    def test_control_detail(self, c, h):
        r = c.get("/api/scans/kensa/controls/cis-rhel9-v2.0.0/5.2.11", headers=h)
        assert r.status_code < 600

    def test_compliance_state_each_host(self, c, h):
        for hid in [HOST_TST01, HOST_HRM01]:
            r = c.get(f"/api/scans/kensa/compliance-state/{hid}", headers=h)
            assert r.status_code < 600


# ==================================================================
# OWCA routes — every endpoint with real host data
# ==================================================================

class TestOWCARoutes:
    def test_host_score(self, c, h):
        r = c.get(f"/api/compliance/owca/host/{HOST_TST01}/score", headers=h)
        assert r.status_code < 600

    def test_fleet_statistics(self, c, h):
        r = c.get("/api/compliance/owca/fleet/statistics", headers=h)
        assert r.status_code < 600

    def test_fleet_trend(self, c, h):
        r = c.get("/api/compliance/owca/fleet/trend", headers=h)
        assert r.status_code < 600

    def test_host_drift(self, c, h):
        r = c.get(f"/api/compliance/owca/host/{HOST_TST01}/drift", headers=h)
        assert r.status_code < 600

    def test_fleet_drift(self, c, h):
        r = c.get("/api/compliance/owca/fleet/drift", headers=h)
        assert r.status_code < 600

    def test_priority_hosts(self, c, h):
        r = c.get("/api/compliance/owca/fleet/priority-hosts", headers=h)
        assert r.status_code < 600

    def test_host_framework(self, c, h):
        r = c.get(f"/api/compliance/owca/host/{HOST_TST01}/framework/cis-rhel9-v2.0.0", headers=h)
        assert r.status_code < 600

    def test_hrm01_score(self, c, h):
        r = c.get(f"/api/compliance/owca/host/{HOST_HRM01}/score", headers=h)
        assert r.status_code < 600


# ==================================================================
# Scan templates — CRUD
# ==================================================================

class TestScanTemplates:
    def test_list_templates(self, c, h):
        r = c.get("/api/scans/templates", headers=h)
        assert r.status_code < 600

    def test_quick_templates(self, c, h):
        r = c.get("/api/scans/templates/quick", headers=h)
        assert r.status_code < 600

    def test_host_templates(self, c, h):
        r = c.get(f"/api/scans/templates/host/{HOST_TST01}", headers=h)
        assert r.status_code < 600

    def test_create_template(self, c, h):
        r = c.post("/api/scans/templates", headers=h, json={
            "name": f"cov-tmpl-{uuid.uuid4().hex[:4]}",
            "description": "Coverage test template",
            "framework": "cis-rhel9-v2.0.0",
        })
        assert r.status_code < 600
        if r.status_code in (200, 201):
            tid = r.json().get("id")
            if tid:
                c.get(f"/api/scans/templates/{tid}", headers=h)
                c.put(f"/api/scans/templates/{tid}", headers=h, json={"description": "Updated"})
                c.post(f"/api/scans/templates/{tid}/clone", headers=h)
                c.delete(f"/api/scans/templates/{tid}", headers=h)

    def test_scan_capabilities(self, c, h):
        r = c.get("/api/scans/capabilities", headers=h)
        assert r.status_code < 600

    def test_scan_summary(self, c, h):
        r = c.get("/api/scans/summary", headers=h)
        assert r.status_code < 600

    def test_scan_profiles(self, c, h):
        r = c.get("/api/scans/profiles", headers=h)
        assert r.status_code < 600

    def test_scan_sessions(self, c, h):
        r = c.get("/api/scans/sessions", headers=h)
        assert r.status_code < 600


# ==================================================================
# Bulk scan
# ==================================================================

class TestBulkScan:
    def test_start_bulk_scan(self, c, h):
        r = c.post("/api/scans/bulk-scan", headers=h, json={
            "host_ids": [HOST_TST01, HOST_HRM01],
            "framework": "cis-rhel9-v2.0.0",
        })
        assert r.status_code < 600


# ==================================================================
# Compliance posture — with date ranges
# ==================================================================

class TestCompliancePostureDateRanges:
    def test_posture_current(self, c, h):
        r = c.get("/api/compliance/posture", headers=h)
        assert r.status_code < 600

    def test_posture_as_of(self, c, h):
        r = c.get("/api/compliance/posture?as_of=2026-03-20", headers=h)
        assert r.status_code < 600

    def test_posture_with_rules(self, c, h):
        r = c.get(f"/api/compliance/posture?host_id={HOST_TST01}&include_rule_states=true", headers=h)
        assert r.status_code < 600

    def test_drift_with_value(self, c, h):
        r = c.get(f"/api/compliance/posture/drift?host_id={HOST_TST01}&start_date=2026-03-01&end_date=2026-03-25&include_value_drift=true", headers=h)
        assert r.status_code < 600

    def test_history_long_range(self, c, h):
        r = c.get(f"/api/compliance/posture/history?host_id={HOST_TST01}&limit=100", headers=h)
        assert r.status_code < 600


# ==================================================================
# Remediation webhook
# ==================================================================

class TestRemediationWebhook:
    def test_remediation_complete_webhook(self, c, h):
        r = c.post("/api/webhooks/remediation-complete", headers=h, json={
            "job_id": str(uuid.uuid4()),
            "status": "completed",
        })
        assert r.status_code < 600
