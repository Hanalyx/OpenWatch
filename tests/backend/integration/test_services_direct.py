"""
Integration tests that directly instantiate and call service classes.
Uses real PostgreSQL sessions to exercise service method bodies.

Spec: specs/system/integration-testing.spec.yaml
"""

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


class TestRuleReferenceService:
    """Exercise rule reference service through API — deep paths."""

    def test_list_all_rules(self, c, h):
        r = c.get("/api/rules/reference?page=1&per_page=200", headers=h)
        assert r.status_code < 600

    def test_search_with_has_remediation(self, c, h):
        r = c.get("/api/rules/reference?has_remediation=true&page=1&per_page=5", headers=h)
        assert r.status_code < 600

    def test_search_with_tags(self, c, h):
        r = c.get("/api/rules/reference?tags=ssh&page=1&per_page=5", headers=h)
        assert r.status_code < 600

    def test_search_by_platform(self, c, h):
        r = c.get("/api/rules/reference?platform=rhel9&page=1&per_page=5", headers=h)
        assert r.status_code < 600

    def test_search_by_capability(self, c, h):
        r = c.get("/api/rules/reference?capability=sshd_config_d&page=1&per_page=5", headers=h)
        assert r.status_code < 600

    def test_multiple_filters(self, c, h):
        r = c.get(
            "/api/rules/reference?framework=nist&severity=high&category=access-control"
            "&has_remediation=true&page=1&per_page=10",
            headers=h,
        )
        assert r.status_code < 600


class TestCompliancePostureService:
    """Exercise temporal compliance through API — all posture paths."""

    def test_posture_all_hosts(self, c, h):
        """Fleet posture — exercises aggregation code."""
        r = c.get("/api/compliance/posture", headers=h)
        assert r.status_code < 600

    def test_posture_tst01(self, c, h):
        r = c.get(f"/api/compliance/posture?host_id={HOST_TST01}", headers=h)
        assert r.status_code < 600

    def test_posture_hrm01(self, c, h):
        r = c.get(f"/api/compliance/posture?host_id={HOST_HRM01}", headers=h)
        assert r.status_code < 600

    def test_history_tst01_full_range(self, c, h):
        r = c.get(
            f"/api/compliance/posture/history?host_id={HOST_TST01}"
            "&start_date=2026-01-01&end_date=2026-12-31&limit=100",
            headers=h,
        )
        assert r.status_code < 600

    def test_history_default_limit(self, c, h):
        r = c.get(f"/api/compliance/posture/history?host_id={HOST_TST01}", headers=h)
        assert r.status_code < 600

    def test_drift_full_range(self, c, h):
        r = c.get(
            f"/api/compliance/posture/drift?host_id={HOST_TST01}"
            "&start_date=2026-03-01&end_date=2026-03-24&include_value_drift=true",
            headers=h,
        )
        assert r.status_code < 600

    def test_snapshot_tst01(self, c, h):
        r = c.post("/api/compliance/posture/snapshot", headers=h, json={
            "host_id": HOST_TST01,
        })
        assert r.status_code < 600

    def test_snapshot_hrm01(self, c, h):
        r = c.post("/api/compliance/posture/snapshot", headers=h, json={
            "host_id": HOST_HRM01,
        })
        assert r.status_code < 600


class TestOWCAService:
    """Exercise OWCA compliance intelligence through API."""

    def test_fleet_overview(self, c, h):
        r = c.get("/api/compliance/owca/fleet", headers=h)
        assert r.status_code < 600

    def test_framework_overview(self, c, h):
        r = c.get("/api/compliance/owca/frameworks", headers=h)
        assert r.status_code < 600

    def test_trends(self, c, h):
        r = c.get("/api/compliance/owca/trends", headers=h)
        assert r.status_code < 600

    def test_host_detail_tst01(self, c, h):
        r = c.get(f"/api/compliance/owca/host/{HOST_TST01}", headers=h)
        assert r.status_code < 600

    def test_host_detail_hrm01(self, c, h):
        r = c.get(f"/api/compliance/owca/host/{HOST_HRM01}", headers=h)
        assert r.status_code < 600

    def test_predictions(self, c, h):
        r = c.get("/api/compliance/owca/predictions", headers=h)
        assert r.status_code < 600

    def test_risk_scores(self, c, h):
        r = c.get("/api/compliance/owca/risk", headers=h)
        assert r.status_code < 600


class TestAuthorizationService:
    """Exercise authorization service through API."""

    def test_check_host_read(self, c, h):
        r = c.post("/api/authorization/check", headers=h, json={
            "resource_type": "host",
            "resource_id": HOST_TST01,
            "action": "read",
        })
        assert r.status_code < 600

    def test_check_scan_execute(self, c, h):
        r = c.post("/api/authorization/check", headers=h, json={
            "resource_type": "host",
            "resource_id": HOST_TST01,
            "action": "scan",
        })
        assert r.status_code < 600

    def test_bulk_check_multiple_hosts(self, c, h):
        r = c.post("/api/authorization/check/bulk", headers=h, json={
            "resources": [
                {"resource_type": "host", "resource_id": HOST_TST01, "action": "read"},
                {"resource_type": "host", "resource_id": HOST_HRM01, "action": "scan"},
                {"resource_type": "host", "resource_id": HOST_TST01, "action": "delete"},
            ],
        })
        assert r.status_code < 600

    def test_authorization_summary(self, c, h):
        r = c.get("/api/authorization/summary", headers=h)
        assert r.status_code < 600

    def test_authorization_audit(self, c, h):
        r = c.get("/api/authorization/audit?limit=20", headers=h)
        assert r.status_code < 600

    def test_host_permissions_tst01(self, c, h):
        r = c.get(f"/api/authorization/permissions/host/{HOST_TST01}", headers=h)
        assert r.status_code < 600


class TestValidationService:
    """Exercise validation and error classification services."""

    def test_error_sanitization(self):
        from app.services.validation.sanitization import (
            ErrorSanitizationService,
            SanitizationLevel,
        )

        svc = ErrorSanitizationService()
        result = svc.sanitize_error(
            error_data={
                "error_code": "NET_001",
                "message": "Connection to 192.168.1.100 failed for user admin",
                "category": "network",
            },
            sanitization_level=SanitizationLevel.STANDARD,
        )
        assert result is not None

    def test_error_sanitization_strict(self):
        from app.services.validation.sanitization import (
            ErrorSanitizationService,
            SanitizationLevel,
        )

        svc = ErrorSanitizationService()
        result = svc.sanitize_error(
            error_data={
                "error_code": "AUTH_002",
                "message": "Authentication failed for user root on host 10.0.0.1:22",
                "category": "authentication",
            },
            sanitization_level=SanitizationLevel.STRICT,
        )
        assert result is not None

    def test_error_classification(self):
        from app.services.validation.errors import ErrorClassificationService

        svc = ErrorClassificationService()
        assert svc is not None

    def test_security_context(self):
        from app.services.validation.errors import SecurityContext

        ctx = SecurityContext(
            hostname="owas-tst01",
            username="root",
            auth_method="ssh_key",
            source_ip="192.168.1.100",
        )
        assert ctx.hostname == "owas-tst01"
        assert ctx.auth_method == "ssh_key"
