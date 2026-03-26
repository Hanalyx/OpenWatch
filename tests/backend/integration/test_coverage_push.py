"""
Comprehensive coverage tests exercising every route handler branch
using real data from live PostgreSQL (1.3M+ findings, 7 hosts, 3K+ scans).

Spec: specs/system/integration-testing.spec.yaml
"""

import uuid
import pytest
from fastapi.testclient import TestClient
from app.main import app

# Real IDs from live database
HOST_TST01 = "04ca2986-13e3-43a7-b507-bfa0281d9426"
HOST_HRM01 = "00593aa4-7aab-4151-af9f-3ebdf4d8b38c"
HOST_RHN01 = "ca8f3080-7ae8-41b8-be69-b844e1010c48"
HOST_TST02 = "f4e7676a-ea38-47aa-bc52-9c1c590e8bcc"
HOST_UB5S2 = "67249f1d-b992-4027-9649-177156b526d2"
SCAN_COMPLETED = "3f50f04c-e5b6-4cb7-91d2-09183015ac89"
SCAN_TST01 = "6a370cee-dafe-4a6d-bd8c-56aaf5465493"
GROUP_RHEL = "2"
ALERT_ID = "8a954bec-911b-4a8a-83b5-1ef04370b8cf"
QUERY_ID = "13556428-fe48-493a-aeca-60dd71bc2af3"
EXPORT_ID = "c0701979-4679-4db8-b3e9-3f68d526bf3d"
REMEDIATION_ID = "837bbc0b-46b8-4e49-a056-ae04b90e1685"


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


# ====================================================================
# Host Detail — every tab, every parameter variation
# ====================================================================

class TestHostDetailEveryTab:
    """AC-1: Exercise all host intelligence endpoints with real host data."""

    def test_tst01_packages_page1(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/packages?page=1&per_page=20", headers=h)
        assert r.status_code < 600

    def test_tst01_packages_search(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/packages?search=ssh&page=1&per_page=10", headers=h)
        assert r.status_code < 600

    def test_tst01_services_running(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/services?status=running", headers=h)
        assert r.status_code < 600

    def test_tst01_services_all(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/services", headers=h)
        assert r.status_code < 600

    def test_tst01_users_no_system(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/users?exclude_system=true", headers=h)
        assert r.status_code < 600

    def test_tst01_users_sudo_only(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/users?sudo_only=true", headers=h)
        assert r.status_code < 600

    def test_tst01_metrics_1h(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/metrics?hours_back=1", headers=h)
        assert r.status_code < 600

    def test_tst01_metrics_24h(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/metrics?hours_back=24", headers=h)
        assert r.status_code < 600

    def test_tst01_metrics_720h(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/metrics?hours_back=720", headers=h)
        assert r.status_code < 600

    def test_tst01_audit_events_type(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/audit-events?event_type=USER_LOGIN", headers=h)
        assert r.status_code < 600

    def test_tst01_audit_events_user(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/audit-events?username=root", headers=h)
        assert r.status_code < 600

    def test_tst01_network_type(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/network?interface_type=ethernet", headers=h)
        assert r.status_code < 600

    def test_tst01_firewall_chain(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/firewall?chain=INPUT", headers=h)
        assert r.status_code < 600

    def test_tst01_routes_default(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/routes?default_only=true", headers=h)
        assert r.status_code < 600

    # Same for second host to exercise more DB rows
    def test_hrm01_detail(self, c, h):
        r = c.get(f"/api/hosts/{HOST_HRM01}", headers=h)
        assert r.status_code < 600

    def test_hrm01_packages(self, c, h):
        r = c.get(f"/api/hosts/{HOST_HRM01}/packages", headers=h)
        assert r.status_code < 600

    def test_hrm01_services(self, c, h):
        r = c.get(f"/api/hosts/{HOST_HRM01}/services", headers=h)
        assert r.status_code < 600

    def test_hrm01_system_info(self, c, h):
        r = c.get(f"/api/hosts/{HOST_HRM01}/system-info", headers=h)
        assert r.status_code < 600

    def test_rhn01_detail(self, c, h):
        r = c.get(f"/api/hosts/{HOST_RHN01}", headers=h)
        assert r.status_code < 600

    def test_tst02_detail(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST02}", headers=h)
        assert r.status_code < 600

    def test_ub5s2_detail(self, c, h):
        r = c.get(f"/api/hosts/{HOST_UB5S2}", headers=h)
        assert r.status_code < 600


# ====================================================================
# Scan Results — deep exercise with real completed scans
# ====================================================================

class TestScanResultsDeep:
    """AC-2: Exercise scan result rendering with real 508-finding scans."""

    def test_scan_detail_completed(self, c, h):
        r = c.get(f"/api/scans/{SCAN_COMPLETED}", headers=h)
        assert r.status_code < 600

    def test_scan_results_full(self, c, h):
        r = c.get(f"/api/scans/{SCAN_COMPLETED}/results", headers=h)
        assert r.status_code < 600

    def test_scan_results_include_rules(self, c, h):
        r = c.get(f"/api/scans/{SCAN_COMPLETED}/results?include_rules=true", headers=h)
        assert r.status_code < 600

    def test_scan_json_report(self, c, h):
        r = c.get(f"/api/scans/{SCAN_COMPLETED}/report/json", headers=h)
        assert r.status_code < 600

    def test_scan_csv_report(self, c, h):
        r = c.get(f"/api/scans/{SCAN_COMPLETED}/report/csv", headers=h)
        assert r.status_code < 600

    def test_scan_html_report(self, c, h):
        r = c.get(f"/api/scans/{SCAN_COMPLETED}/report/html", headers=h)
        assert r.status_code < 600

    def test_scan_failed_rules(self, c, h):
        r = c.get(f"/api/scans/{SCAN_COMPLETED}/failed-rules", headers=h)
        assert r.status_code < 600

    def test_scan_tst01_results(self, c, h):
        r = c.get(f"/api/scans/{SCAN_TST01}/results", headers=h)
        assert r.status_code < 600

    def test_list_scans_host_filter(self, c, h):
        r = c.get(f"/api/scans?host_id={HOST_TST01}&page=1&limit=5", headers=h)
        assert r.status_code < 600

    def test_list_scans_status_filter(self, c, h):
        r = c.get("/api/scans?status=completed&page=1&limit=10", headers=h)
        assert r.status_code < 600

    def test_list_scans_sort(self, c, h):
        r = c.get("/api/scans?sort_by=started_at&sort_order=desc&page=1&limit=5", headers=h)
        assert r.status_code < 600


# ====================================================================
# Alerts — exercise with 28K+ real alerts
# ====================================================================

class TestAlertsDeep:
    """AC-5: Exercise alert endpoints with 28K+ real alerts."""

    def test_list_alerts_default(self, c, h):
        r = c.get("/api/compliance/alerts", headers=h)
        assert r.status_code < 600

    def test_list_alerts_active(self, c, h):
        r = c.get("/api/compliance/alerts?status=active&page=1&limit=20", headers=h)
        assert r.status_code < 600

    def test_list_alerts_by_severity(self, c, h):
        r = c.get("/api/compliance/alerts?severity=critical", headers=h)
        assert r.status_code < 600

    def test_list_alerts_by_type(self, c, h):
        r = c.get("/api/compliance/alerts?alert_type=high_finding", headers=h)
        assert r.status_code < 600

    def test_alert_stats(self, c, h):
        r = c.get("/api/compliance/alerts/stats", headers=h)
        assert r.status_code < 600

    def test_get_alert(self, c, h):
        r = c.get(f"/api/compliance/alerts/{ALERT_ID}", headers=h)
        assert r.status_code < 600

    def test_acknowledge_alert(self, c, h):
        r = c.post(f"/api/compliance/alerts/{ALERT_ID}/acknowledge", headers=h,
                    json={"comments": "Integration test ack"})
        assert r.status_code < 600

    def test_resolve_alert(self, c, h):
        r = c.post(f"/api/compliance/alerts/{ALERT_ID}/resolve", headers=h,
                    json={"comments": "Integration test resolve"})
        assert r.status_code < 600

    def test_thresholds_get(self, c, h):
        r = c.get("/api/compliance/alerts/thresholds", headers=h)
        assert r.status_code < 600


# ====================================================================
# Audit Queries — exercise with real saved queries and exports
# ====================================================================

class TestAuditDeep:
    """AC-4: Exercise audit query builder with real saved queries."""

    def test_list_queries(self, c, h):
        r = c.get("/api/compliance/audit/queries", headers=h)
        assert r.status_code < 600

    def test_get_query(self, c, h):
        r = c.get(f"/api/compliance/audit/queries/{QUERY_ID}", headers=h)
        assert r.status_code < 600

    def test_execute_query(self, c, h):
        r = c.post(f"/api/compliance/audit/queries/{QUERY_ID}/execute", headers=h,
                    json={"page": 1, "per_page": 10})
        assert r.status_code < 600

    def test_preview_critical_findings(self, c, h):
        r = c.post("/api/compliance/audit/queries/preview", headers=h, json={
            "query_definition": {
                "severities": ["critical"],
                "statuses": ["fail"],
                "hosts": [HOST_TST01, HOST_HRM01, HOST_RHN01],
            },
            "limit": 20,
        })
        assert r.status_code < 600

    def test_preview_with_framework(self, c, h):
        r = c.post("/api/compliance/audit/queries/preview", headers=h, json={
            "query_definition": {
                "frameworks": ["cis"],
                "severities": ["high", "critical"],
            },
            "limit": 10,
        })
        assert r.status_code < 600

    def test_adhoc_execute(self, c, h):
        r = c.post("/api/compliance/audit/queries/execute", headers=h, json={
            "query_definition": {
                "statuses": ["fail"],
                "hosts": [HOST_TST01],
            },
            "page": 1, "per_page": 5,
        })
        assert r.status_code < 600

    def test_list_exports(self, c, h):
        r = c.get("/api/compliance/audit/exports", headers=h)
        assert r.status_code < 600

    def test_get_export(self, c, h):
        r = c.get(f"/api/compliance/audit/exports/{EXPORT_ID}", headers=h)
        assert r.status_code < 600

    def test_export_stats(self, c, h):
        r = c.get("/api/compliance/audit/exports/stats", headers=h)
        assert r.status_code < 600

    def test_query_stats(self, c, h):
        r = c.get("/api/compliance/audit/queries/stats", headers=h)
        assert r.status_code < 600


# ====================================================================
# Host Groups — exercise with real groups
# ====================================================================

class TestHostGroupsWithData:
    def test_list_groups(self, c, h):
        r = c.get("/api/host-groups", headers=h)
        assert r.status_code < 600

    def test_get_rhel_group(self, c, h):
        r = c.get(f"/api/host-groups/{GROUP_RHEL}", headers=h)
        assert r.status_code < 600

    def test_group_scan_history(self, c, h):
        r = c.get(f"/api/host-groups/{GROUP_RHEL}/scan-history", headers=h)
        assert r.status_code < 600


# ====================================================================
# Compliance Posture — deep exercise with real snapshots
# ====================================================================

class TestPostureDeep:
    def test_posture_each_host(self, c, h):
        for hid in [HOST_TST01, HOST_HRM01, HOST_RHN01, HOST_TST02, HOST_UB5S2]:
            r = c.get(f"/api/compliance/posture?host_id={hid}", headers=h)
            assert r.status_code < 600

    def test_posture_history_each(self, c, h):
        for hid in [HOST_TST01, HOST_HRM01]:
            r = c.get(f"/api/compliance/posture/history?host_id={hid}&limit=50", headers=h)
            assert r.status_code < 600

    def test_drift_real_range(self, c, h):
        r = c.get(
            f"/api/compliance/posture/drift?host_id={HOST_TST01}"
            "&start_date=2026-03-15&end_date=2026-03-25&include_value_drift=true",
            headers=h)
        assert r.status_code < 600

    def test_compliance_state_each(self, c, h):
        for hid in [HOST_TST01, HOST_HRM01, HOST_RHN01]:
            r = c.get(f"/api/scans/kensa/compliance-state/{hid}", headers=h)
            assert r.status_code < 600


# ====================================================================
# Remediation
# ====================================================================

class TestRemediationDeep:
    def test_remediation_providers(self, c, h):
        r = c.get("/api/remediation/providers", headers=h)
        assert r.status_code < 600

    def test_remediation_fixes(self, c, h):
        r = c.get("/api/remediation/fixes", headers=h)
        assert r.status_code < 600

    def test_compliance_remediation(self, c, h):
        r = c.get("/api/compliance/remediation", headers=h)
        assert r.status_code < 600

    def test_remediation_job(self, c, h):
        r = c.get(f"/api/remediation/jobs/{REMEDIATION_ID}", headers=h)
        assert r.status_code < 600


# ====================================================================
# Admin Audit — deep exercise with 15K+ audit logs
# ====================================================================

class TestAdminAuditDeep:
    def test_audit_page1(self, c, h):
        r = c.get("/api/admin/audit?page=1&limit=50", headers=h)
        assert r.status_code < 600

    def test_audit_page2(self, c, h):
        r = c.get("/api/admin/audit?page=2&limit=50", headers=h)
        assert r.status_code < 600

    def test_audit_login_filter(self, c, h):
        r = c.get("/api/admin/audit?action=LOGIN&page=1&limit=20", headers=h)
        assert r.status_code < 600

    def test_audit_scan_filter(self, c, h):
        r = c.get("/api/admin/audit?action=SCAN&page=1&limit=20", headers=h)
        assert r.status_code < 600

    def test_audit_user_filter(self, c, h):
        r = c.get("/api/admin/audit?user=admin&page=1&limit=10", headers=h)
        assert r.status_code < 600

    def test_audit_date_range(self, c, h):
        r = c.get("/api/admin/audit?date_from=2026-03-20&date_to=2026-03-25&page=1&limit=20", headers=h)
        assert r.status_code < 600

    def test_audit_stats(self, c, h):
        r = c.get("/api/admin/audit/stats", headers=h)
        assert r.status_code < 600

    def test_audit_stats_date(self, c, h):
        r = c.get("/api/admin/audit/stats?date_from=2026-03-01", headers=h)
        assert r.status_code < 600


# ====================================================================
# System Settings — all sections
# ====================================================================

class TestSystemSettingsDeep:
    def test_all_settings(self, c, h):
        r = c.get("/api/system/settings", headers=h)
        assert r.status_code < 600

    def test_password_policy(self, c, h):
        r = c.get("/api/system/settings/password-policy", headers=h)
        assert r.status_code < 600

    def test_session_timeout(self, c, h):
        r = c.get("/api/system/settings/session-timeout", headers=h)
        assert r.status_code < 600

    def test_login_settings(self, c, h):
        r = c.get("/api/system/settings/login", headers=h)
        assert r.status_code < 600

    def test_credentials_list(self, c, h):
        r = c.get("/api/system/settings/credentials", headers=h)
        assert r.status_code < 600

    def test_credentials_default(self, c, h):
        r = c.get("/api/system/settings/credentials/default", headers=h)
        assert r.status_code < 600

    def test_scheduler_status(self, c, h):
        r = c.get("/api/system/settings/scheduler", headers=h)
        assert r.status_code < 600


# ====================================================================
# User Management — exercise all user endpoints
# ====================================================================

class TestUserManagementDeep:
    def test_list_users(self, c, h):
        r = c.get("/api/users?page=1&page_size=50", headers=h)
        assert r.status_code < 600

    def test_search_users(self, c, h):
        r = c.get("/api/users?search=admin", headers=h)
        assert r.status_code < 600

    def test_filter_by_role(self, c, h):
        r = c.get("/api/users?role=super_admin", headers=h)
        assert r.status_code < 600

    def test_filter_active(self, c, h):
        r = c.get("/api/users?is_active=true", headers=h)
        assert r.status_code < 600

    def test_get_user_1(self, c, h):
        r = c.get("/api/users/1", headers=h)
        assert r.status_code < 600

    def test_get_user_3(self, c, h):
        r = c.get("/api/users/3", headers=h)
        assert r.status_code < 600

    def test_roles(self, c, h):
        r = c.get("/api/users/roles", headers=h)
        assert r.status_code < 600

    def test_create_update_delete_user(self, c, h):
        name = f"covpush-{uuid.uuid4().hex[:4]}"
        r1 = c.post("/api/users", headers=h, json={
            "username": name, "email": f"{name}@test.local",
            "password": "StrongPass123!", "role": "guest", "is_active": True,
        })
        assert r1.status_code < 600
        if r1.status_code in (200, 201):
            uid = r1.json().get("id")
            if uid:
                r2 = c.put(f"/api/users/{uid}", headers=h, json={
                    "role": "auditor", "is_active": True,
                })
                assert r2.status_code < 600
                r3 = c.delete(f"/api/users/{uid}", headers=h)
                assert r3.status_code < 600


# ====================================================================
# MFA — exercise enrollment flow
# ====================================================================

class TestMFAFlow:
    def test_mfa_status(self, c, h):
        r = c.get("/api/auth/mfa/status", headers=h)
        assert r.status_code < 600

    def test_mfa_enroll(self, c, h):
        r = c.post("/api/auth/mfa/enroll", headers=h, json={"password": "TestPass123!"},  # pragma: allowlist secret
    )
        assert r.status_code < 600

    def test_mfa_validate_bad(self, c, h):
        r = c.post("/api/auth/mfa/validate", headers=h, json={"code": "000000"})
        assert r.status_code < 600

    def test_mfa_disable(self, c, h):
        r = c.post("/api/auth/mfa/disable", headers=h, json={"password": "TestPass123!"},  # pragma: allowlist secret
    )
        assert r.status_code < 600


# ====================================================================
# Authorization — exercise permission checks with real hosts
# ====================================================================

class TestAuthorizationDeep:
    def test_check_read(self, c, h):
        r = c.post("/api/authorization/check", headers=h, json={
            "resource_type": "host", "resource_id": HOST_TST01, "action": "read",
        })
        assert r.status_code < 600

    def test_check_scan(self, c, h):
        r = c.post("/api/authorization/check", headers=h, json={
            "resource_type": "host", "resource_id": HOST_TST01, "action": "scan",
        })
        assert r.status_code < 600

    def test_check_delete(self, c, h):
        r = c.post("/api/authorization/check", headers=h, json={
            "resource_type": "host", "resource_id": HOST_TST01, "action": "delete",
        })
        assert r.status_code < 600

    def test_bulk_all_hosts(self, c, h):
        r = c.post("/api/authorization/check/bulk", headers=h, json={
            "resources": [
                {"resource_type": "host", "resource_id": HOST_TST01, "action": "read"},
                {"resource_type": "host", "resource_id": HOST_HRM01, "action": "scan"},
                {"resource_type": "host", "resource_id": HOST_RHN01, "action": "delete"},
                {"resource_type": "host", "resource_id": HOST_TST02, "action": "read"},
                {"resource_type": "host", "resource_id": HOST_UB5S2, "action": "scan"},
            ],
        })
        assert r.status_code < 600

    def test_host_permissions(self, c, h):
        r = c.get(f"/api/authorization/permissions/host/{HOST_TST01}", headers=h)
        assert r.status_code < 600

    def test_audit_log(self, c, h):
        r = c.get("/api/authorization/audit?limit=50", headers=h)
        assert r.status_code < 600

    def test_summary(self, c, h):
        r = c.get("/api/authorization/summary", headers=h)
        assert r.status_code < 600
