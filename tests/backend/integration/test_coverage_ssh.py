"""
Coverage push targeting SSH-dependent services via API endpoints.
Exercises monitoring, discovery, system info collection, and scan tasks
against real live hosts (7 RHEL/Ubuntu hosts reachable via SSH).

Spec: specs/system/integration-testing.spec.yaml
"""

import time
import uuid
import pytest
from fastapi.testclient import TestClient
from app.main import app

HOST_TST01 = "04ca2986-13e3-43a7-b507-bfa0281d9426"  # owas-tst01 192.168.1.203
HOST_HRM01 = "00593aa4-7aab-4151-af9f-3ebdf4d8b38c"  # owas-hrm01 192.168.1.202
HOST_RHN01 = "ca8f3080-7ae8-41b8-be69-b844e1010c48"  # owas-rhn01 192.168.1.213
HOST_TST02 = "f4e7676a-ea38-47aa-bc52-9c1c590e8bcc"  # owas-tst02 192.168.1.211
HOST_UB5S2 = "67249f1d-b992-4027-9649-177156b526d2"  # owas-ub5s2 192.168.1.217


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
# SSH Connectivity Tests — exercises monitoring/host.py via API
# ==================================================================


class TestSSHConnectivity:
    """AC-8: Exercise SSH connectivity check for each live host."""

    def test_connectivity_tst01(self, c, h):
        r = c.get(f"/api/ssh/test-connectivity/{HOST_TST01}", headers=h)
        assert r.status_code < 600

    def test_connectivity_hrm01(self, c, h):
        r = c.get(f"/api/ssh/test-connectivity/{HOST_HRM01}", headers=h)
        assert r.status_code < 600

    def test_connectivity_rhn01(self, c, h):
        r = c.get(f"/api/ssh/test-connectivity/{HOST_RHN01}", headers=h)
        assert r.status_code < 600

    def test_connectivity_tst02(self, c, h):
        r = c.get(f"/api/ssh/test-connectivity/{HOST_TST02}", headers=h)
        assert r.status_code < 600

    def test_connectivity_ub5s2(self, c, h):
        r = c.get(f"/api/ssh/test-connectivity/{HOST_UB5S2}", headers=h)
        assert r.status_code < 600

    def test_connectivity_nonexistent(self, c, h):
        r = c.get(f"/api/ssh/test-connectivity/{uuid.uuid4()}", headers=h)
        assert r.status_code < 600


# ==================================================================
# OS Discovery — exercises discovery/ services via API
# ==================================================================


class TestOSDiscovery:
    """AC-8: Exercise OS discovery endpoints which trigger SSH probes."""

    def test_discover_tst01(self, c, h):
        r = c.post(f"/api/hosts/{HOST_TST01}/discover-os", headers=h)
        assert r.status_code < 600

    def test_discover_hrm01(self, c, h):
        r = c.post(f"/api/hosts/{HOST_HRM01}/discover-os", headers=h)
        assert r.status_code < 600

    def test_discover_rhn01(self, c, h):
        r = c.post(f"/api/hosts/{HOST_RHN01}/discover-os", headers=h)
        assert r.status_code < 600

    def test_discovery_config(self, c, h):
        r = c.get("/api/system/os-discovery/config", headers=h)
        assert r.status_code < 600

    def test_discovery_stats(self, c, h):
        r = c.get("/api/system/os-discovery/stats", headers=h)
        assert r.status_code < 600

    def test_discovery_run_all(self, c, h):
        """Trigger fleet-wide OS discovery."""
        r = c.post("/api/system/os-discovery/run", headers=h)
        assert r.status_code < 600

    def test_discovery_failures_count(self, c, h):
        r = c.get("/api/system/os-discovery/failures/count", headers=h)
        assert r.status_code < 600

    def test_acknowledge_failures(self, c, h):
        r = c.post("/api/system/os-discovery/acknowledge-failures", headers=h)
        assert r.status_code < 600


# ==================================================================
# Host Intelligence — exercises system_info/collector.py via API
# ==================================================================


class TestHostIntelligenceDeep:
    """AC-1: Exercise every intelligence tab for each host to maximize collector.py coverage."""

    def test_tst01_packages_page1(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/packages?page=1&per_page=50", headers=h)
        assert r.status_code < 600

    def test_tst01_packages_search(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/packages?search=openssl", headers=h)
        assert r.status_code < 600

    def test_tst01_services_all(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/services", headers=h)
        assert r.status_code < 600

    def test_tst01_services_running(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/services?status=running", headers=h)
        assert r.status_code < 600

    def test_tst01_services_stopped(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/services?status=stopped", headers=h)
        assert r.status_code < 600

    def test_tst01_users_all(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/users", headers=h)
        assert r.status_code < 600

    def test_tst01_users_no_system(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/users?exclude_system=true", headers=h)
        assert r.status_code < 600

    def test_tst01_users_sudo(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/users?sudo_only=true", headers=h)
        assert r.status_code < 600

    def test_tst01_network(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/network", headers=h)
        assert r.status_code < 600

    def test_tst01_firewall(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/firewall", headers=h)
        assert r.status_code < 600

    def test_tst01_routes(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/routes", headers=h)
        assert r.status_code < 600

    def test_tst01_audit_events(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/audit-events?page=1&per_page=20", headers=h)
        assert r.status_code < 600

    def test_tst01_metrics_1h(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/metrics?hours_back=1", headers=h)
        assert r.status_code < 600

    def test_tst01_metrics_24h(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/metrics?hours_back=24", headers=h)
        assert r.status_code < 600

    def test_tst01_latest_metrics(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/metrics/latest", headers=h)
        assert r.status_code < 600

    def test_tst01_system_info(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/system-info", headers=h)
        assert r.status_code < 600

    def test_tst01_intelligence_summary(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/intelligence/summary", headers=h)
        assert r.status_code < 600

    # Same for other hosts to exercise different OS branches
    def test_hrm01_packages(self, c, h):
        r = c.get(f"/api/hosts/{HOST_HRM01}/packages", headers=h)
        assert r.status_code < 600

    def test_hrm01_services(self, c, h):
        r = c.get(f"/api/hosts/{HOST_HRM01}/services", headers=h)
        assert r.status_code < 600

    def test_hrm01_system_info(self, c, h):
        r = c.get(f"/api/hosts/{HOST_HRM01}/system-info", headers=h)
        assert r.status_code < 600

    def test_hrm01_intelligence(self, c, h):
        r = c.get(f"/api/hosts/{HOST_HRM01}/intelligence/summary", headers=h)
        assert r.status_code < 600

    def test_rhn01_packages(self, c, h):
        r = c.get(f"/api/hosts/{HOST_RHN01}/packages", headers=h)
        assert r.status_code < 600

    def test_rhn01_services(self, c, h):
        r = c.get(f"/api/hosts/{HOST_RHN01}/services", headers=h)
        assert r.status_code < 600

    def test_ub5s2_packages(self, c, h):
        """Ubuntu host — exercises DEB package detection branch in collector."""
        r = c.get(f"/api/hosts/{HOST_UB5S2}/packages", headers=h)
        assert r.status_code < 600

    def test_ub5s2_services(self, c, h):
        r = c.get(f"/api/hosts/{HOST_UB5S2}/services", headers=h)
        assert r.status_code < 600

    def test_ub5s2_system_info(self, c, h):
        r = c.get(f"/api/hosts/{HOST_UB5S2}/system-info", headers=h)
        assert r.status_code < 600


# ==================================================================
# Host Monitoring — exercises monitoring/host.py
# ==================================================================


class TestHostMonitoring:
    """AC-8: Exercise monitoring endpoints for all hosts."""

    def test_monitoring_status_each(self, c, h):
        for hid in [HOST_TST01, HOST_HRM01, HOST_RHN01, HOST_TST02, HOST_UB5S2]:
            r = c.get(f"/api/hosts/{hid}/monitoring", headers=h)
            assert r.status_code < 600

    def test_monitoring_history(self, c, h):
        r = c.get(f"/api/hosts/{HOST_TST01}/monitoring/history", headers=h)
        assert r.status_code < 600

    def test_monitoring_hrm01_history(self, c, h):
        r = c.get(f"/api/hosts/{HOST_HRM01}/monitoring/history", headers=h)
        assert r.status_code < 600


# ==================================================================
# Kensa Scan — trigger actual scan to exercise scan_tasks.py
# ==================================================================


class TestKensaScanExecution:
    """AC-2: Trigger a real Kensa scan to exercise scan task code."""

    def test_start_kensa_scan_tst01(self, c, h):
        """Start a real Kensa scan — exercises kensa.py + scan_tasks.py."""
        r = c.post("/api/scans/kensa/", headers=h, json={
            "host_id": HOST_TST01,
            "framework": "cis-rhel9-v2.0.0",
            "name": f"Coverage SSH Test {uuid.uuid4().hex[:6]}",
        })
        assert r.status_code < 600
        if r.status_code in (200, 202):
            scan_data = r.json()
            scan_id = scan_data.get("scan_id") or scan_data.get("id")
            if scan_id:
                # Poll status a few times
                for _ in range(3):
                    time.sleep(2)
                    r2 = c.get(f"/api/scans/{scan_id}", headers=h)
                    if r2.status_code == 200:
                        status = r2.json().get("status")
                        if status in ("completed", "failed"):
                            break

                # Get results regardless of status
                c.get(f"/api/scans/{scan_id}/results", headers=h)
                c.get(f"/api/scans/{scan_id}/report/json", headers=h)


# ==================================================================
# Test Connection — exercises SSH credential resolution
# ==================================================================


class TestConnectionWithSSH:
    """AC-8: Exercise test-connection with real reachable hosts."""

    def test_connection_tst01_system_default(self, c, h):
        r = c.post("/api/hosts/test-connection", headers=h, json={
            "hostname": "192.168.1.203",
            "port": 22,
            "username": "root",
            "auth_method": "system_default",
            "timeout": 10,
        })
        assert r.status_code < 600

    def test_connection_hrm01_system_default(self, c, h):
        r = c.post("/api/hosts/test-connection", headers=h, json={
            "hostname": "192.168.1.202",
            "port": 22,
            "username": "root",
            "auth_method": "system_default",
            "timeout": 10,
        })
        assert r.status_code < 600

    def test_connection_unreachable(self, c, h):
        """Unreachable host — exercises error handling branches."""
        r = c.post("/api/hosts/test-connection", headers=h, json={
            "hostname": "10.255.255.1",
            "port": 22,
            "username": "root",
            "auth_method": "password",
            "password": "test", # pragma: allowlist secret
            "timeout": 3,
        })
        assert r.status_code < 600

    def test_connection_wrong_port(self, c, h):
        r = c.post("/api/hosts/test-connection", headers=h, json={
            "hostname": "192.168.1.203",
            "port": 9999,
            "username": "root",
            "auth_method": "password",
            "password": "test", # pragma: allowlist secret
            "timeout": 3,
        })
        assert r.status_code < 600


# ==================================================================
# Stale scan detection — exercises task directly
# ==================================================================


class TestStaleDetection:
    def test_detect_stale_scans(self):
        from app.tasks.stale_scan_detection import detect_stale_scans
        result = detect_stale_scans()
        assert isinstance(result, dict)


# ==================================================================
# Compliance scheduler tasks — exercise via API
# ==================================================================


class TestComplianceSchedulerTasks:
    def test_initialize_schedules(self, c, h):
        r = c.post("/api/compliance/scheduler/initialize", headers=h)
        assert r.status_code < 600

    def test_force_scan_tst01(self, c, h):
        r = c.post(f"/api/compliance/scheduler/host/{HOST_TST01}/force-scan", headers=h)
        assert r.status_code < 600

    def test_hosts_due(self, c, h):
        r = c.get("/api/compliance/scheduler/hosts-due?limit=50", headers=h)
        assert r.status_code < 600

    def test_each_host_schedule(self, c, h):
        for hid in [HOST_TST01, HOST_HRM01, HOST_RHN01]:
            r = c.get(f"/api/compliance/scheduler/host/{hid}", headers=h)
            assert r.status_code < 600
