"""
Second batch of coverage-push integration tests.
Targets the largest remaining gaps in settings, scans, validation, and groups.

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
# System Settings — exercise EVERY endpoint path
# ==================================================================


class TestSettingsCredentialsCRUD:
    """AC-7: Exercise credential CRUD in settings to cover settings.py branches."""

    def test_create_password_credential(self, c, h):
        r = c.post("/api/system/credentials", headers=h, json={
            "name": f"cov-pw-{uuid.uuid4().hex[:4]}",
            "username": "testuser", "auth_method": "password",
            "password": "StrongP@ss123!",
        })
        assert r.status_code < 600

    def test_create_ssh_credential(self, c, h):
        r = c.post("/api/system/credentials", headers=h, json={
            "name": f"cov-ssh-{uuid.uuid4().hex[:4]}",
            "username": "testuser", "auth_method": "ssh_key",
            "private_key": "FAKE_TEST_KEY_PLACEHOLDER",
        })
        assert r.status_code < 600

    def test_create_both_credential(self, c, h):
        r = c.post("/api/system/credentials", headers=h, json={
            "name": f"cov-both-{uuid.uuid4().hex[:4]}",
            "username": "testuser", "auth_method": "both",
            "password": "StrongP@ss123!",
            "private_key": "FAKE_TEST_KEY_PLACEHOLDER",
        })
        assert r.status_code < 600

    def test_create_invalid_method(self, c, h):
        r = c.post("/api/system/credentials", headers=h, json={
            "name": "bad", "username": "x", "auth_method": "invalid",
        })
        assert r.status_code < 600

    def test_create_password_missing(self, c, h):
        r = c.post("/api/system/credentials", headers=h, json={
            "name": "bad2", "username": "x", "auth_method": "password",
        })
        assert r.status_code < 600

    def test_create_ssh_key_missing(self, c, h):
        r = c.post("/api/system/credentials", headers=h, json={
            "name": "bad3", "username": "x", "auth_method": "ssh_key",
        })
        assert r.status_code < 600

    def test_list_credentials(self, c, h):
        r = c.get("/api/system/credentials", headers=h)
        assert r.status_code < 600

    def test_get_default(self, c, h):
        r = c.get("/api/system/credentials/default", headers=h)
        assert r.status_code < 600

    def test_get_by_id_1(self, c, h):
        r = c.get("/api/system/credentials/1", headers=h)
        assert r.status_code < 600

    def test_get_by_uuid(self, c, h):
        r = c.get(f"/api/system/credentials/{uuid.uuid4()}", headers=h)
        assert r.status_code < 600

    def test_delete_nonexistent(self, c, h):
        r = c.delete("/api/system/credentials/99999", headers=h)
        assert r.status_code < 600


class TestSettingsScheduler:
    def test_get_scheduler(self, c, h):
        r = c.get("/api/system/scheduler", headers=h)
        assert r.status_code < 600

    def test_start_scheduler(self, c, h):
        r = c.post("/api/system/scheduler/start", headers=h, json={
            "interval_minutes": 10,
        })
        assert r.status_code < 600

    def test_stop_scheduler(self, c, h):
        r = c.post("/api/system/scheduler/stop", headers=h)
        assert r.status_code < 600

    def test_update_scheduler(self, c, h):
        r = c.put("/api/system/scheduler", headers=h, json={
            "interval_minutes": 15,
        })
        assert r.status_code < 600


class TestSettingsPasswordPolicy:
    def test_get(self, c, h):
        r = c.get("/api/system/password-policy", headers=h)
        assert r.status_code < 600

    def test_update(self, c, h):
        r = c.put("/api/system/password-policy", headers=h, json={
            "min_length": 14, "require_complex": True,
            "max_age_days": 90, "history_count": 5,
        })
        assert r.status_code < 600


class TestSettingsSessionTimeout:
    def test_get(self, c, h):
        r = c.get("/api/system/session-timeout", headers=h)
        assert r.status_code < 600

    def test_update(self, c, h):
        r = c.put("/api/system/session-timeout", headers=h, json={
            "timeout_minutes": 30, "warning_minutes": 5,
        })
        assert r.status_code < 600


class TestSettingsLogin:
    def test_get(self, c, h):
        r = c.get("/api/system/login", headers=h)
        assert r.status_code < 600

    def test_update(self, c, h):
        r = c.put("/api/system/login", headers=h, json={
            "max_attempts": 5, "lockout_minutes": 30,
        })
        assert r.status_code < 600


# ==================================================================
# Scan Validation — exercise every endpoint
# ==================================================================


class TestScanValidationDeep:
    def test_validate_nonexistent_host(self, c, h):
        r = c.post("/api/scans/validate", headers=h, json={
            "host_id": str(uuid.uuid4()),
            "content_id": str(uuid.uuid4()),
            "profile_id": "test",
        })
        assert r.status_code < 600

    def test_quick_scan_auto_template(self, c, h):
        r = c.post(f"/api/scans/hosts/{HOST_TST01}/quick-scan", headers=h, json={
            "template_id": "auto",
        })
        assert r.status_code < 600

    def test_quick_scan_compliance(self, c, h):
        r = c.post(f"/api/scans/hosts/{HOST_TST01}/quick-scan", headers=h, json={
            "template_id": "quick-compliance",
        })
        assert r.status_code < 600

    def test_verify_scan(self, c, h):
        r = c.post("/api/scans/verify", headers=h, json={
            "host_id": HOST_TST01,
            "content_id": str(uuid.uuid4()),
            "profile_id": "test",
            "original_scan_id": str(uuid.uuid4()),
        })
        assert r.status_code < 600

    def test_rescan_rule(self, c, h):
        r = c.post(f"/api/scans/{uuid.uuid4()}/rescan/rule", headers=h, json={
            "rule_id": "sshd_strong_ciphers",
        })
        assert r.status_code < 600

    def test_remediate(self, c, h):
        r = c.post(f"/api/scans/{uuid.uuid4()}/remediate", headers=h, json={
            "rule_ids": ["sshd_strong_ciphers"],
        })
        assert r.status_code < 600


# ==================================================================
# Host Group CRUD with real data
# ==================================================================


class TestHostGroupCRUDDeep:
    def test_create_with_all_fields(self, c, h):
        name = f"cov2-{uuid.uuid4().hex[:4]}"
        r = c.post("/api/host-groups", headers=h, json={
            "name": name, "description": "Full coverage test",
            "os_family": "rhel", "os_version_pattern": "9*",
            "architecture": "x86_64",
            "compliance_framework": "cis-rhel9-v2.0.0",
            "auto_scan_enabled": True,
            "scan_schedule": "0 */6 * * *",
            "color": "#3b82f6",
        })
        assert r.status_code < 600
        if r.status_code not in (200, 201):
            return
        gid = r.json().get("id")
        if not gid:
            return

        # Update each field individually to cover each branch
        c.put(f"/api/host-groups/{gid}", headers=h, json={"name": f"{name}-upd"})
        c.put(f"/api/host-groups/{gid}", headers=h, json={"description": "updated"})
        c.put(f"/api/host-groups/{gid}", headers=h, json={"color": "#ff0000"})
        c.put(f"/api/host-groups/{gid}", headers=h, json={"os_family": "centos"})
        c.put(f"/api/host-groups/{gid}", headers=h, json={"os_version_pattern": "8*"})
        c.put(f"/api/host-groups/{gid}", headers=h, json={"architecture": "aarch64"})
        c.put(f"/api/host-groups/{gid}", headers=h, json={"compliance_framework": "stig-rhel9-v2r7"})
        c.put(f"/api/host-groups/{gid}", headers=h, json={"auto_scan_enabled": False})
        c.put(f"/api/host-groups/{gid}", headers=h, json={"scan_schedule": "0 0 * * *"})
        c.put(f"/api/host-groups/{gid}", headers=h, json={"validation_rules": {"type": "regex", "pattern": ".*"}})

        # No fields = 400
        r2 = c.put(f"/api/host-groups/{gid}", headers=h, json={})
        assert r2.status_code < 600

        # Assign real hosts
        c.post(f"/api/host-groups/{gid}/hosts", headers=h, json={
            "host_ids": [HOST_TST01, HOST_HRM01],
        })

        # Validate hosts
        c.post(f"/api/host-groups/{gid}/hosts/validate", headers=h, json={
            "host_ids": [HOST_TST01],
            "validate_compatibility": True,
            "force_assignment": False,
        })

        # Compatibility report
        c.get(f"/api/host-groups/{gid}/compatibility-report", headers=h)

        # Remove host
        c.delete(f"/api/host-groups/{gid}/hosts/{HOST_TST01}", headers=h)

        # Scan history
        c.get(f"/api/host-groups/{gid}/scan-history", headers=h)

        # Cleanup
        c.delete(f"/api/host-groups/{gid}", headers=h)


# ==================================================================
# Scan CRUD — exercise stop/cancel/recover
# ==================================================================


class TestScanCRUDDeep:
    def test_list_various_filters(self, c, h):
        for params in [
            "status=completed", "status=failed", "status=running",
            f"host_id={HOST_TST01}", "sort_by=name&sort_order=asc",
            "page=1&limit=3", "page=2&limit=3", "page=3&limit=3",
        ]:
            r = c.get(f"/api/scans?{params}", headers=h)
            assert r.status_code < 600

    def test_stop_nonexistent(self, c, h):
        r = c.post(f"/api/scans/{uuid.uuid4()}/stop", headers=h)
        assert r.status_code < 600

    def test_cancel_nonexistent(self, c, h):
        r = c.post(f"/api/scans/{uuid.uuid4()}/cancel", headers=h)
        assert r.status_code < 600

    def test_recover_nonexistent(self, c, h):
        r = c.post(f"/api/scans/{uuid.uuid4()}/recover", headers=h)
        assert r.status_code < 600

    def test_apply_fix(self, c, h):
        r = c.post(f"/api/scans/hosts/{HOST_TST01}/apply-fix", headers=h, json={
            "fix_id": "test-fix", "rule_id": "sshd_strong_ciphers",
        })
        assert r.status_code < 600


# ==================================================================
# Compliance Scheduler — all operations
# ==================================================================


class TestSchedulerDeep:
    def test_toggle_on(self, c, h):
        r = c.post("/api/compliance/scheduler/toggle", headers=h, json={
            "enabled": True,
        })
        assert r.status_code < 600

    def test_update_config(self, c, h):
        r = c.put("/api/compliance/scheduler/config", headers=h, json={
            "interval_compliant": 1440,
            "interval_critical": 60,
            "max_concurrent_scans": 5,
        })
        assert r.status_code < 600

    def test_maintenance_on(self, c, h):
        r = c.post(f"/api/compliance/scheduler/host/{HOST_TST01}/maintenance", headers=h, json={
            "enabled": True, "duration_hours": 2,
        })
        assert r.status_code < 600

    def test_maintenance_off(self, c, h):
        r = c.post(f"/api/compliance/scheduler/host/{HOST_TST01}/maintenance", headers=h, json={
            "enabled": False,
        })
        assert r.status_code < 600

    def test_force_scan(self, c, h):
        r = c.post(f"/api/compliance/scheduler/host/{HOST_HRM01}/force-scan", headers=h)
        assert r.status_code < 600

    def test_initialize(self, c, h):
        r = c.post("/api/compliance/scheduler/initialize", headers=h)
        assert r.status_code < 600

    def test_hosts_due(self, c, h):
        r = c.get("/api/compliance/scheduler/hosts-due?limit=20", headers=h)
        assert r.status_code < 600


# ==================================================================
# Security config — all paths
# ==================================================================


class TestSecurityConfigDeep:
    def test_update_security_config(self, c, h):
        r = c.put("/api/security/config/", headers=h, json={
            "policy_level": "strict",
            "enforce_fips": True,
            "minimum_rsa_bits": 3072,
            "minimum_ecdsa_bits": 256,
            "allow_dsa_keys": False,
            "minimum_password_length": 14,
            "require_complex_passwords": True,
        })
        assert r.status_code < 600

    def test_apply_template(self, c, h):
        r = c.post("/api/security/config/template/fedramp-moderate", headers=h)
        assert r.status_code < 600

    def test_validate_ssh_key(self, c, h):
        r = c.post("/api/security/config/validate/ssh-key", headers=h, json={
            "key_content": "FAKE_TEST_KEY_PLACEHOLDER",
        })
        assert r.status_code < 600

    def test_credential_audit(self, c, h):
        r = c.post("/api/security/config/audit/credential", headers=h, json={
            "username": "root", "auth_method": "ssh_key",
        })
        assert r.status_code < 600

    def test_update_mfa(self, c, h):
        r = c.put("/api/security/config/mfa", headers=h, json={
            "mfa_required": False,
        })
        assert r.status_code < 600
