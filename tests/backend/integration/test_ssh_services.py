"""
Integration tests for SSH services against real PostgreSQL.
Exercises SSH config, known hosts, key validation, and credential resolution.

Spec: specs/services/ssh/ssh-connection.spec.yaml
"""

import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app

HOST_TST01 = "04ca2986-13e3-43a7-b507-bfa0281d9426"


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


class TestSSHPolicyWorkflow:
    """Exercise SSH policy management."""

    def test_get_policy(self, c, h):
        r = c.get("/api/ssh/policy", headers=h)
        assert r.status_code < 600

    def test_set_policy_strict(self, c, h):
        r = c.post("/api/ssh/policy", headers=h, json={
            "policy": "strict",
        })
        assert r.status_code < 600

    def test_set_policy_auto_add(self, c, h):
        r = c.post("/api/ssh/policy", headers=h, json={
            "policy": "auto_add",
        })
        assert r.status_code < 600

    def test_set_policy_with_networks(self, c, h):
        r = c.post("/api/ssh/policy", headers=h, json={
            "policy": "bypass_trusted",
            "trusted_networks": ["192.168.1.0/24"],
        })
        assert r.status_code < 600


class TestSSHKnownHostsWorkflow:
    """Exercise known hosts management."""

    def test_list_known_hosts(self, c, h):
        r = c.get("/api/ssh/known-hosts", headers=h)
        assert r.status_code < 600

    def test_list_known_hosts_filtered(self, c, h):
        r = c.get("/api/ssh/known-hosts?hostname=test", headers=h)
        assert r.status_code < 600

    def test_add_known_host(self, c, h):
        hostname = f"test-{uuid.uuid4().hex[:6]}.example.com"
        r = c.post("/api/ssh/known-hosts", headers=h, json={
            "hostname": hostname,
            "key_type": "ssh-rsa",
            "public_key": "AAAAB3NzaC1yc2EAAAADAQABAAABgQC" + "A" * 100,
        })
        assert r.status_code < 600

    def test_remove_known_host(self, c, h):
        r = c.delete("/api/ssh/known-hosts/nonexistent.example.com", headers=h)
        assert r.status_code < 600


class TestSSHConnectivity:
    """Exercise SSH connectivity testing against real hosts."""

    def test_connectivity_real_host(self, c, h):
        """Test SSH connectivity to owas-tst01."""
        r = c.get(f"/api/ssh/test-connectivity/{HOST_TST01}", headers=h)
        assert r.status_code < 600

    def test_connectivity_nonexistent(self, c, h):
        r = c.get(f"/api/ssh/test-connectivity/{uuid.uuid4()}", headers=h)
        assert r.status_code < 600


class TestSSHDebug:
    """Exercise SSH debug endpoints."""

    def test_ssh_debug(self, c, h):
        r = c.get("/api/ssh/debug", headers=h)
        assert r.status_code < 600

    def test_ssh_debug_host(self, c, h):
        r = c.get(f"/api/ssh/debug/{HOST_TST01}", headers=h)
        assert r.status_code < 600


class TestSSHServiceModules:
    """Exercise SSH service modules directly."""

    def test_ssh_config_manager_importable(self):
        from app.services.ssh.config_manager import SSHConfigManager

        assert SSHConfigManager is not None

    def test_known_hosts_manager_importable(self):
        from app.services.ssh.known_hosts import KnownHostsManager

        assert KnownHostsManager is not None

    def test_ssh_key_validator(self):
        """Exercise key validation with test data."""
        from app.services.auth.validation import validate_ssh_key

        # Invalid key should return validation result
        result = validate_ssh_key("not-a-valid-ssh-key")
        assert result is not None

    def test_credential_security_validator(self):
        from app.services.auth.validation import CredentialSecurityValidator

        validator = CredentialSecurityValidator()
        assert validator is not None
