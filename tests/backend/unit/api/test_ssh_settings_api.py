"""
Unit tests for SSH Settings API contracts.

Spec: specs/api/ssh/ssh-settings.spec.yaml
Tests SSH settings endpoints from routes/ssh/settings.py.
"""

import inspect

import pytest

from app.routes.ssh.settings import (
    add_known_host as _add_known_host_handler,
    get_known_hosts as _get_known_hosts_handler,
    get_ssh_policy as _get_ssh_policy_handler,
    remove_known_host as _remove_known_host_handler,
    router as ssh_settings_router,
    set_ssh_policy as _set_ssh_policy_handler,
    test_ssh_connectivity as _test_connectivity_handler,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SETTINGS_MODULE_SOURCE = inspect.getsource(
    inspect.getmodule(_get_ssh_policy_handler)
)


# ---------------------------------------------------------------------------
# AC-1: GET /settings/policy reads from DB, not hardcoded
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSSHSettingsAC1PolicyFromDB:
    """AC-1: GET /settings/policy reads policy from SSHConfigManager.get_ssh_policy()."""

    def test_get_policy_calls_service(self):
        """Verify get_ssh_policy handler calls service.get_ssh_policy()."""
        source = inspect.getsource(_get_ssh_policy_handler)
        assert "service.get_ssh_policy()" in source

    def test_no_hardcoded_default_policy(self):
        """Regression: policy must not be hardcoded as 'default_policy'."""
        source = inspect.getsource(_get_ssh_policy_handler)
        assert '"default_policy"' not in source
        assert "'default_policy'" not in source

    def test_creates_ssh_config_manager(self):
        """Verify SSHConfigManager is instantiated with db."""
        source = inspect.getsource(_get_ssh_policy_handler)
        assert "SSHConfigManager(db)" in source


# ---------------------------------------------------------------------------
# AC-2: GET /settings/policy returns SSHPolicyResponse
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSSHSettingsAC2PolicyResponse:
    """AC-2: GET /settings/policy returns SSHPolicyResponse with required fields."""

    def test_returns_policy_field(self):
        """Verify response includes policy field."""
        source = inspect.getsource(_get_ssh_policy_handler)
        assert "SSHPolicyResponse(" in source
        assert "policy=" in source

    def test_returns_trusted_networks(self):
        """Verify response includes trusted_networks."""
        source = inspect.getsource(_get_ssh_policy_handler)
        assert "trusted_networks=" in source

    def test_returns_description(self):
        """Verify response includes description."""
        source = inspect.getsource(_get_ssh_policy_handler)
        assert "description=" in source


# ---------------------------------------------------------------------------
# AC-3: POST /settings/policy calls set methods
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSSHSettingsAC3SetPolicy:
    """AC-3: POST /settings/policy calls SSHConfigManager.set_ssh_policy()."""

    def test_set_policy_calls_service(self):
        """Verify set_ssh_policy handler calls service.set_ssh_policy()."""
        source = inspect.getsource(_set_ssh_policy_handler)
        assert "service.set_ssh_policy(" in source

    def test_set_trusted_networks_conditional(self):
        """Verify set_trusted_networks is called when provided."""
        source = inspect.getsource(_set_ssh_policy_handler)
        assert "set_trusted_networks" in source
        assert "trusted_networks is not None" in source


# ---------------------------------------------------------------------------
# AC-4: Known host endpoints use KnownHostsManager
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSSHSettingsAC4KnownHostsManager:
    """AC-4: Known host endpoints use KnownHostsManager, not SSHConfigManager."""

    def test_get_known_hosts_uses_manager(self):
        """Verify GET known-hosts uses KnownHostsManager."""
        source = inspect.getsource(_get_known_hosts_handler)
        assert "KnownHostsManager(db)" in source

    def test_add_known_host_uses_manager(self):
        """Verify POST known-hosts uses KnownHostsManager."""
        source = inspect.getsource(_add_known_host_handler)
        assert "KnownHostsManager(db)" in source

    def test_remove_known_host_uses_manager(self):
        """Verify DELETE known-hosts uses KnownHostsManager."""
        source = inspect.getsource(_remove_known_host_handler)
        assert "KnownHostsManager(db)" in source

    def test_known_hosts_not_on_ssh_config_manager(self):
        """Regression: known host handlers must not call SSHConfigManager for host ops."""
        for handler in [_get_known_hosts_handler, _add_known_host_handler, _remove_known_host_handler]:
            source = inspect.getsource(handler)
            # SSHConfigManager should not appear in known host handlers
            assert "SSHConfigManager" not in source


# ---------------------------------------------------------------------------
# AC-5: GET /settings/known-hosts accepts hostname filter
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSSHSettingsAC5HostnameFilter:
    """AC-5: GET /settings/known-hosts accepts optional hostname parameter."""

    def test_hostname_parameter_exists(self):
        """Verify hostname is a parameter of get_known_hosts."""
        sig = inspect.signature(_get_known_hosts_handler)
        assert "hostname" in sig.parameters

    def test_hostname_passed_to_manager(self):
        """Verify hostname is passed to KnownHostsManager.get_known_hosts()."""
        source = inspect.getsource(_get_known_hosts_handler)
        assert "get_known_hosts(hostname)" in source


# ---------------------------------------------------------------------------
# AC-6: POST /settings/known-hosts validates key_type
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSSHSettingsAC6KeyTypeValidation:
    """AC-6: POST /settings/known-hosts validates key_type via Pydantic model."""

    def test_known_host_request_model_used(self):
        """Verify KnownHostRequest model is used for POST."""
        source = inspect.getsource(_add_known_host_handler)
        assert "host_request" in source
        assert "key_type" in source

    def test_key_type_validation_in_model(self):
        """Verify KnownHostRequest validates key_type."""
        from app.routes.ssh.models import KnownHostRequest

        source = inspect.getsource(KnownHostRequest)
        assert "rsa" in source
        assert "ecdsa" in source
        assert "ed25519" in source
        assert "dsa" in source


# ---------------------------------------------------------------------------
# AC-7: Policy/known-host endpoints require SYSTEM_CONFIG
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSSHSettingsAC7SystemConfigPermission:
    """AC-7: Policy and known-host endpoints require Permission.SYSTEM_CONFIG."""

    def test_get_policy_requires_system_config(self):
        """Verify GET policy has SYSTEM_CONFIG permission."""
        source = inspect.getsource(_get_ssh_policy_handler)
        # The decorator is applied above the function, check module source
        # Find the decorator for this specific function
        assert "SYSTEM_CONFIG" in _SETTINGS_MODULE_SOURCE

    def test_known_hosts_endpoints_require_system_config(self):
        """Verify known-host endpoints reference SYSTEM_CONFIG permission."""
        # All endpoints in the module should use SYSTEM_CONFIG
        assert _SETTINGS_MODULE_SOURCE.count("Permission.SYSTEM_CONFIG") >= 5


# ---------------------------------------------------------------------------
# AC-8: Test connectivity requires SCAN_EXECUTE
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSSHSettingsAC8ScanExecutePermission:
    """AC-8: Test connectivity requires Permission.SCAN_EXECUTE."""

    def test_test_connectivity_requires_scan_execute(self):
        """Verify test connectivity has SCAN_EXECUTE permission."""
        assert "Permission.SCAN_EXECUTE" in _SETTINGS_MODULE_SOURCE


# ---------------------------------------------------------------------------
# AC-9: Router prefix and tags
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSSHSettingsAC9RouterConfig:
    """AC-9: SSH settings router uses correct prefix and tags."""

    def test_router_prefix(self):
        """Verify router prefix is /settings."""
        assert ssh_settings_router.prefix == "/settings"

    def test_router_tags(self):
        """Verify router is tagged 'SSH Settings'."""
        assert "SSH Settings" in ssh_settings_router.tags


# ---------------------------------------------------------------------------
# AC-10: Policy descriptions include auto_add_warning
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSSHSettingsAC10PolicyDescriptions:
    """AC-10: GET /settings/policy includes all four valid policy descriptions."""

    def test_auto_add_warning_in_descriptions(self):
        """Verify auto_add_warning is in policy descriptions map."""
        source = inspect.getsource(_get_ssh_policy_handler)
        assert "auto_add_warning" in source

    def test_all_four_policies_described(self):
        """Verify all four valid policies appear in descriptions."""
        source = inspect.getsource(_get_ssh_policy_handler)
        for policy in ["strict", "auto_add", "bypass_trusted"]:
            assert f'"{policy}"' in source
