"""
SSH Settings API spec compliance tests.
Verifies that routes/ssh/settings.py implements the behavioral contract
defined in the ssh-settings spec via source inspection.

Spec: specs/api/ssh/ssh-settings.spec.yaml
"""

import inspect

import pytest


@pytest.mark.unit
class TestAC1PolicyRequiresSystemConfig:
    """AC-1: Get/set SSH policy requires SYSTEM_CONFIG permission."""

    def test_get_policy_requires_system_config(self):
        import app.routes.ssh.settings as mod

        source = inspect.getsource(mod.get_ssh_policy)
        assert "require_permission" in source or "SYSTEM_CONFIG" in source

    def test_set_policy_requires_system_config(self):
        import app.routes.ssh.settings as mod

        source = inspect.getsource(mod.set_ssh_policy)
        assert "require_permission" in source or "SYSTEM_CONFIG" in source

    def test_module_imports_system_config_permission(self):
        import app.routes.ssh.settings as mod

        source = inspect.getsource(mod)
        assert "Permission.SYSTEM_CONFIG" in source


@pytest.mark.unit
class TestAC2KnownHostsRequiresSystemConfig:
    """AC-2: Known hosts CRUD requires SYSTEM_CONFIG permission."""

    def test_get_known_hosts_requires_system_config(self):
        import app.routes.ssh.settings as mod

        source = inspect.getsource(mod.get_known_hosts)
        assert "require_permission" in source or "SYSTEM_CONFIG" in source

    def test_add_known_host_requires_system_config(self):
        import app.routes.ssh.settings as mod

        source = inspect.getsource(mod.add_known_host)
        assert "require_permission" in source or "SYSTEM_CONFIG" in source

    def test_remove_known_host_requires_system_config(self):
        import app.routes.ssh.settings as mod

        source = inspect.getsource(mod.remove_known_host)
        assert "require_permission" in source or "SYSTEM_CONFIG" in source


@pytest.mark.unit
class TestAC3ConnectivityRequiresScanExecute:
    """AC-3: Test SSH connectivity requires SCAN_EXECUTE permission."""

    def test_test_connectivity_requires_scan_execute(self):
        import app.routes.ssh.settings as mod

        source = inspect.getsource(mod.test_ssh_connectivity)
        assert "require_permission" in source or "SCAN_EXECUTE" in source

    def test_module_imports_scan_execute_permission(self):
        import app.routes.ssh.settings as mod

        source = inspect.getsource(mod)
        assert "Permission.SCAN_EXECUTE" in source


@pytest.mark.unit
class TestAC4PolicyDelegatesToSSHConfigManager:
    """AC-4: Policy operations delegate to SSHConfigManager."""

    def test_get_policy_uses_ssh_config_manager(self):
        import app.routes.ssh.settings as mod

        source = inspect.getsource(mod.get_ssh_policy)
        assert "SSHConfigManager" in source

    def test_set_policy_uses_ssh_config_manager(self):
        import app.routes.ssh.settings as mod

        source = inspect.getsource(mod.set_ssh_policy)
        assert "SSHConfigManager" in source

    def test_module_imports_ssh_config_manager(self):
        import app.routes.ssh.settings as mod

        source = inspect.getsource(mod)
        assert "SSHConfigManager" in source


@pytest.mark.unit
class TestAC5KnownHostsSupportsHostnameFilter:
    """AC-5: Known host operations support hostname filter."""

    def test_get_known_hosts_has_hostname_param(self):
        import app.routes.ssh.settings as mod

        source = inspect.getsource(mod.get_known_hosts)
        assert "hostname" in source

    def test_get_known_hosts_passes_hostname_filter(self):
        import app.routes.ssh.settings as mod

        source = inspect.getsource(mod.get_known_hosts)
        assert "get_known_hosts(hostname)" in source


@pytest.mark.unit
class TestAC6ConnectivityDelegatesToHostMonitor:
    """AC-6: Test connectivity delegates to HostMonitor.check_ssh_connectivity."""

    def test_connectivity_uses_host_monitor(self):
        import app.routes.ssh.settings as mod

        source = inspect.getsource(mod.test_ssh_connectivity)
        assert "HostMonitor" in source

    def test_connectivity_calls_check_ssh(self):
        import app.routes.ssh.settings as mod

        source = inspect.getsource(mod.test_ssh_connectivity)
        assert "check_ssh_connectivity" in source
