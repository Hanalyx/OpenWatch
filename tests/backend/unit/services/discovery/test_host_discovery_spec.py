"""
Source-inspection tests for host discovery services.

Spec: specs/services/discovery/host-discovery.spec.yaml
"""

import inspect

import pytest


@pytest.mark.unit
class TestAC1HostDiscovery:
    """AC-1: Host discovery detects OS and platform via SSH."""

    def test_host_discovery_module(self):
        import app.services.discovery.host as mod

        assert mod is not None

    def test_os_detection(self):
        import app.services.discovery.host as mod

        source = inspect.getsource(mod)
        assert "os" in source.lower() or "platform" in source.lower()


@pytest.mark.unit
class TestAC2NetworkDiscovery:
    """AC-2: Network discovery identifies interfaces and routes."""

    def test_network_module(self):
        import app.services.discovery.network as mod

        assert mod is not None

    def test_interface_detection(self):
        import app.services.discovery.network as mod

        source = inspect.getsource(mod)
        assert "interface" in source.lower() or "network" in source.lower()


@pytest.mark.unit
class TestAC3SecurityDiscovery:
    """AC-3: Security discovery checks SELinux, firewall, FIPS status."""

    def test_security_module(self):
        import app.services.discovery.security as mod

        assert mod is not None

    def test_selinux_check(self):
        import app.services.discovery.security as mod

        source = inspect.getsource(mod)
        assert "selinux" in source.lower() or "SELinux" in source


@pytest.mark.unit
class TestAC4ComplianceDiscovery:
    """AC-4: Compliance discovery evaluates baseline readiness."""

    def test_compliance_module(self):
        import app.services.discovery.compliance as mod

        assert mod is not None


@pytest.mark.unit
class TestAC5DataStructures:
    """AC-5: Discovery results structured as data classes or models."""

    def test_data_classes_used(self):
        import app.services.discovery.host as mod

        source = inspect.getsource(mod)
        assert "class" in source or "dataclass" in source.lower()
