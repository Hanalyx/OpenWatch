"""
Server Intelligence Collector Service spec compliance tests.
Verifies that services/system_info/collector.py implements the behavioral
contract defined in the server-intelligence spec via source inspection.

Spec: specs/services/system-info/server-intelligence.spec.yaml
"""

import inspect

import pytest


@pytest.mark.unit
class TestAC1SystemInfoDataclass:
    """AC-1: SystemInfo dataclass captures OS, kernel, hardware, security state."""

    def test_system_info_class_exists(self):
        from app.services.system_info.collector import SystemInfo

        assert SystemInfo is not None

    def test_system_info_is_dataclass(self):
        import dataclasses

        from app.services.system_info.collector import SystemInfo

        assert dataclasses.is_dataclass(SystemInfo)

    def test_system_info_has_os_name(self):
        from app.services.system_info.collector import SystemInfo

        fields = {f.name for f in SystemInfo.__dataclass_fields__.values()}
        assert "os_name" in fields

    def test_system_info_has_os_version(self):
        from app.services.system_info.collector import SystemInfo

        fields = {f.name for f in SystemInfo.__dataclass_fields__.values()}
        assert "os_version" in fields

    def test_system_info_has_kernel_version(self):
        from app.services.system_info.collector import SystemInfo

        fields = {f.name for f in SystemInfo.__dataclass_fields__.values()}
        assert "kernel_version" in fields

    def test_system_info_has_kernel_release(self):
        from app.services.system_info.collector import SystemInfo

        fields = {f.name for f in SystemInfo.__dataclass_fields__.values()}
        assert "kernel_release" in fields

    def test_system_info_has_architecture(self):
        from app.services.system_info.collector import SystemInfo

        fields = {f.name for f in SystemInfo.__dataclass_fields__.values()}
        assert "architecture" in fields

    def test_system_info_has_cpu_model(self):
        from app.services.system_info.collector import SystemInfo

        fields = {f.name for f in SystemInfo.__dataclass_fields__.values()}
        assert "cpu_model" in fields

    def test_system_info_has_cpu_cores(self):
        from app.services.system_info.collector import SystemInfo

        fields = {f.name for f in SystemInfo.__dataclass_fields__.values()}
        assert "cpu_cores" in fields

    def test_system_info_has_memory_total_mb(self):
        from app.services.system_info.collector import SystemInfo

        fields = {f.name for f in SystemInfo.__dataclass_fields__.values()}
        assert "memory_total_mb" in fields

    def test_system_info_has_selinux_status(self):
        from app.services.system_info.collector import SystemInfo

        fields = {f.name for f in SystemInfo.__dataclass_fields__.values()}
        assert "selinux_status" in fields

    def test_system_info_has_selinux_mode(self):
        from app.services.system_info.collector import SystemInfo

        fields = {f.name for f in SystemInfo.__dataclass_fields__.values()}
        assert "selinux_mode" in fields

    def test_system_info_has_firewall_status(self):
        from app.services.system_info.collector import SystemInfo

        fields = {f.name for f in SystemInfo.__dataclass_fields__.values()}
        assert "firewall_status" in fields

    def test_system_info_has_firewall_service(self):
        from app.services.system_info.collector import SystemInfo

        fields = {f.name for f in SystemInfo.__dataclass_fields__.values()}
        assert "firewall_service" in fields


@pytest.mark.unit
class TestAC2PackageInfoDataclass:
    """AC-2: PackageInfo captures name, version, release, arch, source_repo."""

    def test_package_info_class_exists(self):
        from app.services.system_info.collector import PackageInfo

        assert PackageInfo is not None

    def test_package_info_is_dataclass(self):
        import dataclasses

        from app.services.system_info.collector import PackageInfo

        assert dataclasses.is_dataclass(PackageInfo)

    def test_package_info_has_name(self):
        from app.services.system_info.collector import PackageInfo

        fields = {f.name for f in PackageInfo.__dataclass_fields__.values()}
        assert "name" in fields

    def test_package_info_has_version(self):
        from app.services.system_info.collector import PackageInfo

        fields = {f.name for f in PackageInfo.__dataclass_fields__.values()}
        assert "version" in fields

    def test_package_info_has_release(self):
        from app.services.system_info.collector import PackageInfo

        fields = {f.name for f in PackageInfo.__dataclass_fields__.values()}
        assert "release" in fields

    def test_package_info_has_arch(self):
        from app.services.system_info.collector import PackageInfo

        fields = {f.name for f in PackageInfo.__dataclass_fields__.values()}
        assert "arch" in fields

    def test_package_info_has_source_repo(self):
        from app.services.system_info.collector import PackageInfo

        fields = {f.name for f in PackageInfo.__dataclass_fields__.values()}
        assert "source_repo" in fields


@pytest.mark.unit
class TestAC3ServiceInfoDataclass:
    """AC-3: ServiceInfo captures name, status, enabled state."""

    def test_service_info_class_exists(self):
        from app.services.system_info.collector import ServiceInfo

        assert ServiceInfo is not None

    def test_service_info_is_dataclass(self):
        import dataclasses

        from app.services.system_info.collector import ServiceInfo

        assert dataclasses.is_dataclass(ServiceInfo)

    def test_service_info_has_name(self):
        from app.services.system_info.collector import ServiceInfo

        fields = {f.name for f in ServiceInfo.__dataclass_fields__.values()}
        assert "name" in fields

    def test_service_info_has_status(self):
        from app.services.system_info.collector import ServiceInfo

        fields = {f.name for f in ServiceInfo.__dataclass_fields__.values()}
        assert "status" in fields

    def test_service_info_has_enabled(self):
        from app.services.system_info.collector import ServiceInfo

        fields = {f.name for f in ServiceInfo.__dataclass_fields__.values()}
        assert "enabled" in fields

    def test_service_info_status_values_documented(self):
        import app.services.system_info.collector as mod

        source = inspect.getsource(mod.ServiceInfo)
        assert "running" in source
        assert "stopped" in source
        assert "failed" in source


@pytest.mark.unit
class TestAC4UserInfoDataclass:
    """AC-4: UserInfo captures username, uid, groups, sudo status."""

    def test_user_info_class_exists(self):
        from app.services.system_info.collector import UserInfo

        assert UserInfo is not None

    def test_user_info_is_dataclass(self):
        import dataclasses

        from app.services.system_info.collector import UserInfo

        assert dataclasses.is_dataclass(UserInfo)

    def test_user_info_has_username(self):
        from app.services.system_info.collector import UserInfo

        fields = {f.name for f in UserInfo.__dataclass_fields__.values()}
        assert "username" in fields

    def test_user_info_has_uid(self):
        from app.services.system_info.collector import UserInfo

        fields = {f.name for f in UserInfo.__dataclass_fields__.values()}
        assert "uid" in fields

    def test_user_info_has_groups(self):
        from app.services.system_info.collector import UserInfo

        fields = {f.name for f in UserInfo.__dataclass_fields__.values()}
        assert "groups" in fields

    def test_user_info_has_sudo_rules(self):
        from app.services.system_info.collector import UserInfo

        fields = {f.name for f in UserInfo.__dataclass_fields__.values()}
        assert "sudo_rules" in fields

    def test_user_info_has_sudo_all(self):
        from app.services.system_info.collector import UserInfo

        fields = {f.name for f in UserInfo.__dataclass_fields__.values()}
        assert "has_sudo_all" in fields

    def test_user_info_has_sudo_nopasswd(self):
        from app.services.system_info.collector import UserInfo

        fields = {f.name for f in UserInfo.__dataclass_fields__.values()}
        assert "has_sudo_nopasswd" in fields


@pytest.mark.unit
class TestAC5SupportsRHELAndDebian:
    """AC-5: Collection supports RHEL/CentOS, Debian/Ubuntu distributions."""

    def test_module_documents_rhel_support(self):
        import app.services.system_info.collector as mod

        source = inspect.getsource(mod)
        assert "RHEL" in source

    def test_module_documents_debian_support(self):
        import app.services.system_info.collector as mod

        source = inspect.getsource(mod)
        assert "Debian" in source

    def test_module_documents_ubuntu_support(self):
        import app.services.system_info.collector as mod

        source = inspect.getsource(mod)
        assert "Ubuntu" in source

    def test_module_documents_rpm_detection(self):
        import app.services.system_info.collector as mod

        source = inspect.getsource(mod)
        assert "rpm" in source.lower() or "RPM" in source

    def test_module_documents_deb_detection(self):
        import app.services.system_info.collector as mod

        source = inspect.getsource(mod)
        assert "dpkg" in source or "DEB" in source

    def test_module_documents_firewalld(self):
        import app.services.system_info.collector as mod

        source = inspect.getsource(mod)
        assert "firewalld" in source

    def test_module_documents_ufw(self):
        import app.services.system_info.collector as mod

        source = inspect.getsource(mod)
        assert "ufw" in source

    def test_module_documents_iptables(self):
        import app.services.system_info.collector as mod

        source = inspect.getsource(mod)
        assert "iptables" in source
