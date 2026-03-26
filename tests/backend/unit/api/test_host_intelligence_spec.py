"""
Host Intelligence API spec compliance tests.
Verifies that routes/hosts/intelligence.py implements the behavioral contract
defined in the host-intelligence spec via source inspection.

Spec: specs/api/hosts/host-intelligence.spec.yaml
"""

import inspect

import pytest


@pytest.mark.unit
class TestAC1AllEndpointsRequireHostRead:
    """AC-1: All intelligence endpoints require HOST_READ permission."""

    def test_list_packages_requires_host_read(self):
        import app.routes.hosts.intelligence as mod

        source = inspect.getsource(mod.list_host_packages)
        assert "require_permission" in source or "Permission.HOST_READ" in source

    def test_list_services_requires_host_read(self):
        import app.routes.hosts.intelligence as mod

        source = inspect.getsource(mod.list_host_services)
        assert "require_permission" in source or "Permission.HOST_READ" in source

    def test_get_system_info_requires_host_read(self):
        import app.routes.hosts.intelligence as mod

        source = inspect.getsource(mod.get_host_system_info)
        assert "require_permission" in source or "Permission.HOST_READ" in source

    def test_list_users_requires_host_read(self):
        import app.routes.hosts.intelligence as mod

        source = inspect.getsource(mod.list_host_users)
        assert "require_permission" in source or "Permission.HOST_READ" in source

    def test_list_network_requires_host_read(self):
        import app.routes.hosts.intelligence as mod

        source = inspect.getsource(mod.list_host_network)
        assert "require_permission" in source or "Permission.HOST_READ" in source

    def test_list_metrics_requires_host_read(self):
        import app.routes.hosts.intelligence as mod

        source = inspect.getsource(mod.list_host_metrics)
        assert "require_permission" in source or "Permission.HOST_READ" in source

    def test_module_imports_permission(self):
        import app.routes.hosts.intelligence as mod

        source = inspect.getsource(mod)
        assert "Permission.HOST_READ" in source


@pytest.mark.unit
class TestAC2PackageListingPaginationAndSearch:
    """AC-2: Package listing supports pagination and search."""

    def test_packages_has_limit_param(self):
        import app.routes.hosts.intelligence as mod

        source = inspect.getsource(mod.list_host_packages)
        assert "limit" in source

    def test_packages_has_offset_param(self):
        import app.routes.hosts.intelligence as mod

        source = inspect.getsource(mod.list_host_packages)
        assert "offset" in source

    def test_packages_has_search_param(self):
        import app.routes.hosts.intelligence as mod

        source = inspect.getsource(mod.list_host_packages)
        assert "search" in source


@pytest.mark.unit
class TestAC3ServiceListingStatusFilter:
    """AC-3: Service listing supports status filter."""

    def test_services_has_status_filter(self):
        import app.routes.hosts.intelligence as mod

        source = inspect.getsource(mod.list_host_services)
        assert "status" in source

    def test_services_passes_status_to_service(self):
        import app.routes.hosts.intelligence as mod

        source = inspect.getsource(mod.list_host_services)
        assert "status=status" in source


@pytest.mark.unit
class TestAC4UserListingSystemAndSudoFilters:
    """AC-4: User listing can exclude system accounts and filter by sudo."""

    def test_users_has_include_system_param(self):
        import app.routes.hosts.intelligence as mod

        source = inspect.getsource(mod.list_host_users)
        assert "include_system" in source

    def test_users_has_sudo_filter(self):
        import app.routes.hosts.intelligence as mod

        source = inspect.getsource(mod.list_host_users)
        assert "has_sudo" in source


@pytest.mark.unit
class TestAC5NetworkListingInterfaceTypeFilter:
    """AC-5: Network listing supports interface type filter."""

    def test_network_has_interface_type_param(self):
        import app.routes.hosts.intelligence as mod

        source = inspect.getsource(mod.list_host_network)
        assert "interface_type" in source

    def test_network_passes_interface_type_to_service(self):
        import app.routes.hosts.intelligence as mod

        source = inspect.getsource(mod.list_host_network)
        assert "interface_type=interface_type" in source


@pytest.mark.unit
class TestAC6MetricsHoursBackMax720:
    """AC-6: Metrics endpoint limits hours_back to maximum 720."""

    def test_metrics_hours_back_max_720(self):
        import app.routes.hosts.intelligence as mod

        source = inspect.getsource(mod.list_host_metrics)
        assert "le=720" in source

    def test_metrics_hours_back_parameter_exists(self):
        import app.routes.hosts.intelligence as mod

        source = inspect.getsource(mod.list_host_metrics)
        assert "hours_back" in source


@pytest.mark.unit
class TestAC7SystemInfoReturns404:
    """AC-7: System info returns 404 if no data collected."""

    def test_system_info_returns_404_when_missing(self):
        import app.routes.hosts.intelligence as mod

        source = inspect.getsource(mod.get_host_system_info)
        assert "404" in source

    def test_system_info_checks_none_result(self):
        import app.routes.hosts.intelligence as mod

        source = inspect.getsource(mod.get_host_system_info)
        assert "not result" in source


@pytest.mark.unit
class TestAC8DelegatesToSystemInfoService:
    """AC-8: All endpoints delegate to SystemInfoService."""

    def test_packages_delegates_to_service(self):
        import app.routes.hosts.intelligence as mod

        source = inspect.getsource(mod.list_host_packages)
        assert "SystemInfoService" in source

    def test_services_delegates_to_service(self):
        import app.routes.hosts.intelligence as mod

        source = inspect.getsource(mod.list_host_services)
        assert "SystemInfoService" in source

    def test_system_info_delegates_to_service(self):
        import app.routes.hosts.intelligence as mod

        source = inspect.getsource(mod.get_host_system_info)
        assert "SystemInfoService" in source

    def test_users_delegates_to_service(self):
        import app.routes.hosts.intelligence as mod

        source = inspect.getsource(mod.list_host_users)
        assert "SystemInfoService" in source

    def test_network_delegates_to_service(self):
        import app.routes.hosts.intelligence as mod

        source = inspect.getsource(mod.list_host_network)
        assert "SystemInfoService" in source
