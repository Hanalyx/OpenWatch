"""
Host Groups CRUD and Scanning API spec compliance tests.
Verifies that routes/host_groups/crud.py and scans.py implement the
behavioral contract defined in the host-groups-crud spec via source inspection.

Spec: specs/api/host-groups/host-groups-crud.spec.yaml
"""

import inspect

import pytest


@pytest.mark.unit
class TestAC1ListHostGroupsMemberCount:
    """AC-1: List host groups includes member count via LEFT JOIN."""

    def test_list_groups_joins_memberships(self):
        import app.routes.host_groups.crud as mod

        source = inspect.getsource(mod.list_host_groups)
        assert "LEFT JOIN host_group_memberships" in source

    def test_list_groups_counts_members(self):
        import app.routes.host_groups.crud as mod

        source = inspect.getsource(mod.list_host_groups)
        assert "COUNT" in source

    def test_list_groups_uses_coalesce(self):
        import app.routes.host_groups.crud as mod

        source = inspect.getsource(mod.list_host_groups)
        assert "COALESCE" in source


@pytest.mark.unit
class TestAC2GetHostGroupWithComplianceData:
    """AC-2: Get host group includes aggregate compliance data."""

    def test_get_group_joins_memberships(self):
        import app.routes.host_groups.crud as mod

        source = inspect.getsource(mod.get_host_group)
        assert "LEFT JOIN host_group_memberships" in source

    def test_get_group_returns_404(self):
        import app.routes.host_groups.crud as mod

        source = inspect.getsource(mod.get_host_group)
        assert "404" in source


@pytest.mark.unit
class TestAC3CreateHostGroupInsert:
    """AC-3: Create host group uses parameterized INSERT."""

    def test_create_group_uses_insert(self):
        import app.routes.host_groups.crud as mod

        source = inspect.getsource(mod.create_host_group)
        assert "INSERT INTO host_groups" in source

    def test_create_group_uses_returning(self):
        import app.routes.host_groups.crud as mod

        source = inspect.getsource(mod.create_host_group)
        assert "RETURNING" in source

    def test_create_group_checks_duplicate_name(self):
        import app.routes.host_groups.crud as mod

        source = inspect.getsource(mod.create_host_group)
        assert "QueryBuilder" in source
        assert "name already exists" in source


@pytest.mark.unit
class TestAC4UpdateHostGroupDynamicSets:
    """AC-4: Update host group builds dynamic SET clauses."""

    def test_update_group_uses_update_sql(self):
        import app.routes.host_groups.crud as mod

        source = inspect.getsource(mod.update_host_group)
        assert "UPDATE host_groups" in source

    def test_update_group_uses_returning(self):
        import app.routes.host_groups.crud as mod

        source = inspect.getsource(mod.update_host_group)
        assert "RETURNING" in source

    def test_update_group_conditional_fields(self):
        import app.routes.host_groups.crud as mod

        source = inspect.getsource(mod.update_host_group)
        assert "is not None" in source


@pytest.mark.unit
class TestAC5DeleteHostGroupCascade:
    """AC-5: Delete host group removes memberships first via DeleteBuilder."""

    def test_delete_group_removes_memberships(self):
        import app.routes.host_groups.crud as mod

        source = inspect.getsource(mod.delete_host_group)
        assert 'DeleteBuilder("host_group_memberships")' in source

    def test_delete_group_removes_group(self):
        import app.routes.host_groups.crud as mod

        source = inspect.getsource(mod.delete_host_group)
        assert 'DeleteBuilder("host_groups")' in source

    def test_delete_memberships_before_group(self):
        import app.routes.host_groups.crud as mod

        source = inspect.getsource(mod.delete_host_group)
        memberships_pos = source.find('DeleteBuilder("host_group_memberships")')
        groups_pos = source.find('DeleteBuilder("host_groups")')
        assert memberships_pos < groups_pos


@pytest.mark.unit
class TestAC6StartGroupScanPermission:
    """AC-6: Start group scan requires scans:create permission."""

    def test_start_scan_requires_scans_create(self):
        import app.routes.host_groups.scans as mod

        source = inspect.getsource(mod.start_group_scan)
        assert "scans:create" in source

    def test_start_scan_calls_require_permissions(self):
        import app.routes.host_groups.scans as mod

        source = inspect.getsource(mod.start_group_scan)
        assert "require_permissions" in source


@pytest.mark.unit
class TestAC7GroupScanUsesBulkOrchestrator:
    """AC-7: Group scan uses BulkScanOrchestrator."""

    def test_start_scan_uses_orchestrator(self):
        import app.routes.host_groups.scans as mod

        source = inspect.getsource(mod.start_group_scan)
        assert "BulkScanOrchestrator" in source

    def test_module_imports_orchestrator(self):
        import app.routes.host_groups.scans as mod

        source = inspect.getsource(mod)
        assert "from app.services.bulk_scan_orchestrator import BulkScanOrchestrator" in source


@pytest.mark.unit
class TestAC8GroupScanCreatesSession:
    """AC-8: Group scan creates group_scan_sessions record."""

    def test_start_scan_inserts_session(self):
        import app.routes.host_groups.scans as mod

        source = inspect.getsource(mod.start_group_scan)
        assert "group_scan_sessions" in source

    def test_start_scan_uses_insert(self):
        import app.routes.host_groups.scans as mod

        source = inspect.getsource(mod.start_group_scan)
        assert "INSERT INTO group_scan_sessions" in source


@pytest.mark.unit
class TestAC9GroupScanProgressEndpoint:
    """AC-9: Group scan progress endpoint is available."""

    def test_scans_module_has_progress_function(self):
        import app.routes.host_groups.scans as mod

        source = inspect.getsource(mod)
        assert "progress" in source.lower()

    def test_progress_uses_query_builder(self):
        import app.routes.host_groups.scans as mod

        source = inspect.getsource(mod)
        assert "QueryBuilder" in source


@pytest.mark.unit
class TestAC10CancelGroupScanPermission:
    """AC-10: Cancel group scan endpoint requires scans:cancel permission."""

    def test_cancel_scan_exists(self):
        import app.routes.host_groups.scans as mod

        source = inspect.getsource(mod)
        assert "cancel" in source.lower()

    def test_cancel_requires_permissions(self):
        import app.routes.host_groups.scans as mod

        source = inspect.getsource(mod)
        assert "scans:cancel" in source
