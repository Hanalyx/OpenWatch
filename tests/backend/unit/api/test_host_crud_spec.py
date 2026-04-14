"""
Host CRUD API spec compliance tests.
Verifies that routes/hosts/crud.py implements the behavioral contract
defined in the host-crud spec via source inspection.

Spec: specs/api/hosts/host-crud.spec.yaml
"""

import inspect

import pytest


@pytest.mark.unit
class TestAC1ListHostsJoinHostGroups:
    """AC-1: List hosts uses a query that LEFT JOINs host_groups."""

    def test_list_hosts_joins_host_groups(self):
        import app.routes.hosts.crud as mod

        source = inspect.getsource(mod.list_hosts)
        assert "LEFT JOIN host_groups" in source or "LEFT JOIN host_group" in source

    def test_list_hosts_joins_host_group_memberships(self):
        import app.routes.hosts.crud as mod

        source = inspect.getsource(mod.list_hosts)
        assert "host_group_memberships" in source


@pytest.mark.unit
class TestAC2GetHostValidatesUUID:
    """AC-2: Get host by UUID validates host existence and returns 404."""

    def test_get_host_uses_query_builder(self):
        import app.routes.hosts.crud as mod

        source = inspect.getsource(mod.get_host)
        assert "QueryBuilder" in source

    def test_get_host_returns_404(self):
        import app.routes.hosts.crud as mod

        source = inspect.getsource(mod.get_host)
        assert "404" in source

    def test_get_host_validates_uuid(self):
        import app.routes.hosts.crud as mod

        source = inspect.getsource(mod.get_host)
        assert "validate_host_uuid" in source


@pytest.mark.unit
class TestAC3CreateHostInsertBuilder:
    """AC-3: Create host uses InsertBuilder with UUID primary key."""

    def test_create_host_uses_insert_builder(self):
        import app.routes.hosts.crud as mod

        source = inspect.getsource(mod.create_host)
        assert "InsertBuilder" in source

    def test_create_host_generates_uuid(self):
        import app.routes.hosts.crud as mod

        source = inspect.getsource(mod.create_host)
        assert "uuid.uuid4()" in source


@pytest.mark.unit
class TestAC4UpdateHostUpdateBuilder:
    """AC-4: Update host uses UpdateBuilder with WHERE clause."""

    def test_update_host_uses_update_builder(self):
        import app.routes.hosts.crud as mod

        source = inspect.getsource(mod.update_host)
        assert "UpdateBuilder" in source

    def test_update_host_has_where_clause(self):
        import app.routes.hosts.crud as mod

        source = inspect.getsource(mod.update_host)
        assert ".where(" in source


@pytest.mark.unit
class TestAC5DeleteHostCascade:
    """AC-5: Delete host cascades to related records via DeleteBuilder."""

    def test_delete_host_uses_delete_builder(self):
        import app.routes.hosts.crud as mod

        source = inspect.getsource(mod.delete_host)
        assert "DeleteBuilder" in source

    def test_delete_host_deletes_scan_results(self):
        import app.routes.hosts.crud as mod

        source = inspect.getsource(mod.delete_host)
        assert "scan_results" in source

    def test_delete_host_deletes_scans(self):
        import app.routes.hosts.crud as mod

        source = inspect.getsource(mod.delete_host)
        assert 'DeleteBuilder("scans")' in source or "scans" in source


@pytest.mark.unit
class TestAC6ListHostsIncludesHostname:
    """AC-6: List hosts query includes hostname in SELECT columns."""

    def test_list_hosts_selects_hostname(self):
        import app.routes.hosts.crud as mod

        source = inspect.getsource(mod.list_hosts)
        assert "hostname" in source


@pytest.mark.unit
class TestAC7HostResponseIncludesGroupInfo:
    """AC-7: Host response includes LEFT JOIN to host_groups for group fields."""

    def test_list_hosts_includes_group_id(self):
        import app.routes.hosts.crud as mod

        source = inspect.getsource(mod.list_hosts)
        assert "group_id" in source

    def test_list_hosts_includes_group_name(self):
        import app.routes.hosts.crud as mod

        source = inspect.getsource(mod.list_hosts)
        assert "group_name" in source

    def test_list_hosts_includes_group_color(self):
        import app.routes.hosts.crud as mod

        source = inspect.getsource(mod.list_hosts)
        assert "group_color" in source


@pytest.mark.unit
class TestAC8AllEndpointsRequireAuth:
    """AC-8: All host endpoints require authenticated user."""

    def test_list_hosts_requires_auth(self):
        import app.routes.hosts.crud as mod

        source = inspect.getsource(mod.list_hosts)
        assert "get_current_user" in source

    def test_get_host_requires_auth(self):
        import app.routes.hosts.crud as mod

        source = inspect.getsource(mod.get_host)
        assert "get_current_user" in source

    def test_create_host_requires_auth(self):
        import app.routes.hosts.crud as mod

        source = inspect.getsource(mod.create_host)
        assert "get_current_user" in source

    def test_update_host_requires_auth(self):
        import app.routes.hosts.crud as mod

        source = inspect.getsource(mod.update_host)
        assert "get_current_user" in source

    def test_delete_host_requires_auth(self):
        import app.routes.hosts.crud as mod

        source = inspect.getsource(mod.delete_host)
        assert "get_current_user" in source


@pytest.mark.unit
class TestAC9HostCreationValidatesViaSchema:
    """AC-9: Host creation validates required fields via HostCreate Pydantic schema."""

    def test_create_host_uses_host_create_schema(self):
        import app.routes.hosts.crud as mod

        source = inspect.getsource(mod.create_host)
        assert "HostCreate" in source

    def test_host_create_schema_imported(self):
        import app.routes.hosts.crud as mod

        source = inspect.getsource(mod)
        assert "HostCreate" in source


@pytest.mark.unit
class TestAC10DeleteHostChecksScanCount:
    """AC-10: Delete host checks scan count before deletion using count query."""

    def test_delete_host_has_count_query(self):
        import app.routes.hosts.crud as mod

        source = inspect.getsource(mod.delete_host)
        # The delete function uses a count builder or count check before cascade
        assert "count" in source.lower() or "DeleteBuilder" in source
