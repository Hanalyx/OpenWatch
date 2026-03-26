"""
Source-inspection tests for the Admin Audit Events API route.
Verifies that routes/admin/audit.py implements all acceptance criteria
from the audit-events spec: RBAC via RBACManager, QueryBuilder with LEFT JOIN,
raw SQL CASE expressions for stats, and InsertBuilder for log creation.

Spec: specs/api/admin/audit-events.spec.yaml
"""
import inspect

import pytest


@pytest.mark.unit
class TestAC1AuditReadPermission:
    """AC-1: Get audit events requires audit:read permission via RBACManager."""

    def test_get_events_uses_rbac_manager(self):
        import app.routes.admin.audit as mod

        source = inspect.getsource(mod.get_audit_events)
        assert "RBACManager" in source, "Must use RBACManager for permission check"

    def test_get_events_checks_audit_read(self):
        import app.routes.admin.audit as mod

        source = inspect.getsource(mod.get_audit_events)
        assert '"audit"' in source, "Must check audit resource"
        assert '"read"' in source, "Must check read permission"

    def test_get_events_calls_can_access_resource(self):
        import app.routes.admin.audit as mod

        source = inspect.getsource(mod.get_audit_events)
        assert "can_access_resource" in source, "Must call RBACManager.can_access_resource"

    def test_get_events_returns_403(self):
        import app.routes.admin.audit as mod

        source = inspect.getsource(mod.get_audit_events)
        assert "403" in source, "Must return 403 on insufficient permissions"

    def test_get_stats_uses_rbac_manager(self):
        import app.routes.admin.audit as mod

        source = inspect.getsource(mod.get_audit_stats)
        assert "RBACManager" in source, "Stats must also check RBACManager"
        assert "can_access_resource" in source, "Stats must call can_access_resource"


@pytest.mark.unit
class TestAC2AuditEventFiltering:
    """AC-2: Audit events support search, action, resource_type, user, date filters."""

    def test_events_support_search_filter(self):
        import app.routes.admin.audit as mod

        source = inspect.getsource(mod.get_audit_events)
        assert "search:" in source or "search =" in source, "Must accept search parameter"

    def test_events_support_action_filter(self):
        import app.routes.admin.audit as mod

        source = inspect.getsource(mod.get_audit_events)
        assert "action:" in source or "action =" in source, "Must accept action parameter"

    def test_events_support_resource_type_filter(self):
        import app.routes.admin.audit as mod

        source = inspect.getsource(mod.get_audit_events)
        assert "resource_type" in source, "Must accept resource_type parameter"

    def test_events_support_user_filter(self):
        import app.routes.admin.audit as mod

        source = inspect.getsource(mod.get_audit_events)
        assert "user:" in source or "user =" in source, "Must accept user parameter"

    def test_events_support_date_from_filter(self):
        import app.routes.admin.audit as mod

        source = inspect.getsource(mod.get_audit_events)
        assert "date_from" in source, "Must accept date_from parameter"

    def test_events_support_date_to_filter(self):
        import app.routes.admin.audit as mod

        source = inspect.getsource(mod.get_audit_events)
        assert "date_to" in source, "Must accept date_to parameter"

    def test_search_uses_ilike(self):
        import app.routes.admin.audit as mod

        source = inspect.getsource(mod.get_audit_events)
        assert "ILIKE" in source, "Search must use ILIKE for case-insensitive matching"


@pytest.mark.unit
class TestAC3QueryBuilderWithLeftJoin:
    """AC-3: Audit events use QueryBuilder with LEFT JOIN to users table."""

    def test_events_use_query_builder(self):
        import app.routes.admin.audit as mod

        source = inspect.getsource(mod.get_audit_events)
        assert "QueryBuilder" in source, "Must use QueryBuilder"

    def test_events_use_audit_logs_table(self):
        import app.routes.admin.audit as mod

        source = inspect.getsource(mod.get_audit_events)
        assert "audit_logs" in source, "Must query audit_logs table"

    def test_events_left_join_users(self):
        import app.routes.admin.audit as mod

        source = inspect.getsource(mod.get_audit_events)
        assert "users u" in source, "Must join to users table"
        assert "LEFT" in source, "Must use LEFT join type"

    def test_events_join_on_user_id(self):
        import app.routes.admin.audit as mod

        source = inspect.getsource(mod.get_audit_events)
        assert "al.user_id = u.id" in source, "Must join on user_id = id"


@pytest.mark.unit
class TestAC4RawSQLCaseExpressions:
    """AC-4: Audit stats use raw SQL with CASE expressions (documented exception)."""

    def test_stats_use_raw_sql(self):
        import app.routes.admin.audit as mod

        source = inspect.getsource(mod.get_audit_stats)
        assert "text(" in source, "Stats must use raw SQL via text()"

    def test_stats_use_case_expressions(self):
        import app.routes.admin.audit as mod

        source = inspect.getsource(mod.get_audit_stats)
        assert "CASE WHEN" in source, "Stats must use CASE WHEN expressions"

    def test_stats_count_login_attempts(self):
        import app.routes.admin.audit as mod

        source = inspect.getsource(mod.get_audit_stats)
        assert "login_attempts" in source, "Stats must count login_attempts"

    def test_stats_count_failed_logins(self):
        import app.routes.admin.audit as mod

        source = inspect.getsource(mod.get_audit_stats)
        assert "failed_logins" in source, "Stats must count failed_logins"

    def test_stats_count_security_events(self):
        import app.routes.admin.audit as mod

        source = inspect.getsource(mod.get_audit_stats)
        assert "security_events" in source, "Stats must count security_events"

    def test_stats_count_unique_users_and_ips(self):
        import app.routes.admin.audit as mod

        source = inspect.getsource(mod.get_audit_stats)
        assert "unique_users" in source, "Stats must count unique_users"
        assert "unique_ips" in source, "Stats must count unique_ips"


@pytest.mark.unit
class TestAC5InsertBuilderForAuditLog:
    """AC-5: Create audit log uses InsertBuilder("audit_logs")."""

    def test_create_log_uses_insert_builder(self):
        import app.routes.admin.audit as mod

        source = inspect.getsource(mod.create_audit_log)
        assert "InsertBuilder" in source, "Must use InsertBuilder for insert"

    def test_create_log_targets_audit_logs_table(self):
        import app.routes.admin.audit as mod

        source = inspect.getsource(mod.create_audit_log)
        assert 'InsertBuilder("audit_logs")' in source, "Must target audit_logs table"

    def test_create_log_uses_columns_and_values(self):
        import app.routes.admin.audit as mod

        source = inspect.getsource(mod.create_audit_log)
        assert ".columns(" in source, "Must use .columns() method"
        assert ".values(" in source, "Must use .values() method"

    def test_helper_function_also_uses_insert_builder(self):
        import app.routes.admin.audit as mod

        source = inspect.getsource(mod.log_audit_event)
        assert "InsertBuilder" in source, "Helper must also use InsertBuilder"
        assert '"audit_logs"' in source, "Helper must also target audit_logs"

    def test_module_imports_insert_builder(self):
        import app.routes.admin.audit as mod

        source = inspect.getsource(mod)
        assert "from ...utils.mutation_builders import InsertBuilder" in source, (
            "Module must import InsertBuilder from mutation_builders"
        )
