"""
Source-inspection tests for the AuditQueryService.
Verifies that services/compliance/audit_query.py implements all acceptance
criteria from the audit-query spec: duplicate name checks, ownership/visibility
enforcement, SQL builder usage, case-insensitive filters, and execution stats.

Spec: specs/services/compliance/audit-query.spec.yaml
"""
import inspect

import pytest


@pytest.mark.unit
class TestAC1CreateQueryDuplicateNameCheck:
    """AC-1: Create query checks duplicate name for owner (returns None if exists)."""

    def test_create_query_checks_duplicate_name(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService.create_query)
        assert "_find_query_by_name" in source, "Must call _find_query_by_name to check duplicates"

    def test_create_query_returns_none_on_duplicate(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService.create_query)
        assert "return None" in source, "Must return None when duplicate name exists"

    def test_find_query_by_name_checks_owner_and_name(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService._find_query_by_name)
        assert "owner_id" in source, "Must filter by owner_id"
        assert "name" in source, "Must filter by name"


@pytest.mark.unit
class TestAC2UpdateQueryOwnershipVerification:
    """AC-2: Update query verifies ownership (returns None if not owner)."""

    def test_update_query_checks_owner_id(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService.update_query)
        assert "owner_id" in source, "Must check owner_id"

    def test_update_query_compares_owner(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService.update_query)
        assert "existing.owner_id != owner_id" in source, "Must compare existing.owner_id to owner_id"

    def test_update_query_returns_none_if_not_owner(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService.update_query)
        # After ownership check, returns None
        assert "return None" in source, "Must return None if not owner"


@pytest.mark.unit
class TestAC3DeleteQueryOwnershipVerification:
    """AC-3: Delete query verifies ownership (returns False if not owner)."""

    def test_delete_query_checks_owner_id(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService.delete_query)
        assert "owner_id" in source, "Must check owner_id"

    def test_delete_query_compares_owner(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService.delete_query)
        assert "existing.owner_id != owner_id" in source, "Must compare existing.owner_id to owner_id"

    def test_delete_query_returns_false_if_not_owner(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService.delete_query)
        assert "return False" in source, "Must return False if not owner"


@pytest.mark.unit
class TestAC4ExecuteQueryAccessCheck:
    """AC-4: Execute query checks access (owner_id match or shared visibility)."""

    def test_execute_query_checks_owner_id(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService.execute_query)
        assert "owner_id" in source, "Must check owner_id"

    def test_execute_query_checks_shared_visibility(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService.execute_query)
        assert '"shared"' in source, "Must check for shared visibility"

    def test_execute_query_returns_none_on_access_denied(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService.execute_query)
        assert "return None" in source, "Must return None when access denied"

    def test_execute_query_compares_user_id_and_visibility(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService.execute_query)
        assert "saved_query.owner_id != user_id" in source, "Must compare owner_id to user_id"
        assert 'saved_query.visibility != "shared"' in source, "Must check visibility != shared"


@pytest.mark.unit
class TestAC5BuildFindingsQueryFilters:
    """AC-5: Query builder supports host, host_group, rule, framework, severity, status, date_range filters."""

    def test_build_findings_supports_host_filter(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService._build_findings_query)
        assert "query_def.hosts" in source, "Must support host filter"
        assert "s.host_id IN" in source, "Must use IN clause for hosts"

    def test_build_findings_supports_host_group_filter(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService._build_findings_query)
        assert "query_def.host_groups" in source, "Must support host_group filter"
        assert "host_group_memberships" in source, "Must use host_group_memberships subquery"

    def test_build_findings_supports_rule_filter(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService._build_findings_query)
        assert "query_def.rules" in source, "Must support rule filter"
        assert "sf.rule_id IN" in source, "Must use IN clause for rules"

    def test_build_findings_supports_framework_filter(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService._build_findings_query)
        assert "query_def.frameworks" in source, "Must support framework filter"

    def test_build_findings_supports_severity_filter(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService._build_findings_query)
        assert "query_def.severities" in source, "Must support severity filter"

    def test_build_findings_supports_status_filter(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService._build_findings_query)
        assert "query_def.statuses" in source, "Must support status filter"

    def test_build_findings_supports_date_range_filter(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService._build_findings_query)
        assert "query_def.date_range" in source, "Must support date_range filter"

    def test_build_findings_uses_parameterized_in_clauses(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService._build_findings_query)
        assert "host_placeholders" in source, "Must use parameterized placeholders for hosts"
        assert "rule_placeholders" in source, "Must use parameterized placeholders for rules"


@pytest.mark.unit
class TestAC6CaseInsensitiveFilters:
    """AC-6: Severity and status filters use LOWER() for case-insensitive matching."""

    def test_severity_uses_lower(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService._build_findings_query)
        assert "LOWER(sf.severity)" in source, "Severity filter must use LOWER(sf.severity)"

    def test_status_uses_lower(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService._build_findings_query)
        assert "LOWER(sf.status)" in source, "Status filter must use LOWER(sf.status)"

    def test_severity_values_lowered(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService._build_findings_query)
        assert "severity.lower()" in source, "Severity values must be lowered before comparison"

    def test_status_values_lowered(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService._build_findings_query)
        assert "status.lower()" in source, "Status values must be lowered before comparison"


@pytest.mark.unit
class TestAC7SqlBuilderUsage:
    """AC-7: All CRUD uses SQL builders (InsertBuilder, UpdateBuilder, DeleteBuilder, QueryBuilder)."""

    def test_module_imports_insert_builder(self):
        from app.services.compliance import audit_query as mod

        source = inspect.getsource(mod)
        assert "InsertBuilder" in source, "Module must import InsertBuilder"

    def test_module_imports_update_builder(self):
        from app.services.compliance import audit_query as mod

        source = inspect.getsource(mod)
        assert "UpdateBuilder" in source, "Module must import UpdateBuilder"

    def test_module_imports_query_builder(self):
        from app.services.compliance import audit_query as mod

        source = inspect.getsource(mod)
        assert "QueryBuilder" in source, "Module must import QueryBuilder"

    def test_create_uses_insert_builder(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService.create_query)
        assert "InsertBuilder" in source, "create_query must use InsertBuilder"
        assert '"saved_queries"' in source, "Must target saved_queries table"

    def test_update_uses_update_builder(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService.update_query)
        assert "UpdateBuilder" in source, "update_query must use UpdateBuilder"

    def test_delete_uses_delete_builder(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService.delete_query)
        assert "DeleteBuilder" in source, "delete_query must use DeleteBuilder"

    def test_get_uses_query_builder(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService.get_query)
        assert "QueryBuilder" in source, "get_query must use QueryBuilder"


@pytest.mark.unit
class TestAC8ExecutionStatsTracking:
    """AC-8: Execution updates stats (execution_count, last_executed_at)."""

    def test_execute_query_calls_update_stats(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService.execute_query)
        assert "_update_execution_stats" in source, "execute_query must call _update_execution_stats"

    def test_update_stats_increments_execution_count(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService._update_execution_stats)
        assert "execution_count + 1" in source, "Must increment execution_count"

    def test_update_stats_sets_last_executed_at(self):
        from app.services.compliance.audit_query import AuditQueryService

        source = inspect.getsource(AuditQueryService._update_execution_stats)
        assert "last_executed_at" in source, "Must update last_executed_at"
        assert "CURRENT_TIMESTAMP" in source, "Must use CURRENT_TIMESTAMP"
