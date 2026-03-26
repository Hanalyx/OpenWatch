"""
Source-inspection tests for the Audit Query API route.
Verifies that routes/compliance/audit.py implements all acceptance criteria
from the audit-queries spec: CRUD, ownership/visibility checks, license gating,
export validation, and service delegation.

Spec: specs/api/compliance/audit-queries.spec.yaml
"""
import inspect

import pytest


@pytest.mark.unit
class TestAC1CreateSavedQuery:
    """AC-1: Create saved query with name, description, query_definition, visibility."""

    def test_create_query_accepts_saved_query_create(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.create_query)
        assert "SavedQueryCreate" in source, "create_query must use SavedQueryCreate schema"

    def test_create_query_passes_name(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.create_query)
        assert "request.name" in source, "create_query must pass request.name to service"

    def test_create_query_passes_visibility(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.create_query)
        assert "request.visibility" in source, "create_query must pass visibility"

    def test_create_query_passes_owner_id(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.create_query)
        assert "owner_id" in source, "create_query must pass owner_id from current_user"


@pytest.mark.unit
class TestAC2DuplicateQueryName409:
    """AC-2: Duplicate query name returns 409 CONFLICT."""

    def test_create_query_returns_409_on_duplicate(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.create_query)
        assert "HTTP_409_CONFLICT" in source, "Must return 409 on duplicate name"

    def test_create_query_checks_none_result(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.create_query)
        assert "not query" in source, "Must check for None result from service"


@pytest.mark.unit
class TestAC3GetQueryVisibilityCheck:
    """AC-3: Get query checks visibility (owner or shared); returns 403 for private non-owned."""

    def test_get_query_checks_owner_id(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.get_query)
        assert "owner_id" in source, "get_query must check owner_id"

    def test_get_query_checks_visibility_shared(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.get_query)
        assert '"shared"' in source, "get_query must check for shared visibility"

    def test_get_query_returns_403_on_access_denied(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.get_query)
        assert "HTTP_403_FORBIDDEN" in source, "Must return 403 for private non-owned queries"


@pytest.mark.unit
class TestAC4UpdateQueryOwnership:
    """AC-4: Update query requires ownership; returns 403 if not owner."""

    def test_update_query_passes_owner_id(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.update_query)
        assert "owner_id" in source, "update_query must pass owner_id for ownership check"

    def test_update_query_returns_403_if_not_owner(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.update_query)
        assert "HTTP_403_FORBIDDEN" in source, "Must return 403 if user is not the owner"

    def test_update_query_uses_saved_query_update_schema(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.update_query)
        assert "SavedQueryUpdate" in source or "request:" in source, (
            "Must accept update request schema"
        )


@pytest.mark.unit
class TestAC5DeleteQueryOwnership:
    """AC-5: Delete query requires ownership; returns 204 on success."""

    def test_delete_query_returns_204(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.delete_query)
        assert "HTTP_204_NO_CONTENT" in source, "delete_query must return 204 on success"

    def test_delete_query_returns_403_if_not_owner(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.delete_query)
        assert "HTTP_403_FORBIDDEN" in source, "Must return 403 if not owner"

    def test_delete_query_passes_owner_id(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.delete_query)
        assert "current_user" in source, "Must use current_user for ownership"


@pytest.mark.unit
class TestAC6PreviewQueryLicenseGating:
    """AC-6: Preview query with date_range requires OpenWatch+ license (403)."""

    def test_preview_query_checks_date_range(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.preview_query)
        assert "date_range" in source, "preview_query must check for date_range"

    def test_preview_query_uses_license_service(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.preview_query)
        assert "LicenseService" in source, "Must use LicenseService for feature gating"

    def test_preview_query_checks_temporal_queries_feature(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.preview_query)
        assert "temporal_queries" in source, "Must check temporal_queries feature"

    def test_preview_query_returns_403_without_license(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.preview_query)
        assert "HTTP_403_FORBIDDEN" in source, "Must return 403 without license"


@pytest.mark.unit
class TestAC7ExecuteSavedQueryAccessCheck:
    """AC-7: Execute saved query checks access (owner or shared visibility)."""

    def test_execute_saved_query_checks_access(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.execute_saved_query)
        assert "execute_query" in source, "Must call service.execute_query"

    def test_execute_saved_query_returns_403_on_access_denied(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.execute_saved_query)
        assert "HTTP_403_FORBIDDEN" in source, "Must return 403 if access denied"

    def test_execute_saved_query_passes_user_id(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.execute_saved_query)
        assert "user_id" in source, "Must pass user_id for access check"


@pytest.mark.unit
class TestAC8ExecuteAdhocQueryLicenseGating:
    """AC-8: Execute adhoc query with date_range requires OpenWatch+ license."""

    def test_adhoc_query_checks_date_range(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.execute_adhoc_query)
        assert "date_range" in source, "Must check for date_range"

    def test_adhoc_query_uses_license_service(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.execute_adhoc_query)
        assert "LicenseService" in source, "Must use LicenseService"

    def test_adhoc_query_returns_403_without_license(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.execute_adhoc_query)
        assert "HTTP_403_FORBIDDEN" in source, "Must return 403 without license"


@pytest.mark.unit
class TestAC9CreateExportValidation:
    """AC-9: Create export validates query_id or query_definition provided (400)."""

    def test_create_export_checks_both_fields(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.create_export)
        assert "query_id" in source, "Must check query_id"
        assert "query_definition" in source, "Must check query_definition"

    def test_create_export_returns_400_when_neither_provided(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.create_export)
        assert "HTTP_400_BAD_REQUEST" in source, "Must return 400 when neither field provided"

    def test_create_export_checks_neither_condition(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.create_export)
        assert "not request.query_id and not request.query_definition" in source, (
            "Must validate that at least one of query_id or query_definition is provided"
        )


@pytest.mark.unit
class TestAC10DownloadExportValidation:
    """AC-10: Download export requires ownership, completed status, and non-expired (400/410)."""

    def test_download_checks_ownership(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.download_export)
        assert "requested_by" in source, "Must check requested_by for ownership"

    def test_download_checks_completed_status(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.download_export)
        assert '"completed"' in source, "Must check for completed status"

    def test_download_returns_400_for_incomplete(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.download_export)
        assert "HTTP_400_BAD_REQUEST" in source, "Must return 400 for incomplete exports"

    def test_download_returns_410_for_expired(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.download_export)
        assert "HTTP_410_GONE" in source, "Must return 410 for expired exports"

    def test_download_checks_is_expired(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.download_export)
        assert "is_expired" in source, "Must check is_expired property"


@pytest.mark.unit
class TestAC11ExportFilenamePattern:
    """AC-11: Export filename follows pattern audit_export_{id}.{format}."""

    def test_download_uses_correct_filename_pattern(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.download_export)
        assert "audit_export_" in source, "Filename must start with audit_export_"
        assert "export.format" in source, "Filename must include export format"

    def test_download_returns_file_response(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.download_export)
        assert "FileResponse" in source, "Must return FileResponse for download"


@pytest.mark.unit
class TestAC12AllOperationsDelegateToServices:
    """AC-12: All query operations delegate to AuditQueryService."""

    def test_module_imports_audit_query_service(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod)
        assert "AuditQueryService" in source, "Module must import AuditQueryService"

    def test_module_imports_audit_export_service(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod)
        assert "AuditExportService" in source, "Module must import AuditExportService"

    def test_create_query_delegates_to_service(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.create_query)
        assert "AuditQueryService(db)" in source, "Must instantiate AuditQueryService(db)"

    def test_list_queries_delegates_to_service(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.list_queries)
        assert "AuditQueryService(db)" in source, "Must instantiate AuditQueryService(db)"

    def test_create_export_delegates_to_service(self):
        import app.routes.compliance.audit as mod

        source = inspect.getsource(mod.create_export)
        assert "AuditExportService(db)" in source, "Must instantiate AuditExportService(db)"
