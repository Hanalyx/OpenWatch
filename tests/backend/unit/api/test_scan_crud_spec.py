"""
Scan CRUD API spec compliance tests.
Verifies that routes/scans/crud.py implements the behavioral contract
defined in the scan-crud spec via source inspection.

Spec: specs/api/scans/scan-crud.spec.yaml
"""

import inspect

import pytest


@pytest.mark.unit
class TestAC1ListScansQueryBuilderWithJoins:
    """AC-1: List scans uses QueryBuilder with LEFT JOIN to hosts and scan_results."""

    def test_list_scans_uses_query_builder(self):
        import app.routes.scans.crud as mod

        source = inspect.getsource(mod.list_scans)
        assert "QueryBuilder" in source

    def test_list_scans_joins_hosts(self):
        import app.routes.scans.crud as mod

        source = inspect.getsource(mod.list_scans)
        assert 'join("hosts h"' in source or ".join(" in source

    def test_list_scans_joins_scan_results(self):
        import app.routes.scans.crud as mod

        source = inspect.getsource(mod.list_scans)
        assert "scan_results" in source


@pytest.mark.unit
class TestAC2GetScanParsesMetadata:
    """AC-2: Get scan parses scan_metadata from JSON."""

    def test_get_scan_uses_json_loads(self):
        import app.routes.scans.crud as mod

        source = inspect.getsource(mod.get_scan)
        assert "json.loads" in source

    def test_get_scan_handles_scan_options(self):
        import app.routes.scans.crud as mod

        source = inspect.getsource(mod.get_scan)
        assert "scan_options" in source


@pytest.mark.unit
class TestAC3UpdateScanUpdateBuilderSetIf:
    """AC-3: Update scan uses UpdateBuilder with set_if for optional fields."""

    def test_update_scan_uses_update_builder(self):
        import app.routes.scans.crud as mod

        source = inspect.getsource(mod.update_scan)
        assert "UpdateBuilder" in source

    def test_update_scan_uses_set_if(self):
        import app.routes.scans.crud as mod

        source = inspect.getsource(mod.update_scan)
        assert "set_if" in source

    def test_update_scan_set_if_status(self):
        import app.routes.scans.crud as mod

        source = inspect.getsource(mod.update_scan)
        assert 'set_if("status"' in source

    def test_update_scan_set_if_progress(self):
        import app.routes.scans.crud as mod

        source = inspect.getsource(mod.update_scan)
        assert 'set_if("progress"' in source


@pytest.mark.unit
class TestAC4DeleteScanCascade:
    """AC-4: Delete scan cascades (scan_results deleted before scan)."""

    def test_delete_scan_deletes_scan_results_first(self):
        import app.routes.scans.crud as mod

        source = inspect.getsource(mod.delete_scan)
        assert "DeleteBuilder" in source

    def test_delete_scan_results_before_scan(self):
        import app.routes.scans.crud as mod

        source = inspect.getsource(mod.delete_scan)
        # scan_results deletion appears before scans deletion
        results_pos = source.find("scan_results")
        scans_delete_pos = source.find('DeleteBuilder("scans")')
        assert results_pos < scans_delete_pos


@pytest.mark.unit
class TestAC5StopScanRevokesCelery:
    """AC-5: Stop/cancel scan revokes Celery task."""

    def test_stop_scan_revokes_celery_task(self):
        import app.routes.scans.crud as mod

        source = inspect.getsource(mod.stop_scan)
        assert "revoke" in source

    def test_stop_scan_uses_terminate(self):
        import app.routes.scans.crud as mod

        source = inspect.getsource(mod.stop_scan)
        assert "terminate=True" in source


@pytest.mark.unit
class TestAC6StopScanUpdatesStatus:
    """AC-6: Stop scan updates status to 'stopped' and sets completed_at."""

    def test_stop_scan_sets_stopped_status(self):
        import app.routes.scans.crud as mod

        source = inspect.getsource(mod.stop_scan)
        assert '"stopped"' in source

    def test_stop_scan_sets_completed_at(self):
        import app.routes.scans.crud as mod

        source = inspect.getsource(mod.stop_scan)
        assert "completed_at" in source

    def test_stop_scan_uses_update_builder(self):
        import app.routes.scans.crud as mod

        source = inspect.getsource(mod.stop_scan)
        assert "UpdateBuilder" in source


@pytest.mark.unit
class TestAC7RecoverScanClassifiesError:
    """AC-7: Recover scan classifies error and creates new scan."""

    def test_recover_scan_classifies_error(self):
        import app.routes.scans.crud as mod

        source = inspect.getsource(mod.recover_scan)
        assert "classify_error" in source

    def test_recover_scan_creates_new_scan(self):
        import app.routes.scans.crud as mod

        source = inspect.getsource(mod.recover_scan)
        assert "InsertBuilder" in source

    def test_recover_scan_checks_can_retry(self):
        import app.routes.scans.crud as mod

        source = inspect.getsource(mod.recover_scan)
        assert "can_retry" in source


@pytest.mark.unit
class TestAC8ListScansPaginationViaCountQuery:
    """AC-8: List scans supports pagination via count_query()."""

    def test_list_scans_uses_count_query(self):
        import app.routes.scans.crud as mod

        source = inspect.getsource(mod.list_scans)
        assert "count_query()" in source

    def test_list_scans_has_pagination_params(self):
        import app.routes.scans.crud as mod

        source = inspect.getsource(mod.list_scans)
        assert "limit" in source
        assert "offset" in source
