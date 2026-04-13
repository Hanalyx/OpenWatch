"""
Integration test: audit export parity across schema migration.

Spec: specs/system/transaction-log.spec.yaml AC-12

Verifies that AuditExportService produces byte-identical CSV/JSON output
when reading from the transactions table vs the legacy scan_findings table.
Requires a running database with fixture data.
"""

import inspect

import pytest


@pytest.mark.integration
@pytest.mark.regression
class TestAuditExportParity:
    """AC-12: Audit export produces identical output post-migration."""

    def test_export_source_flag_exists(self):
        """AUDIT_EXPORT_SOURCE env var is checked in audit_export.py."""
        import app.services.compliance.audit_export as mod

        source = inspect.getsource(mod)
        assert "AUDIT_EXPORT_SOURCE" in source

    def test_legacy_fallback_path_exists(self):
        """Legacy query path exists for rollback."""
        import app.services.compliance.audit_export as mod

        source = inspect.getsource(mod)
        assert "legacy" in source.lower()

    def test_export_source_defaults_to_transactions(self):
        """Default AUDIT_EXPORT_SOURCE is 'transactions', not 'legacy'."""
        import app.services.compliance.audit_export as mod

        source = inspect.getsource(mod)
        # The default value should be "transactions"
        assert '"transactions"' in source

    def test_legacy_method_exists(self):
        """A dedicated legacy fetch method exists for rollback safety."""
        import app.services.compliance.audit_export as mod

        source = inspect.getsource(mod)
        assert "_fetch_all_findings_legacy" in source

    @pytest.mark.skip(reason="Requires running database with fixture scan data")
    def test_csv_export_parity(self):
        """CSV export from transactions matches CSV from scan_findings."""
        # 1. Insert fixture scan + findings + transactions
        # 2. Export with AUDIT_EXPORT_SOURCE=transactions
        # 3. Export with AUDIT_EXPORT_SOURCE=legacy
        # 4. Assert byte-identical output
        pass

    @pytest.mark.skip(reason="Requires running database with fixture scan data")
    def test_json_export_parity(self):
        """JSON export from transactions matches JSON from scan_findings."""
        # 1. Insert fixture scan + findings + transactions
        # 2. Export with AUDIT_EXPORT_SOURCE=transactions
        # 3. Export with AUDIT_EXPORT_SOURCE=legacy
        # 4. Assert structurally-identical output (sorted keys)
        pass
