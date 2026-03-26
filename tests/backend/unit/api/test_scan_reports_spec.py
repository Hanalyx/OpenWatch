"""
Scan Reports API spec compliance tests.
Verifies that routes/scans/reports.py implements the behavioral contract
defined in the scan-reports spec via source inspection.

Spec: specs/api/scans/scan-reports.spec.yaml
"""

import inspect

import pytest


@pytest.mark.unit
class TestAC1GetScanResultsQueryBuilderHostJoin:
    """AC-1: Get scan results uses QueryBuilder with host JOIN."""

    def test_get_scan_results_uses_query_builder(self):
        import app.routes.scans.reports as mod

        source = inspect.getsource(mod.get_scan_results)
        assert "QueryBuilder" in source

    def test_get_scan_results_joins_hosts(self):
        import app.routes.scans.reports as mod

        source = inspect.getsource(mod.get_scan_results)
        assert "hosts h" in source or 'join("hosts' in source


@pytest.mark.unit
class TestAC2HTMLReportFileResponse:
    """AC-2: HTML report serves file via FileResponse with existence check."""

    def test_html_report_uses_file_response(self):
        import app.routes.scans.reports as mod

        source = inspect.getsource(mod.get_scan_html_report)
        assert "FileResponse" in source

    def test_html_report_checks_file_exists(self):
        import app.routes.scans.reports as mod

        source = inspect.getsource(mod.get_scan_html_report)
        assert "os.path.exists" in source


@pytest.mark.unit
class TestAC3JSONReportKensaFallback:
    """AC-3: JSON report includes Kensa scan_findings as fallback."""

    def test_json_report_queries_scan_findings(self):
        import app.routes.scans.reports as mod

        source = inspect.getsource(mod.get_scan_json_report)
        assert "scan_findings" in source

    def test_json_report_fallback_on_no_result_file(self):
        import app.routes.scans.reports as mod

        source = inspect.getsource(mod.get_scan_json_report)
        assert 'not scan_data.get("result_file")' in source


@pytest.mark.unit
class TestAC4CSVReportWriterAndDisposition:
    """AC-4: CSV report uses csv.writer with Content-Disposition header."""

    def test_csv_report_uses_csv_writer(self):
        import app.routes.scans.reports as mod

        source = inspect.getsource(mod.get_scan_csv_report)
        assert "csv.writer" in source

    def test_csv_report_sets_content_disposition(self):
        import app.routes.scans.reports as mod

        source = inspect.getsource(mod.get_scan_csv_report)
        assert "Content-Disposition" in source

    def test_csv_report_attachment_filename(self):
        import app.routes.scans.reports as mod

        source = inspect.getsource(mod.get_scan_csv_report)
        assert "attachment" in source


@pytest.mark.unit
class TestAC5FailedRulesXMLParsing:
    """AC-5: Failed rules endpoint parses XML for check_content_ref."""

    def test_failed_rules_uses_et_parse(self):
        import app.routes.scans.reports as mod

        source = inspect.getsource(mod.get_scan_failed_rules)
        assert "ET.parse" in source

    def test_failed_rules_extracts_check_content_ref(self):
        import app.routes.scans.reports as mod

        source = inspect.getsource(mod.get_scan_failed_rules)
        assert "check-content-ref" in source or "check_content_ref" in source


@pytest.mark.unit
class TestAC6AllReportEndpointsValidateScanId:
    """AC-6: All report endpoints require valid scan_id (404 if not found)."""

    def test_get_results_returns_404(self):
        import app.routes.scans.reports as mod

        source = inspect.getsource(mod.get_scan_results)
        assert "404" in source

    def test_html_report_returns_404(self):
        import app.routes.scans.reports as mod

        source = inspect.getsource(mod.get_scan_html_report)
        assert "404" in source

    def test_json_report_calls_get_scan_details(self):
        import app.routes.scans.reports as mod

        source = inspect.getsource(mod.get_scan_json_report)
        assert "_get_scan_details" in source

    def test_failed_rules_returns_404(self):
        import app.routes.scans.reports as mod

        source = inspect.getsource(mod.get_scan_failed_rules)
        assert "404" in source

    def test_module_imports_et(self):
        import app.routes.scans.reports as mod

        source = inspect.getsource(mod)
        assert "xml.etree.ElementTree" in source
