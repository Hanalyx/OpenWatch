"""
Unit tests for engine result parsers.

Tests RuleResult, ResultStatistics, ParsedResults data classes,
BaseResultParser normalization methods, and XCCDFResultParser.
"""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.services.engine.result_parsers.base import (
    BaseResultParser,
    ParsedResults,
    ResultStatistics,
    RuleResult,
    RuleResultStatus,
    SeverityLevel,
)


# ---------------------------------------------------------------------------
# RuleResultStatus enum
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestRuleResultStatusEnum:
    """Test RuleResultStatus enum values."""

    def test_all_expected_values(self) -> None:
        expected = {
            "pass",
            "fail",
            "error",
            "unknown",
            "notapplicable",
            "notchecked",
            "notselected",
            "informational",
            "fixed",
        }
        actual = {s.value for s in RuleResultStatus}
        assert actual == expected

    def test_values_are_strings(self) -> None:
        for status in RuleResultStatus:
            assert isinstance(status.value, str)


# ---------------------------------------------------------------------------
# SeverityLevel enum
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestSeverityLevelEnum:
    """Test SeverityLevel enum values."""

    def test_all_expected_values(self) -> None:
        expected = {"critical", "high", "medium", "low", "info", "unknown"}
        actual = {s.value for s in SeverityLevel}
        assert actual == expected


# ---------------------------------------------------------------------------
# RuleResult dataclass
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestRuleResult:
    """Test RuleResult dataclass."""

    def test_minimal_creation(self) -> None:
        r = RuleResult(rule_id="rule-1", result=RuleResultStatus.PASS)
        assert r.rule_id == "rule-1"
        assert r.result == RuleResultStatus.PASS
        assert r.severity == SeverityLevel.UNKNOWN
        assert r.title == ""

    def test_full_creation(self) -> None:
        r = RuleResult(
            rule_id="xccdf_org.ssgproject.content_rule_foo",
            result=RuleResultStatus.FAIL,
            severity=SeverityLevel.HIGH,
            title="Test Rule",
            description="A test rule",
            fix_text="Fix it",
            weight=5.0,
        )
        assert r.severity == SeverityLevel.HIGH
        assert r.weight == 5.0

    def test_is_compliant_pass(self) -> None:
        r = RuleResult(rule_id="r1", result=RuleResultStatus.PASS)
        assert r.is_compliant is True

    def test_is_compliant_notapplicable(self) -> None:
        r = RuleResult(rule_id="r1", result=RuleResultStatus.NOTAPPLICABLE)
        assert r.is_compliant is True

    def test_is_compliant_fixed(self) -> None:
        r = RuleResult(rule_id="r1", result=RuleResultStatus.FIXED)
        assert r.is_compliant is True

    def test_is_compliant_fail(self) -> None:
        r = RuleResult(rule_id="r1", result=RuleResultStatus.FAIL)
        assert r.is_compliant is False

    def test_is_finding_fail(self) -> None:
        r = RuleResult(rule_id="r1", result=RuleResultStatus.FAIL)
        assert r.is_finding is True

    def test_is_finding_error(self) -> None:
        r = RuleResult(rule_id="r1", result=RuleResultStatus.ERROR)
        assert r.is_finding is True

    def test_is_finding_pass(self) -> None:
        r = RuleResult(rule_id="r1", result=RuleResultStatus.PASS)
        assert r.is_finding is False

    def test_to_dict(self) -> None:
        ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
        r = RuleResult(
            rule_id="r1",
            result=RuleResultStatus.PASS,
            severity=SeverityLevel.LOW,
            timestamp=ts,
        )
        d = r.to_dict()
        assert d["rule_id"] == "r1"
        assert d["result"] == "pass"
        assert d["severity"] == "low"
        assert d["timestamp"] == ts.isoformat()

    def test_to_dict_no_timestamp(self) -> None:
        r = RuleResult(rule_id="r1", result=RuleResultStatus.PASS)
        d = r.to_dict()
        assert d["timestamp"] is None


# ---------------------------------------------------------------------------
# ResultStatistics dataclass
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestResultStatistics:
    """Test ResultStatistics computation."""

    def test_defaults(self) -> None:
        stats = ResultStatistics()
        assert stats.total_rules == 0
        assert stats.pass_rate == 0.0

    def test_pass_rate_calculation(self) -> None:
        stats = ResultStatistics(total_rules=10, pass_count=7)
        assert stats.pass_rate == 70.0

    def test_pass_rate_excludes_notselected(self) -> None:
        """notselected/notchecked excluded from denominator."""
        stats = ResultStatistics(
            total_rules=10,
            pass_count=5,
            notselected_count=2,
            notchecked_count=1,
        )
        # Evaluated = 10 - 2 - 1 = 7; compliant = 5; rate = 5/7 * 100
        assert stats.pass_rate == pytest.approx(71.43, abs=0.01)

    def test_pass_rate_includes_notapplicable_and_fixed(self) -> None:
        stats = ResultStatistics(
            total_rules=10,
            pass_count=3,
            notapplicable_count=2,
            fixed_count=1,
        )
        # compliant = 3 + 2 + 1 = 6; evaluated = 10; rate = 60.0
        assert stats.pass_rate == 60.0

    def test_zero_evaluated(self) -> None:
        stats = ResultStatistics(
            total_rules=5,
            notselected_count=3,
            notchecked_count=2,
        )
        assert stats.pass_rate == 0.0

    def test_from_rule_results(self) -> None:
        results = [
            RuleResult(rule_id="r1", result=RuleResultStatus.PASS),
            RuleResult(rule_id="r2", result=RuleResultStatus.FAIL, severity=SeverityLevel.HIGH),
            RuleResult(rule_id="r3", result=RuleResultStatus.NOTAPPLICABLE),
            RuleResult(rule_id="r4", result=RuleResultStatus.ERROR, severity=SeverityLevel.CRITICAL),
        ]
        stats = ResultStatistics.from_rule_results(results)
        assert stats.total_rules == 4
        assert stats.pass_count == 1
        assert stats.fail_count == 1
        assert stats.error_count == 1
        assert stats.notapplicable_count == 1
        assert stats.pass_rate == 50.0  # (1 pass + 1 na) / 4 = 50%

    def test_from_rule_results_severity_breakdown(self) -> None:
        results = [
            RuleResult(rule_id="r1", result=RuleResultStatus.FAIL, severity=SeverityLevel.HIGH),
            RuleResult(rule_id="r2", result=RuleResultStatus.FAIL, severity=SeverityLevel.HIGH),
            RuleResult(rule_id="r3", result=RuleResultStatus.FAIL, severity=SeverityLevel.LOW),
            RuleResult(rule_id="r4", result=RuleResultStatus.PASS, severity=SeverityLevel.HIGH),
        ]
        stats = ResultStatistics.from_rule_results(results)
        # Only findings (fail/error) counted in severity breakdown
        assert stats.severity_breakdown["high"] == 2
        assert stats.severity_breakdown["low"] == 1
        assert "high" not in stats.severity_breakdown or stats.severity_breakdown.get("high") == 2

    def test_from_rule_results_empty(self) -> None:
        stats = ResultStatistics.from_rule_results([])
        assert stats.total_rules == 0
        assert stats.pass_rate == 0.0

    def test_to_dict(self) -> None:
        stats = ResultStatistics(total_rules=5, pass_count=3, fail_count=2)
        d = stats.to_dict()
        assert d["total_rules"] == 5
        assert d["pass_count"] == 3
        assert d["fail_count"] == 2
        assert "pass_rate" in d


# ---------------------------------------------------------------------------
# ParsedResults dataclass
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestParsedResults:
    """Test ParsedResults container."""

    def test_auto_statistics(self) -> None:
        """Statistics auto-computed from rule_results."""
        rules = [
            RuleResult(rule_id="r1", result=RuleResultStatus.PASS),
            RuleResult(rule_id="r2", result=RuleResultStatus.FAIL, severity=SeverityLevel.HIGH),
        ]
        parsed = ParsedResults(
            format_type="xccdf",
            source_file="/tmp/test.xml",
            parse_timestamp=datetime.now(tz=timezone.utc),
            rule_results=rules,
        )
        assert parsed.statistics.total_rules == 2
        assert parsed.statistics.pass_count == 1
        assert parsed.statistics.fail_count == 1

    def test_get_findings(self) -> None:
        rules = [
            RuleResult(rule_id="r1", result=RuleResultStatus.PASS),
            RuleResult(rule_id="r2", result=RuleResultStatus.FAIL),
            RuleResult(rule_id="r3", result=RuleResultStatus.ERROR),
            RuleResult(rule_id="r4", result=RuleResultStatus.NOTAPPLICABLE),
        ]
        parsed = ParsedResults(
            format_type="xccdf",
            source_file="/tmp/test.xml",
            parse_timestamp=datetime.now(tz=timezone.utc),
            rule_results=rules,
        )
        findings = parsed.get_findings()
        assert len(findings) == 2
        assert all(f.is_finding for f in findings)

    def test_get_findings_by_severity(self) -> None:
        rules = [
            RuleResult(rule_id="r1", result=RuleResultStatus.FAIL, severity=SeverityLevel.HIGH),
            RuleResult(rule_id="r2", result=RuleResultStatus.FAIL, severity=SeverityLevel.LOW),
            RuleResult(rule_id="r3", result=RuleResultStatus.ERROR, severity=SeverityLevel.HIGH),
        ]
        parsed = ParsedResults(
            format_type="xccdf",
            source_file="/tmp/test.xml",
            parse_timestamp=datetime.now(tz=timezone.utc),
            rule_results=rules,
        )
        high = parsed.get_findings_by_severity(SeverityLevel.HIGH)
        assert len(high) == 2

    def test_to_dict(self) -> None:
        parsed = ParsedResults(
            format_type="xccdf",
            source_file="/tmp/test.xml",
            parse_timestamp=datetime.now(tz=timezone.utc),
            benchmark_id="bench-1",
            profile_id="prof-1",
        )
        d = parsed.to_dict()
        assert d["format_type"] == "xccdf"
        assert d["benchmark_id"] == "bench-1"
        assert "statistics" in d
        assert "rule_results" in d


# ---------------------------------------------------------------------------
# BaseResultParser normalization methods
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestBaseResultParserNormalization:
    """Test normalization helper methods via a concrete subclass."""

    class ConcreteParser(BaseResultParser):
        """Minimal concrete implementation for testing base methods."""

        @property
        def format_name(self) -> str:
            return "test"

        def can_parse(self, file_path: Path) -> bool:
            return False

        def parse(self, file_path: Path) -> ParsedResults:
            raise NotImplementedError

    @pytest.fixture
    def parser(self) -> "TestBaseResultParserNormalization.ConcreteParser":
        return self.ConcreteParser()

    # -- Status normalization --
    def test_normalize_pass(self, parser: BaseResultParser) -> None:
        assert parser._normalize_result_status("pass") == RuleResultStatus.PASS

    def test_normalize_passed(self, parser: BaseResultParser) -> None:
        assert parser._normalize_result_status("passed") == RuleResultStatus.PASS

    def test_normalize_fail(self, parser: BaseResultParser) -> None:
        assert parser._normalize_result_status("fail") == RuleResultStatus.FAIL

    def test_normalize_failed(self, parser: BaseResultParser) -> None:
        assert parser._normalize_result_status("failed") == RuleResultStatus.FAIL

    def test_normalize_error(self, parser: BaseResultParser) -> None:
        assert parser._normalize_result_status("error") == RuleResultStatus.ERROR

    def test_normalize_err(self, parser: BaseResultParser) -> None:
        assert parser._normalize_result_status("err") == RuleResultStatus.ERROR

    def test_normalize_notapplicable_variants(self, parser: BaseResultParser) -> None:
        assert parser._normalize_result_status("notapplicable") == RuleResultStatus.NOTAPPLICABLE
        assert parser._normalize_result_status("not_applicable") == RuleResultStatus.NOTAPPLICABLE

    def test_normalize_notchecked_variants(self, parser: BaseResultParser) -> None:
        assert parser._normalize_result_status("notchecked") == RuleResultStatus.NOTCHECKED
        assert parser._normalize_result_status("not_checked") == RuleResultStatus.NOTCHECKED

    def test_normalize_notselected_variants(self, parser: BaseResultParser) -> None:
        assert parser._normalize_result_status("notselected") == RuleResultStatus.NOTSELECTED
        assert parser._normalize_result_status("not_selected") == RuleResultStatus.NOTSELECTED

    def test_normalize_informational(self, parser: BaseResultParser) -> None:
        assert parser._normalize_result_status("informational") == RuleResultStatus.INFORMATIONAL
        assert parser._normalize_result_status("info") == RuleResultStatus.INFORMATIONAL

    def test_normalize_fixed(self, parser: BaseResultParser) -> None:
        assert parser._normalize_result_status("fixed") == RuleResultStatus.FIXED

    def test_normalize_unknown_value(self, parser: BaseResultParser) -> None:
        assert parser._normalize_result_status("garbage") == RuleResultStatus.UNKNOWN

    def test_normalize_case_insensitive(self, parser: BaseResultParser) -> None:
        assert parser._normalize_result_status("PASS") == RuleResultStatus.PASS
        assert parser._normalize_result_status("Fail") == RuleResultStatus.FAIL

    def test_normalize_with_whitespace(self, parser: BaseResultParser) -> None:
        assert parser._normalize_result_status("  pass  ") == RuleResultStatus.PASS

    # -- Severity normalization --
    def test_severity_critical(self, parser: BaseResultParser) -> None:
        assert parser._normalize_severity("critical") == SeverityLevel.CRITICAL
        assert parser._normalize_severity("crit") == SeverityLevel.CRITICAL

    def test_severity_high(self, parser: BaseResultParser) -> None:
        assert parser._normalize_severity("high") == SeverityLevel.HIGH
        assert parser._normalize_severity("important") == SeverityLevel.HIGH

    def test_severity_medium(self, parser: BaseResultParser) -> None:
        assert parser._normalize_severity("medium") == SeverityLevel.MEDIUM
        assert parser._normalize_severity("moderate") == SeverityLevel.MEDIUM
        assert parser._normalize_severity("med") == SeverityLevel.MEDIUM

    def test_severity_low(self, parser: BaseResultParser) -> None:
        assert parser._normalize_severity("low") == SeverityLevel.LOW
        assert parser._normalize_severity("minor") == SeverityLevel.LOW

    def test_severity_info(self, parser: BaseResultParser) -> None:
        assert parser._normalize_severity("info") == SeverityLevel.INFO
        assert parser._normalize_severity("informational") == SeverityLevel.INFO
        assert parser._normalize_severity("none") == SeverityLevel.INFO

    def test_severity_unknown(self, parser: BaseResultParser) -> None:
        assert parser._normalize_severity("garbage") == SeverityLevel.UNKNOWN


# ---------------------------------------------------------------------------
# BaseResultParser path validation
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestBaseResultParserPathValidation:
    """Test file path validation security."""

    class ConcreteParser(BaseResultParser):
        @property
        def format_name(self) -> str:
            return "test"

        def can_parse(self, file_path: Path) -> bool:
            return False

        def parse(self, file_path: Path) -> ParsedResults:
            raise NotImplementedError

    @pytest.fixture
    def parser(self) -> "TestBaseResultParserPathValidation.ConcreteParser":
        return self.ConcreteParser()

    def test_disallowed_path(self, parser: BaseResultParser) -> None:
        """Paths outside allowed directories are rejected."""
        with pytest.raises(ValueError, match="not in allowed directory"):
            parser.validate_file_path(Path("/etc/passwd"))

    def test_nonexistent_file(self, parser: BaseResultParser, tmp_path: Path) -> None:
        """Nonexistent files raise FileNotFoundError."""
        # tmp_path is under /tmp, which is allowed
        with pytest.raises(FileNotFoundError):
            parser.validate_file_path(tmp_path / "nonexistent.xml")

    def test_allowed_tmp_path(self, parser: BaseResultParser, tmp_path: Path) -> None:
        """Files under /tmp are allowed."""
        f = tmp_path / "test.xml"
        f.write_text("<xml/>")
        # Should not raise
        parser.validate_file_path(f)


# ---------------------------------------------------------------------------
# XCCDFResultParser
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestXCCDFResultParser:
    """Test XCCDFResultParser."""

    def test_format_name(self) -> None:
        from app.services.engine.result_parsers.xccdf import XCCDFResultParser

        parser = XCCDFResultParser()
        assert parser.format_name == "xccdf"

    def test_can_parse_xccdf_file(self, tmp_path: Path) -> None:
        """Detects XCCDF result files."""
        from app.services.engine.result_parsers.xccdf import XCCDFResultParser

        f = tmp_path / "results.xml"
        f.write_text(
            '<?xml version="1.0"?>\n'
            '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">\n'
            "  <TestResult/>\n"
            "</Benchmark>"
        )
        parser = XCCDFResultParser()
        assert parser.can_parse(f) is True

    def test_cannot_parse_random_xml(self, tmp_path: Path) -> None:
        """Rejects non-XCCDF XML files."""
        from app.services.engine.result_parsers.xccdf import XCCDFResultParser

        f = tmp_path / "other.xml"
        f.write_text('<?xml version="1.0"?>\n<root><element/></root>')
        parser = XCCDFResultParser()
        assert parser.can_parse(f) is False

    def test_cannot_parse_nonexistent(self, tmp_path: Path) -> None:
        """Returns False for nonexistent files."""
        from app.services.engine.result_parsers.xccdf import XCCDFResultParser

        parser = XCCDFResultParser()
        assert parser.can_parse(tmp_path / "missing.xml") is False


# ---------------------------------------------------------------------------
# Module factory functions
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestParserFactory:
    """Test result parser factory functions."""

    def test_get_parser_xccdf(self) -> None:
        from app.services.engine.result_parsers import get_parser

        parser = get_parser("xccdf")
        assert parser.format_name == "xccdf"

    def test_get_parser_invalid(self) -> None:
        from app.services.engine.result_parsers import get_parser

        with pytest.raises((ValueError, KeyError)):
            get_parser("invalid_format")
