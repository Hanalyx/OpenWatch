"""
Base Result Parser Abstract Class

This module defines the abstract base class for all scan result parsers.
Parsers extract normalized data from SCAP result files (XCCDF, ARF, OVAL).

Design Philosophy:
- Single Responsibility: Parsers extract data, nothing else
- Stateless Design: No persistent state between parse operations
- Security First: Input validation, XXE prevention, sanitized errors
- Defensive Coding: Graceful handling of malformed files

Parser vs Scanner Responsibilities:
    Parser: Read result files, extract rule results, compute statistics
    Scanner: Validate content, build commands, execute scans

Output Format:
    All parsers produce a standardized ParsedResults object containing:
    - List of individual rule results (pass/fail/error/notapplicable)
    - Statistics (counts, pass rate, severity breakdown)
    - Metadata (scan time, profile, benchmark info)

Implementation Requirements:
- All abstract methods must be implemented
- File access must validate paths (no traversal attacks)
- XML parsing must use defused parsers (XXE prevention)
- Large files should be handled efficiently (streaming)
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class RuleResultStatus(str, Enum):
    """
    Standardized rule result status values.

    Based on XCCDF 1.2 specification for rule-result status.
    These values are normalized from various SCAP result formats.
    """

    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    UNKNOWN = "unknown"
    NOTAPPLICABLE = "notapplicable"
    NOTCHECKED = "notchecked"
    NOTSELECTED = "notselected"
    INFORMATIONAL = "informational"
    FIXED = "fixed"


class SeverityLevel(str, Enum):
    """
    Standardized severity levels for compliance findings.

    Based on CVSS and common security rating systems.
    Used for risk-based prioritization of remediation.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


@dataclass
class RuleResult:
    """
    Individual rule evaluation result.

    Represents the outcome of evaluating a single compliance rule
    against a target system. Includes all relevant metadata for
    reporting and remediation guidance.

    Attributes:
        rule_id: Full XCCDF rule identifier
        result: Evaluation result status
        severity: Severity level of the finding
        title: Human-readable rule title
        description: Detailed rule description
        rationale: Why this rule matters for security
        fix_text: Remediation instructions (if available)
        check_content_ref: Reference to check definition
        oval_id: Associated OVAL definition ID
        cce_id: CCE identifier (if available)
        weight: Rule weight for scoring
        timestamp: When the rule was evaluated
        evidence: Supporting evidence for the result
    """

    rule_id: str
    result: RuleResultStatus
    severity: SeverityLevel = SeverityLevel.UNKNOWN
    title: str = ""
    description: str = ""
    rationale: str = ""
    fix_text: str = ""
    check_content_ref: str = ""
    oval_id: str = ""
    cce_id: str = ""
    weight: float = 1.0
    timestamp: Optional[datetime] = None
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert rule result to dictionary format.

        Returns:
            Dictionary representation suitable for JSON serialization.
        """
        return {
            "rule_id": self.rule_id,
            "result": self.result.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "rationale": self.rationale,
            "fix_text": self.fix_text,
            "check_content_ref": self.check_content_ref,
            "oval_id": self.oval_id,
            "cce_id": self.cce_id,
            "weight": self.weight,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "evidence": self.evidence,
        }

    @property
    def is_compliant(self) -> bool:
        """Check if result indicates compliance."""
        return self.result in (
            RuleResultStatus.PASS,
            RuleResultStatus.NOTAPPLICABLE,
            RuleResultStatus.FIXED,
        )

    @property
    def is_finding(self) -> bool:
        """Check if result is a compliance finding requiring attention."""
        return self.result in (RuleResultStatus.FAIL, RuleResultStatus.ERROR)


@dataclass
class ResultStatistics:
    """
    Aggregated statistics from scan results.

    Provides summary metrics for reporting and dashboards.
    All counts are derived from the individual rule results.

    Attributes:
        total_rules: Total number of rules evaluated
        pass_count: Rules that passed evaluation
        fail_count: Rules that failed evaluation
        error_count: Rules with evaluation errors
        unknown_count: Rules with unknown status
        notapplicable_count: Rules not applicable to target
        notchecked_count: Rules skipped or not checked
        notselected_count: Rules not selected in profile
        informational_count: Informational-only rules
        fixed_count: Rules marked as fixed
        pass_rate: Percentage of passing rules (0-100)
        severity_breakdown: Count by severity level
    """

    total_rules: int = 0
    pass_count: int = 0
    fail_count: int = 0
    error_count: int = 0
    unknown_count: int = 0
    notapplicable_count: int = 0
    notchecked_count: int = 0
    notselected_count: int = 0
    informational_count: int = 0
    fixed_count: int = 0
    pass_rate: float = 0.0
    severity_breakdown: Dict[str, int] = field(default_factory=dict)

    def __post_init__(self):
        """Calculate derived statistics after initialization."""
        self._calculate_pass_rate()

    def _calculate_pass_rate(self) -> None:
        """
        Calculate pass rate percentage.

        Pass rate is calculated as:
        (pass + notapplicable + fixed) / (total - notselected - notchecked) * 100

        This excludes rules that were not evaluated from the calculation.
        """
        # Evaluated rules = total minus skipped rules
        evaluated = self.total_rules - self.notselected_count - self.notchecked_count

        if evaluated > 0:
            compliant = self.pass_count + self.notapplicable_count + self.fixed_count
            self.pass_rate = round((compliant / evaluated) * 100, 2)
        else:
            self.pass_rate = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert statistics to dictionary format.

        Returns:
            Dictionary representation suitable for JSON serialization.
        """
        return {
            "total_rules": self.total_rules,
            "pass_count": self.pass_count,
            "fail_count": self.fail_count,
            "error_count": self.error_count,
            "unknown_count": self.unknown_count,
            "notapplicable_count": self.notapplicable_count,
            "notchecked_count": self.notchecked_count,
            "notselected_count": self.notselected_count,
            "informational_count": self.informational_count,
            "fixed_count": self.fixed_count,
            "pass_rate": self.pass_rate,
            "severity_breakdown": self.severity_breakdown,
        }

    @classmethod
    def from_rule_results(cls, results: List[RuleResult]) -> "ResultStatistics":
        """
        Create statistics from a list of rule results.

        Args:
            results: List of RuleResult objects to analyze.

        Returns:
            ResultStatistics with computed values.
        """
        stats = cls(total_rules=len(results))
        severity_counts: Dict[str, int] = {}

        for rule in results:
            # Count by result status
            if rule.result == RuleResultStatus.PASS:
                stats.pass_count += 1
            elif rule.result == RuleResultStatus.FAIL:
                stats.fail_count += 1
            elif rule.result == RuleResultStatus.ERROR:
                stats.error_count += 1
            elif rule.result == RuleResultStatus.UNKNOWN:
                stats.unknown_count += 1
            elif rule.result == RuleResultStatus.NOTAPPLICABLE:
                stats.notapplicable_count += 1
            elif rule.result == RuleResultStatus.NOTCHECKED:
                stats.notchecked_count += 1
            elif rule.result == RuleResultStatus.NOTSELECTED:
                stats.notselected_count += 1
            elif rule.result == RuleResultStatus.INFORMATIONAL:
                stats.informational_count += 1
            elif rule.result == RuleResultStatus.FIXED:
                stats.fixed_count += 1

            # Count by severity (only for findings)
            if rule.is_finding:
                sev_key = rule.severity.value
                severity_counts[sev_key] = severity_counts.get(sev_key, 0) + 1

        stats.severity_breakdown = severity_counts
        stats._calculate_pass_rate()

        return stats


@dataclass
class ParsedResults:
    """
    Complete parsed scan results.

    Top-level container for all parsed data from a scan result file.
    Includes individual rule results, statistics, and metadata.

    Attributes:
        format_type: Result format (xccdf, arf, oval)
        source_file: Path to original result file
        parse_timestamp: When parsing occurred
        benchmark_id: XCCDF benchmark identifier
        profile_id: XCCDF profile that was evaluated
        target_info: Information about scanned target
        scan_start: When scan started (if available)
        scan_end: When scan ended (if available)
        rule_results: List of individual rule results
        statistics: Aggregated statistics
        metadata: Additional metadata from result file
    """

    format_type: str
    source_file: str
    parse_timestamp: datetime
    benchmark_id: str = ""
    profile_id: str = ""
    target_info: Dict[str, Any] = field(default_factory=dict)
    scan_start: Optional[datetime] = None
    scan_end: Optional[datetime] = None
    rule_results: List[RuleResult] = field(default_factory=list)
    statistics: ResultStatistics = field(default_factory=ResultStatistics)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Initialize statistics from rule results if not provided."""
        if self.rule_results and self.statistics.total_rules == 0:
            self.statistics = ResultStatistics.from_rule_results(self.rule_results)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert parsed results to dictionary format.

        Returns:
            Dictionary representation suitable for JSON serialization.
        """
        return {
            "format_type": self.format_type,
            "source_file": self.source_file,
            "parse_timestamp": self.parse_timestamp.isoformat(),
            "benchmark_id": self.benchmark_id,
            "profile_id": self.profile_id,
            "target_info": self.target_info,
            "scan_start": self.scan_start.isoformat() if self.scan_start else None,
            "scan_end": self.scan_end.isoformat() if self.scan_end else None,
            "rule_results": [r.to_dict() for r in self.rule_results],
            "statistics": self.statistics.to_dict(),
            "metadata": self.metadata,
        }

    def get_findings(self) -> List[RuleResult]:
        """
        Get only the rules that are findings (fail or error).

        Returns:
            List of RuleResult objects that require remediation.
        """
        return [r for r in self.rule_results if r.is_finding]

    def get_findings_by_severity(self, severity: SeverityLevel) -> List[RuleResult]:
        """
        Get findings filtered by severity level.

        Args:
            severity: Severity level to filter by.

        Returns:
            List of RuleResult objects matching the severity.
        """
        return [r for r in self.rule_results if r.is_finding and r.severity == severity]


class BaseResultParser(ABC):
    """
    Abstract base class for scan result parsers.

    Parsers extract normalized data from SCAP result files.
    Each implementation handles a specific format (XCCDF, ARF, etc.).

    The parser is stateless - all operations take file paths as
    arguments and do not maintain internal state.

    Subclasses must implement:
    - format_name: Return the format this parser handles
    - can_parse(): Check if parser can handle a file
    - parse(): Parse file and return ParsedResults

    Usage:
        class MyParser(BaseResultParser):
            @property
            def format_name(self):
                return "my_format"

            def can_parse(self, file_path):
                # Detection logic
                pass

            def parse(self, file_path):
                # Parsing logic
                pass

        parser = MyParser()
        if parser.can_parse(path):
            results = parser.parse(path)
    """

    def __init__(self, name: str = "BaseResultParser"):
        """
        Initialize the base parser.

        Args:
            name: Human-readable name for logging and debugging.
        """
        self.name = name
        self._logger = logging.getLogger(f"{__name__}.{name}")

    @property
    @abstractmethod
    def format_name(self) -> str:
        """
        Return the format this parser handles.

        Returns:
            Format identifier (e.g., 'xccdf', 'arf', 'oval').
        """

    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        """
        Check if this parser can handle the given file.

        Examines the file content to determine if this parser
        is appropriate. Should be fast and not parse entire file.

        Args:
            file_path: Path to the result file.

        Returns:
            True if parser can handle this file.

        Note:
            This should examine file content, not just extension,
            since extensions can be inconsistent.
        """

    @abstractmethod
    def parse(self, file_path: Path) -> ParsedResults:
        """
        Parse the result file and return normalized data.

        Reads the result file and extracts all rule results,
        statistics, and metadata into a ParsedResults object.

        Args:
            file_path: Path to the result file.

        Returns:
            ParsedResults containing all extracted data.

        Raises:
            ValueError: If file cannot be parsed.
            FileNotFoundError: If file does not exist.
            PermissionError: If file cannot be read.

        Security:
            - Validates file path before access
            - Uses defused XML parsing (XXE prevention)
            - Sanitizes error messages
        """

    def validate_file_path(self, file_path: Path) -> None:
        """
        Validate file path for security and accessibility.

        Checks:
        - Path is absolute or safely resolvable
        - File exists and is readable
        - No path traversal attacks

        Args:
            file_path: Path to validate.

        Raises:
            FileNotFoundError: If file does not exist.
            PermissionError: If file cannot be read.
            ValueError: If path appears malicious.
        """
        # Resolve to absolute path
        resolved = file_path.resolve()

        # Check for path traversal
        # File must be under /app/data or /tmp for security
        allowed_prefixes = ["/app/data", "/tmp", "/var/tmp"]
        path_str = str(resolved)

        is_allowed = any(path_str.startswith(prefix) for prefix in allowed_prefixes)
        if not is_allowed:
            # Log security event but don't expose path in error
            self._logger.warning("Path traversal attempt blocked: %s", path_str[:50])  # Truncate for logging
            raise ValueError("File path not in allowed directory")

        # Check file exists
        if not resolved.exists():
            raise FileNotFoundError(f"Result file not found: {resolved.name}")

        # Check readable
        if not resolved.is_file():
            raise ValueError(f"Path is not a file: {resolved.name}")

    def _normalize_result_status(self, status: str) -> RuleResultStatus:
        """
        Normalize result status string to enum value.

        SCAP formats may use different casings or variations.
        This method normalizes them to standard enum values.

        Args:
            status: Raw status string from result file.

        Returns:
            Normalized RuleResultStatus enum value.
        """
        status_lower = status.lower().strip()

        # Map various status strings to enum
        status_map = {
            "pass": RuleResultStatus.PASS,
            "passed": RuleResultStatus.PASS,
            "fail": RuleResultStatus.FAIL,
            "failed": RuleResultStatus.FAIL,
            "error": RuleResultStatus.ERROR,
            "err": RuleResultStatus.ERROR,
            "unknown": RuleResultStatus.UNKNOWN,
            "notapplicable": RuleResultStatus.NOTAPPLICABLE,
            "not_applicable": RuleResultStatus.NOTAPPLICABLE,
            "notchecked": RuleResultStatus.NOTCHECKED,
            "not_checked": RuleResultStatus.NOTCHECKED,
            "notselected": RuleResultStatus.NOTSELECTED,
            "not_selected": RuleResultStatus.NOTSELECTED,
            "informational": RuleResultStatus.INFORMATIONAL,
            "info": RuleResultStatus.INFORMATIONAL,
            "fixed": RuleResultStatus.FIXED,
        }

        return status_map.get(status_lower, RuleResultStatus.UNKNOWN)

    def _normalize_severity(self, severity: str) -> SeverityLevel:
        """
        Normalize severity string to enum value.

        SCAP uses various severity terms. This normalizes them
        to a consistent set for reporting.

        Args:
            severity: Raw severity string from result file.

        Returns:
            Normalized SeverityLevel enum value.
        """
        severity_lower = severity.lower().strip()

        # Map various severity strings to enum
        severity_map = {
            "critical": SeverityLevel.CRITICAL,
            "crit": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "important": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "moderate": SeverityLevel.MEDIUM,
            "med": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "minor": SeverityLevel.LOW,
            "info": SeverityLevel.INFO,
            "informational": SeverityLevel.INFO,
            "none": SeverityLevel.INFO,
        }

        return severity_map.get(severity_lower, SeverityLevel.UNKNOWN)

    def _read_file_header(self, file_path: Path, bytes_to_read: int = 4096) -> str:
        """
        Read the beginning of a file for format detection.

        Args:
            file_path: Path to the file.
            bytes_to_read: Number of bytes to read (default 4KB).

        Returns:
            String content of file header.
        """
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read(bytes_to_read)
        except Exception as e:
            self._logger.debug("Could not read file header: %s", e)
            return ""

    def log_parse_result(
        self,
        file_path: Path,
        success: bool,
        rule_count: int = 0,
        duration_ms: float = 0,
    ) -> None:
        """
        Log parsing result for observability.

        Args:
            file_path: Path to parsed file.
            success: Whether parsing succeeded.
            rule_count: Number of rules extracted.
            duration_ms: Parsing duration in milliseconds.
        """
        if success:
            self._logger.info(
                "Parsed %s: %d rules in %.2fms",
                file_path.name,
                rule_count,
                duration_ms,
            )
        else:
            self._logger.warning(
                "Failed to parse %s after %.2fms",
                file_path.name,
                duration_ms,
            )
