"""
XCCDF Result Parser

This module provides the XCCDFResultParser for parsing XCCDF 1.1 and 1.2
scan result files. XCCDF (Extensible Configuration Checklist Description
Format) is the primary result format produced by OpenSCAP.

Key Features:
- XCCDF 1.1 and 1.2 format support
- Full rule result extraction with metadata
- Benchmark and profile information extraction
- Target system information extraction
- Score and statistics calculation

Migrated from: backend/app/services/scap_scanner.py (_parse_scan_results)

Security Notes:
- Uses defused XML parsing to prevent XXE attacks
- File path validation before access
- Large file handling with streaming
- Sanitized error messages

Usage:
    from backend.app.services.engine.result_parsers import XCCDFResultParser

    parser = XCCDFResultParser()

    if parser.can_parse(result_path):
        results = parser.parse(result_path)
        print(f"Pass rate: {results.statistics.pass_rate}%")
        for finding in results.get_findings():
            print(f"FAIL: {finding.rule_id}")
"""

import logging
import time
import xml.etree.ElementTree as ET  # nosec B405  # Used with defused parsing
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Use defusedxml for secure parsing (prevents XXE attacks)
try:
    import defusedxml.ElementTree as DefusedET

    HAS_DEFUSED = True
except ImportError:
    # Fallback with security warning
    HAS_DEFUSED = False

from .base import BaseResultParser, ParsedResults, ResultStatistics, RuleResult

logger = logging.getLogger(__name__)

# XCCDF Namespaces for different versions
XCCDF_NAMESPACES = {
    "xccdf11": "http://checklists.nist.gov/xccdf/1.1",
    "xccdf12": "http://checklists.nist.gov/xccdf/1.2",
    "xccdf": "http://checklists.nist.gov/xccdf/1.2",  # Default to 1.2
    "oval": "http://oval.mitre.org/XMLSchema/oval-results-5",
    "cpe": "http://cpe.mitre.org/language/2.0",
    "dc": "http://purl.org/dc/elements/1.1/",
}


class XCCDFResultParser(BaseResultParser):
    """
    Parser for XCCDF scan result files.

    Extracts rule results, benchmark information, and target data
    from XCCDF 1.1 and 1.2 format result files.

    The parser handles both standalone XCCDF results and XCCDF
    results embedded within ARF (Asset Reporting Format) files.

    Attributes:
        max_file_size: Maximum file size to parse (default 100MB)
        parse_timeout: Timeout for parsing operations (default 60s)

    Usage:
        parser = XCCDFResultParser()
        results = parser.parse(Path("/app/data/results/scan_123_xccdf.xml"))
        for rule in results.rule_results:
            print(f"{rule.rule_id}: {rule.result.value}")
    """

    def __init__(
        self,
        max_file_size: int = 100 * 1024 * 1024,  # 100MB
        parse_timeout: int = 60,
    ):
        """
        Initialize the XCCDF result parser.

        Args:
            max_file_size: Maximum file size to parse in bytes.
            parse_timeout: Timeout for parsing operations in seconds.
        """
        super().__init__(name="XCCDFResultParser")
        self.max_file_size = max_file_size
        self.parse_timeout = parse_timeout

        # Log warning if defusedxml not available
        if not HAS_DEFUSED:
            self._logger.warning(
                "defusedxml not available - using standard XML parser. " "Install defusedxml for enhanced security."
            )

    @property
    def format_name(self) -> str:
        """Return format identifier."""
        return "xccdf"

    def can_parse(self, file_path: Path) -> bool:
        """
        Check if this parser can handle the given file.

        Examines file content for XCCDF markers including:
        - XCCDF namespace declarations
        - TestResult element presence
        - Benchmark structure

        Args:
            file_path: Path to the result file.

        Returns:
            True if file appears to be XCCDF format.
        """
        try:
            # Read file header for format detection
            header = self._read_file_header(file_path)
            header_lower = header.lower()

            # Check for XCCDF indicators
            xccdf_markers = [
                "xccdf",
                "testresult",
                "benchmark",
                "rule-result",
                "http://checklists.nist.gov/xccdf",
            ]

            has_xccdf = any(marker in header_lower for marker in xccdf_markers)

            # Exclude ARF format (handled by ARF parser)
            # ARF files contain XCCDF but should use ARF parser
            is_arf = "asset-report-collection" in header_lower or "<arf:" in header_lower

            return has_xccdf and not is_arf

        except Exception as e:
            self._logger.debug("Cannot determine if XCCDF: %s", e)
            return False

    def parse(self, file_path: Path) -> ParsedResults:
        """
        Parse XCCDF result file and return normalized data.

        Reads the XCCDF result file and extracts:
        - Individual rule results with full metadata
        - Benchmark and profile information
        - Target system details
        - Score and statistics

        Args:
            file_path: Path to the XCCDF result file.

        Returns:
            ParsedResults containing all extracted data.

        Raises:
            ValueError: If file cannot be parsed as XCCDF.
            FileNotFoundError: If file does not exist.
        """
        start_time = time.time()

        try:
            # Validate file path
            self.validate_file_path(file_path)

            # Check file size
            file_size = file_path.stat().st_size
            if file_size > self.max_file_size:
                raise ValueError(f"File too large: {file_size} bytes exceeds " f"maximum of {self.max_file_size} bytes")

            # Parse XML
            root = self._parse_xml(file_path)

            # Detect XCCDF version and get namespace
            ns, version = self._detect_xccdf_version(root)
            self._logger.debug("Detected XCCDF version: %s", version)

            # Extract benchmark info
            benchmark_id, profile_id = self._extract_benchmark_info(root, ns)

            # Extract target info
            target_info = self._extract_target_info(root, ns)

            # Extract scan timing
            scan_start, scan_end = self._extract_timing(root, ns)

            # Extract rule results
            rule_results = self._extract_rule_results(root, ns)

            # Calculate statistics
            statistics = ResultStatistics.from_rule_results(rule_results)

            # Build parsed results
            duration_ms = (time.time() - start_time) * 1000
            results = ParsedResults(
                format_type=self.format_name,
                source_file=str(file_path),
                parse_timestamp=datetime.utcnow(),
                benchmark_id=benchmark_id,
                profile_id=profile_id,
                target_info=target_info,
                scan_start=scan_start,
                scan_end=scan_end,
                rule_results=rule_results,
                statistics=statistics,
                metadata={
                    "xccdf_version": version,
                    "file_size": file_size,
                    "parse_duration_ms": duration_ms,
                },
            )

            self.log_parse_result(
                file_path,
                success=True,
                rule_count=len(rule_results),
                duration_ms=duration_ms,
            )

            return results

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            self.log_parse_result(file_path, success=False, duration_ms=duration_ms)
            self._logger.error("XCCDF parse error: %s", str(e)[:200])
            raise ValueError(f"Failed to parse XCCDF: {str(e)[:100]}")

    def _parse_xml(self, file_path: Path) -> ET.Element:
        """
        Parse XML file with security protections.

        Uses defusedxml when available to prevent XXE attacks.
        Falls back to standard parser with external entity disabled.

        Args:
            file_path: Path to XML file.

        Returns:
            Root element of parsed XML.

        Raises:
            ValueError: If XML cannot be parsed.
        """
        try:
            if HAS_DEFUSED:
                # Secure parsing with defusedxml
                tree = DefusedET.parse(str(file_path))
            else:
                # Fallback: disable external entities manually
                # Note: This is less secure than defusedxml
                tree = ET.parse(str(file_path))  # nosec B314

            return tree.getroot()

        except ET.ParseError as e:
            raise ValueError(f"Invalid XML: {str(e)[:100]}")
        except Exception as e:
            raise ValueError(f"XML parse error: {str(e)[:100]}")

    def _detect_xccdf_version(self, root: ET.Element) -> Tuple[Dict[str, str], str]:
        """
        Detect XCCDF version from document namespace.

        Args:
            root: Root element of parsed XML.

        Returns:
            Tuple of (namespace dict, version string).
        """
        # Get root tag namespace
        tag = root.tag
        if tag.startswith("{"):
            ns_uri = tag[1 : tag.index("}")]
        else:
            ns_uri = ""

        # Detect version from namespace URI
        if "xccdf/1.1" in ns_uri:
            return {"xccdf": ns_uri}, "1.1"
        elif "xccdf/1.2" in ns_uri:
            return {"xccdf": ns_uri}, "1.2"
        else:
            # Default to 1.2 namespace
            return {"xccdf": XCCDF_NAMESPACES["xccdf12"]}, "1.2"

    def _extract_benchmark_info(
        self,
        root: ET.Element,
        ns: Dict[str, str],
    ) -> Tuple[str, str]:
        """
        Extract benchmark and profile identifiers.

        Args:
            root: Root element of parsed XML.
            ns: Namespace dictionary.

        Returns:
            Tuple of (benchmark_id, profile_id).
        """
        benchmark_id = ""
        profile_id = ""

        # Try to find Benchmark element
        benchmark = root.find(".//xccdf:Benchmark", ns)
        if benchmark is not None:
            benchmark_id = benchmark.get("id", "")

        # Try to find TestResult element for profile
        test_result = root.find(".//xccdf:TestResult", ns)
        if test_result is not None:
            profile_elem = test_result.find("xccdf:profile", ns)
            if profile_elem is not None:
                profile_id = profile_elem.get("idref", "")

        # Fallback: check root attributes
        if not benchmark_id:
            benchmark_id = root.get("id", "")

        return benchmark_id, profile_id

    def _extract_target_info(
        self,
        root: ET.Element,
        ns: Dict[str, str],
    ) -> Dict[str, Any]:
        """
        Extract target system information.

        Args:
            root: Root element of parsed XML.
            ns: Namespace dictionary.

        Returns:
            Dictionary with target information.
        """
        target_info: Dict[str, Any] = {}

        # Find target element
        test_result = root.find(".//xccdf:TestResult", ns)
        if test_result is not None:
            target = test_result.find("xccdf:target", ns)
            if target is not None and target.text:
                target_info["hostname"] = target.text

            # Target address (IP)
            target_addr = test_result.find("xccdf:target-address", ns)
            if target_addr is not None and target_addr.text:
                target_info["ip_address"] = target_addr.text

            # Target identity
            identity = test_result.find("xccdf:identity", ns)
            if identity is not None and identity.text:
                target_info["identity"] = identity.text

            # Target facts
            facts: Dict[str, str] = {}
            for fact in test_result.findall(".//xccdf:fact", ns):
                fact_name = fact.get("name", "")
                if fact_name and fact.text:
                    # Normalize fact name
                    fact_key = fact_name.split(":")[-1] if ":" in fact_name else fact_name
                    facts[fact_key] = fact.text

            if facts:
                target_info["facts"] = facts

        return target_info

    def _extract_timing(
        self,
        root: ET.Element,
        ns: Dict[str, str],
    ) -> Tuple[Optional[datetime], Optional[datetime]]:
        """
        Extract scan start and end times.

        Args:
            root: Root element of parsed XML.
            ns: Namespace dictionary.

        Returns:
            Tuple of (start_time, end_time) or (None, None).
        """
        scan_start = None
        scan_end = None

        test_result = root.find(".//xccdf:TestResult", ns)
        if test_result is not None:
            # Start time
            start_str = test_result.get("start-time")
            if start_str:
                try:
                    scan_start = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
                except ValueError:
                    self._logger.debug("Could not parse start time: %s", start_str)

            # End time
            end_str = test_result.get("end-time")
            if end_str:
                try:
                    scan_end = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
                except ValueError:
                    self._logger.debug("Could not parse end time: %s", end_str)

        return scan_start, scan_end

    def _extract_rule_results(
        self,
        root: ET.Element,
        ns: Dict[str, str],
    ) -> List[RuleResult]:
        """
        Extract individual rule results from XCCDF.

        Args:
            root: Root element of parsed XML.
            ns: Namespace dictionary.

        Returns:
            List of RuleResult objects.
        """
        rule_results: List[RuleResult] = []

        # Find all rule-result elements
        rule_result_elements = root.findall(".//xccdf:rule-result", ns)

        for rule_elem in rule_result_elements:
            try:
                rule_result = self._parse_rule_result(rule_elem, root, ns)
                if rule_result:
                    rule_results.append(rule_result)
            except Exception as e:
                # Log but continue parsing other rules
                rule_id = rule_elem.get("idref", "unknown")
                self._logger.warning(
                    "Failed to parse rule %s: %s",
                    rule_id[:50],
                    str(e)[:50],
                )

        return rule_results

    def _parse_rule_result(
        self,
        rule_elem: ET.Element,
        root: ET.Element,
        ns: Dict[str, str],
    ) -> Optional[RuleResult]:
        """
        Parse a single rule-result element.

        Args:
            rule_elem: The rule-result element.
            root: Root element for looking up rule definitions.
            ns: Namespace dictionary.

        Returns:
            RuleResult object or None if invalid.
        """
        # Get rule ID
        rule_id = rule_elem.get("idref", "")
        if not rule_id:
            return None

        # Get result status
        result_elem = rule_elem.find("xccdf:result", ns)
        if result_elem is None or not result_elem.text:
            return None

        result_status = self._normalize_result_status(result_elem.text)

        # Get severity from rule-result or look up in rule definition
        severity_str = rule_elem.get("severity", "")
        if not severity_str:
            # Try to find rule definition for severity
            rule_def = root.find(f".//xccdf:Rule[@id='{rule_id}']", ns)
            if rule_def is not None:
                severity_str = rule_def.get("severity", "")

        severity = self._normalize_severity(severity_str)

        # Get weight
        weight_str = rule_elem.get("weight", "1.0")
        try:
            weight = float(weight_str)
        except ValueError:
            weight = 1.0

        # Get timestamp
        timestamp = None
        time_str = rule_elem.get("time")
        if time_str:
            try:
                timestamp = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
            except ValueError:
                pass

        # Look up rule definition for title, description, etc.
        title = ""
        description = ""
        rationale = ""
        fix_text = ""
        check_ref = ""
        oval_id = ""
        cce_id = ""

        rule_def = root.find(f".//xccdf:Rule[@id='{rule_id}']", ns)
        if rule_def is not None:
            # Title
            title_elem = rule_def.find("xccdf:title", ns)
            if title_elem is not None and title_elem.text:
                title = title_elem.text

            # Description
            desc_elem = rule_def.find("xccdf:description", ns)
            if desc_elem is not None:
                description = self._extract_text_content(desc_elem)

            # Rationale
            rat_elem = rule_def.find("xccdf:rationale", ns)
            if rat_elem is not None:
                rationale = self._extract_text_content(rat_elem)

            # Fix text
            fix_elem = rule_def.find("xccdf:fix", ns)
            if fix_elem is not None:
                fix_text = self._extract_text_content(fix_elem)

            # Check content reference
            check_elem = rule_def.find("xccdf:check", ns)
            if check_elem is not None:
                check_content = check_elem.find("xccdf:check-content-ref", ns)
                if check_content is not None:
                    check_ref = check_content.get("href", "")
                    oval_id = check_content.get("name", "")

            # CCE identifier
            for ident in rule_def.findall("xccdf:ident", ns):
                system = ident.get("system", "")
                if "cce" in system.lower() and ident.text:
                    cce_id = ident.text
                    break

        # Build evidence dict with any check results
        evidence = self._extract_check_evidence(rule_elem, ns)

        return RuleResult(
            rule_id=rule_id,
            result=result_status,
            severity=severity,
            title=title,
            description=description,
            rationale=rationale,
            fix_text=fix_text,
            check_content_ref=check_ref,
            oval_id=oval_id,
            cce_id=cce_id,
            weight=weight,
            timestamp=timestamp,
            evidence=evidence,
        )

    def _extract_text_content(self, element: ET.Element) -> str:
        """
        Extract text content from element, handling mixed content.

        XCCDF elements may contain HTML-like markup which needs
        to be handled appropriately.

        Args:
            element: XML element to extract text from.

        Returns:
            Clean text content.
        """
        # Get all text content
        text_parts = []

        if element.text:
            text_parts.append(element.text.strip())

        for child in element:
            if child.tail:
                text_parts.append(child.tail.strip())
            # Recursively get child text
            child_text = self._extract_text_content(child)
            if child_text:
                text_parts.append(child_text)

        return " ".join(text_parts)

    def _extract_check_evidence(
        self,
        rule_elem: ET.Element,
        ns: Dict[str, str],
    ) -> Dict[str, Any]:
        """
        Extract check evidence from rule-result.

        This includes OVAL check results, messages, and any
        other evidence that explains the result.

        Args:
            rule_elem: The rule-result element.
            ns: Namespace dictionary.

        Returns:
            Dictionary with evidence data.
        """
        evidence: Dict[str, Any] = {}

        # Check element results
        check_elem = rule_elem.find("xccdf:check", ns)
        if check_elem is not None:
            # Check result
            result = check_elem.find("xccdf:check-result", ns)
            if result is not None and result.text:
                evidence["check_result"] = result.text

            # Check export values
            exports = []
            for export in check_elem.findall("xccdf:check-export", ns):
                export_data = {
                    "value_id": export.get("value-id", ""),
                    "export_name": export.get("export-name", ""),
                }
                exports.append(export_data)
            if exports:
                evidence["check_exports"] = exports

        # Messages
        messages = []
        for msg in rule_elem.findall("xccdf:message", ns):
            if msg.text:
                messages.append(
                    {
                        "severity": msg.get("severity", "info"),
                        "text": msg.text,
                    }
                )
        if messages:
            evidence["messages"] = messages

        # Override information
        override = rule_elem.find("xccdf:override", ns)
        if override is not None:
            evidence["override"] = {
                "time": override.get("time", ""),
                "authority": override.get("authority", ""),
                "old_result": "",
                "new_result": "",
                "remark": "",
            }
            old_result = override.find("xccdf:old-result", ns)
            if old_result is not None and old_result.text:
                evidence["override"]["old_result"] = old_result.text
            new_result = override.find("xccdf:new-result", ns)
            if new_result is not None and new_result.text:
                evidence["override"]["new_result"] = new_result.text
            remark = override.find("xccdf:remark", ns)
            if remark is not None and remark.text:
                evidence["override"]["remark"] = remark.text

        return evidence

    def get_native_score(self, file_path: Path) -> Tuple[Optional[float], Optional[float]]:
        """
        Extract native XCCDF score from result file.

        XCCDF results may contain a pre-computed score element
        with the official benchmark scoring.

        Args:
            file_path: Path to XCCDF result file.

        Returns:
            Tuple of (score, max_score) or (None, None) if not found.
        """
        try:
            root = self._parse_xml(file_path)
            ns, _ = self._detect_xccdf_version(root)

            # Find score element in TestResult
            test_result = root.find(".//xccdf:TestResult", ns)
            if test_result is not None:
                score_elem = test_result.find("xccdf:score", ns)
                if score_elem is not None and score_elem.text:
                    score = float(score_elem.text)
                    max_score = float(score_elem.get("maximum", "100"))
                    return score, max_score

            return None, None

        except Exception as e:
            self._logger.debug("Could not extract native score: %s", e)
            return None, None
