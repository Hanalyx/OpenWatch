"""
ARF (Asset Reporting Format) Result Parser

This module provides the ARFResultParser for parsing ARF result files.
ARF is a comprehensive reporting format that contains XCCDF results along
with asset information, OVAL results, and system characteristics.

Key Features:
- ARF 1.1 format support (NIST specification)
- XCCDF result extraction (delegates to XCCDFResultParser)
- Asset and report metadata extraction
- OVAL definition and test result extraction
- System characteristics extraction

ARF Structure:
    ARF files contain multiple report types:
    - Asset reports (system inventory)
    - XCCDF results (compliance findings)
    - OVAL results (detailed check outcomes)
    - System characteristics (collected system data)

Security Notes:
- Uses defused XML parsing to prevent XXE attacks
- File path validation before access
- Large file handling considerations
- Sanitized error messages

Usage:
    from backend.app.services.engine.result_parsers import ARFResultParser

    parser = ARFResultParser()

    if parser.can_parse(result_path):
        results = parser.parse(result_path)
        print(f"Asset: {results.target_info.get('hostname')}")
        print(f"Findings: {results.statistics.fail_count}")
"""

import logging
import time
import xml.etree.ElementTree as ET  # nosec B405  # Used with defused parsing
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Use defusedxml for secure parsing (prevents XXE attacks)
try:
    import defusedxml.ElementTree as DefusedET

    HAS_DEFUSED = True
except ImportError:
    HAS_DEFUSED = False

from .base import BaseResultParser, ParsedResults, ResultStatistics, RuleResult
from .xccdf import XCCDFResultParser

logger = logging.getLogger(__name__)

# ARF and related namespaces
ARF_NAMESPACES = {
    "arf": "http://scap.nist.gov/schema/asset-reporting-format/1.1",
    "ai": "http://scap.nist.gov/schema/asset-identification/1.1",
    "core": "http://scap.nist.gov/schema/reporting-core/1.1",
    "xccdf": "http://checklists.nist.gov/xccdf/1.2",
    "xccdf11": "http://checklists.nist.gov/xccdf/1.1",
    "oval-res": "http://oval.mitre.org/XMLSchema/oval-results-5",
    "oval-sc": "http://oval.mitre.org/XMLSchema/oval-system-characteristics-5",
    "oval-def": "http://oval.mitre.org/XMLSchema/oval-definitions-5",
    "cpe": "http://cpe.mitre.org/language/2.0",
    "cpe-dict": "http://cpe.mitre.org/dictionary/2.0",
}


class ARFResultParser(BaseResultParser):
    """
    Parser for ARF (Asset Reporting Format) scan result files.

    ARF is a comprehensive format that packages XCCDF results with
    asset information, OVAL results, and system characteristics.
    This parser extracts all components and provides unified access.

    The parser delegates XCCDF-specific parsing to XCCDFResultParser
    for consistent rule result extraction.

    Attributes:
        max_file_size: Maximum file size to parse (default 200MB)
        parse_timeout: Timeout for parsing operations (default 120s)
        xccdf_parser: Internal XCCDF parser for rule extraction

    Usage:
        parser = ARFResultParser()
        results = parser.parse(Path("/app/data/results/scan_123_arf.xml"))

        # Access XCCDF results
        for rule in results.rule_results:
            print(f"{rule.rule_id}: {rule.result.value}")

        # Access asset information
        print(f"Host: {results.target_info.get('hostname')}")

        # Access OVAL details in metadata
        oval_results = results.metadata.get('oval_results', {})
    """

    def __init__(
        self,
        max_file_size: int = 200 * 1024 * 1024,  # 200MB (ARF files are larger)
        parse_timeout: int = 120,
    ):
        """
        Initialize the ARF result parser.

        Args:
            max_file_size: Maximum file size to parse in bytes.
            parse_timeout: Timeout for parsing operations in seconds.
        """
        super().__init__(name="ARFResultParser")
        self.max_file_size = max_file_size
        self.parse_timeout = parse_timeout

        # Delegate XCCDF parsing to specialized parser
        self.xccdf_parser = XCCDFResultParser()

        if not HAS_DEFUSED:
            self._logger.warning(
                "defusedxml not available - using standard XML parser. "
                "Install defusedxml for enhanced security."
            )

    @property
    def format_name(self) -> str:
        """Return format identifier."""
        return "arf"

    def can_parse(self, file_path: Path) -> bool:
        """
        Check if this parser can handle the given file.

        Examines file content for ARF markers including:
        - ARF namespace declarations
        - asset-report-collection element
        - Report structure elements

        Args:
            file_path: Path to the result file.

        Returns:
            True if file appears to be ARF format.
        """
        try:
            header = self._read_file_header(file_path)
            header_lower = header.lower()

            # Check for ARF indicators
            arf_markers = [
                "asset-report-collection",
                "asset-reporting-format",
                "<arf:",
                "scap.nist.gov/schema/asset-reporting-format",
            ]

            return any(marker in header_lower for marker in arf_markers)

        except Exception as e:
            self._logger.debug("Cannot determine if ARF: %s", e)
            return False

    def parse(self, file_path: Path) -> ParsedResults:
        """
        Parse ARF result file and return normalized data.

        Extracts:
        - XCCDF results (delegated to XCCDFResultParser)
        - Asset identification information
        - OVAL definition results
        - System characteristics

        Args:
            file_path: Path to the ARF result file.

        Returns:
            ParsedResults containing all extracted data.

        Raises:
            ValueError: If file cannot be parsed as ARF.
            FileNotFoundError: If file does not exist.
        """
        start_time = time.time()

        try:
            # Validate file path
            self.validate_file_path(file_path)

            # Check file size
            file_size = file_path.stat().st_size
            if file_size > self.max_file_size:
                raise ValueError(
                    f"File too large: {file_size} bytes exceeds "
                    f"maximum of {self.max_file_size} bytes"
                )

            # Parse XML
            root = self._parse_xml(file_path)

            # Extract asset information
            asset_info = self._extract_asset_info(root)

            # Extract report metadata
            report_metadata = self._extract_report_metadata(root)

            # Find and parse XCCDF results
            rule_results, xccdf_metadata = self._extract_xccdf_results(root)

            # Extract OVAL results (for additional evidence)
            oval_results = self._extract_oval_results(root)

            # Calculate statistics
            statistics = ResultStatistics.from_rule_results(rule_results)

            # Combine target info from asset and XCCDF
            target_info = asset_info.copy()
            if xccdf_metadata.get("target_info"):
                target_info.update(xccdf_metadata["target_info"])

            # Build parsed results
            duration_ms = (time.time() - start_time) * 1000
            results = ParsedResults(
                format_type=self.format_name,
                source_file=str(file_path),
                parse_timestamp=datetime.utcnow(),
                benchmark_id=xccdf_metadata.get("benchmark_id", ""),
                profile_id=xccdf_metadata.get("profile_id", ""),
                target_info=target_info,
                scan_start=xccdf_metadata.get("scan_start"),
                scan_end=xccdf_metadata.get("scan_end"),
                rule_results=rule_results,
                statistics=statistics,
                metadata={
                    "arf_version": "1.1",
                    "file_size": file_size,
                    "parse_duration_ms": duration_ms,
                    "report_metadata": report_metadata,
                    "oval_results": oval_results,
                    "xccdf_metadata": xccdf_metadata,
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
            self._logger.error("ARF parse error: %s", str(e)[:200])
            raise ValueError(f"Failed to parse ARF: {str(e)[:100]}")

    def _parse_xml(self, file_path: Path) -> ET.Element:
        """
        Parse XML file with security protections.

        Args:
            file_path: Path to XML file.

        Returns:
            Root element of parsed XML.

        Raises:
            ValueError: If XML cannot be parsed.
        """
        try:
            if HAS_DEFUSED:
                tree = DefusedET.parse(str(file_path))
            else:
                tree = ET.parse(str(file_path))  # nosec B314

            return tree.getroot()

        except ET.ParseError as e:
            raise ValueError(f"Invalid XML: {str(e)[:100]}")
        except Exception as e:
            raise ValueError(f"XML parse error: {str(e)[:100]}")

    def _extract_asset_info(self, root: ET.Element) -> Dict[str, Any]:
        """
        Extract asset identification information from ARF.

        Args:
            root: Root element of parsed XML.

        Returns:
            Dictionary with asset information.
        """
        asset_info: Dict[str, Any] = {}
        ns = ARF_NAMESPACES

        try:
            # Find asset element
            assets = root.findall(".//ai:asset", ns)

            for asset in assets:
                # Asset ID
                asset_id = asset.get("id", "")
                if asset_id:
                    asset_info["asset_id"] = asset_id

                # Computing device info
                computing_device = asset.find("ai:computing-device", ns)
                if computing_device is not None:
                    # Hostname
                    hostname = computing_device.find("ai:hostname", ns)
                    if hostname is not None and hostname.text:
                        asset_info["hostname"] = hostname.text

                    # FQDN
                    fqdn = computing_device.find("ai:fqdn", ns)
                    if fqdn is not None and fqdn.text:
                        asset_info["fqdn"] = fqdn.text

                    # IP addresses
                    ips = []
                    for conn in computing_device.findall(".//ai:ip-address", ns):
                        ip_v4 = conn.find("ai:ip-v4", ns)
                        if ip_v4 is not None and ip_v4.text:
                            ips.append(ip_v4.text)
                        ip_v6 = conn.find("ai:ip-v6", ns)
                        if ip_v6 is not None and ip_v6.text:
                            ips.append(ip_v6.text)
                    if ips:
                        asset_info["ip_addresses"] = ips
                        asset_info["ip_address"] = ips[0]  # Primary IP

                    # MAC addresses
                    macs = []
                    for conn in computing_device.findall(".//ai:mac-address", ns):
                        if conn.text:
                            macs.append(conn.text)
                    if macs:
                        asset_info["mac_addresses"] = macs

                # CPE references
                cpes = []
                for cpe in asset.findall(".//ai:cpe", ns):
                    if cpe.text:
                        cpes.append(cpe.text)
                if cpes:
                    asset_info["cpe_references"] = cpes

        except Exception as e:
            self._logger.debug("Error extracting asset info: %s", e)

        return asset_info

    def _extract_report_metadata(self, root: ET.Element) -> Dict[str, Any]:
        """
        Extract report-level metadata from ARF.

        Args:
            root: Root element of parsed XML.

        Returns:
            Dictionary with report metadata.
        """
        metadata: Dict[str, Any] = {}
        ns = ARF_NAMESPACES

        try:
            # Find reports element
            reports = root.find("arf:reports", ns)
            if reports is not None:
                report_list = []
                for report in reports.findall("arf:report", ns):
                    report_info = {
                        "id": report.get("id", ""),
                    }

                    # Report request reference
                    request_ref = report.find("arf:report-request-ref", ns)
                    if request_ref is not None:
                        report_info["request_ref"] = request_ref.get("idref", "")

                    report_list.append(report_info)

                metadata["reports"] = report_list
                metadata["report_count"] = len(report_list)

            # Find report requests
            requests = root.find("arf:report-requests", ns)
            if requests is not None:
                metadata["request_count"] = len(requests.findall("arf:report-request", ns))

        except Exception as e:
            self._logger.debug("Error extracting report metadata: %s", e)

        return metadata

    def _extract_xccdf_results(self, root: ET.Element) -> Tuple[List[RuleResult], Dict[str, Any]]:
        """
        Extract XCCDF results from ARF.

        Finds the embedded XCCDF TestResult and extracts rule results.

        Args:
            root: Root element of parsed XML.

        Returns:
            Tuple of (rule_results list, xccdf_metadata dict).
        """
        rule_results: List[RuleResult] = []
        xccdf_metadata: Dict[str, Any] = {}
        ns = ARF_NAMESPACES

        try:
            # Find XCCDF TestResult within ARF reports
            # Try multiple namespace prefixes for compatibility
            test_result = None

            # Search paths for XCCDF results in ARF
            search_paths = [
                ".//xccdf:TestResult",
                ".//xccdf11:TestResult",
                ".//TestResult",
                ".//arf:report/arf:content//xccdf:TestResult",
            ]

            for path in search_paths:
                try:
                    test_result = root.find(path, ns)
                    if test_result is not None:
                        break
                except Exception:
                    continue

            if test_result is None:
                self._logger.warning("No XCCDF TestResult found in ARF")
                return rule_results, xccdf_metadata

            # Determine XCCDF namespace from TestResult
            xccdf_ns = self._detect_xccdf_namespace(test_result)

            # Extract benchmark and profile info
            xccdf_metadata["benchmark_id"] = self._find_benchmark_id(root, xccdf_ns)

            profile_elem = test_result.find(f"{{{xccdf_ns}}}profile", None)
            if profile_elem is not None:
                xccdf_metadata["profile_id"] = profile_elem.get("idref", "")

            # Extract timing
            start_str = test_result.get("start-time")
            if start_str:
                try:
                    xccdf_metadata["scan_start"] = datetime.fromisoformat(
                        start_str.replace("Z", "+00:00")
                    )
                except ValueError:
                    pass

            end_str = test_result.get("end-time")
            if end_str:
                try:
                    xccdf_metadata["scan_end"] = datetime.fromisoformat(
                        end_str.replace("Z", "+00:00")
                    )
                except ValueError:
                    pass

            # Extract target info
            target_info: Dict[str, Any] = {}
            target = test_result.find(f"{{{xccdf_ns}}}target", None)
            if target is not None and target.text:
                target_info["hostname"] = target.text

            target_addr = test_result.find(f"{{{xccdf_ns}}}target-address", None)
            if target_addr is not None and target_addr.text:
                target_info["ip_address"] = target_addr.text

            xccdf_metadata["target_info"] = target_info

            # Extract rule results
            rule_results = self._parse_xccdf_rule_results(test_result, root, xccdf_ns)

        except Exception as e:
            self._logger.error("Error extracting XCCDF from ARF: %s", e)

        return rule_results, xccdf_metadata

    def _detect_xccdf_namespace(self, element: ET.Element) -> str:
        """
        Detect XCCDF namespace from element tag.

        Args:
            element: XML element to examine.

        Returns:
            XCCDF namespace URI.
        """
        tag = element.tag
        if tag.startswith("{"):
            return tag[1 : tag.index("}")]
        return ARF_NAMESPACES["xccdf"]  # Default

    def _find_benchmark_id(self, root: ET.Element, xccdf_ns: str) -> str:
        """
        Find benchmark ID in ARF document.

        Args:
            root: Root element.
            xccdf_ns: XCCDF namespace URI.

        Returns:
            Benchmark ID or empty string.
        """
        try:
            benchmark = root.find(f".//{{{xccdf_ns}}}Benchmark", None)
            if benchmark is not None:
                return benchmark.get("id", "")
        except Exception:
            pass
        return ""

    def _parse_xccdf_rule_results(
        self,
        test_result: ET.Element,
        root: ET.Element,
        xccdf_ns: str,
    ) -> List[RuleResult]:
        """
        Parse rule-result elements from XCCDF TestResult.

        Args:
            test_result: TestResult element.
            root: Root element for rule lookups.
            xccdf_ns: XCCDF namespace URI.

        Returns:
            List of RuleResult objects.
        """
        rule_results: List[RuleResult] = []

        # Find all rule-result elements
        rule_result_elements = test_result.findall(f"{{{xccdf_ns}}}rule-result", None)

        for rule_elem in rule_result_elements:
            try:
                rule_id = rule_elem.get("idref", "")
                if not rule_id:
                    continue

                # Get result status
                result_elem = rule_elem.find(f"{{{xccdf_ns}}}result", None)
                if result_elem is None or not result_elem.text:
                    continue

                result_status = self._normalize_result_status(result_elem.text)

                # Get severity
                severity_str = rule_elem.get("severity", "")
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

                # Try to find rule definition for additional info
                title = ""
                rule_def = root.find(f".//{{{xccdf_ns}}}Rule[@id='{rule_id}']", None)
                if rule_def is not None:
                    title_elem = rule_def.find(f"{{{xccdf_ns}}}title", None)
                    if title_elem is not None and title_elem.text:
                        title = title_elem.text

                rule_result = RuleResult(
                    rule_id=rule_id,
                    result=result_status,
                    severity=severity,
                    title=title,
                    weight=weight,
                    timestamp=timestamp,
                )

                rule_results.append(rule_result)

            except Exception as e:
                rule_id = rule_elem.get("idref", "unknown")
                self._logger.warning(
                    "Failed to parse rule %s: %s",
                    rule_id[:50],
                    str(e)[:50],
                )

        return rule_results

    def _extract_oval_results(self, root: ET.Element) -> Dict[str, Any]:
        """
        Extract OVAL results from ARF.

        OVAL results provide detailed check outcomes including
        the actual values found on the system.

        Args:
            root: Root element of parsed XML.

        Returns:
            Dictionary with OVAL result summary.
        """
        oval_results: Dict[str, Any] = {}
        ns = ARF_NAMESPACES

        try:
            # Find OVAL results
            oval_results_elem = root.find(".//oval-res:oval_results", ns)

            if oval_results_elem is not None:
                # Count definitions by result
                def_results: Dict[str, int] = {}
                definitions = oval_results_elem.findall(".//oval-res:definition", ns)

                for defn in definitions:
                    result = defn.get("result", "unknown")
                    def_results[result] = def_results.get(result, 0) + 1

                oval_results["definition_results"] = def_results
                oval_results["total_definitions"] = len(definitions)

                # Get generator info
                generator = oval_results_elem.find("oval-res:generator", ns)
                if generator is not None:
                    product = generator.find("oval-res:product_name", ns)
                    if product is not None and product.text:
                        oval_results["generator"] = product.text

        except Exception as e:
            self._logger.debug("Error extracting OVAL results: %s", e)

        return oval_results

    def get_system_characteristics(self, file_path: Path) -> Dict[str, Any]:
        """
        Extract OVAL system characteristics from ARF file.

        System characteristics contain the actual data collected
        from the target system during the scan.

        Args:
            file_path: Path to ARF file.

        Returns:
            Dictionary with system characteristics data.
        """
        characteristics: Dict[str, Any] = {}

        try:
            root = self._parse_xml(file_path)
            ns = ARF_NAMESPACES

            # Find system characteristics
            sys_char = root.find(".//oval-sc:oval_system_characteristics", ns)

            if sys_char is not None:
                # System info
                sys_info = sys_char.find("oval-sc:system_info", ns)
                if sys_info is not None:
                    os_name = sys_info.find("oval-sc:os_name", ns)
                    if os_name is not None and os_name.text:
                        characteristics["os_name"] = os_name.text

                    os_version = sys_info.find("oval-sc:os_version", ns)
                    if os_version is not None and os_version.text:
                        characteristics["os_version"] = os_version.text

                    arch = sys_info.find("oval-sc:architecture", ns)
                    if arch is not None and arch.text:
                        characteristics["architecture"] = arch.text

                    hostname = sys_info.find("oval-sc:primary_host_name", ns)
                    if hostname is not None and hostname.text:
                        characteristics["hostname"] = hostname.text

                # Count collected objects
                collected = sys_char.find("oval-sc:collected_objects", ns)
                if collected is not None:
                    objects = collected.findall("oval-sc:object", ns)
                    characteristics["collected_objects"] = len(objects)

                    # Flag summary
                    flags: Dict[str, int] = {}
                    for obj in objects:
                        flag = obj.get("flag", "unknown")
                        flags[flag] = flags.get(flag, 0) + 1
                    characteristics["object_flags"] = flags

        except Exception as e:
            self._logger.debug("Error extracting system characteristics: %s", e)

        return characteristics
