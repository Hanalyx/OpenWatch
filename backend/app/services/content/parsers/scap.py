"""
SCAP Content Parser for OpenWatch

This module provides parsing for SCAP (Security Content Automation Protocol)
content files including XCCDF benchmarks and standalone XCCDF files. It extracts
compliance rules, profiles, and metadata into the normalized ParsedContent format.

Supported Formats:
- XCCDF 1.2 benchmark files
- Standalone XCCDF rule files

Note: SCAP 1.3 datastreams (bundled format) are handled by the DatastreamParser.
This parser focuses on XCCDF content extraction and normalization.

Security Considerations:
- XXE prevention: Uses defusedxml or lxml with secure settings
- File size limits: 100MB maximum (inherited from BaseContentParser)
- Path traversal prevention: All paths resolved before access
- Input validation: All extracted values sanitized

Usage:
    from backend.app.services.content.parsers.scap import SCAPParser

    parser = SCAPParser()
    content = parser.parse("/path/to/benchmark.xml")
    print(f"Parsed {content.rule_count} rules")
"""

import hashlib
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Security: Use defusedxml for XXE prevention if available, fallback to lxml
try:
    import defusedxml.ElementTree as ET

    USING_DEFUSED_XML = True
except ImportError:
    # Fallback to lxml with secure settings
    from lxml import etree as ET

    USING_DEFUSED_XML = False

from ..exceptions import ContentParseError
from ..models import ContentFormat, ContentSeverity, ParsedContent, ParsedProfile, ParsedRule
from . import register_parser
from .base import BaseContentParser

logger = logging.getLogger(__name__)


# XML namespaces used in SCAP/XCCDF files
# These are standardized by NIST and are required for proper element resolution
XCCDF_NAMESPACES: Dict[str, str] = {
    "ds": "http://scap.nist.gov/schema/scap/source/1.2",
    "xccdf": "http://checklists.nist.gov/xccdf/1.2",
    "xccdf-1.2": "http://checklists.nist.gov/xccdf/1.2",
    "oval": "http://oval.mitre.org/XMLSchema/oval-common-5",
    "oval-def": "http://oval.mitre.org/XMLSchema/oval-definitions-5",
    "cpe-dict": "http://cpe.mitre.org/dictionary/2.0",
    "dc": "http://purl.org/dc/elements/1.1/",
    "xlink": "http://www.w3.org/1999/xlink",
    "html": "http://www.w3.org/1999/xhtml",
}


# Framework reference patterns for extracting compliance framework mappings
# These patterns help categorize references into standard frameworks
FRAMEWORK_PATTERNS: Dict[str, Dict[str, Any]] = {
    "nist": {
        "pattern": r"NIST-800-53|NIST.*800-53",
        "version_patterns": {
            "800-53r4": r"NIST.*800-53.*r4|NIST.*800-53.*Revision 4",
            "800-53r5": r"NIST.*800-53.*r5|NIST.*800-53.*Revision 5",
        },
    },
    "cis": {
        "pattern": r"CIS",
        "version_extraction": r"CIS.*v?(\d+\.\d+(?:\.\d+)?)",
    },
    "stig": {
        "pattern": r"DISA.*STIG|stigid",
        "id_extraction": r"([A-Z]+-\d+-\d+)",
    },
    "pci_dss": {
        "pattern": r"PCI.*DSS",
        "version_extraction": r"PCI.*DSS.*v?(\d+\.\d+(?:\.\d+)?)",
    },
    "hipaa": {
        "pattern": r"HIPAA",
        "section_extraction": r"§?\s*(\d+\.\d+)",
    },
    "iso27001": {
        "pattern": r"ISO.*27001",
        "control_extraction": r"(\d+\.\d+\.\d+)",
    },
}


# Category patterns for automatic rule categorization based on content
# These keywords help classify rules into logical security categories
CATEGORY_PATTERNS: Dict[str, List[str]] = {
    "authentication": ["auth", "login", "password", "pam", "sudo", "su"],
    "access_control": ["permission", "ownership", "acl", "rbac", "selinux"],
    "audit": ["audit", "log", "rsyslog", "journald"],
    "network": ["firewall", "iptables", "tcp", "udp", "port", "network"],
    "crypto": ["crypto", "encrypt", "certificate", "tls", "ssl", "key"],
    "kernel": ["kernel", "sysctl", "module", "grub"],
    "service": ["service", "daemon", "systemd", "xinetd"],
    "filesystem": ["mount", "partition", "filesystem", "disk"],
    "package": ["package", "rpm", "yum", "dnf", "update"],
    "system": ["system", "boot", "init", "cron"],
}


# Tag patterns for extracting semantic tags from rule content
TAG_PATTERNS: Dict[str, str] = {
    "ssh": r"\bssh\b|openssh",
    "audit": r"\baudit\b|auditd",
    "firewall": r"\bfirewall\b|iptables|firewalld",
    "selinux": r"\bselinux\b",
    "kernel": r"\bkernel\b|sysctl",
    "authentication": r"\bauth\b|authentication|login|password",
    "crypto": r"\bcrypto\b|encryption|certificate|tls|ssl",
    "network": r"\bnetwork\b|tcp|udp|port",
    "filesystem": r"\bfile\b|filesystem|permission|ownership",
    "service": r"\bservice\b|daemon|systemd",
}


# Security function mapping for high-level categorization
SECURITY_FUNCTION_MAP: Dict[str, str] = {
    "authentication": "identity_management",
    "access_control": "access_management",
    "audit": "security_monitoring",
    "network": "network_protection",
    "crypto": "data_encryption",
    "kernel": "system_hardening",
    "service": "service_management",
    "filesystem": "data_protection",
    "package": "vulnerability_management",
    "system": "system_configuration",
}


@register_parser
class SCAPParser(BaseContentParser):
    """
    Parser for SCAP/XCCDF compliance content.

    This parser handles XCCDF benchmark files and extracts:
    - Compliance rules with full metadata
    - Profiles (collections of selected rules)
    - Framework mappings (NIST, CIS, STIG, etc.)
    - Check content (OVAL references)
    - Fix/remediation content

    The parser produces normalized ParsedContent objects that can be
    transformed and imported into MongoDB by downstream components.

    Attributes:
        rules_parsed: Counter for successfully parsed rules
        errors: List of parsing errors encountered
        warnings: List of non-fatal warnings

    Example:
        >>> parser = SCAPParser()
        >>> content = parser.parse("/app/data/scap/ssg-rhel8-xccdf.xml")
        >>> print(f"Rules: {content.rule_count}, Profiles: {content.profile_count}")
    """

    def __init__(self) -> None:
        """
        Initialize SCAP Parser.

        Initializes counters and error/warning lists for tracking
        parsing progress and issues.
        """
        super().__init__()
        self.rules_parsed: int = 0
        self.errors: List[Dict[str, Any]] = []
        self.warnings: List[str] = []
        # Profile-to-rules mapping populated during parsing
        self._profile_rules: Dict[str, List[str]] = {}

    @property
    def supported_formats(self) -> List[ContentFormat]:
        """
        Return list of content formats this parser supports.

        Returns:
            List containing XCCDF format (SCAP datastreams handled separately).
        """
        return [ContentFormat.XCCDF]

    def _parse_file_impl(
        self,
        file_path: Path,
        content_format: ContentFormat,
    ) -> ParsedContent:
        """
        Parse XCCDF content from a file.

        This is the main parsing implementation for file sources. It reads
        the XML file, extracts the benchmark, and parses all rules and profiles.

        Args:
            file_path: Path to the XCCDF file.
            content_format: The content format (XCCDF).

        Returns:
            ParsedContent with all extracted rules, profiles, and metadata.

        Raises:
            ContentParseError: If parsing fails.
        """
        # Reset state for this parse operation
        self._reset_state()

        try:
            # Calculate file hash for integrity tracking
            file_hash = self._calculate_file_hash(file_path)

            # Parse XML securely
            root = self._parse_xml_file(file_path)

            # Find the Benchmark element
            benchmark = self._find_benchmark(root)
            if benchmark is None:
                raise ContentParseError(
                    message="No Benchmark element found in XCCDF file",
                    source_file=str(file_path),
                    details={"hint": "File may not be a valid XCCDF benchmark"},
                )

            # Extract profiles first to build rule membership mapping
            profiles = self._parse_all_profiles(benchmark)

            # Extract all rules
            rules = self._parse_all_rules(benchmark)

            # Extract benchmark metadata
            metadata = self._extract_benchmark_metadata(benchmark)
            metadata["file_hash"] = file_hash
            metadata["parsed_at"] = datetime.utcnow().isoformat()

            # Build the ParsedContent result
            return ParsedContent(
                format=content_format,
                rules=rules,
                profiles=profiles,
                oval_definitions=[],  # OVAL extracted separately if needed
                metadata=metadata,
                source_file=str(file_path),
                parse_warnings=self.warnings.copy(),
            )

        except ContentParseError:
            raise
        except Exception as e:
            logger.error("Failed to parse XCCDF file %s: %s", file_path, str(e))
            raise ContentParseError(
                message=f"Failed to parse XCCDF file: {str(e)}",
                source_file=str(file_path),
                details={"error_type": type(e).__name__},
            ) from e

    def _parse_bytes_impl(
        self,
        content_bytes: bytes,
        content_format: ContentFormat,
    ) -> ParsedContent:
        """
        Parse XCCDF content from raw bytes.

        Args:
            content_bytes: Raw XML bytes.
            content_format: The content format (XCCDF).

        Returns:
            ParsedContent with all extracted rules, profiles, and metadata.

        Raises:
            ContentParseError: If parsing fails.
        """
        # Reset state for this parse operation
        self._reset_state()

        try:
            # Calculate content hash
            content_hash = hashlib.sha256(content_bytes).hexdigest()

            # Parse XML from bytes
            root = self._parse_xml_bytes(content_bytes)

            # Find the Benchmark element
            benchmark = self._find_benchmark(root)
            if benchmark is None:
                raise ContentParseError(
                    message="No Benchmark element found in XCCDF content",
                    details={"hint": "Content may not be a valid XCCDF benchmark"},
                )

            # Extract profiles first
            profiles = self._parse_all_profiles(benchmark)

            # Extract all rules
            rules = self._parse_all_rules(benchmark)

            # Extract metadata
            metadata = self._extract_benchmark_metadata(benchmark)
            metadata["content_hash"] = content_hash
            metadata["parsed_at"] = datetime.utcnow().isoformat()

            return ParsedContent(
                format=content_format,
                rules=rules,
                profiles=profiles,
                oval_definitions=[],
                metadata=metadata,
                parse_warnings=self.warnings.copy(),
            )

        except ContentParseError:
            raise
        except Exception as e:
            logger.error("Failed to parse XCCDF bytes: %s", str(e))
            raise ContentParseError(
                message=f"Failed to parse XCCDF content: {str(e)}",
                details={"error_type": type(e).__name__},
            ) from e

    def _reset_state(self) -> None:
        """Reset parser state for a new parse operation."""
        self.rules_parsed = 0
        self.errors.clear()
        self.warnings.clear()
        self._profile_rules.clear()

    def _calculate_file_hash(self, file_path: Path) -> str:
        """
        Calculate SHA-256 hash of a file.

        Uses chunked reading to handle large files efficiently.

        Args:
            file_path: Path to the file.

        Returns:
            Hexadecimal SHA-256 hash string.
        """
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            # Read in 4KB chunks for memory efficiency
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _parse_xml_file(self, file_path: Path) -> Any:
        """
        Parse XML file with security measures.

        Uses defusedxml if available, otherwise lxml with XXE prevention.

        Args:
            file_path: Path to the XML file.

        Returns:
            Parsed XML root element.

        Raises:
            ContentParseError: If XML parsing fails.
        """
        try:
            if USING_DEFUSED_XML:
                tree = ET.parse(str(file_path))
                return tree.getroot()
            else:
                # lxml with secure settings
                parser = ET.XMLParser(
                    resolve_entities=False,
                    no_network=True,
                    remove_pis=True,
                    huge_tree=False,  # Prevent billion laughs attack
                )
                tree = ET.parse(str(file_path), parser)
                return tree.getroot()
        except Exception as e:
            raise ContentParseError(
                message=f"XML parsing failed: {str(e)}",
                source_file=str(file_path),
                details={"parser": "defusedxml" if USING_DEFUSED_XML else "lxml"},
            ) from e

    def _parse_xml_bytes(self, content_bytes: bytes) -> Any:
        """
        Parse XML from bytes with security measures.

        Args:
            content_bytes: Raw XML bytes.

        Returns:
            Parsed XML root element.

        Raises:
            ContentParseError: If XML parsing fails.
        """
        try:
            if USING_DEFUSED_XML:
                return ET.fromstring(content_bytes)
            else:
                parser = ET.XMLParser(
                    resolve_entities=False,
                    no_network=True,
                    remove_pis=True,
                    huge_tree=False,
                )
                return ET.fromstring(content_bytes, parser)
        except Exception as e:
            raise ContentParseError(
                message=f"XML parsing failed: {str(e)}",
                details={"parser": "defusedxml" if USING_DEFUSED_XML else "lxml"},
            ) from e

    def _find_benchmark(self, root: Any) -> Optional[Any]:
        """
        Find the Benchmark element in the XML document.

        Tries multiple namespace variants to handle different XCCDF versions.

        Args:
            root: XML root element.

        Returns:
            Benchmark element or None if not found.
        """
        # Try XCCDF 1.2 namespace first (most common)
        benchmark = root.find(".//xccdf-1.2:Benchmark", XCCDF_NAMESPACES)
        if benchmark is not None:
            return benchmark

        # Try alternative XCCDF namespace
        benchmark = root.find(".//xccdf:Benchmark", XCCDF_NAMESPACES)
        if benchmark is not None:
            return benchmark

        # Try without namespace (some files don't use namespaces)
        for elem in root.iter():
            if elem.tag.endswith("Benchmark"):
                return elem

        return None

    def _extract_benchmark_metadata(self, benchmark: Any) -> Dict[str, Any]:
        """
        Extract metadata from the Benchmark element.

        Args:
            benchmark: The Benchmark XML element.

        Returns:
            Dictionary containing benchmark metadata.
        """
        metadata: Dict[str, Any] = {
            "id": benchmark.get("id", "unknown"),
            "resolved": benchmark.get("resolved", "false") == "true",
            "style": benchmark.get("style"),
            "lang": benchmark.get("{http://www.w3.org/XML/1998/namespace}lang", "en-US"),
        }

        # Extract title
        title = self._find_element(benchmark, "title")
        if title is not None:
            metadata["title"] = self._extract_text_content(title)

        # Extract description
        desc = self._find_element(benchmark, "description")
        if desc is not None:
            metadata["description"] = self._extract_text_content(desc)

        # Extract version
        version = self._find_element(benchmark, "version")
        if version is not None:
            metadata["version"] = version.text

        # Extract status
        status = self._find_element(benchmark, "status")
        if status is not None:
            metadata["status"] = status.text
            metadata["status_date"] = status.get("date")

        return metadata

    def _parse_all_profiles(self, benchmark: Any) -> List[ParsedProfile]:
        """
        Parse all Profile elements from the benchmark.

        Also builds the internal profile-to-rules mapping for later use.

        Args:
            benchmark: The Benchmark XML element.

        Returns:
            List of ParsedProfile objects.
        """
        profiles: List[ParsedProfile] = []

        # Find all Profile elements
        profile_elements = benchmark.findall(".//xccdf-1.2:Profile", XCCDF_NAMESPACES)
        if not profile_elements:
            profile_elements = benchmark.findall(".//xccdf:Profile", XCCDF_NAMESPACES)

        logger.debug("Found %d profile elements", len(profile_elements))

        for profile_elem in profile_elements:
            try:
                profile = self._parse_profile(profile_elem)
                if profile:
                    profiles.append(profile)
                    # Build mapping for rule profile membership
                    self._profile_rules[profile.profile_id] = list(profile.selected_rules)
            except Exception as e:
                profile_id = profile_elem.get("id", "unknown")
                logger.warning("Failed to parse profile %s: %s", profile_id, str(e))
                self.warnings.append(f"Failed to parse profile {profile_id}: {str(e)}")

        return profiles

    def _parse_profile(self, profile_elem: Any) -> Optional[ParsedProfile]:
        """
        Parse a single Profile element.

        Args:
            profile_elem: The Profile XML element.

        Returns:
            ParsedProfile object or None if parsing fails.
        """
        profile_id = profile_elem.get("id", "")
        if not profile_id:
            return None

        # Extract title
        title_elem = self._find_element(profile_elem, "title")
        title = self._extract_text_content(title_elem) if title_elem is not None else profile_id

        # Extract description
        desc_elem = self._find_element(profile_elem, "description")
        description = self._extract_text_content(desc_elem) if desc_elem is not None else ""

        # Extract selected rules
        selected_rules: List[str] = []
        for select in profile_elem.findall(".//xccdf-1.2:select", XCCDF_NAMESPACES):
            if select.get("selected", "true").lower() == "true":
                rule_idref = select.get("idref", "")
                if rule_idref:
                    selected_rules.append(rule_idref)

        # Check for extended profile
        extends = profile_elem.get("extends")

        return ParsedProfile(
            profile_id=profile_id,
            title=title,
            description=description,
            selected_rules=selected_rules,
            extends=extends,
            metadata={
                "abstract": profile_elem.get("abstract", "false") == "true",
                "prohibit_changes": profile_elem.get("prohibitChanges", "false") == "true",
            },
        )

    def _parse_all_rules(self, benchmark: Any) -> List[ParsedRule]:
        """
        Parse all Rule elements from the benchmark.

        Args:
            benchmark: The Benchmark XML element.

        Returns:
            List of ParsedRule objects.
        """
        rules: List[ParsedRule] = []

        # Find all Rule elements
        rule_elements = benchmark.findall(".//xccdf-1.2:Rule", XCCDF_NAMESPACES)
        if not rule_elements:
            rule_elements = benchmark.findall(".//xccdf:Rule", XCCDF_NAMESPACES)

        logger.info("Found %d rule elements to parse", len(rule_elements))

        for rule_elem in rule_elements:
            try:
                rule = self._parse_rule(rule_elem)
                if rule:
                    rules.append(rule)
                    self.rules_parsed += 1
            except Exception as e:
                rule_id = rule_elem.get("id", "unknown")
                logger.error("Failed to parse rule %s: %s", rule_id, str(e))
                self.errors.append({"rule_id": rule_id, "error": str(e)})

        return rules

    def _parse_rule(self, rule_elem: Any) -> Optional[ParsedRule]:
        """
        Parse a single Rule element into a ParsedRule object.

        Extracts all rule metadata including title, description, severity,
        references, check content, and fix content.

        Args:
            rule_elem: The Rule XML element.

        Returns:
            ParsedRule object or None if rule_id is missing.
        """
        rule_id = rule_elem.get("id", "")
        if not rule_id:
            return None

        # Extract severity and normalize to ContentSeverity
        severity_str = rule_elem.get("severity", "unknown").lower()
        severity = self._normalize_severity(severity_str)

        # Extract text elements
        title = self._get_element_text(rule_elem, "title") or rule_id
        description = self._get_element_text(rule_elem, "description") or ""
        rationale = self._get_element_text(rule_elem, "rationale") or ""

        # Extract references
        references = self._extract_references(rule_elem)

        # Extract platforms
        platforms = self._extract_platforms(rule_elem)

        # Extract check and fix content
        check_content = self._extract_check_content(rule_elem)
        fix_content = self._extract_fix_content(rule_elem)

        # Determine category and tags
        category = self._determine_category(rule_id, title, description)
        tags = self._extract_tags(title, description)

        # Get profile membership
        profile_membership = self._get_profile_membership(rule_id)

        # Build metadata dictionary
        metadata: Dict[str, Any] = {
            "selected": rule_elem.get("selected", "true") == "true",
            "weight": float(rule_elem.get("weight", "1.0")),
            "category": category,
            "security_function": SECURITY_FUNCTION_MAP.get(category, "system_configuration"),
            "warning": self._get_element_text(rule_elem, "warning"),
            "check": check_content,
            "fix": fix_content,
            "profiles": profile_membership,
            "tags": tags,
            "frameworks": self._map_to_frameworks(references),
            "identifiers": self._extract_identifiers(rule_elem),
            "complex_check": self._extract_complex_check(rule_elem),
        }

        return ParsedRule(
            rule_id=rule_id,
            title=title,
            description=description,
            severity=severity,
            rationale=rationale,
            check_content=check_content.get("content", {}).get("name", ""),
            fix_content=fix_content.get("fixes", [{}])[0].get("content", "") if fix_content.get("fixes") else "",
            references=references,
            platforms=platforms,
            metadata=metadata,
        )

    def _normalize_severity(self, severity_str: str) -> ContentSeverity:
        """
        Normalize severity string to ContentSeverity enum.

        Args:
            severity_str: Severity string from XCCDF (high, medium, low, etc.)

        Returns:
            Corresponding ContentSeverity value.
        """
        severity_map = {
            "critical": ContentSeverity.CRITICAL,
            "high": ContentSeverity.HIGH,
            "medium": ContentSeverity.MEDIUM,
            "low": ContentSeverity.LOW,
            "info": ContentSeverity.INFO,
            "informational": ContentSeverity.INFO,
        }
        return severity_map.get(severity_str, ContentSeverity.UNKNOWN)

    def _find_element(self, parent: Any, tag: str) -> Optional[Any]:
        """
        Find a child element by tag name, trying multiple namespaces.

        Args:
            parent: Parent XML element.
            tag: Tag name to find.

        Returns:
            Found element or None.
        """
        # Try XCCDF 1.2 namespace
        elem = parent.find(f".//xccdf-1.2:{tag}", XCCDF_NAMESPACES)
        if elem is not None:
            return elem

        # Try alternative XCCDF namespace
        elem = parent.find(f".//xccdf:{tag}", XCCDF_NAMESPACES)
        if elem is not None:
            return elem

        # Try without namespace
        return parent.find(f".//{tag}")

    def _get_element_text(self, parent: Any, tag: str) -> Optional[str]:
        """
        Get text content from a child element.

        Args:
            parent: Parent XML element.
            tag: Tag name to find.

        Returns:
            Text content or None.
        """
        elem = self._find_element(parent, tag)
        if elem is not None:
            return self._extract_text_content(elem)
        return None

    def _extract_text_content(self, elem: Any) -> str:
        """
        Extract text content from an element, including nested HTML.

        Handles common XCCDF HTML elements like <br/>, <code>, <em>, <strong>.

        Args:
            elem: XML element.

        Returns:
            Extracted text content with basic markdown formatting.
        """
        if elem is None:
            return ""

        text = elem.text or ""

        # Process child elements (HTML content)
        for child in elem:
            tag_name = child.tag.split("}")[-1] if "}" in child.tag else child.tag

            if tag_name == "br":
                text += "\n"
            elif tag_name == "code":
                text += f"`{child.text or ''}`"
            elif tag_name == "em":
                text += f"_{child.text or ''}_"
            elif tag_name == "strong":
                text += f"**{child.text or ''}**"
            else:
                text += child.text or ""

            text += child.tail or ""

        return text.strip()

    def _extract_references(self, rule_elem: Any) -> Dict[str, List[str]]:
        """
        Extract and categorize references from a rule.

        References are categorized by framework (NIST, CIS, STIG, etc.)
        for easier framework mapping.

        Args:
            rule_elem: Rule XML element.

        Returns:
            Dictionary mapping framework names to lists of reference strings.
        """
        references: Dict[str, List[str]] = {}

        for ref in rule_elem.findall(".//xccdf-1.2:reference", XCCDF_NAMESPACES):
            ref_text = ref.text or ""
            href = ref.get("href", "")
            combined = f"{ref_text} {href}".lower()

            # Categorize by framework
            if "nist" in combined:
                framework = "nist"
            elif "cis" in combined:
                framework = "cis"
            elif "stig" in combined or "disa" in combined:
                framework = "stig"
            elif "pci" in combined:
                framework = "pci_dss"
            elif "hipaa" in combined:
                framework = "hipaa"
            elif "iso" in combined and "27001" in combined:
                framework = "iso27001"
            else:
                framework = "other"

            if framework not in references:
                references[framework] = []
            references[framework].append(ref_text)

        return references

    def _extract_platforms(self, rule_elem: Any) -> List[str]:
        """
        Extract platform identifiers from a rule.

        Args:
            rule_elem: Rule XML element.

        Returns:
            List of platform identifiers (CPE IDs).
        """
        platforms: List[str] = []

        for platform in rule_elem.findall(".//xccdf-1.2:platform", XCCDF_NAMESPACES):
            platform_id = platform.get("idref", "")
            if platform_id:
                platforms.append(platform_id)

        return platforms

    def _extract_identifiers(self, rule_elem: Any) -> Dict[str, Optional[str]]:
        """
        Extract rule identifiers (CCE, CVE, RHSA).

        Args:
            rule_elem: Rule XML element.

        Returns:
            Dictionary of identifier type to value.
        """
        identifiers: Dict[str, Optional[str]] = {}

        for ident in rule_elem.findall(".//xccdf-1.2:ident", XCCDF_NAMESPACES):
            system = ident.get("system", "unknown")
            value = ident.text

            # Map system URI to simple key
            system_lower = system.lower()
            if "cce" in system_lower:
                identifiers["cce"] = value
            elif "cve" in system_lower:
                identifiers["cve"] = value
            elif "rhsa" in system_lower:
                identifiers["rhsa"] = value
            else:
                # Use last path segment as key
                key = system.split("/")[-1]
                identifiers[key] = value

        return identifiers

    def _extract_check_content(self, rule_elem: Any) -> Dict[str, Any]:
        """
        Extract check content (OVAL reference) from a rule.

        Args:
            rule_elem: Rule XML element.

        Returns:
            Dictionary containing check system and content reference.
        """
        check_content: Dict[str, Any] = {
            "system": None,
            "content": {},
            "multi_check": False,
        }

        check = self._find_element(rule_elem, "check")
        if check is None:
            return check_content

        check_content["system"] = check.get("system", "")

        # Extract check-content-ref
        ref = self._find_element(check, "check-content-ref")
        if ref is not None:
            check_content["content"] = {
                "href": ref.get("href", ""),
                "name": ref.get("name", ""),
                "multi_check": ref.get("multi-check", "false") == "true",
            }
            check_content["multi_check"] = check_content["content"]["multi_check"]

        # Extract check-export variables
        exports: Dict[str, str] = {}
        for export in check.findall(".//xccdf-1.2:check-export", XCCDF_NAMESPACES):
            var_name = export.get("export-name", "")
            value_id = export.get("value-id", "")
            if var_name and value_id:
                exports[var_name] = value_id
        if exports:
            check_content["exports"] = exports

        return check_content

    def _extract_fix_content(self, rule_elem: Any) -> Dict[str, Any]:
        """
        Extract fix/remediation content from a rule.

        Args:
            rule_elem: Rule XML element.

        Returns:
            Dictionary containing fix availability and fix scripts.
        """
        fixes_list: List[Dict[str, Any]] = []
        fix_content: Dict[str, Any] = {
            "available": False,
            "fixes": fixes_list,
        }

        fixes = rule_elem.findall(".//xccdf-1.2:fix", XCCDF_NAMESPACES)
        if not fixes:
            fixes = rule_elem.findall(".//xccdf:fix", XCCDF_NAMESPACES)

        for fix in fixes:
            fix_data: Dict[str, Any] = {
                "system": fix.get("system", ""),
                "platform": fix.get("platform", ""),
                "complexity": fix.get("complexity", "low"),
                "disruption": fix.get("disruption", "low"),
                "reboot": fix.get("reboot", "false") == "true",
                "strategy": fix.get("strategy", ""),
                "content": self._extract_text_content(fix),
            }
            fixes_list.append(fix_data)

        if fixes_list:
            fix_content["available"] = True

        return fix_content

    def _extract_complex_check(self, rule_elem: Any) -> Optional[Dict[str, Any]]:
        """
        Extract complex check with boolean logic.

        Args:
            rule_elem: Rule XML element.

        Returns:
            Dictionary with operator and nested checks, or None.
        """
        complex_elem = self._find_element(rule_elem, "complex-check")
        if complex_elem is None:
            return None

        checks_list: List[Dict[str, Any]] = []
        complex_check: Dict[str, Any] = {
            "operator": complex_elem.get("operator", "AND"),
            "checks": checks_list,
        }

        for check in complex_elem.findall(".//xccdf-1.2:check", XCCDF_NAMESPACES):
            check_data: Dict[str, Any] = {
                "system": check.get("system", ""),
                "negate": check.get("negate", "false") == "true",
            }

            ref = self._find_element(check, "check-content-ref")
            if ref is not None:
                check_data["ref"] = {
                    "href": ref.get("href", ""),
                    "name": ref.get("name", ""),
                }

            checks_list.append(check_data)

        return complex_check if checks_list else None

    def _determine_category(
        self,
        rule_id: str,
        title: str,
        description: str,
    ) -> str:
        """
        Determine rule category based on content analysis.

        Uses keyword matching against predefined category patterns.

        Args:
            rule_id: Rule identifier.
            title: Rule title.
            description: Rule description.

        Returns:
            Category string (e.g., "authentication", "network").
        """
        combined_text = f"{rule_id} {title} {description}".lower()

        for category, keywords in CATEGORY_PATTERNS.items():
            for keyword in keywords:
                if keyword in combined_text:
                    return category

        return "system"  # Default category

    def _extract_tags(self, title: str, description: str) -> List[str]:
        """
        Extract semantic tags from rule content.

        Args:
            title: Rule title.
            description: Rule description.

        Returns:
            List of extracted tag strings.
        """
        tags: Set[str] = set()
        combined_text = f"{title} {description}".lower()

        for tag, pattern in TAG_PATTERNS.items():
            if re.search(pattern, combined_text, re.IGNORECASE):
                tags.add(tag)

        return list(tags)

    def _get_profile_membership(self, rule_id: str) -> List[str]:
        """
        Get list of profiles that include this rule.

        Args:
            rule_id: Rule identifier.

        Returns:
            List of profile IDs that select this rule.
        """
        profiles: List[str] = []
        for profile_id, rule_ids in self._profile_rules.items():
            if rule_id in rule_ids:
                profiles.append(profile_id)
        return profiles

    def _map_to_frameworks(
        self,
        references: Dict[str, List[str]],
    ) -> Dict[str, Dict[str, Any]]:
        """
        Map references to structured framework data.

        Extracts control IDs and versions from reference text for
        each framework.

        Args:
            references: Dictionary of framework to reference texts.

        Returns:
            Dictionary mapping framework to version/control mappings.
        """
        frameworks: Dict[str, Dict[str, Any]] = {}

        # Process NIST references
        if "nist" in references:
            nist_data: Dict[str, List[str]] = {}
            for ref_text in references["nist"]:
                # Extract control IDs (e.g., AC-2, IA-5)
                control_ids = re.findall(r"([A-Z]{2}-\d+(?:\(\d+\))?)", ref_text)

                # Determine version
                if "r5" in ref_text.lower() or "revision 5" in ref_text.lower():
                    version = "800-53r5"
                elif "r4" in ref_text.lower() or "revision 4" in ref_text.lower():
                    version = "800-53r4"
                else:
                    version = "800-53r5"  # Default to r5

                if control_ids:
                    if version not in nist_data:
                        nist_data[version] = []
                    nist_data[version].extend(control_ids)

            if nist_data:
                frameworks["nist"] = nist_data

        # Process CIS references
        if "cis" in references:
            cis_data: Dict[str, List[str]] = {}
            for ref_text in references["cis"]:
                control_nums = re.findall(r"(\d+(?:\.\d+)+)", ref_text)
                version_match = re.search(r"v?(\d+\.\d+(?:\.\d+)?)", ref_text)
                version = f"v{version_match.group(1)}" if version_match else "v2.0.0"

                if control_nums:
                    if version not in cis_data:
                        cis_data[version] = []
                    cis_data[version].extend(control_nums)

            if cis_data:
                frameworks["cis"] = cis_data

        # Process STIG references
        if "stig" in references:
            stig_data: Dict[str, str] = {}
            for ref_text in references["stig"]:
                stig_ids = re.findall(r"([A-Z]+-\d+-\d+)", ref_text)
                for stig_id in stig_ids:
                    if stig_id.startswith("RHEL-08"):
                        stig_data["rhel8_v1r11"] = stig_id
                    elif stig_id.startswith("RHEL-09"):
                        stig_data["rhel9_v1r1"] = stig_id
                    else:
                        stig_data["generic"] = stig_id

            if stig_data:
                frameworks["stig"] = stig_data

        return frameworks
