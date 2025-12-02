"""
SCAP 1.3 Data-Stream Parser for OpenWatch

This module provides parsing for SCAP 1.3 data-stream format files, which bundle
multiple SCAP components (XCCDF benchmarks, OVAL definitions, CPE dictionaries)
into a single XML file.

Data-stream format is the preferred distribution format for SCAP content as it:
- Bundles all dependencies in a single file
- Includes cryptographic signatures (optional)
- Supports multiple benchmarks per file
- Enables efficient content distribution

Supported Formats:
- SCAP 1.3 data-stream collections
- SCAP source data-streams
- ZIP archives containing SCAP content

Security Considerations:
- XXE prevention using lxml secure parser settings
- Path traversal prevention for file operations
- Subprocess execution with explicit argument lists (no shell=True)
- ZIP extraction with content validation
- File size limits enforced

Usage:
    from backend.app.services.content.parsers.datastream import DatastreamParser

    parser = DatastreamParser()
    content = parser.parse("/path/to/ssg-rhel8-ds.xml")
    print(f"Parsed {content.rule_count} rules from {len(content.profiles)} profiles")

Dependencies:
    - OpenSCAP (oscap command-line tool) for validation
    - lxml for secure XML parsing
"""

import hashlib
import logging
import os
import subprocess
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from lxml import etree

from ..exceptions import ContentParseError
from ..models import (
    ContentFormat,
    ContentSeverity,
    ParsedContent,
    ParsedOVALDefinition,
    ParsedProfile,
    ParsedRule,
)
from . import register_parser
from .base import BaseContentParser

logger = logging.getLogger(__name__)


# Namespaces used in SCAP 1.3 data-streams
# These are standardized by NIST SCAP specification
DATASTREAM_NAMESPACES: Dict[str, str] = {
    "ds": "http://scap.nist.gov/schema/scap/source/1.2",
    "xccdf": "http://checklists.nist.gov/xccdf/1.2",
    "cpe": "http://cpe.mitre.org/language/2.0",
    "oval": "http://oval.mitre.org/XMLSchema/oval-definitions-5",
    "xlink": "http://www.w3.org/1999/xlink",
}


# Category patterns for automatic rule categorization
# These patterns match common security control domains
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


@register_parser
class DatastreamParser(BaseContentParser):
    """
    Parser for SCAP 1.3 data-stream format.

    This parser handles SCAP data-stream collections, which bundle multiple
    SCAP components (XCCDF, OVAL, CPE) into a single distributable file.
    It uses the OpenSCAP (oscap) command-line tool for validation and
    metadata extraction, with fallback to direct XML parsing.

    The parser extracts:
    - All XCCDF benchmarks contained in the data-stream
    - Profiles from each benchmark with rule selections
    - Rules with full metadata (title, description, severity, references)
    - OVAL definition references
    - CPE platform specifications

    Attributes:
        content_dir: Default directory for SCAP content storage
        errors: List of parsing errors encountered
        warnings: List of non-fatal warnings

    Example:
        >>> parser = DatastreamParser()
        >>> content = parser.parse("/app/data/scap/ssg-rhel8-ds.xml")
        >>> for profile in content.profiles:
        ...     print(f"{profile.title}: {len(profile.selected_rules)} rules")
    """

    def __init__(self, content_dir: str = "/app/data/scap") -> None:
        """
        Initialize Data-stream Parser.

        Args:
            content_dir: Directory for SCAP content storage. Created if needed.
        """
        super().__init__()
        self.content_dir = Path(content_dir)
        self.content_dir.mkdir(parents=True, exist_ok=True)
        self.errors: List[Dict[str, Any]] = []
        self.warnings: List[str] = []
        # Profile-to-rules mapping populated during parsing
        self._profile_rules: Dict[str, List[str]] = {}

    @property
    def supported_formats(self) -> List[ContentFormat]:
        """
        Return list of content formats this parser supports.

        Returns:
            List containing SCAP_DATASTREAM format.
        """
        return [ContentFormat.SCAP_DATASTREAM]

    def _parse_file_impl(
        self,
        file_path: Path,
        content_format: ContentFormat,
    ) -> ParsedContent:
        """
        Parse SCAP data-stream from a file.

        This is the main parsing implementation. It handles:
        - ZIP archives containing SCAP content
        - SCAP data-stream XML files
        - Validation using oscap tool
        - Fallback to XCCDF parsing if not a data-stream

        Args:
            file_path: Path to the data-stream file.
            content_format: The content format (SCAP_DATASTREAM).

        Returns:
            ParsedContent with all extracted rules, profiles, and metadata.

        Raises:
            ContentParseError: If parsing fails.
        """
        # Reset state for this parse operation
        self._reset_state()

        try:
            str_path = str(file_path)

            # Handle ZIP files (common for DISA distributions)
            if zipfile.is_zipfile(str_path):
                return self._parse_zip_content(file_path)

            # Validate data-stream using oscap
            validation_result = self._validate_with_oscap(str_path)

            # Calculate file hash for integrity tracking
            file_hash = self._calculate_file_hash(file_path)

            # Parse XML content securely
            root = self._parse_xml_file(file_path)

            # Extract components based on content type
            if self._is_datastream_collection(root):
                # Full data-stream processing
                profiles = self._extract_profiles_from_tree(root)
                rules = self._extract_all_rules(root)
                oval_defs = self._extract_oval_definitions(root)
                metadata = self._extract_datastream_metadata(root)
            else:
                # Fallback to benchmark parsing
                profiles = self._extract_profiles_from_tree(root)
                rules = self._extract_all_rules(root)
                oval_defs = []
                metadata = self._extract_benchmark_metadata(root)

            # Enhance metadata with validation results
            metadata["file_hash"] = file_hash
            metadata["parsed_at"] = datetime.utcnow().isoformat()
            metadata["validation_status"] = validation_result.get("status", "unknown")

            return ParsedContent(
                format=content_format,
                rules=rules,
                profiles=profiles,
                oval_definitions=oval_defs,
                metadata=metadata,
                source_file=str(file_path),
                parse_warnings=self.warnings.copy(),
            )

        except ContentParseError:
            raise
        except Exception as e:
            logger.error("Failed to parse data-stream %s: %s", file_path, str(e))
            raise ContentParseError(
                message=f"Failed to parse data-stream: {str(e)}",
                source_file=str(file_path),
                details={"error_type": type(e).__name__},
            ) from e

    def _parse_bytes_impl(
        self,
        content_bytes: bytes,
        content_format: ContentFormat,
    ) -> ParsedContent:
        """
        Parse SCAP data-stream from raw bytes.

        For data-streams, we write to a temporary file to enable oscap
        validation, then parse the content.

        Args:
            content_bytes: Raw XML bytes.
            content_format: The content format (SCAP_DATASTREAM).

        Returns:
            ParsedContent with all extracted rules, profiles, and metadata.

        Raises:
            ContentParseError: If parsing fails.
        """
        # Reset state
        self._reset_state()

        try:
            # Write to temporary file for oscap validation
            with tempfile.NamedTemporaryFile(
                suffix=".xml",
                delete=False,
            ) as temp_file:
                temp_file.write(content_bytes)
                temp_path = Path(temp_file.name)

            try:
                # Parse using file implementation
                result = self._parse_file_impl(temp_path, content_format)
                # Replace source file with hash since it was temporary
                result.source_file = ""
                result.metadata["content_hash"] = hashlib.sha256(content_bytes).hexdigest()
                return result
            finally:
                # Clean up temporary file
                temp_path.unlink(missing_ok=True)

        except ContentParseError:
            raise
        except Exception as e:
            logger.error("Failed to parse data-stream bytes: %s", str(e))
            raise ContentParseError(
                message=f"Failed to parse data-stream content: {str(e)}",
                details={"error_type": type(e).__name__},
            ) from e

    def _reset_state(self) -> None:
        """Reset parser state for a new parse operation."""
        self.errors.clear()
        self.warnings.clear()
        self._profile_rules.clear()

    def _calculate_file_hash(self, file_path: Path) -> str:
        """
        Calculate SHA-256 hash of a file.

        Args:
            file_path: Path to the file.

        Returns:
            Hexadecimal SHA-256 hash string.
        """
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _parse_xml_file(self, file_path: Path) -> Any:
        """
        Parse XML file with secure settings.

        Uses lxml with XXE prevention settings.

        Args:
            file_path: Path to the XML file.

        Returns:
            Parsed XML root element.

        Raises:
            ContentParseError: If XML parsing fails.
        """
        try:
            # lxml with secure settings to prevent XXE attacks
            parser = etree.XMLParser(
                resolve_entities=False,  # Prevent XXE
                no_network=True,  # No network access
                remove_pis=True,  # Remove processing instructions
                huge_tree=False,  # Prevent billion laughs
            )
            tree = etree.parse(str(file_path), parser)
            return tree.getroot()
        except Exception as e:
            raise ContentParseError(
                message=f"XML parsing failed: {str(e)}",
                source_file=str(file_path),
            ) from e

    def _validate_with_oscap(self, file_path: str) -> Dict[str, Any]:
        """
        Validate data-stream using OpenSCAP tool.

        Tries data-stream validation first, falls back to XCCDF validation.

        Args:
            file_path: Path to the content file.

        Returns:
            Dictionary with validation status and any errors.
        """
        result: Dict[str, Any] = {"status": "unknown", "errors": []}

        try:
            # Try data-stream validation first
            ds_result = subprocess.run(
                ["oscap", "ds", "sds-validate", file_path],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if ds_result.returncode == 0:
                result["status"] = "valid_datastream"
                return result

            # Fallback to XCCDF validation
            xccdf_result = subprocess.run(
                ["oscap", "xccdf", "validate", file_path],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if xccdf_result.returncode == 0:
                result["status"] = "valid_xccdf"
                self.warnings.append("Content is XCCDF, not data-stream format")
            else:
                result["status"] = "invalid"
                result["errors"].append(ds_result.stderr)
                result["errors"].append(xccdf_result.stderr)

        except subprocess.TimeoutExpired:
            result["status"] = "timeout"
            result["errors"].append("Validation timed out")
            self.warnings.append("oscap validation timed out")

        except FileNotFoundError:
            # oscap not installed - log warning but continue
            result["status"] = "oscap_unavailable"
            self.warnings.append("oscap tool not available for validation")
            logger.warning("oscap command not found, skipping validation")

        except Exception as e:
            result["status"] = "error"
            result["errors"].append(str(e))
            logger.warning("oscap validation failed: %s", str(e))

        return result

    def _is_datastream_collection(self, root: Any) -> bool:
        """
        Check if root element is a data-stream collection.

        Args:
            root: XML root element.

        Returns:
            True if this is a data-stream collection.
        """
        return root.tag.endswith("data-stream-collection")

    def _parse_zip_content(self, zip_path: Path) -> ParsedContent:
        """
        Parse SCAP content from a ZIP archive.

        Extracts the archive to a temporary directory, finds the main
        SCAP content file, and parses it.

        Args:
            zip_path: Path to the ZIP file.

        Returns:
            ParsedContent from the extracted content.

        Raises:
            ContentParseError: If no valid SCAP content found.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            try:
                with zipfile.ZipFile(zip_path, "r") as zip_file:
                    # Extract all files with path validation
                    for file_info in zip_file.filelist:
                        # Security: Skip paths with traversal attempts
                        if ".." in file_info.filename or file_info.filename.startswith("/"):
                            self.warnings.append(f"Skipped suspicious path: {file_info.filename}")
                            continue
                        zip_file.extract(file_info, temp_dir)

                # Find SCAP content files
                scap_files: List[Path] = []
                for root_dir, dirs, files in os.walk(temp_dir):
                    # Security: Validate we're still within temp directory
                    root_path = Path(root_dir)
                    if not str(root_path).startswith(str(temp_path)):
                        continue

                    for file_name in files:
                        if file_name.endswith((".xml", ".scap")):
                            full_path = root_path / file_name
                            # Skip small files (likely metadata)
                            if full_path.stat().st_size > 1000:
                                scap_files.append(full_path)

                if not scap_files:
                    raise ContentParseError(
                        message="No SCAP content found in ZIP archive",
                        source_file=str(zip_path),
                    )

                # Parse the largest file (usually the main content)
                main_file = max(scap_files, key=lambda p: p.stat().st_size)
                result = self._parse_file_impl(main_file, ContentFormat.SCAP_DATASTREAM)

                # Update metadata to reflect ZIP source
                result.metadata["source_format"] = "zip"
                result.metadata["extracted_from"] = zip_path.name
                result.source_file = str(zip_path)

                return result

            except zipfile.BadZipFile as e:
                raise ContentParseError(
                    message=f"Invalid ZIP file: {str(e)}",
                    source_file=str(zip_path),
                ) from e

    def _extract_datastream_metadata(self, root: Any) -> Dict[str, Any]:
        """
        Extract metadata from data-stream collection.

        Args:
            root: XML root element.

        Returns:
            Dictionary containing data-stream metadata.
        """
        metadata: Dict[str, Any] = {
            "content_type": "SCAP Data Stream Collection",
            "scap_version": root.get("schematron-version", "1.2"),
            "data_streams": [],
        }

        # Extract data-stream information
        ds_elements = root.xpath(".//ds:data-stream", namespaces=DATASTREAM_NAMESPACES)
        metadata["data_stream_count"] = len(ds_elements)

        for ds_elem in ds_elements:
            ds_info = {
                "id": ds_elem.get("id", ""),
                "timestamp": ds_elem.get("timestamp", ""),
                "version": ds_elem.get("scap-version", "1.2"),
            }
            metadata["data_streams"].append(ds_info)

        # Extract Dublin Core metadata if present
        metadata_elem = root.find(".//xccdf:metadata", DATASTREAM_NAMESPACES)
        if metadata_elem is not None:
            dc_elements = metadata_elem.xpath(
                './/*[namespace-uri()="http://purl.org/dc/elements/1.1/"]'
            )
            for dc_elem in dc_elements:
                tag_name = dc_elem.tag.split("}")[-1]
                if dc_elem.text:
                    metadata[f"dc_{tag_name}"] = dc_elem.text

        return metadata

    def _extract_benchmark_metadata(self, root: Any) -> Dict[str, Any]:
        """
        Extract metadata from XCCDF benchmark.

        Args:
            root: Benchmark XML element.

        Returns:
            Dictionary containing benchmark metadata.
        """
        # Find benchmark element (might be root or nested)
        benchmark = root
        if not root.tag.endswith("Benchmark"):
            benchmark = root.find(".//xccdf:Benchmark", DATASTREAM_NAMESPACES)
            if benchmark is None:
                return {"content_type": "Unknown"}

        metadata: Dict[str, Any] = {
            "content_type": "XCCDF Benchmark",
            "id": benchmark.get("id", ""),
            "version": benchmark.get("version", ""),
            "resolved": benchmark.get("resolved", "false") == "true",
        }

        # Extract title
        title_elem = benchmark.find(".//xccdf:title", DATASTREAM_NAMESPACES)
        if title_elem is not None and title_elem.text:
            metadata["title"] = title_elem.text

        # Extract description
        desc_elem = benchmark.find(".//xccdf:description", DATASTREAM_NAMESPACES)
        if desc_elem is not None:
            metadata["description"] = self._extract_text_content(desc_elem)

        # Extract status
        status_elem = benchmark.find(".//xccdf:status", DATASTREAM_NAMESPACES)
        if status_elem is not None:
            metadata["status"] = status_elem.text
            metadata["status_date"] = status_elem.get("date", "")

        return metadata

    def _extract_profiles_from_tree(self, root: Any) -> List[ParsedProfile]:
        """
        Extract all profiles from the XML tree.

        Also populates the internal profile-to-rules mapping.

        Args:
            root: XML root element.

        Returns:
            List of ParsedProfile objects.
        """
        profiles: List[ParsedProfile] = []

        # Find all Profile elements
        profile_elements = root.xpath(".//xccdf:Profile", namespaces=DATASTREAM_NAMESPACES)
        logger.debug("Found %d profile elements", len(profile_elements))

        for profile_elem in profile_elements:
            try:
                profile = self._parse_profile_element(profile_elem)
                if profile:
                    profiles.append(profile)
                    # Build mapping for rule profile membership
                    self._profile_rules[profile.profile_id] = list(profile.selected_rules)
            except Exception as e:
                profile_id = profile_elem.get("id", "unknown")
                logger.warning("Failed to parse profile %s: %s", profile_id, str(e))
                self.warnings.append(f"Failed to parse profile {profile_id}")

        return profiles

    def _parse_profile_element(self, profile_elem: Any) -> Optional[ParsedProfile]:
        """
        Parse a single Profile element.

        Args:
            profile_elem: Profile XML element.

        Returns:
            ParsedProfile object or None if parsing fails.
        """
        profile_id = profile_elem.get("id", "")
        if not profile_id:
            return None

        # Extract title
        title_elem = profile_elem.find("xccdf:title", DATASTREAM_NAMESPACES)
        title = title_elem.text if title_elem is not None and title_elem.text else profile_id

        # Extract description
        desc_elem = profile_elem.find("xccdf:description", DATASTREAM_NAMESPACES)
        description = self._extract_text_content(desc_elem) if desc_elem is not None else ""

        # Extract selected rules
        selected_rules: List[str] = []
        for select in profile_elem.xpath(
            './/xccdf:select[@selected="true"]',
            namespaces=DATASTREAM_NAMESPACES,
        ):
            rule_idref = select.get("idref", "")
            if rule_idref:
                selected_rules.append(rule_idref)

        # Check for extended profile
        extends = profile_elem.get("extends")

        # Extract platform specifications
        platforms = profile_elem.xpath(".//xccdf:platform", namespaces=DATASTREAM_NAMESPACES)
        platform_refs = [p.get("idref", "") for p in platforms if p.get("idref")]

        return ParsedProfile(
            profile_id=profile_id,
            title=title,
            description=description,
            selected_rules=selected_rules,
            extends=extends,
            metadata={
                "abstract": profile_elem.get("abstract", "false") == "true",
                "prohibit_changes": profile_elem.get("prohibitChanges", "false") == "true",
                "platforms": platform_refs,
                "rule_count": len(selected_rules),
            },
        )

    def _extract_all_rules(self, root: Any) -> List[ParsedRule]:
        """
        Extract all rules from the XML tree.

        Args:
            root: XML root element.

        Returns:
            List of ParsedRule objects.
        """
        rules: List[ParsedRule] = []

        # Find all Rule elements
        rule_elements = root.xpath(".//xccdf:Rule", namespaces=DATASTREAM_NAMESPACES)
        logger.info("Found %d rule elements to parse", len(rule_elements))

        for rule_elem in rule_elements:
            try:
                rule = self._parse_rule_element(rule_elem)
                if rule:
                    rules.append(rule)
            except Exception as e:
                rule_id = rule_elem.get("id", "unknown")
                logger.error("Failed to parse rule %s: %s", rule_id, str(e))
                self.errors.append({"rule_id": rule_id, "error": str(e)})

        return rules

    def _parse_rule_element(self, rule_elem: Any) -> Optional[ParsedRule]:
        """
        Parse a single Rule element.

        Args:
            rule_elem: Rule XML element.

        Returns:
            ParsedRule object or None if rule_id is missing.
        """
        rule_id = rule_elem.get("id", "")
        if not rule_id:
            return None

        # Extract and normalize severity
        severity_str = rule_elem.get("severity", "unknown").lower()
        severity = self._normalize_severity(severity_str)

        # Extract text elements
        title_elem = rule_elem.find(".//xccdf:title", DATASTREAM_NAMESPACES)
        title = title_elem.text if title_elem is not None and title_elem.text else rule_id

        desc_elem = rule_elem.find(".//xccdf:description", DATASTREAM_NAMESPACES)
        description = self._extract_text_content(desc_elem) if desc_elem is not None else ""

        rationale_elem = rule_elem.find(".//xccdf:rationale", DATASTREAM_NAMESPACES)
        rationale = self._extract_text_content(rationale_elem) if rationale_elem is not None else ""

        # Extract references
        references = self._extract_rule_references(rule_elem)

        # Extract platforms
        platforms = self._extract_rule_platforms(rule_elem)

        # Extract check content
        check_content = self._extract_check_content(rule_elem)

        # Extract fix content
        fix_content = self._extract_fix_content(rule_elem)

        # Determine category
        category = self._determine_category(rule_id, title, description)

        # Get profile membership
        profile_membership = self._get_profile_membership(rule_id)

        # Build metadata
        metadata: Dict[str, Any] = {
            "selected": rule_elem.get("selected", "true") == "true",
            "weight": float(rule_elem.get("weight", "1.0")),
            "category": category,
            "profiles": profile_membership,
            "check": check_content,
            "fix": fix_content,
        }

        return ParsedRule(
            rule_id=rule_id,
            title=title,
            description=description,
            severity=severity,
            rationale=rationale,
            check_content=check_content.get("name", ""),
            fix_content=fix_content.get("content", "") if fix_content.get("available") else "",
            references=references,
            platforms=platforms,
            metadata=metadata,
        )

    def _normalize_severity(self, severity_str: str) -> ContentSeverity:
        """
        Normalize severity string to ContentSeverity enum.

        Args:
            severity_str: Severity string from XCCDF.

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

    def _extract_text_content(self, elem: Any) -> str:
        """
        Extract text content from an element, including nested HTML.

        Args:
            elem: XML element.

        Returns:
            Extracted text content.
        """
        if elem is None:
            return ""

        text = elem.text or ""

        # Process child elements
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

    def _extract_rule_references(self, rule_elem: Any) -> Dict[str, List[str]]:
        """
        Extract and categorize references from a rule.

        Args:
            rule_elem: Rule XML element.

        Returns:
            Dictionary mapping framework names to reference lists.
        """
        references: Dict[str, List[str]] = {}

        for ref in rule_elem.xpath(".//xccdf:reference", namespaces=DATASTREAM_NAMESPACES):
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

    def _extract_rule_platforms(self, rule_elem: Any) -> List[str]:
        """
        Extract platform identifiers from a rule.

        Args:
            rule_elem: Rule XML element.

        Returns:
            List of platform identifiers.
        """
        platforms: List[str] = []

        for platform in rule_elem.xpath(".//xccdf:platform", namespaces=DATASTREAM_NAMESPACES):
            platform_id = platform.get("idref", "")
            if platform_id:
                platforms.append(platform_id)

        return platforms

    def _extract_check_content(self, rule_elem: Any) -> Dict[str, Any]:
        """
        Extract check content (OVAL reference) from a rule.

        Args:
            rule_elem: Rule XML element.

        Returns:
            Dictionary with check information.
        """
        check_info: Dict[str, Any] = {
            "system": None,
            "href": "",
            "name": "",
        }

        check = rule_elem.find(".//xccdf:check", DATASTREAM_NAMESPACES)
        if check is None:
            return check_info

        check_info["system"] = check.get("system", "")

        ref = check.find(".//xccdf:check-content-ref", DATASTREAM_NAMESPACES)
        if ref is not None:
            check_info["href"] = ref.get("href", "")
            check_info["name"] = ref.get("name", "")

        return check_info

    def _extract_fix_content(self, rule_elem: Any) -> Dict[str, Any]:
        """
        Extract fix/remediation content from a rule.

        Args:
            rule_elem: Rule XML element.

        Returns:
            Dictionary with fix information.
        """
        fix_info: Dict[str, Any] = {
            "available": False,
            "content": "",
            "system": "",
        }

        fix = rule_elem.find(".//xccdf:fix", DATASTREAM_NAMESPACES)
        if fix is None:
            return fix_info

        fix_info["available"] = True
        fix_info["system"] = fix.get("system", "")
        fix_info["content"] = self._extract_text_content(fix)

        return fix_info

    def _determine_category(
        self,
        rule_id: str,
        title: str,
        description: str,
    ) -> str:
        """
        Determine rule category based on content analysis.

        Args:
            rule_id: Rule identifier.
            title: Rule title.
            description: Rule description.

        Returns:
            Category string.
        """
        combined_text = f"{rule_id} {title} {description}".lower()

        for category, keywords in CATEGORY_PATTERNS.items():
            for keyword in keywords:
                if keyword in combined_text:
                    return category

        return "system"

    def _get_profile_membership(self, rule_id: str) -> List[str]:
        """
        Get list of profiles that include this rule.

        Args:
            rule_id: Rule identifier.

        Returns:
            List of profile IDs.
        """
        profiles: List[str] = []
        for profile_id, rule_ids in self._profile_rules.items():
            if rule_id in rule_ids:
                profiles.append(profile_id)
        return profiles

    def _extract_oval_definitions(self, root: Any) -> List[ParsedOVALDefinition]:
        """
        Extract OVAL definition references from the data-stream.

        Note: This extracts references, not the full OVAL content.
        Full OVAL parsing would require a separate OVAL parser.

        Args:
            root: XML root element.

        Returns:
            List of ParsedOVALDefinition objects (references only).
        """
        oval_defs: List[ParsedOVALDefinition] = []
        seen_refs: Set[str] = set()

        # Find check-content-ref elements that reference OVAL
        check_refs = root.xpath(".//xccdf:check-content-ref", namespaces=DATASTREAM_NAMESPACES)

        for check_ref in check_refs:
            href = check_ref.get("href", "")
            name = check_ref.get("name", "")

            # Only process OVAL references
            if not ("oval" in href.lower() or name.startswith("oval:")):
                continue

            # Skip duplicates
            if name in seen_refs:
                continue
            seen_refs.add(name)

            oval_defs.append(
                ParsedOVALDefinition(
                    definition_id=name,
                    title=name,
                    description=f"OVAL check from {href}",
                    definition_class="compliance",
                    metadata={"href": href},
                )
            )

        return oval_defs
