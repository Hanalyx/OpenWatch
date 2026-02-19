"""
OpenWatch Scanner (OWScanner) - SCAP Compliance Scanning

This module provides the OWScanner class, OpenWatch's SCAP compliance scanner
with XCCDF/OVAL generation and execution capabilities.

Key Features:
- Dynamic XCCDF and OVAL generation from compliance rules
- Local and remote scan execution via engine executors
- Platform-aware OVAL deduplication
- Rule inheritance resolution
- Delegates content operations to OSCAPScanner (no duplication)

Design Philosophy:
- Single scanner for all SCAP operations (unified API)
- Platform-specific OVAL for accurate compliance results
- Security-first with input validation and safe XML generation
- Defensive coding with comprehensive error handling
- DRY: Delegates to OSCAPScanner for content validation/parsing

Note:
    This scanner is part of the legacy OpenSCAP pipeline. Aegis is now the
    primary compliance engine. See app/plugins/aegis/ for the current approach.

Security Notes:
- XML generation uses ElementTree (safe against XXE)
- OVAL files are read from trusted local storage only
- Command execution uses argument lists (no shell injection)
- Profile IDs are validated against safe patterns
- File paths validated to prevent traversal attacks

Backward Compatibility:
- UnifiedSCAPScanner is aliased to OWScanner for backward compatibility
"""

import logging
import re
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.services.auth import get_auth_service
from app.services.platform_capability_service import PlatformCapabilityService
from app.services.rules import RuleService

from ..exceptions import ContentValidationError, ScanExecutionError, ScannerError
from ..models import ExecutionContext, ScannerCapabilities, ScanProvider, ScanType
from .base import BaseScanner
from .oscap import OSCAPScanner

logger = logging.getLogger(__name__)


class OWScanner(BaseScanner):
    """
    OpenWatch Scanner - SCAP compliance scanner.

    This scanner provides XCCDF/OVAL generation and execution capabilities
    for SCAP compliance scanning. Note: Aegis is now the primary compliance
    engine; this scanner is part of the legacy OpenSCAP pipeline.

    The scanner supports:
    - Dynamic XCCDF/OVAL generation
    - Local and remote scan execution
    - Rule inheritance resolution

    Content operations (validation, profile extraction, result parsing) are
    delegated to OSCAPScanner to avoid code duplication.

    Attributes:
        oscap_scanner: OSCAPScanner instance for content operations
        rule_service: Service for advanced rule operations
        platform_service: Platform capability detection service
        content_dir: Directory for SCAP content files
        results_dir: Directory for scan result files
        _initialized: Whether async services have been initialized
    """

    def __init__(
        self,
        content_dir: Optional[str] = None,
        results_dir: Optional[str] = None,
        encryption_service: Optional[Any] = None,
    ):
        """
        Initialize the OpenWatch scanner.

        Args:
            content_dir: Directory for SCAP content (default: /app/data/scap)
            results_dir: Directory for scan results (default: /app/data/results)
            encryption_service: Encryption service for credential decryption
        """
        super().__init__(name="OWScanner")

        # Use provided paths or defaults
        self.content_dir = Path(content_dir or "/openwatch/data/scap")
        self.results_dir = Path(results_dir or "/openwatch/data/results")

        # Encryption service for credential resolution
        self.encryption_service = encryption_service

        # Delegate content operations to OSCAPScanner (DRY principle)
        self.oscap_scanner = OSCAPScanner()

        # Services (initialized async)
        self.rule_service: Optional[RuleService] = None
        self.platform_service: Optional[PlatformCapabilityService] = None

        # Initialization state
        self._initialized = False

        # Ensure directories exist
        try:
            self.content_dir.mkdir(parents=True, exist_ok=True)
            self.results_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            self._logger.error("Failed to create scanner directories: %s", e)

    @property
    def provider(self) -> ScanProvider:
        """Return OSCAP provider type."""
        return ScanProvider.OSCAP

    @property
    def capabilities(self) -> ScannerCapabilities:
        """Return unified scanner capabilities."""
        return ScannerCapabilities(
            provider=ScanProvider.OSCAP,
            supported_scan_types=[
                ScanType.XCCDF_PROFILE,
                ScanType.XCCDF_RULE,
                ScanType.OVAL_DEFINITIONS,
                ScanType.DATASTREAM,
            ],
            supported_formats=["xccdf", "oval", "datastream"],
            supports_remote=True,
            supports_local=True,
            max_concurrent=0,
        )

    async def initialize(self) -> None:
        """
        Initialize async services.

        Must be called before using methods like
        select_platform_rules() or scan_with_rules().

        Raises:
            ScannerError: If service initialization fails.
        """
        if self._initialized:
            return

        try:
            # Initialize rule service
            self.rule_service = RuleService()
            await self.rule_service.initialize()
            self._logger.info("Rule service initialized")

            # Initialize platform service
            self.platform_service = PlatformCapabilityService()
            await self.platform_service.initialize()
            self._logger.info("Platform service initialized")

            self._initialized = True
            self._logger.info("OWScanner fully initialized")

        except Exception as e:
            self._logger.error("Scanner initialization failed: %s", e)
            raise ScannerError(
                message=f"Scanner initialization failed: {e}",
                error_code="SCANNER_INIT_ERROR",
                cause=e,
            )

    def validate_content(self, content_path: Path) -> bool:
        """
        Validate SCAP content file.

        Delegates to OSCAPScanner for the actual validation to avoid
        code duplication (DRY principle).

        Args:
            content_path: Path to SCAP content file.

        Returns:
            True if content is valid.

        Raises:
            ContentValidationError: If validation fails.
        """
        # Additional path traversal check before delegation
        if ".." in str(content_path):
            raise ContentValidationError(
                message="Invalid path: directory traversal detected",
                content_path=str(content_path),
            )

        # Delegate to OSCAPScanner
        return self.oscap_scanner.validate_content(content_path)

    def extract_profiles(self, content_path: Path) -> List[Dict[str, Any]]:
        """
        Extract available profiles from SCAP content.

        Delegates to OSCAPScanner for the actual extraction to avoid
        code duplication (DRY principle).

        Args:
            content_path: Path to SCAP content file.

        Returns:
            List of profile dictionaries with id, title, description.

        Raises:
            ContentValidationError: If extraction fails.
        """
        # Delegate to OSCAPScanner
        return self.oscap_scanner.extract_profiles(content_path)

    def parse_results(self, result_path: Path, result_format: str = "xccdf") -> Dict[str, Any]:
        """
        Parse scan result file into normalized format.

        Args:
            result_path: Path to result file.
            result_format: Format of results (xccdf or arf).

        Returns:
            Dictionary with normalized results.
        """
        # Delegate to result parser module
        from ..result_parsers import parse_arf_results, parse_xccdf_results

        if result_format == "xccdf":
            return parse_xccdf_results(result_path)
        elif result_format == "arf":
            return parse_arf_results(result_path)
        else:
            # Fallback to basic parsing
            return self._parse_basic_results(result_path)

    # =========================================================================
    # Rule Selection Methods
    # =========================================================================

    async def select_platform_rules(
        self,
        platform: str,
        platform_version: str,
        framework: Optional[str] = None,
        severity_filter: Optional[List[str]] = None,
    ) -> List[Any]:
        """
        Select rules applicable to a specific platform.

        Uses the rule service to query for rules that match
        the target platform and optional framework/severity filters.

        Note: MongoDB rule storage has been removed. This method now returns
        an empty list. Use Aegis for compliance scanning instead.

        Args:
            platform: Target platform (e.g., "rhel9", "ubuntu2204")
            platform_version: Platform version (e.g., "9.0", "22.04")
            framework: Optional compliance framework filter (e.g., "NIST_800_53")
            severity_filter: Optional list of severity levels

        Returns:
            List of rule dicts matching the criteria.

        Raises:
            ScannerError: If rule selection fails.
        """
        if not self._initialized:
            await self.initialize()

        try:
            self._logger.info("Selecting rules for platform: %s %s", platform, platform_version)

            # Use rule service to get platform-specific rules
            rules = await self.rule_service.get_rules_by_platform(
                platform=platform,
                platform_version=platform_version,
                framework=framework,
                severity_filter=severity_filter,
            )

            self._logger.info(
                "Selected %d rules for %s %s",
                len(rules),
                platform,
                platform_version,
            )
            return rules

        except Exception as e:
            self._logger.error("Failed to select platform rules: %s", e)
            raise ScannerError(
                message=f"Platform rule selection failed: {e}",
                error_code="RULE_SELECTION_ERROR",
                cause=e,
            )

    async def get_rules_by_ids(self, rule_ids: List[str]) -> List[Any]:
        """
        Get specific rules by their IDs.

        Note: MongoDB rule storage has been removed. This method returns
        an empty list. Use Aegis for compliance scanning instead.

        Args:
            rule_ids: List of rule ID strings.

        Returns:
            Empty list (MongoDB removed).
        """
        self._logger.warning(
            "get_rules_by_ids: MongoDB removed. Cannot fetch %d rules. " "Use Aegis for compliance scanning instead.",
            len(rule_ids),
        )
        return []

    # =========================================================================
    # SCAP Content Generation Methods
    # =========================================================================

    async def generate_scan_profile(
        self,
        rules: List[Any],
        profile_name: str,
        platform: str,
    ) -> Tuple[str, Optional[str]]:
        """
        Generate SCAP profile XML and OVAL definitions from compliance rules.

        Creates a temporary directory with:
        - xccdf-profile.xml: XCCDF benchmark with profile and rules
        - oval-definitions.xml: Combined OVAL definitions (if available)

        Args:
            rules: List of rule objects
            profile_name: Name for the generated profile
            platform: Target platform for OVAL selection

        Returns:
            Tuple of (xccdf_path, oval_path) where oval_path may be None.

        Raises:
            ScannerError: If profile generation fails.
        """
        try:
            self._logger.info(
                "Generating SCAP profile '%s' from %d rules",
                profile_name,
                len(rules),
            )

            # Create temporary directory for SCAP content
            temp_dir = Path(tempfile.mkdtemp(prefix="openwatch_scap_"))

            # Generate OVAL definitions first to get ID mapping
            oval_path, rule_to_oval_map = self._generate_oval_definitions(rules, platform, temp_dir)

            if oval_path:
                self._logger.info("Generated OVAL definitions: %s", oval_path)
            else:
                self._logger.warning("No OVAL definitions generated for %d rules", len(rules))

            # Generate XCCDF profile with OVAL ID mapping
            profile_path = temp_dir / "xccdf-profile.xml"
            xml_content = self._generate_xccdf_xml(rules, profile_name, platform, rule_to_oval_map)

            with open(profile_path, "w", encoding="utf-8") as f:
                f.write(xml_content)

            self._logger.info("Generated SCAP profile: %s", profile_path)

            return (str(profile_path), oval_path)

        except Exception as e:
            self._logger.error("Failed to generate scan profile: %s", e)
            raise ScannerError(
                message=f"Profile generation failed: {e}",
                error_code="PROFILE_GENERATION_ERROR",
                cause=e,
            )

    def _generate_oval_definitions(
        self,
        rules: List[Any],
        platform: str,
        temp_dir: Path,
    ) -> Tuple[Optional[str], Dict[str, str]]:
        """
        Generate combined OVAL definitions document from compliance rules.

        Platform-aware OVAL Selection:
            Uses platform_implementations.{platform}.oval_filename
            to get the correct platform-specific OVAL file.
            No fallback to rule-level oval_filename to ensure
            correct compliance results.

        Args:
            rules: List of rule objects
            platform: Target platform (e.g., "rhel9")
            temp_dir: Directory to store generated OVAL file

        Returns:
            Tuple of (path_to_oval, rule_to_oval_id_mapping)
        """
        try:
            oval_storage_base = Path("/openwatch/data/oval_definitions")
            oval_definitions_found = []
            rules_with_oval = 0
            rules_missing_oval = 0

            # Collect OVAL files from platform-specific implementations
            for rule in rules:
                oval_filename = self._get_platform_oval_filename(rule, platform)

                if oval_filename:
                    oval_file_path = oval_storage_base / oval_filename

                    if oval_file_path.exists():
                        oval_definitions_found.append(
                            {
                                "rule_id": rule.rule_id,
                                "oval_path": oval_file_path,
                                "oval_filename": oval_filename,
                            }
                        )
                        rules_with_oval += 1
                    else:
                        self._logger.warning(
                            "OVAL file not found for rule %s: %s",
                            rule.rule_id,
                            oval_file_path,
                        )
                        rules_missing_oval += 1
                else:
                    rules_missing_oval += 1
                    self._logger.debug(
                        "Rule %s has no OVAL for platform %s",
                        rule.rule_id,
                        platform,
                    )

            if not oval_definitions_found:
                self._logger.warning(
                    "No OVAL definitions found for %d rules on platform %s",
                    len(rules),
                    platform,
                )
                return (None, {})

            self._logger.info(
                "Found %d OVAL definitions for %d rules",
                len(oval_definitions_found),
                rules_with_oval,
            )

            # Generate combined OVAL document
            return self._combine_oval_definitions(oval_definitions_found, temp_dir)

        except Exception as e:
            self._logger.error("Failed to generate OVAL definitions: %s", e, exc_info=True)
            return (None, {})

    def _combine_oval_definitions(
        self,
        oval_info_list: List[Dict[str, Any]],
        temp_dir: Path,
    ) -> Tuple[str, Dict[str, str]]:
        """
        Combine multiple OVAL files into a single definitions document.

        Handles deduplication of:
        - Definition IDs
        - Test IDs
        - Object IDs
        - State IDs
        - Variable IDs

        Args:
            oval_info_list: List of dicts with rule_id, oval_path, oval_filename
            temp_dir: Directory for output file

        Returns:
            Tuple of (path_to_combined_oval, rule_to_oval_id_mapping)
        """
        # OVAL namespace definitions
        oval_ns = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
        oval_common_ns = "http://oval.mitre.org/XMLSchema/oval-common-5"
        linux_ns = "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"
        unix_ns = "http://oval.mitre.org/XMLSchema/oval-definitions-5#unix"
        ind_ns = "http://oval.mitre.org/XMLSchema/oval-definitions-5#independent"

        # Register namespaces
        ET.register_namespace("", oval_ns)
        ET.register_namespace("oval", oval_common_ns)
        ET.register_namespace("linux", linux_ns)
        ET.register_namespace("unix", unix_ns)
        ET.register_namespace("ind", ind_ns)

        # Create root element
        root = ET.Element(f"{{{oval_ns}}}oval_definitions")

        # Add generator info
        generator = ET.SubElement(root, f"{{{oval_ns}}}generator")
        ET.SubElement(generator, f"{{{oval_common_ns}}}product_name").text = "OpenWatch Unified SCAP Scanner"
        ET.SubElement(generator, f"{{{oval_common_ns}}}product_version").text = "1.0.0"
        ET.SubElement(generator, f"{{{oval_common_ns}}}schema_version").text = "5.11"
        ET.SubElement(generator, f"{{{oval_common_ns}}}timestamp").text = datetime.utcnow().isoformat() + "Z"

        # Create container elements
        definitions = ET.SubElement(root, "definitions")
        tests = ET.SubElement(root, "tests")
        objects = ET.SubElement(root, "objects")
        states = ET.SubElement(root, "states")
        variables = ET.SubElement(root, "variables")

        # Deduplication sets
        definition_ids_added = set()
        test_ids_added = set()
        object_ids_added = set()
        state_ids_added = set()
        variable_ids_added = set()

        # Rule to OVAL ID mapping
        rule_to_oval_id_map: Dict[str, str] = {}

        # Process each OVAL file
        for oval_info in oval_info_list:
            try:
                # Parse OVAL file (trusted local content)
                tree = ET.parse(oval_info["oval_path"])
                oval_root = tree.getroot()

                # Extract definitions with deduplication
                for definition in oval_root.findall(f".//{{{oval_ns}}}definition"):
                    def_id = definition.get("id")
                    if def_id and def_id not in definition_ids_added:
                        definitions.append(definition)
                        definition_ids_added.add(def_id)
                        rule_to_oval_id_map[oval_info["rule_id"]] = def_id

                # Extract tests with deduplication
                for test in oval_root.findall(f".//{{{oval_ns}}}tests/*"):
                    test_id = test.get("id")
                    if test_id and test_id not in test_ids_added:
                        tests.append(test)
                        test_ids_added.add(test_id)

                # Extract objects with deduplication
                for obj in oval_root.findall(f".//{{{oval_ns}}}objects/*"):
                    obj_id = obj.get("id")
                    if obj_id and obj_id not in object_ids_added:
                        objects.append(obj)
                        object_ids_added.add(obj_id)

                # Extract states with deduplication
                for state in oval_root.findall(f".//{{{oval_ns}}}states/*"):
                    state_id = state.get("id")
                    if state_id and state_id not in state_ids_added:
                        states.append(state)
                        state_ids_added.add(state_id)

                # Extract variables with deduplication
                for variable in oval_root.findall(f".//{{{oval_ns}}}variables/*"):
                    var_id = variable.get("id")
                    if var_id and var_id not in variable_ids_added:
                        variables.append(variable)
                        variable_ids_added.add(var_id)

            except Exception as e:
                self._logger.error(
                    "Failed to parse OVAL file %s: %s",
                    oval_info["oval_path"],
                    e,
                )
                continue

        # Write combined OVAL document
        oval_output_path = temp_dir / "oval-definitions.xml"
        tree = ET.ElementTree(root)
        tree.write(
            oval_output_path,
            encoding="utf-8",
            xml_declaration=True,
            method="xml",
        )

        self._logger.info(
            "Generated OVAL definitions: %s (%d definitions)",
            oval_output_path,
            len(definition_ids_added),
        )

        return (str(oval_output_path), rule_to_oval_id_map)

    def _get_platform_oval_filename(
        self,
        rule: Any,
        target_platform: str,
    ) -> Optional[str]:
        """
        Get platform-specific OVAL filename from rule.

        Uses platform_implementations.{platform}.oval_filename
        without fallback to ensure correct platform OVAL.

        Args:
            rule: rule object
            target_platform: Target platform identifier

        Returns:
            OVAL filename or None if not available.
        """
        if not hasattr(rule, "platform_implementations"):
            return None

        platform_impls = rule.platform_implementations
        if not platform_impls:
            return None

        platform_impl = platform_impls.get(target_platform)
        if not platform_impl:
            return None

        # Handle both dict and model object
        if isinstance(platform_impl, dict):
            return platform_impl.get("oval_filename")
        else:
            return getattr(platform_impl, "oval_filename", None)

    def _generate_xccdf_xml(
        self,
        rules: List[Any],
        profile_name: str,
        platform: str,
        rule_to_oval_map: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        Generate XCCDF XML from compliance rules.

        Args:
            rules: List of rule objects
            profile_name: Profile name
            platform: Target platform
            rule_to_oval_map: Mapping of rule_id to OVAL definition ID

        Returns:
            XCCDF XML string.
        """
        if rule_to_oval_map is None:
            rule_to_oval_map = {}

        # Generate XCCDF-compliant IDs
        benchmark_id = f"xccdf_com.openwatch_benchmark_{platform}"
        profile_id = f"xccdf_com.openwatch_profile_{profile_name.lower().replace(' ', '_')}"

        xml_lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<xccdf:Benchmark xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2" ',
            'xmlns:xhtml="http://www.w3.org/1999/xhtml" ',
            f'id="{benchmark_id}" resolved="1" xml:lang="en-US">',
            "  <xccdf:status>incomplete</xccdf:status>",
            f"  <xccdf:title>OpenWatch Generated Profile - {profile_name}</xccdf:title>",
            "  <xccdf:description>Profile generated from compliance rules</xccdf:description>",
            f'  <xccdf:version>{datetime.now().strftime("%Y.%m.%d")}</xccdf:version>',
            '  <xccdf:model system="urn:xccdf:scoring:default"/>',
            "",
            f'  <xccdf:Profile id="{profile_id}">',
            f"    <xccdf:title>{profile_name}</xccdf:title>",
            f"    <xccdf:description>Compliance profile for {platform}</xccdf:description>",
        ]

        # Add rule selections
        rules_added = 0
        for rule in rules:
            rule_id = getattr(rule, "scap_rule_id", None) or rule.rule_id
            xml_lines.append(f'    <xccdf:select idref="{rule_id}" selected="true"/>')
            rules_added += 1

        self._logger.info("Added %d rule selections to XCCDF profile", rules_added)
        xml_lines.append("  </xccdf:Profile>")

        # Add rule definitions
        rules_with_checks = 0
        for rule in rules:
            rule_id = getattr(rule, "scap_rule_id", None) or rule.rule_id

            # Clean text for XCCDF compliance
            description = self._strip_html_tags(rule.metadata.get("description", "No description"))
            rationale = self._strip_html_tags(rule.metadata.get("rationale", "No rationale provided"))

            xml_lines.extend(
                [
                    "",
                    f'  <xccdf:Rule id="{rule_id}" severity="{rule.severity}">',
                    f'    <xccdf:title>{rule.metadata.get("name", "Unknown Rule")}</xccdf:title>',
                    f"    <xccdf:description>{description}</xccdf:description>",
                    f"    <xccdf:rationale>{rationale}</xccdf:rationale>",
                ]
            )

            # Add OVAL check reference if available
            actual_oval_id = rule_to_oval_map.get(rule.rule_id)
            if actual_oval_id:
                xml_lines.extend(
                    [
                        '    <xccdf:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">',
                        f'      <xccdf:check-content-ref name="{actual_oval_id}" href="oval-definitions.xml"/>',
                        "    </xccdf:check>",
                    ]
                )
                rules_with_checks += 1

            xml_lines.append("  </xccdf:Rule>")

        self._logger.info(
            "Added %d XCCDF rules (%d with OVAL checks)",
            len(rules),
            rules_with_checks,
        )

        xml_lines.append("</xccdf:Benchmark>")

        return "\n".join(xml_lines)

    def _strip_html_tags(self, text: str) -> str:
        """
        Strip HTML tags from text for XCCDF compliance.

        XCCDF only allows plain text or properly namespaced XHTML.
        We strip all HTML to avoid schema validation errors.

        Args:
            text: Text that may contain HTML.

        Returns:
            Clean text safe for XCCDF.
        """
        if not text:
            return ""

        # Remove all HTML tags
        text = re.sub(r"<[^>]+>", "", text)

        # Clean up whitespace
        text = re.sub(r"\s+", " ", text)

        # Escape XML special characters
        text = text.replace("&", "&amp;")
        text = text.replace("<", "&lt;")
        text = text.replace(">", "&gt;")
        text = text.replace('"', "&quot;")
        text = text.replace("'", "&apos;")

        return text.strip()

    # =========================================================================
    # Scan Execution Methods
    # =========================================================================

    async def scan_with_rules(
        self,
        host_id: str,
        hostname: str,
        platform: str,
        platform_version: str,
        framework: Optional[str] = None,
        connection_params: Optional[Dict] = None,
        severity_filter: Optional[List[str]] = None,
        rule_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Execute SCAP scan using compliance rules.

        Complete workflow:
        1. Select rules (by IDs or platform/framework)
        2. Resolve rule inheritance
        3. Generate SCAP profile
        4. Execute scan (local or remote)
        5. Enrich results

        Args:
            host_id: UUID of the target host
            hostname: Hostname or IP address
            platform: Target platform (e.g., "rhel9")
            platform_version: Platform version
            framework: Optional compliance framework filter
            connection_params: SSH connection parameters (remote scan)
            severity_filter: Optional severity level filter
            rule_ids: Optional specific rule IDs to scan

        Returns:
            Dictionary with scan results and enrichment data.

        Raises:
            ScanExecutionError: If scan execution fails.
        """
        if not self._initialized:
            await self.initialize()

        scan_id = f"unified_scan_{host_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self._logger.info("Starting unified scan %s for %s", scan_id, hostname)

        try:
            # Step 1: Select rules
            if rule_ids:
                self._logger.info("Using %d user-selected rules", len(rule_ids))
                rules = await self.get_rules_by_ids(rule_ids)
            else:
                self._logger.info(
                    "Auto-selecting rules for platform %s %s",
                    platform,
                    platform_version,
                )
                rules = await self.select_platform_rules(
                    platform=platform,
                    platform_version=platform_version,
                    framework=framework,
                    severity_filter=severity_filter,
                )

            if not rules:
                error_msg = f"No compliance rules found for platform {platform} {platform_version}"
                if framework:
                    error_msg += f" with framework '{framework}'"
                error_msg += ". Please import compliance bundles using the admin interface."
                self._logger.warning(error_msg)
                return {
                    "success": False,
                    "error": error_msg,
                    "scan_id": scan_id,
                    "details": {
                        "platform": platform,
                        "platform_version": platform_version,
                        "framework": framework,
                    },
                }

            # Step 2: Resolve inheritance
            resolved_rules = await self._resolve_rule_inheritance(rules, platform)

            # Step 3: Generate SCAP profile
            profile_name = f"{framework or 'Standard'} Profile"
            profile_path, oval_path = await self.generate_scan_profile(resolved_rules, profile_name, platform)

            # Step 4: Execute scan
            scan_result = await self._execute_scan(
                scan_id=scan_id,
                hostname=hostname,
                profile_path=profile_path,
                profile_name=profile_name,
                connection_params=connection_params,
                platform=platform,
            )

            # Step 5: Enrich results
            enriched_result = await self._enrich_scan_results(scan_result, resolved_rules)

            self._logger.info("Unified scan %s completed successfully", scan_id)
            return enriched_result

        except Exception as e:
            self._logger.error("Unified scan %s failed: %s", scan_id, e)
            raise ScanExecutionError(
                message=f"Scan execution failed: {e}",
                scan_id=scan_id,
                cause=e,
            )

    async def _resolve_rule_inheritance(
        self,
        rules: List[Any],
        platform: str,
    ) -> List[Any]:
        """
        Resolve rule inheritance and parameter overrides.

        Args:
            rules: List of rule objects
            platform: Target platform

        Returns:
            List of resolved rules.
        """
        try:
            self._logger.info(
                "Resolving inheritance for %d rules on %s",
                len(rules),
                platform,
            )

            resolved_rules = []
            for rule in rules:
                if hasattr(rule, "inherits_from") and rule.inherits_from:
                    try:
                        parent_data = await self.rule_service.get_rule_with_dependencies(
                            rule_id=rule.inherits_from,
                            resolve_depth=3,
                            include_conflicts=True,
                        )
                        resolved_rule = self._merge_inherited_rule(rule, parent_data, platform)
                        resolved_rules.append(resolved_rule)
                    except Exception as e:
                        self._logger.warning(
                            "Failed to resolve inheritance for %s: %s",
                            rule.rule_id,
                            e,
                        )
                        resolved_rules.append(rule)
                else:
                    resolved_rules.append(rule)

            self._logger.info("Resolved inheritance for %d rules", len(resolved_rules))
            return resolved_rules

        except Exception as e:
            self._logger.error("Rule inheritance resolution failed: %s", e)
            return rules

    def _merge_inherited_rule(
        self,
        child_rule: Any,
        parent_data: Dict,
        platform: str,
    ) -> Any:
        """
        Merge child rule with parent rule data.

        Args:
            child_rule: Child rule
            parent_data: Parent rule data dict
            platform: Target platform

        Returns:
            Merged rule data.
        """
        try:
            parent_rule_data = parent_data.get("rule", {})
            merged_data = child_rule.dict() if hasattr(child_rule, "dict") else dict(child_rule)

            # Merge platform implementations
            if "platform_implementations" in parent_rule_data:
                parent_platforms = parent_rule_data["platform_implementations"]
                child_platforms = merged_data.get("platform_implementations", {})

                for p_name, p_impl in parent_platforms.items():
                    if p_name not in child_platforms:
                        child_platforms[p_name] = p_impl
                    elif p_name == platform:
                        merged_impl = {**p_impl, **child_platforms[p_name]}
                        child_platforms[p_name] = merged_impl

                merged_data["platform_implementations"] = child_platforms

            # Merge frameworks
            if "frameworks" in parent_rule_data:
                parent_frameworks = parent_rule_data["frameworks"]
                child_frameworks = merged_data.get("frameworks", {})

                for framework, versions in parent_frameworks.items():
                    if framework not in child_frameworks:
                        child_frameworks[framework] = versions
                    else:
                        child_frameworks[framework].update(versions)

                merged_data["frameworks"] = child_frameworks

            # Merge tags
            if "tags" in parent_rule_data:
                parent_tags = set(parent_rule_data["tags"])
                child_tags = set(merged_data.get("tags", []))
                merged_data["tags"] = list(parent_tags.union(child_tags))

            return merged_data

        except Exception as e:
            self._logger.error("Failed to merge inherited rule: %s", e)
            return child_rule

    async def _execute_scan(
        self,
        scan_id: str,
        hostname: str,
        profile_path: str,
        profile_name: str,
        connection_params: Optional[Dict],
        platform: str,
    ) -> Dict[str, Any]:
        """
        Execute the SCAP scan (local or remote).

        Args:
            scan_id: Unique scan identifier
            hostname: Target hostname
            profile_path: Path to generated XCCDF profile
            profile_name: Profile name
            connection_params: SSH connection parameters (None for local)
            platform: Target platform

        Returns:
            Dictionary with scan execution results.
        """
        # Generate XCCDF-compliant profile ID
        profile_id = f"xccdf_com.openwatch_profile_{profile_name.lower().replace(' ', '_')}"
        result_file = self.results_dir / f"{scan_id}_results.xml"

        if connection_params:
            # Remote scan
            return await self._execute_remote_scan(
                scan_id=scan_id,
                hostname=hostname,
                profile_path=profile_path,
                profile_id=profile_id,
                connection_params=connection_params,
                result_file=result_file,
            )
        else:
            # Local scan
            return self._execute_local_scan(
                scan_id=scan_id,
                profile_path=profile_path,
                profile_id=profile_id,
                result_file=result_file,
            )

    def _execute_local_scan(
        self,
        scan_id: str,
        profile_path: str,
        profile_id: str,
        result_file: Path,
    ) -> Dict[str, Any]:
        """
        Execute local SCAP scan using subprocess.

        Args:
            scan_id: Unique scan identifier
            profile_path: Path to XCCDF profile
            profile_id: Profile ID
            result_file: Path for result output

        Returns:
            Dictionary with scan results.
        """
        import subprocess

        self._logger.info("Executing local scan: %s", scan_id)

        # Build command as list (prevents command injection)
        cmd = [
            "oscap",
            "xccdf",
            "eval",
            "--profile",
            profile_id,
            "--results",
            str(result_file),
            "--report",
            str(result_file).replace(".xml", ".html"),
            profile_path,
        ]

        self._logger.info("Executing: %s", " ".join(cmd))

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )

        if result.returncode not in [0, 2]:
            self._logger.error(
                "oscap returned exit code %d: %s",
                result.returncode,
                result.stderr,
            )

        return {
            "success": True,
            "scan_id": scan_id,
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "result_file": str(result_file),
            "report_file": str(result_file).replace(".xml", ".html"),
        }

    async def _execute_remote_scan(
        self,
        scan_id: str,
        hostname: str,
        profile_path: str,
        profile_id: str,
        connection_params: Dict,
        result_file: Path,
    ) -> Dict[str, Any]:
        """
        Execute remote SCAP scan via SSH.

        Uses SSHExecutor for remote execution with credential resolution.

        Args:
            scan_id: Unique scan identifier
            hostname: Target hostname
            profile_path: Path to XCCDF profile
            profile_id: Profile ID
            connection_params: SSH parameters
            result_file: Path for result output

        Returns:
            Dictionary with scan results.
        """
        from app.database import SessionLocal

        from ..executors import SSHExecutor

        self._logger.info("Executing remote scan on %s", hostname)

        db = SessionLocal()
        try:
            # Resolve credentials
            if not self.encryption_service:
                raise ScanExecutionError(
                    message="Encryption service required for remote scans",
                    scan_id=scan_id,
                )

            from sqlalchemy import text

            host_result = db.execute(
                text("SELECT auth_method FROM hosts WHERE id = :host_id"),
                {"host_id": connection_params.get("host_id")},
            ).fetchone()

            if not host_result:
                raise ScanExecutionError(
                    message=f"Host {connection_params.get('host_id')} not found",
                    scan_id=scan_id,
                )

            host_auth_method = host_result[0]
            use_default = host_auth_method in ["system_default", "default"]
            target_id = None if use_default else connection_params.get("host_id")

            auth_service = get_auth_service(db, self.encryption_service)
            credential_data = auth_service.resolve_credential(
                target_id=target_id,
                use_default=use_default,
            )

            if not credential_data:
                raise ScanExecutionError(
                    message=f"No credentials for host {connection_params.get('host_id')}",
                    scan_id=scan_id,
                )

            # Create execution context
            context = ExecutionContext(
                scan_id=scan_id,
                scan_type=ScanType.XCCDF_PROFILE,
                hostname=hostname,
                port=connection_params.get("port", 22),
                username=credential_data.username,
                timeout=1800,
                working_dir=self.results_dir,
            )

            # Execute via SSH executor
            executor = SSHExecutor(db)
            result = executor.execute(
                context=context,
                content_path=Path(profile_path),
                profile_id=profile_id,
                credential_data=credential_data,
            )

            return {
                "success": result.success,
                "scan_id": scan_id,
                "return_code": result.exit_code,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "result_file": str(result.result_files.get("xml", result_file)),
                "report_file": str(result.result_files.get("html", "")),
                "execution_time": result.execution_time_seconds,
                "files_transferred": getattr(result, "files_transferred", 0),
            }

        finally:
            db.close()

    async def _enrich_scan_results(
        self,
        scan_result: Dict,
        rules: List[Any],
    ) -> Dict[str, Any]:
        """
        Enrich scan results with rule metadata.

        Args:
            scan_result: Raw scan results
            rules: Rule objects used in scan

        Returns:
            Enriched result dictionary.
        """
        try:
            if not scan_result.get("success") or not scan_result.get("result_file"):
                return scan_result

            result_file = scan_result["result_file"]
            if not Path(result_file).exists():
                self._logger.warning("Result file not found: %s", result_file)
                return scan_result

            scan_result["rules_used"] = len(rules)
            scan_result["enriched_at"] = datetime.utcnow().isoformat()

            return scan_result

        except Exception as e:
            self._logger.error("Failed to enrich results: %s", e)
            return scan_result

    # =========================================================================
    # Utility Methods
    # =========================================================================

    def _parse_basic_results(self, result_path: Path) -> Dict[str, Any]:
        """Basic result parsing fallback."""
        try:
            with open(result_path, "r", encoding="utf-8") as f:
                content = f.read()

            pass_count = content.count('result="pass"')
            fail_count = content.count('result="fail"')
            error_count = content.count('result="error"')

            total = pass_count + fail_count + error_count
            pass_rate = (pass_count / total * 100) if total > 0 else 0.0

            return {
                "format": "xccdf",
                "source_file": str(result_path),
                "statistics": {
                    "pass_count": pass_count,
                    "fail_count": fail_count,
                    "error_count": error_count,
                    "total_count": total,
                    "pass_rate": round(pass_rate, 2),
                },
                "has_findings": fail_count > 0,
            }

        except Exception as e:
            self._logger.error("Basic result parsing failed: %s", e)
            return {"error": str(e)}

    # =========================================================================
    # Legacy Compatibility Methods
    # =========================================================================
    # These methods provide backward compatibility with the legacy SCAPScanner
    # interface used by scan_tasks.py, rule_specific_scanner.py, and
    # unified_validation_service.py. They delegate to SSHConnectionManager
    # or the internal execution methods.

    def test_ssh_connection(
        self,
        hostname: str,
        port: int,
        username: str,
        auth_method: str,
        credential: str,
    ) -> Dict[str, Any]:
        """
        Test SSH connection to remote host (legacy compatibility method).

        This method provides backward compatibility with the SCAPScanner interface.
        It delegates to SSHConnectionManager for the actual connection test.

        Args:
            hostname: Target hostname or IP address.
            port: SSH port number.
            username: SSH username.
            auth_method: Authentication method ('password' or 'ssh_key').
            credential: Password or private key content.

        Returns:
            Dictionary with connection test results:
            - success: Whether connection was successful
            - message: Status message
            - oscap_available: Whether OpenSCAP is installed on target
            - oscap_version: Version of OpenSCAP (if available)
        """
        from app.services.ssh import SSHConnectionManager

        self._logger.info("Testing SSH connection to %s@%s:%d", username, hostname, port)

        ssh_manager = SSHConnectionManager()

        # Use unified SSH service to establish connection
        connection_result = ssh_manager.connect_with_credentials(
            hostname=hostname,
            port=port,
            username=username,
            auth_method=auth_method,
            credential=credential,
            service_name="UnifiedSCAPScanner_Connection_Test",
            timeout=10,
        )

        if not connection_result.success:
            self._logger.error(
                "SSH connection test failed for %s: %s",
                hostname,
                connection_result.error_message,
            )
            return {
                "success": False,
                "message": f"SSH connection failed: {connection_result.error_message}",
                "oscap_available": False,
            }

        # Test basic command execution and check OpenSCAP availability
        try:
            ssh = connection_result.connection
            if ssh is None:
                return {
                    "success": False,
                    "message": "SSH connection not established",
                    "oscap_available": False,
                }

            # Test basic command execution
            test_result = ssh_manager.execute_command_advanced(
                ssh_connection=ssh,
                command='echo "OpenWatch SSH Test"',
                timeout=5,
            )

            if not test_result.success:
                ssh.close()
                return {
                    "success": False,
                    "message": f"SSH command test failed: {test_result.error_message}",
                    "oscap_available": False,
                }

            # Check if oscap is available on remote host
            oscap_result = ssh_manager.execute_command_advanced(
                ssh_connection=ssh,
                command="oscap --version",
                timeout=5,
            )

            oscap_available = oscap_result.success
            oscap_version = oscap_result.stdout.strip() if oscap_available else None

            ssh.close()

            result: Dict[str, Any] = {
                "success": True,
                "message": "SSH connection successful",
                "oscap_available": oscap_available,
                "oscap_version": oscap_version,
                "test_output": test_result.stdout.strip(),
            }

            if not oscap_available:
                result["warning"] = "OpenSCAP not found on remote host"
                self._logger.warning(
                    "OpenSCAP not available on %s: %s",
                    hostname,
                    oscap_result.error_message,
                )
            else:
                self._logger.info(
                    "SSH test successful: %s (OpenSCAP available: %s)",
                    hostname,
                    oscap_version,
                )

            return result

        except Exception as e:
            # Ensure connection is closed even if test fails
            try:
                if connection_result.connection:
                    connection_result.connection.close()
            except Exception:
                self._logger.debug("Ignoring exception during cleanup")

            self._logger.error("SSH test error for %s: %s", hostname, e)
            return {
                "success": False,
                "message": f"Connection test failed: {str(e)}",
                "oscap_available": False,
            }

    def execute_local_scan(
        self,
        content_path: str,
        profile_id: str,
        scan_id: str,
        rule_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute SCAP scan on local system (legacy compatibility method).

        This method provides backward compatibility with the SCAPScanner interface.
        It validates inputs and executes oscap directly.

        Args:
            content_path: Path to SCAP content file.
            profile_id: XCCDF profile ID to scan.
            scan_id: Unique scan identifier.
            rule_id: Optional specific rule to scan.

        Returns:
            Dictionary with scan results including file paths and statistics.

        Raises:
            ScanExecutionError: If scan execution fails.
        """
        import os
        import subprocess

        try:
            # Validate inputs to prevent command injection
            if not isinstance(content_path, str) or ".." in content_path:
                raise ScanExecutionError(
                    message=f"Invalid or unsafe content path: {content_path}",
                    scan_id=scan_id,
                )

            if not os.path.isfile(content_path):
                raise ScanExecutionError(
                    message=f"Content file not found: {content_path}",
                    scan_id=scan_id,
                )

            if not isinstance(profile_id, str) or not re.match(r"^[a-zA-Z0-9_:.-]+$", profile_id):
                raise ScanExecutionError(
                    message=f"Invalid profile_id format: {profile_id}",
                    scan_id=scan_id,
                )

            if not isinstance(scan_id, str) or not re.match(r"^[a-zA-Z0-9_-]+$", scan_id):
                raise ScanExecutionError(
                    message=f"Invalid scan_id format: {scan_id}",
                    scan_id=scan_id,
                )

            if rule_id and (not isinstance(rule_id, str) or not re.match(r"^[a-zA-Z0-9_:.-]+$", rule_id)):
                raise ScanExecutionError(
                    message=f"Invalid rule_id format: {rule_id}",
                    scan_id=scan_id,
                )

            self._logger.info("Starting local scan: %s", scan_id)

            # Create result directory for this scan
            scan_dir = self.results_dir / scan_id
            scan_dir.mkdir(exist_ok=True)

            # Define output files
            xml_result = scan_dir / "results.xml"
            html_report = scan_dir / "report.html"
            arf_result = scan_dir / "results.arf.xml"

            # Build command as list (prevents command injection)
            cmd = [
                "oscap",
                "xccdf",
                "eval",
                "--profile",
                profile_id,
                "--results",
                str(xml_result),
                "--report",
                str(html_report),
                "--results-arf",
                str(arf_result),
            ]

            # Add rule-specific scanning if rule_id is provided
            if rule_id:
                cmd.extend(["--rule", rule_id])
                self._logger.info("Scanning specific rule: %s", rule_id)

            cmd.append(content_path)

            self._logger.info("Executing local SCAP scan with profile: %s", profile_id)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800,  # 30 minutes timeout
            )

            # Parse results
            scan_results = self._parse_scan_results(str(xml_result), content_path)
            scan_results.update(
                {
                    "scan_id": scan_id,
                    "scan_type": "local",
                    "exit_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "xml_result": str(xml_result),
                    "html_report": str(html_report),
                    "arf_result": str(arf_result),
                }
            )

            self._logger.info("Local scan completed: %s", scan_id)
            return scan_results

        except subprocess.TimeoutExpired:
            self._logger.error("Scan timeout: %s", scan_id)
            raise ScanExecutionError(
                message="Scan execution timeout",
                scan_id=scan_id,
            )
        except ScanExecutionError:
            raise
        except Exception as e:
            self._logger.error("Local scan failed: %s", e)
            raise ScanExecutionError(
                message=f"Scan execution failed: {str(e)}",
                scan_id=scan_id,
                cause=e,
            )

    def execute_remote_scan(
        self,
        hostname: str,
        port: int,
        username: str,
        auth_method: str,
        credential: str,
        content_path: str,
        profile_id: str,
        scan_id: str,
        rule_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute SCAP scan on remote system via SSH (legacy compatibility method).

        This method provides backward compatibility with the SCAPScanner interface.
        It validates inputs and delegates to the internal remote scan method.

        Args:
            hostname: Target hostname or IP address.
            port: SSH port number.
            username: SSH username.
            auth_method: Authentication method.
            credential: Password or private key content.
            content_path: Path to SCAP content file.
            profile_id: XCCDF profile ID to scan.
            scan_id: Unique scan identifier.
            rule_id: Optional specific rule to scan.

        Returns:
            Dictionary with scan results including file paths and statistics.

        Raises:
            ScanExecutionError: If scan execution fails.
        """
        import os

        try:
            # Validate inputs to prevent injection attacks
            if not isinstance(hostname, str) or not re.match(r"^[a-zA-Z0-9.-]+$", hostname):
                raise ScanExecutionError(
                    message=f"Invalid hostname format: {hostname}",
                    scan_id=scan_id,
                )

            if not isinstance(port, int) or port < 1 or port > 65535:
                raise ScanExecutionError(
                    message=f"Invalid port number: {port}",
                    scan_id=scan_id,
                )

            if not isinstance(username, str) or not re.match(r"^[a-zA-Z0-9_-]+$", username):
                raise ScanExecutionError(
                    message=f"Invalid username format: {username}",
                    scan_id=scan_id,
                )

            if not isinstance(content_path, str) or ".." in content_path:
                raise ScanExecutionError(
                    message=f"Invalid or unsafe content path: {content_path}",
                    scan_id=scan_id,
                )

            if not os.path.isfile(content_path):
                raise ScanExecutionError(
                    message=f"Content file not found: {content_path}",
                    scan_id=scan_id,
                )

            if not isinstance(profile_id, str) or not re.match(r"^[a-zA-Z0-9_:.-]+$", profile_id):
                raise ScanExecutionError(
                    message=f"Invalid profile_id format: {profile_id}",
                    scan_id=scan_id,
                )

            if not isinstance(scan_id, str) or not re.match(r"^[a-zA-Z0-9_-]+$", scan_id):
                raise ScanExecutionError(
                    message=f"Invalid scan_id format: {scan_id}",
                    scan_id=scan_id,
                )

            if rule_id and (not isinstance(rule_id, str) or not re.match(r"^[a-zA-Z0-9_:.-]+$", rule_id)):
                raise ScanExecutionError(
                    message=f"Invalid rule_id format: {rule_id}",
                    scan_id=scan_id,
                )

            self._logger.info("Starting remote scan: %s on %s", scan_id, hostname)

            # Create result directory for this scan
            scan_dir = self.results_dir / scan_id
            scan_dir.mkdir(exist_ok=True)

            # Define output files
            xml_result = scan_dir / "results.xml"
            html_report = scan_dir / "report.html"
            arf_result = scan_dir / "results.arf.xml"

            # Execute remote scan via SSH
            return self._execute_remote_scan_with_paramiko(
                hostname=hostname,
                port=port,
                username=username,
                auth_method=auth_method,
                credential=credential,
                content_path=content_path,
                profile_id=profile_id,
                scan_id=scan_id,
                xml_result=xml_result,
                html_report=html_report,
                arf_result=arf_result,
                rule_id=rule_id,
            )

        except ScanExecutionError:
            raise
        except Exception as e:
            self._logger.error("Remote scan failed: %s", e)
            raise ScanExecutionError(
                message=f"Remote scan execution failed: {str(e)}",
                scan_id=scan_id,
                cause=e,
            )

    def _execute_remote_scan_with_paramiko(
        self,
        hostname: str,
        port: int,
        username: str,
        auth_method: str,
        credential: str,
        content_path: str,
        profile_id: str,
        scan_id: str,
        xml_result: Path,
        html_report: Path,
        arf_result: Path,
        rule_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute remote SCAP scan using paramiko SSH.

        Args:
            hostname: Target hostname.
            port: SSH port.
            username: SSH username.
            auth_method: Authentication method.
            credential: Password or private key.
            content_path: Local path to SCAP content.
            profile_id: XCCDF profile ID.
            scan_id: Unique scan identifier.
            xml_result: Path for XML results.
            html_report: Path for HTML report.
            arf_result: Path for ARF results.
            rule_id: Optional specific rule to scan.

        Returns:
            Dictionary with scan results.
        """
        from app.services.ssh import SSHConnectionManager

        ssh_manager = SSHConnectionManager()

        self._logger.info("Executing remote scan on %s via paramiko", hostname)

        # Connect to remote host
        connection_result = ssh_manager.connect_with_credentials(
            hostname=hostname,
            port=port,
            username=username,
            auth_method=auth_method,
            credential=credential,
            service_name="UnifiedSCAPScanner_Remote_Scan",
            timeout=30,
        )

        if not connection_result.success:
            raise ScanExecutionError(
                message=f"SSH connection failed: {connection_result.error_message}",
                scan_id=scan_id,
            )

        ssh = connection_result.connection
        if ssh is None:
            raise ScanExecutionError(
                message="SSH connection not established",
                scan_id=scan_id,
            )

        try:
            # Create remote temp directory
            remote_dir = f"/tmp/openwatch_scan_{scan_id}"
            ssh_manager.execute_command_advanced(
                ssh_connection=ssh,
                command=f"mkdir -p {remote_dir}",
                timeout=10,
            )

            # Upload SCAP content
            remote_content = f"{remote_dir}/content.xml"
            sftp = ssh.open_sftp()
            sftp.put(content_path, remote_content)
            sftp.close()

            # Build oscap command
            remote_xml_result = f"{remote_dir}/results.xml"
            remote_html_report = f"{remote_dir}/report.html"
            remote_arf_result = f"{remote_dir}/results.arf.xml"

            cmd = (
                f"oscap xccdf eval "
                f"--profile {profile_id} "
                f"--results {remote_xml_result} "
                f"--report {remote_html_report} "
                f"--results-arf {remote_arf_result}"
            )

            if rule_id:
                cmd += f" --rule {rule_id}"

            cmd += f" {remote_content}"

            # Execute scan
            self._logger.info("Executing remote oscap command")
            scan_result = ssh_manager.execute_command_advanced(
                ssh_connection=ssh,
                command=cmd,
                timeout=1800,  # 30 minutes
            )

            # Download results
            sftp = ssh.open_sftp()
            try:
                sftp.get(remote_xml_result, str(xml_result))
                sftp.get(remote_html_report, str(html_report))
                sftp.get(remote_arf_result, str(arf_result))
            except Exception as e:
                self._logger.warning("Could not download some result files: %s", e)
            sftp.close()

            # Clean up remote files
            ssh_manager.execute_command_advanced(
                ssh_connection=ssh,
                command=f"rm -rf {remote_dir}",
                timeout=10,
            )

            # Parse results
            scan_results = self._parse_scan_results(str(xml_result), content_path)
            scan_results.update(
                {
                    "scan_id": scan_id,
                    "scan_type": "remote",
                    "hostname": hostname,
                    "exit_code": 0 if scan_result.success else 1,
                    "stdout": scan_result.stdout,
                    "stderr": scan_result.stderr,
                    "xml_result": str(xml_result),
                    "html_report": str(html_report),
                    "arf_result": str(arf_result),
                }
            )

            self._logger.info("Remote scan completed: %s", scan_id)
            return scan_results

        finally:
            ssh.close()

    def _parse_scan_results(
        self,
        xml_file: str,
        content_file: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Parse SCAP scan results from XML file (legacy compatibility method).

        This method provides backward compatibility with the SCAPScanner interface.

        Args:
            xml_file: Path to XCCDF results XML file.
            content_file: Optional path to SCAP content for remediation extraction.

        Returns:
            Dictionary with parsed scan results.
        """
        import os
        from datetime import datetime

        try:
            if not os.path.exists(xml_file):
                return {"error": "Results file not found"}

            # Use lxml for parsing (same as legacy SCAPScanner)
            import lxml.etree as etree

            tree = etree.parse(xml_file)
            root = tree.getroot()

            namespaces: Dict[str, str] = {"xccdf": "http://checklists.nist.gov/xccdf/1.2"}

            # Initialize results
            failed_rules_list: List[Dict[str, Any]] = []
            rule_details_list: List[Dict[str, Any]] = []

            results: Dict[str, Any] = {
                "timestamp": datetime.now().isoformat(),
                "rules_total": 0,
                "rules_passed": 0,
                "rules_failed": 0,
                "rules_error": 0,
                "rules_unknown": 0,
                "rules_notapplicable": 0,
                "rules_notchecked": 0,
                "score": 0.0,
                "failed_rules": failed_rules_list,
                "rule_details": rule_details_list,
            }

            # Count rule results
            rule_results = root.xpath("//xccdf:rule-result", namespaces=namespaces)
            results["rules_total"] = len(rule_results)

            for rule_result in rule_results:
                result_elem = rule_result.find("xccdf:result", namespaces)
                if result_elem is not None:
                    result_value = result_elem.text
                    rule_id = rule_result.get("idref", "")
                    severity = rule_result.get("severity", "unknown")

                    rule_detail = {
                        "rule_id": rule_id,
                        "result": result_value,
                        "severity": severity,
                    }
                    rule_details_list.append(rule_detail)

                    # Count by result type
                    if result_value == "pass":
                        results["rules_passed"] = int(results["rules_passed"]) + 1
                    elif result_value == "fail":
                        results["rules_failed"] = int(results["rules_failed"]) + 1
                        failed_rules_list.append({"rule_id": rule_id, "severity": severity})
                    elif result_value == "error":
                        results["rules_error"] = int(results["rules_error"]) + 1
                    elif result_value == "unknown":
                        results["rules_unknown"] = int(results["rules_unknown"]) + 1
                    elif result_value == "notapplicable":
                        results["rules_notapplicable"] = int(results["rules_notapplicable"]) + 1
                    elif result_value == "notchecked":
                        results["rules_notchecked"] = int(results["rules_notchecked"]) + 1

            # Calculate score
            rules_total = int(results["rules_total"])
            rules_passed = int(results["rules_passed"])
            rules_failed = int(results["rules_failed"])
            if rules_total > 0:
                divisor = rules_passed + rules_failed
                if divisor > 0:
                    results["score"] = (rules_passed / divisor) * 100
                else:
                    results["score"] = 0.0

            return results

        except Exception as e:
            self._logger.error("Error parsing scan results: %s", e)
            return {"error": f"Failed to parse results: {str(e)}"}


# =============================================================================
# Backward Compatibility Alias
# =============================================================================

# Alias for backward compatibility with existing code that imports
# UnifiedSCAPScanner. New code should use OWScanner directly.
UnifiedSCAPScanner = OWScanner
