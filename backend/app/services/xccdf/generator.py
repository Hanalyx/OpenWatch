#!/usr/bin/env python3
"""
XCCDF Generator Service - Generate XCCDF 1.2 Data-Streams from MongoDB Rules

This service generates compliant XCCDF 1.2 XML content for scanning:
- Benchmarks with rules, groups, profiles
- XCCDF Value elements for scan-time customization
- Tailoring files for variable overrides
- Integration with OVAL definitions

Part of Phase 1, Issue #3: XCCDF Data-Stream Generator from MongoDB
"""

import logging
import xml.etree.ElementTree as ET  # nosec B405 - parsing trusted SCAP content
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from xml.dom import minidom  # nosec B408 - parsing trusted XCCDF output

from motor.motor_asyncio import AsyncIOMotorDatabase

logger = logging.getLogger(__name__)


class XCCDFGeneratorService:
    """
    Generates XCCDF 1.2 compliant XML from MongoDB compliance rules

    XCCDF (Extensible Configuration Checklist Description Format) is the
    standard format for security configuration checklists.

    Spec: https://csrc.nist.gov/publications/detail/nistir/7275/rev-4/final
    """

    # XCCDF 1.2 XML Namespaces
    NAMESPACES = {
        "xccdf": "http://checklists.nist.gov/xccdf/1.2",
        "xhtml": "http://www.w3.org/1999/xhtml",
        "dc": "http://purl.org/dc/elements/1.1/",
        "xsi": "http://www.w3.org/2001/XMLSchema-instance",
    }

    # Register namespaces for ElementTree
    for prefix, uri in NAMESPACES.items():
        ET.register_namespace(prefix, uri)

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.compliance_rules
        # Phase 3: Target platform for platform-aware OVAL selection
        # Set during generate_benchmark() call, used by _create_xccdf_rule()
        self._target_platform: Optional[str] = None

    async def generate_benchmark(
        self,
        benchmark_id: str,
        title: str,
        description: str,
        version: str,
        framework: Optional[str] = None,
        framework_version: Optional[str] = None,
        rule_filter: Optional[Dict] = None,
        target_capabilities: Optional[Set[str]] = None,
        oval_base_path: Optional[Path] = None,
        target_platform: Optional[str] = None,
    ) -> str:
        """
        Generate XCCDF Benchmark XML from MongoDB rules.

        Args:
            benchmark_id: Unique benchmark identifier (e.g., "openwatch-nist-800-53r5")
            title: Human-readable benchmark title
            description: Detailed description of the benchmark
            version: Benchmark version string
            framework: Framework to filter by (nist, cis, stig, etc.)
            framework_version: Specific framework version (e.g., "800-53r5")
            rule_filter: Additional MongoDB query filter
            target_capabilities: Set of components available on target system
                               (e.g., {'gnome', 'openssh', 'audit'})
                               Rules requiring missing components will be excluded
                               to reduce scan errors and improve pass rates
            oval_base_path: Base path to OVAL definitions directory
                           (default: /app/data/oval_definitions)
                           Used to validate OVAL check availability
            target_platform: Target host platform identifier (e.g., "rhel9", "ubuntu2204").
                           CRITICAL: When provided, only rules with platform-specific OVAL
                           definitions (platform_implementations.{platform}.oval_filename)
                           will be included. Rules without matching platform OVAL are
                           skipped and marked as "not applicable" for compliance accuracy.

        Returns:
            XCCDF Benchmark XML as string

        Platform-Aware OVAL Selection (Phase 3):
            When target_platform is provided:
            1. Uses platform_implementations.{platform}.oval_filename for OVAL lookup
            2. Rules without platform-specific OVAL are skipped (not applicable)
            3. No fallback to rule-level oval_filename (compliance accuracy)

            This ensures compliance scans use platform-correct OVAL definitions,
            preventing false positives/negatives from cross-platform OVAL mismatches.

        Component Filtering Strategy:
            If target_capabilities is provided, rules are filtered by:
            1. Component applicability: Rules with components not in target_capabilities
               are excluded (marked as "notapplicable" in native OpenSCAP terms)
            2. OVAL check availability: Rules without OVAL definition files are excluded
               (marked as "notchecked" in native OpenSCAP terms)

            This filtering replicates native OpenSCAP behavior and reduces scan errors
            from checking inapplicable rules (e.g., GUI rules on headless systems).

            Expected Impact:
            - Reduce errors by 20-30 (from ~149 to ~120)
            - Improve pass rate by 4-7% (from 77% to ~81-84%)
            - Exclude ~16 GUI rules on headless systems
            - Exclude ~24 rules without OVAL checks
        """
        logger.info(f"Generating XCCDF Benchmark: {benchmark_id}")

        # Phase 3: Store target platform for platform-aware OVAL selection
        # Used by _create_xccdf_rule() to look up platform-specific OVAL
        self._target_platform = target_platform

        # Build query filter
        query = {"is_latest": True}
        if rule_filter:
            query.update(rule_filter)

        # Framework-specific filtering
        if framework and framework_version:
            query[f"frameworks.{framework}.{framework_version}"] = {"$exists": True}

        # Fetch rules from MongoDB
        rules = await self.collection.find(query).to_list(length=None)
        logger.info(f"Found {len(rules)} rules matching criteria")

        # Set default OVAL base path if not provided
        if oval_base_path is None:
            oval_base_path = Path("/openwatch/data/oval_definitions")

        # Component-based filtering (if target capabilities provided)
        if target_capabilities is not None:
            original_count = len(rules)

            # Apply component and OVAL availability filtering
            # Pass target_platform for platform-aware OVAL lookup (Phase 3)
            rules, filter_stats = self._filter_by_capabilities(
                rules, target_capabilities, oval_base_path, target_platform
            )

            filtered_count = original_count - len(rules)
            logger.info(
                f"Component filtering: {filtered_count} rules excluded "
                f"({filter_stats['notapplicable']} notapplicable, "
                f"{filter_stats['notchecked']} notchecked), "
                f"{len(rules)} rules remaining"
            )
        elif target_platform is not None:
            # Platform-aware OVAL filtering without component filtering
            # This ensures only rules with platform-specific OVAL are included
            original_count = len(rules)
            rules, filter_stats = self._filter_by_platform_oval(rules, oval_base_path, target_platform)

            filtered_count = original_count - len(rules)
            logger.info(
                f"Platform OVAL filtering: {filtered_count} rules excluded "
                f"(missing {target_platform} OVAL), "
                f"{len(rules)} rules remaining"
            )

        # Create root Benchmark element
        benchmark = self._create_benchmark_element(benchmark_id, title, description, version)

        # Extract all unique variables across rules
        all_variables = self._extract_all_variables(rules)

        # Add XCCDF Value elements
        for var_id, var_def in all_variables.items():
            value_elem = self._create_xccdf_value(var_def)
            benchmark.append(value_elem)

        # Create Profile elements FIRST (XCCDF 1.2 schema requires profiles before groups)
        profiles = self._create_profiles(rules, framework, framework_version)
        for profile in profiles:
            benchmark.append(profile)

        # Group rules by category for better organization
        rules_by_category = self._group_rules_by_category(rules)

        # Create Group elements for each category
        for category, category_rules in rules_by_category.items():
            group = self._create_xccdf_group(category, category_rules)
            benchmark.append(group)

        # Convert to pretty-printed XML string
        return self._prettify_xml(benchmark)

    async def generate_tailoring(
        self,
        tailoring_id: str,
        benchmark_href: str,
        benchmark_version: str,
        profile_id: str,
        variable_overrides: Dict[str, str],
        title: Optional[str] = None,
        description: Optional[str] = None,
    ) -> str:
        """
        Generate XCCDF Tailoring file for variable customization

        Tailoring files allow users to customize variable values without
        modifying the original benchmark.

        Args:
            tailoring_id: Unique tailoring identifier
            benchmark_href: Reference to benchmark file
            benchmark_version: Version of benchmark being tailored
            profile_id: Profile to customize
            variable_overrides: Dict mapping variable IDs to custom values
            title: Optional custom title
            description: Optional description

        Returns:
            XCCDF Tailoring XML as string
        """
        logger.info(f"Generating XCCDF Tailoring: {tailoring_id}")

        # Create root Tailoring element
        tailoring = ET.Element(
            f"{{{self.NAMESPACES['xccdf']}}}Tailoring",
            {
                "id": tailoring_id,
                f"{{{self.NAMESPACES['xsi']}}}schemaLocation": "http://checklists.nist.gov/xccdf/1.2 "
                "http://scap.nist.gov/schema/xccdf/1.2/xccdf_1.2.xsd",
            },
        )

        # Add version
        version_elem = ET.SubElement(
            tailoring,
            f"{{{self.NAMESPACES['xccdf']}}}version",
            {"time": datetime.now(timezone.utc).isoformat()},
        )
        version_elem.text = "1.0"

        # Add benchmark reference
        _benchmark_elem = ET.SubElement(  # noqa: F841 - required by XCCDF spec, unused in Python
            tailoring,
            f"{{{self.NAMESPACES['xccdf']}}}benchmark",
            {"href": benchmark_href, "id": benchmark_version},
        )

        # Create Profile with variable overrides
        profile = ET.SubElement(
            tailoring,
            f"{{{self.NAMESPACES['xccdf']}}}Profile",
            {"id": f"{profile_id}_customized", "extends": profile_id},
        )

        # Add title
        title_elem = ET.SubElement(profile, f"{{{self.NAMESPACES['xccdf']}}}title")
        title_elem.text = title or f"Customized {profile_id}"

        # Add description
        if description:
            desc_elem = ET.SubElement(profile, f"{{{self.NAMESPACES['xccdf']}}}description")
            desc_elem.text = description

        # Add variable overrides
        for var_id, var_value in variable_overrides.items():
            set_value = ET.SubElement(profile, f"{{{self.NAMESPACES['xccdf']}}}set-value", {"idref": var_id})
            set_value.text = str(var_value)

        return self._prettify_xml(tailoring)

    async def generate_oval_definitions_file(
        self,
        rules: List[Dict[str, Any]],
        platform: str,
        output_path: Path,
    ) -> Optional[Path]:
        """
        Aggregate individual OVAL XML files into single oval-definitions.xml file.

        This method reads individual OVAL files from /app/data/oval_definitions/{platform}/
        and combines them into a single OVAL document that OSCAP can consume.

        Phase 3 Enhancement (Platform-Aware OVAL):
            Uses Option B schema for OVAL lookup:
            - Retrieves oval_filename from platform_implementations.{platform}.oval_filename
            - No fallback to rule-level oval_filename
            - Ensures correct platform OVAL is aggregated

        Args:
            rules: List of ComplianceRule documents
            platform: Platform identifier (rhel8, rhel9, ubuntu2204, etc.)
            output_path: Where to write the aggregated oval-definitions.xml

        Returns:
            Path to generated oval-definitions.xml, or None if no OVAL files found

        Example:
            >>> rules = await repo.find_by_platform("rhel8")
            >>> output_path = Path("/tmp/oval-definitions.xml")
            >>> result = await xccdf_gen.generate_oval_definitions_file(rules, "rhel8", output_path)
            >>> print(f"Created {result} with {len(rules)} definitions")
        """
        logger.info(f"Generating aggregated OVAL definitions file for platform: {platform}")

        oval_base_dir = Path("/openwatch/data/oval_definitions")

        # Collect unique OVAL filenames from rules
        # Phase 3: Use platform-specific OVAL from platform_implementations
        oval_filenames: Set[str] = set()
        for rule in rules:
            # Try platform-specific OVAL first (Option B schema)
            oval_filename = self._get_platform_oval_filename(rule, platform)

            # Validate it belongs to the correct platform
            if oval_filename and oval_filename.startswith(f"{platform}/"):
                oval_filenames.add(oval_filename)

        if not oval_filenames:
            logger.warning(f"No OVAL files found for platform {platform}")
            return None

        logger.info(f"Found {len(oval_filenames)} unique OVAL files for aggregation")

        # OVAL 5.11 namespaces
        oval_def_ns = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
        oval_common_ns = "http://oval.mitre.org/XMLSchema/oval-common-5"

        ET.register_namespace("oval-def", oval_def_ns)
        ET.register_namespace("oval", oval_common_ns)

        # Create root oval_definitions element
        root = ET.Element(
            f"{{{oval_def_ns}}}oval_definitions",
            {
                f"{{{self.NAMESPACES['xsi']}}}schemaLocation": "http://oval.mitre.org/XMLSchema/oval-definitions-5 "
                "oval-definitions-schema.xsd "
                "http://oval.mitre.org/XMLSchema/oval-common-5 "
                "oval-common-schema.xsd"
            },
        )

        # Create generator section (uses oval-common namespace per OVAL 5.11 spec)
        generator = ET.SubElement(root, f"{{{oval_def_ns}}}generator")
        product_name = ET.SubElement(generator, f"{{{oval_common_ns}}}product_name")
        product_name.text = "OpenWatch OVAL Aggregator"
        product_version = ET.SubElement(generator, f"{{{oval_common_ns}}}product_version")
        product_version.text = "1.0.0"
        schema_version = ET.SubElement(generator, f"{{{oval_common_ns}}}schema_version")
        schema_version.text = "5.11"
        timestamp = ET.SubElement(generator, f"{{{oval_common_ns}}}timestamp")
        timestamp.text = datetime.now(timezone.utc).isoformat()

        # Create container sections
        definitions_section = ET.SubElement(root, f"{{{oval_def_ns}}}definitions")
        tests_section = ET.SubElement(root, f"{{{oval_def_ns}}}tests")
        objects_section = ET.SubElement(root, f"{{{oval_def_ns}}}objects")
        states_section = ET.SubElement(root, f"{{{oval_def_ns}}}states")
        variables_section = ET.SubElement(root, f"{{{oval_def_ns}}}variables")

        # Track unique IDs to prevent duplicates
        seen_def_ids: Set[str] = set()
        seen_test_ids: Set[str] = set()
        seen_obj_ids: Set[str] = set()
        seen_state_ids: Set[str] = set()
        seen_var_ids: Set[str] = set()

        # Process each OVAL file
        processed_count = 0
        skipped_count = 0

        for oval_filename in sorted(oval_filenames):
            oval_file_path = oval_base_dir / oval_filename

            if not oval_file_path.exists():
                logger.warning(f"OVAL file not found: {oval_file_path}")
                skipped_count += 1
                continue

            try:
                # Parse individual OVAL file
                tree = ET.parse(oval_file_path)  # nosec B314 - parsing trusted OVAL files
                oval_root = tree.getroot()

                # Extract and append definitions (with deduplication)
                for definition in oval_root.findall(f".//{{{oval_def_ns}}}definition"):
                    def_id = definition.get("id")
                    if def_id and def_id not in seen_def_ids:
                        definitions_section.append(definition)
                        seen_def_ids.add(def_id)

                # Extract and append tests (with deduplication)
                for test in oval_root.findall(f".//{{{oval_def_ns}}}tests/*"):
                    test_id = test.get("id")
                    if test_id and test_id not in seen_test_ids:
                        tests_section.append(test)
                        seen_test_ids.add(test_id)

                # Extract and append objects (with deduplication)
                for obj in oval_root.findall(f".//{{{oval_def_ns}}}objects/*"):
                    obj_id = obj.get("id")
                    if obj_id and obj_id not in seen_obj_ids:
                        objects_section.append(obj)
                        seen_obj_ids.add(obj_id)

                # Extract and append states (with deduplication)
                for state in oval_root.findall(f".//{{{oval_def_ns}}}states/*"):
                    state_id = state.get("id")
                    if state_id and state_id not in seen_state_ids:
                        states_section.append(state)
                        seen_state_ids.add(state_id)

                # Extract and append variables (with deduplication - FIX FOR DUPLICATE VARIABLES)
                for variable in oval_root.findall(f".//{{{oval_def_ns}}}variables/*"):
                    var_id = variable.get("id")
                    if var_id and var_id not in seen_var_ids:
                        variables_section.append(variable)
                        seen_var_ids.add(var_id)

                processed_count += 1

            except ET.ParseError as e:
                logger.error(f"Failed to parse OVAL file {oval_filename}: {e}")
                skipped_count += 1
                continue

        # Remove empty sections (OVAL 5.11 allows empty sections, but cleaner without)
        if len(tests_section) == 0:
            root.remove(tests_section)
        if len(objects_section) == 0:
            root.remove(objects_section)
        if len(states_section) == 0:
            root.remove(states_section)
        if len(variables_section) == 0:
            root.remove(variables_section)

        # Write aggregated OVAL file
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "wb") as f:
            f.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
            tree = ET.ElementTree(root)
            tree.write(f, encoding="utf-8", xml_declaration=False)

        logger.info(
            f"OVAL aggregation complete: {processed_count} files processed, "
            f"{skipped_count} skipped, output: {output_path}"
        )

        return output_path if processed_count > 0 else None

    def _read_oval_definition_id(self, oval_filename: str) -> Optional[str]:
        """
        Read OVAL XML file and extract definition ID

        Args:
            oval_filename: Relative path like "rhel8/accounts_password_minlen_login_defs.xml"

        Returns:
            OVAL definition ID (e.g., "oval:ssg-accounts_password_minlen_login_defs:def:1")
            or None if file not found or parsing fails

        Example:
            >>> oval_id = self._read_oval_definition_id("rhel8/accounts_tmout.xml")
            >>> print(oval_id)
            oval:ssg-accounts_tmout:def:1
        """
        oval_base_dir = Path("/openwatch/data/oval_definitions")
        oval_file_path = oval_base_dir / oval_filename

        if not oval_file_path.exists():
            logger.warning(f"OVAL file not found: {oval_file_path}")
            return None

        try:
            tree = ET.parse(oval_file_path)  # nosec B314 - parsing trusted OVAL files
            oval_ns = "http://oval.mitre.org/XMLSchema/oval-definitions-5"

            # Find first definition element
            definition = tree.find(f".//{{{oval_ns}}}definition")

            if definition is not None:
                return definition.get("id")
            else:
                logger.warning(f"No definition element found in {oval_filename}")
                return None

        except ET.ParseError as e:
            logger.error(f"Failed to parse OVAL file {oval_filename}: {e}")
            return None

    def _create_benchmark_element(self, benchmark_id: str, title: str, description: str, version: str) -> ET.Element:
        """Create root Benchmark element with metadata"""
        # XCCDF 1.2 requires benchmark IDs to follow xccdf_<reverse-DNS>_benchmark_<name>
        if not benchmark_id.startswith("xccdf_"):
            benchmark_id = f"xccdf_com.hanalyx.openwatch_benchmark_{benchmark_id}"

        benchmark = ET.Element(
            f"{{{self.NAMESPACES['xccdf']}}}Benchmark",
            {
                "id": benchmark_id,
                "resolved": "true",
                f"{{{self.NAMESPACES['xsi']}}}schemaLocation": "http://checklists.nist.gov/xccdf/1.2 "
                "http://scap.nist.gov/schema/xccdf/1.2/xccdf_1.2.xsd",
            },
        )

        # Add status
        status = ET.SubElement(
            benchmark,
            f"{{{self.NAMESPACES['xccdf']}}}status",
            {"date": datetime.now(timezone.utc).strftime("%Y-%m-%d")},
        )
        status.text = "draft"

        # Add title
        title_elem = ET.SubElement(benchmark, f"{{{self.NAMESPACES['xccdf']}}}title")
        title_elem.text = title

        # Add description
        desc_elem = ET.SubElement(benchmark, f"{{{self.NAMESPACES['xccdf']}}}description")
        desc_elem.text = description

        # Add version
        version_elem = ET.SubElement(
            benchmark,
            f"{{{self.NAMESPACES['xccdf']}}}version",
            {"time": datetime.now(timezone.utc).isoformat()},
        )
        version_elem.text = version

        # Add metadata
        metadata = ET.SubElement(benchmark, f"{{{self.NAMESPACES['xccdf']}}}metadata")
        creator = ET.SubElement(metadata, f"{{{self.NAMESPACES['dc']}}}creator")
        creator.text = "OpenWatch SCAP Generator"

        publisher = ET.SubElement(metadata, f"{{{self.NAMESPACES['dc']}}}publisher")
        publisher.text = "Hanalyx OpenWatch"

        return benchmark

    def _create_xccdf_value(self, var_def: Dict[str, Any]) -> ET.Element:
        """
        Create XCCDF Value element from XCCDFVariable definition

        Example output:
        <xccdf:Value id="xccdf_com.hanalyx.openwatch_value_var_accounts_tmout" type="number">
          <xccdf:title>Session Timeout</xccdf:title>
          <xccdf:description>Timeout for inactive sessions</xccdf:description>
          <xccdf:value>600</xccdf:value>
          <xccdf:lower-bound>60</xccdf:lower-bound>
          <xccdf:upper-bound>3600</xccdf:upper-bound>
        </xccdf:Value>
        """
        var_type = var_def.get("type", "string")
        var_id = var_def["id"]

        # XCCDF 1.2 requires value IDs to follow xccdf_<reverse-DNS>_value_<name>
        if not var_id.startswith("xccdf_"):
            var_id = f"xccdf_com.hanalyx.openwatch_value_{var_id}"

        value = ET.Element(
            f"{{{self.NAMESPACES['xccdf']}}}Value",
            {
                "id": var_id,
                "type": var_type,
                "interactive": str(var_def.get("interactive", True)).lower(),
            },
        )

        # Add title
        title = ET.SubElement(value, f"{{{self.NAMESPACES['xccdf']}}}title")
        title.text = var_def.get("title", var_def["id"])

        # Add description if present
        if var_def.get("description"):
            desc = ET.SubElement(value, f"{{{self.NAMESPACES['xccdf']}}}description")
            desc.text = var_def["description"]

        # Add default value
        value_elem = ET.SubElement(value, f"{{{self.NAMESPACES['xccdf']}}}value")
        value_elem.text = str(var_def.get("default_value", ""))

        # Add constraints
        constraints = var_def.get("constraints", {})

        if var_type == "number":
            if "min_value" in constraints:
                lower = ET.SubElement(value, f"{{{self.NAMESPACES['xccdf']}}}lower-bound")
                lower.text = str(constraints["min_value"])

            if "max_value" in constraints:
                upper = ET.SubElement(value, f"{{{self.NAMESPACES['xccdf']}}}upper-bound")
                upper.text = str(constraints["max_value"])

        elif var_type == "string":
            if "choices" in constraints:
                for choice in constraints["choices"]:
                    choice_elem = ET.SubElement(value, f"{{{self.NAMESPACES['xccdf']}}}choice")
                    choice_elem.text = str(choice)

            if "pattern" in constraints:
                match = ET.SubElement(value, f"{{{self.NAMESPACES['xccdf']}}}match")
                match.text = constraints["pattern"]

        return value

    def _create_xccdf_rule(self, rule: Dict[str, Any]) -> ET.Element:
        """
        Create XCCDF Rule element from MongoDB ComplianceRule

        Example output:
        <xccdf:Rule id="ow-accounts_tmout" severity="medium" selected="true">
          <xccdf:title>Set Session Timeout</xccdf:title>
          <xccdf:description>Configure automatic session timeout</xccdf:description>
          <xccdf:rationale>Prevents unauthorized access</xccdf:rationale>
          <xccdf:ident system="http://cce.mitre.org">CCE-27557-8</xccdf:ident>
          <xccdf:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
            <xccdf:check-content-ref href="oval-definitions.xml" name="oval:ow:def:1234"/>
          </xccdf:check>
        </xccdf:Rule>
        """
        # XCCDF 1.2 requires rule IDs to follow xccdf_<reverse-DNS>_rule_<name>
        rule_id = rule["rule_id"]
        if not rule_id.startswith("xccdf_"):
            # Remove 'ow-' prefix if present
            rule_name = rule_id.replace("ow-", "")
            rule_id = f"xccdf_com.hanalyx.openwatch_rule_{rule_name}"

        rule_elem = ET.Element(
            f"{{{self.NAMESPACES['xccdf']}}}Rule",
            {
                "id": rule_id,
                "severity": rule.get("severity", "medium"),
                "selected": "true",
            },
        )

        # Add title
        title = ET.SubElement(rule_elem, f"{{{self.NAMESPACES['xccdf']}}}title")
        title.text = rule["metadata"].get("name", rule["rule_id"])

        # Add description
        desc = ET.SubElement(rule_elem, f"{{{self.NAMESPACES['xccdf']}}}description")
        desc.text = rule["metadata"].get("description", "")

        # Add rationale
        if rule["metadata"].get("rationale"):
            rationale = ET.SubElement(rule_elem, f"{{{self.NAMESPACES['xccdf']}}}rationale")
            rationale.text = rule["metadata"]["rationale"]

        # Add identifiers (CCE, CVE, etc.)
        identifiers = rule.get("identifiers", {})
        for ident_type, ident_value in identifiers.items():
            ident_elem = ET.SubElement(
                rule_elem,
                f"{{{self.NAMESPACES['xccdf']}}}ident",
                {"system": f"http://{ident_type}.mitre.org"},
            )
            ident_elem.text = ident_value

        # Add check reference (OVAL or custom)
        # Phase 3: Use platform-specific OVAL when target_platform is set
        if self._target_platform:
            oval_filename = self._get_platform_oval_filename(rule, self._target_platform)
        else:
            oval_filename = rule.get("oval_filename")

        scanner_type = rule.get("scanner_type", "oscap")

        # If rule has OVAL definition, use OVAL check system
        if oval_filename:
            check_system = "http://oval.mitre.org/XMLSchema/oval-definitions-5"

            # Read OVAL definition ID from file
            oval_def_id = self._read_oval_definition_id(oval_filename)

            check = ET.SubElement(rule_elem, f"{{{self.NAMESPACES['xccdf']}}}check", {"system": check_system})

            # Reference aggregated oval-definitions.xml file
            check_ref_attrs = {"href": "oval-definitions.xml"}

            # Add name attribute if we successfully extracted OVAL ID
            if oval_def_id:
                check_ref_attrs["name"] = oval_def_id

            _check_ref_oval = ET.SubElement(  # noqa: F841 - required by XCCDF spec, unused in Python
                check,
                f"{{{self.NAMESPACES['xccdf']}}}check-content-ref",
                check_ref_attrs,
            )
        else:
            # Fallback to legacy scanner-specific check
            if scanner_type == "oscap":
                check_system = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
            elif scanner_type == "kubernetes":
                check_system = "http://openwatch.hanalyx.com/scanner/kubernetes"
            else:
                check_system = f"http://openwatch.hanalyx.com/scanner/{scanner_type}"

            check = ET.SubElement(rule_elem, f"{{{self.NAMESPACES['xccdf']}}}check", {"system": check_system})

            _check_ref = ET.SubElement(  # noqa: F841 - required by XCCDF spec, unused in Python
                check,
                f"{{{self.NAMESPACES['xccdf']}}}check-content-ref",
                {
                    "href": f"{scanner_type}-definitions.xml",
                    "name": rule.get("scap_rule_id", rule["rule_id"]),
                },
            )

        # Add variable exports if rule has variables
        if rule.get("xccdf_variables"):
            for var_id in rule["xccdf_variables"].keys():
                _export = ET.SubElement(  # noqa: F841 - required by XCCDF spec, unused in Python
                    check,
                    f"{{{self.NAMESPACES['xccdf']}}}check-export",
                    {"export-name": var_id, "value-id": var_id},
                )

        return rule_elem

    def _create_xccdf_group(self, category: str, rules: List[Dict[str, Any]]) -> ET.Element:
        """Create XCCDF Group element containing related rules"""
        # XCCDF 1.2 requires group IDs to follow xccdf_<reverse-DNS>_group_<name>
        group_id = f"xccdf_com.hanalyx.openwatch_group_{category}"

        group = ET.Element(f"{{{self.NAMESPACES['xccdf']}}}Group", {"id": group_id})

        # Add title
        title = ET.SubElement(group, f"{{{self.NAMESPACES['xccdf']}}}title")
        title.text = category.replace("_", " ").title()

        # Add description
        desc = ET.SubElement(group, f"{{{self.NAMESPACES['xccdf']}}}description")
        desc.text = f"Rules related to {category.replace('_', ' ')}"

        # Add all rules in this category
        for rule in rules:
            rule_elem = self._create_xccdf_rule(rule)
            group.append(rule_elem)

        return group

    def _create_profiles(
        self,
        rules: List[Dict[str, Any]],
        framework: Optional[str],
        framework_version: Optional[str],
    ) -> List[ET.Element]:
        """Create XCCDF Profile elements (one per framework)"""
        profiles = []

        # If specific framework requested, create one profile
        if framework and framework_version:
            profile = self._create_single_profile(framework, framework_version, rules)
            if profile is not None:
                profiles.append(profile)
        else:
            # Create profiles for all frameworks found in rules
            frameworks_found = set()
            for rule in rules:
                for fw, versions in rule.get("frameworks", {}).items():
                    for version in versions.keys():
                        frameworks_found.add((fw, version))

            for fw, version in frameworks_found:
                profile = self._create_single_profile(fw, version, rules)
                if profile is not None:
                    profiles.append(profile)

        return profiles

    def _create_single_profile(
        self, framework: str, framework_version: str, rules: List[Dict[str, Any]]
    ) -> Optional[ET.Element]:
        """Create a single XCCDF Profile for a framework"""
        # Filter rules that belong to this framework version
        matching_rules = [
            r for r in rules if framework in r.get("frameworks", {}) and framework_version in r["frameworks"][framework]
        ]

        if not matching_rules:
            return None

        # XCCDF 1.2 requires profile IDs to follow xccdf_<reverse-DNS>_profile_<name>
        profile_name = f"{framework}_{framework_version}".replace("-", "_").replace(".", "_")
        profile_id = f"xccdf_com.hanalyx.openwatch_profile_{profile_name}"

        profile = ET.Element(f"{{{self.NAMESPACES['xccdf']}}}Profile", {"id": profile_id})

        # Add title
        title = ET.SubElement(profile, f"{{{self.NAMESPACES['xccdf']}}}title")
        title.text = f"{framework.upper()} {framework_version}"

        # Add description
        desc = ET.SubElement(profile, f"{{{self.NAMESPACES['xccdf']}}}description")
        desc.text = f"Profile for {framework.upper()} {framework_version} compliance"

        # Select all rules in this profile
        for rule in matching_rules:
            # Format rule ID properly
            rule_id = rule["rule_id"]
            if not rule_id.startswith("xccdf_"):
                rule_name = rule_id.replace("ow-", "")
                rule_id = f"xccdf_com.hanalyx.openwatch_rule_{rule_name}"

            _select = ET.SubElement(  # noqa: F841 - required by XCCDF spec, unused in Python
                profile,
                f"{{{self.NAMESPACES['xccdf']}}}select",
                {"idref": rule_id, "selected": "true"},
            )

        return profile

    def _extract_all_variables(self, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract all unique XCCDF variables across rules"""
        all_variables = {}

        for rule in rules:
            if rule.get("xccdf_variables"):
                for var_id, var_def in rule["xccdf_variables"].items():
                    if var_id not in all_variables:
                        all_variables[var_id] = var_def

        return all_variables

    def _group_rules_by_category(self, rules: List[Dict[str, Any]]) -> Dict[str, List[Dict]]:
        """Group rules by category for organizational purposes"""
        groups = {}

        for rule in rules:
            category = rule.get("category", "uncategorized")
            if category not in groups:
                groups[category] = []
            groups[category].append(rule)

        return groups

    def _filter_by_capabilities(
        self,
        rules: List[Dict],
        target_capabilities: Set[str],
        oval_base_path: Path,
        target_platform: Optional[str] = None,
    ) -> tuple[List[Dict], Dict[str, int]]:
        """
        Filter rules based on target system capabilities and OVAL availability.

        This method implements the same two-stage filtering strategy as native OpenSCAP:
        1. Component applicability check (notapplicable) - ACTIVE since 2025-11-21
        2. OVAL check availability (notchecked) - ACTIVE since 2025-11-22

        Phase 3 Enhancement (Platform-Aware OVAL):
            When target_platform is provided, OVAL lookup uses Option B schema:
            - platform_implementations.{platform}.oval_filename instead of rule-level oval_filename
            - Rules without platform-specific OVAL are excluded (no fallback)
            - This ensures compliance accuracy by using platform-correct OVAL definitions

        Filtering Strategy:
            Rules are excluded if:
            - They require components NOT present on target system (notapplicable)
            - They lack OVAL definition files for automated checking (notchecked)
            - They lack platform-specific OVAL when target_platform is provided (notchecked)

        This reduces scan errors and improves pass rates by filtering out:
        - Component-specific rules (e.g., gnome rules on headless systems)
        - Rules without automated checks (e.g., rules requiring manual verification)
        - Rules without platform-specific OVAL (e.g., RHEL rule on Ubuntu host)

        Performance Impact (measured on owas-hrm01, RHEL 9 headless):
            - Component filtering (notapplicable): 533 rules excluded (26.48%)
            - OVAL filtering (notchecked): ~277 rules excluded (3.8%)
            - Total filtering: ~810 rules excluded (40.2%)
            - Pass rate improvement: +4-7% (from 77% to 81-84%)

        Args:
            rules: List of rule documents from MongoDB
            target_capabilities: Set of available components on target
                               (e.g., {'filesystem', 'openssh', 'audit'})
            oval_base_path: Base path to OVAL definitions directory
                          (e.g., /app/data/oval_definitions)
            target_platform: Target host platform identifier (e.g., "rhel9", "ubuntu2204").
                           When provided, uses platform_implementations.{platform}.oval_filename
                           for OVAL lookup instead of rule-level oval_filename.

        Returns:
            Tuple of (filtered_rules, statistics_dict)
            - filtered_rules: List of applicable rules with OVAL checks
            - statistics_dict: {
                'total': int,           # Total rules before filtering
                'included': int,        # Rules passing all filters
                'notapplicable': int,   # Rules missing required components
                'notchecked': int       # Rules missing OVAL definitions
              }

        Example:
            >>> rules = await self.collection.find({}).to_list(None)
            >>> capabilities = {'filesystem', 'openssh', 'audit'}
            >>> oval_path = Path("/openwatch/data/oval_definitions")
            >>> filtered, stats = self._filter_by_capabilities(
            ...     rules, capabilities, oval_path, target_platform="rhel9"
            ... )
            >>> print(f"Excluded {stats['notapplicable']} GUI rules on headless system")

        Performance:
            - O(n) where n = number of rules
            - File existence checks cached by OS
            - Typical execution: <100ms for 390 rules
        """
        stats = {
            "total": len(rules),
            "included": 0,
            "notapplicable": 0,
            "notchecked": 0,
        }

        applicable_rules = []

        for rule in rules:
            rule_id = rule.get("rule_id", "unknown")
            rule_components = set(rule.get("metadata", {}).get("components", []))

            # Check 1: Component applicability
            # Rules with no components are universal (always applicable)
            if rule_components:
                # Check if ALL required components are available
                if not rule_components.issubset(target_capabilities):
                    missing = rule_components - target_capabilities
                    logger.debug(f"Rule {rule_id} notapplicable: missing components {missing}")
                    stats["notapplicable"] += 1
                    continue  # Skip this rule (notapplicable)

            # Check 2: OVAL check availability
            # Filter out rules that do not have OVAL automated check definitions
            # This prevents OpenSCAP from marking them as "notchecked" during scans
            #
            # OVAL (Open Vulnerability and Assessment Language) files provide
            # automated check logic for compliance rules. Rules without OVAL
            # require manual verification, so we exclude them to improve pass rates.
            #
            # Phase 3: When target_platform is provided, uses platform-specific OVAL
            # from platform_implementations.{platform}.oval_filename (Option B schema).
            # No fallback to rule-level oval_filename for compliance accuracy.
            if not self._has_oval_check(rule, oval_base_path, target_platform):
                logger.debug(f"Rule {rule_id} notchecked: missing OVAL for platform {target_platform}")
                stats["notchecked"] += 1
                continue

            # Rule passes both checks - include in benchmark
            applicable_rules.append(rule)
            stats["included"] += 1

        logger.info(
            f"Filtering complete: {stats['included']}/{stats['total']} rules included, "
            f"{stats['notapplicable']} notapplicable, {stats['notchecked']} notchecked"
        )

        return applicable_rules, stats

    def _filter_by_platform_oval(
        self,
        rules: List[Dict],
        oval_base_path: Path,
        target_platform: str,
    ) -> tuple[List[Dict], Dict[str, int]]:
        """
        Filter rules based on platform-specific OVAL availability only.

        This method filters rules when target_platform is provided but
        target_capabilities is not. It ensures only rules with platform-specific
        OVAL definitions are included in the generated XCCDF benchmark.

        Phase 3 Enhancement:
            Uses Option B schema for OVAL lookup:
            - platform_implementations.{platform}.oval_filename
            - No fallback to rule-level oval_filename
            - Ensures compliance accuracy by using correct platform OVAL

        Args:
            rules: List of rule documents from MongoDB
            oval_base_path: Base path to OVAL definitions directory
            target_platform: Target host platform identifier (e.g., "rhel9")

        Returns:
            Tuple of (filtered_rules, statistics_dict)
            - filtered_rules: List of rules with platform-specific OVAL
            - statistics_dict: {
                'total': int,
                'included': int,
                'notchecked': int
              }

        Example:
            >>> rules = await self.collection.find({}).to_list(None)
            >>> oval_path = Path("/openwatch/data/oval_definitions")
            >>> filtered, stats = self._filter_by_platform_oval(
            ...     rules, oval_path, "rhel9"
            ... )
            >>> print(f"Included {stats['included']} rules with RHEL 9 OVAL")
        """
        stats = {
            "total": len(rules),
            "included": 0,
            "notchecked": 0,
        }

        applicable_rules = []

        for rule in rules:
            rule_id = rule.get("rule_id", "unknown")

            # Check platform-specific OVAL availability
            if self._has_oval_check(rule, oval_base_path, target_platform):
                applicable_rules.append(rule)
                stats["included"] += 1
            else:
                logger.debug(f"Rule {rule_id} excluded: missing {target_platform} OVAL")
                stats["notchecked"] += 1

        logger.info(
            f"Platform OVAL filtering: {stats['included']}/{stats['total']} rules included, "
            f"{stats['notchecked']} missing {target_platform} OVAL"
        )

        return applicable_rules, stats

    def _has_oval_check(self, rule: Dict, oval_base_path: Path, target_platform: Optional[str] = None) -> bool:
        """
        Check if OVAL definition file exists for this rule.

        OVAL (Open Vulnerability and Assessment Language) files provide
        automated check logic for compliance rules. Rules without OVAL
        definitions require manual verification.

        This method validates OVAL file existence before including rules
        in generated XCCDF benchmarks, preventing "notchecked" results
        from oscap scanner.

        Phase 3 Enhancement (Platform-Aware OVAL):
            When target_platform is provided, uses Option B schema:
            - Looks up platform_implementations.{platform}.oval_filename
            - No fallback to rule-level oval_filename (compliance accuracy)
            - Returns False if platform-specific OVAL not found

        Args:
            rule: Rule document from MongoDB
            oval_base_path: Base path to OVAL definitions directory
                          (e.g., /app/data/oval_definitions)
            target_platform: Target host platform identifier (e.g., "rhel9", "ubuntu2204").
                           When provided, uses platform-specific OVAL lookup.

        Returns:
            True if OVAL file exists for the specified platform (or any platform
            if target_platform is None), False otherwise.

        OVAL File Path Implementation:
            Option B schema stores OVAL per-platform:
            - platform_implementations.rhel9.oval_filename = "rhel9/package_cups_removed.xml"
            - platform_implementations.ubuntu2204.oval_filename = "ubuntu2204/package_cups_removed.xml"

            OVAL file paths follow this pattern:
            - "rhel8/accounts_password_minlen.xml"
            - "rhel9/package_cups_removed.xml"
            - "ubuntu2204/ensure_tmp_configured.xml"

        Example:
            >>> rule = {
            ...     'rule_id': 'ow-package_cups_removed',
            ...     'platform_implementations': {
            ...         'rhel9': {'oval_filename': 'rhel9/package_cups_removed.xml'}
            ...     }
            ... }
            >>> oval_path = Path("/openwatch/data/oval_definitions")
            >>> if self._has_oval_check(rule, oval_path, target_platform="rhel9"):
            ...     print("Rule has automated check for RHEL 9")
            ... else:
            ...     print("Manual verification required")

        Implementation Notes:
            - ACTIVE filtering: Rules without OVAL files are excluded
            - Platform-specific: When target_platform provided, no fallback
            - Compliance accuracy: Wrong-platform OVAL can give false results
        """
        # Phase 3: Platform-aware OVAL lookup (Option B schema)
        if target_platform:
            oval_filename = self._get_platform_oval_filename(rule, target_platform)
        else:
            # Legacy behavior: Use rule-level oval_filename
            oval_filename = rule.get("oval_filename")

        # If no oval_filename found, exclude rule (notchecked)
        if not oval_filename:
            return False  # Rule requires manual verification

        # Validate OVAL file exists on disk
        oval_path = oval_base_path / oval_filename
        exists = oval_path.exists()

        if not exists:
            # File path is in MongoDB but file missing from disk
            # This should be rare - log as warning for investigation
            logger.warning(f"OVAL file referenced but missing for rule {rule.get('rule_id')}: {oval_path}")

        return exists

    def _get_platform_oval_filename(self, rule: Dict, target_platform: str) -> Optional[str]:
        """
        Get platform-specific OVAL filename from Option B schema.

        This method implements the platform-aware OVAL lookup for Phase 3.
        It retrieves oval_filename from platform_implementations.{platform}.oval_filename
        without any fallback to rule-level oval_filename.

        Args:
            rule: Rule document from MongoDB
            target_platform: Target host platform identifier (e.g., "rhel9", "ubuntu2204")

        Returns:
            OVAL filename string if found, None otherwise.
            Example: "rhel9/package_cups_removed.xml"

        IMPORTANT:
            This method intentionally does NOT fall back to rule-level oval_filename.
            Using wrong-platform OVAL definitions can produce incorrect compliance
            results (false positives/negatives). Rules without platform-specific
            OVAL should be skipped (marked as "not applicable").

        Example:
            >>> rule = {
            ...     'platform_implementations': {
            ...         'rhel9': {'oval_filename': 'rhel9/pkg_test.xml'},
            ...         'ubuntu2204': {'oval_filename': 'ubuntu2204/pkg_test.xml'}
            ...     }
            ... }
            >>> filename = self._get_platform_oval_filename(rule, "rhel9")
            >>> print(filename)  # "rhel9/pkg_test.xml"
            >>> filename = self._get_platform_oval_filename(rule, "centos7")
            >>> print(filename)  # None - no fallback
        """
        platform_impls = rule.get("platform_implementations", {})
        if not platform_impls:
            return None

        platform_impl = platform_impls.get(target_platform, {})
        if not platform_impl:
            return None

        # Handle both dict and object access patterns
        if isinstance(platform_impl, dict):
            return platform_impl.get("oval_filename")
        else:
            # PlatformImplementation model object
            return getattr(platform_impl, "oval_filename", None)

    def _prettify_xml(self, elem: ET.Element) -> str:
        """Convert ElementTree to pretty-printed XML string"""
        rough_string = ET.tostring(elem, encoding="utf-8")
        reparsed = minidom.parseString(rough_string)  # nosec B318 - parsing own generated XCCDF
        return reparsed.toprettyxml(indent="  ", encoding="utf-8").decode("utf-8")
