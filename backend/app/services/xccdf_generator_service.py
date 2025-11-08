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
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from xml.dom import minidom

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

    async def generate_benchmark(
        self,
        benchmark_id: str,
        title: str,
        description: str,
        version: str,
        framework: Optional[str] = None,
        framework_version: Optional[str] = None,
        rule_filter: Optional[Dict] = None,
    ) -> str:
        """
        Generate XCCDF Benchmark XML from MongoDB rules

        Args:
            benchmark_id: Unique benchmark identifier (e.g., "openwatch-nist-800-53r5")
            title: Human-readable benchmark title
            description: Detailed description of the benchmark
            version: Benchmark version string
            framework: Framework to filter by (nist, cis, stig, etc.)
            framework_version: Specific framework version (e.g., "800-53r5")
            rule_filter: Additional MongoDB query filter

        Returns:
            XCCDF Benchmark XML as string
        """
        logger.info(f"Generating XCCDF Benchmark: {benchmark_id}")

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
        benchmark_elem = ET.SubElement(
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
            set_value = ET.SubElement(
                profile, f"{{{self.NAMESPACES['xccdf']}}}set-value", {"idref": var_id}
            )
            set_value.text = str(var_value)

        return self._prettify_xml(tailoring)

    async def generate_oval_definitions_file(
        self,
        rules: List[Dict[str, Any]],
        platform: str,
        output_path: Path,
    ) -> Optional[Path]:
        """
        Aggregate individual OVAL XML files into single oval-definitions.xml file

        This method reads individual OVAL files from /app/data/oval_definitions/{platform}/
        and combines them into a single OVAL document that OSCAP can consume.

        Args:
            rules: List of ComplianceRule documents (must have oval_filename field)
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

        oval_base_dir = Path("/app/data/oval_definitions")

        # Collect unique OVAL filenames from rules
        oval_filenames: Set[str] = set()
        for rule in rules:
            oval_filename = rule.get("oval_filename")
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
                tree = ET.parse(oval_file_path)
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
        oval_base_dir = Path("/app/data/oval_definitions")
        oval_file_path = oval_base_dir / oval_filename

        if not oval_file_path.exists():
            logger.warning(f"OVAL file not found: {oval_file_path}")
            return None

        try:
            tree = ET.parse(oval_file_path)
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

    def _create_benchmark_element(
        self, benchmark_id: str, title: str, description: str, version: str
    ) -> ET.Element:
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
        oval_filename = rule.get("oval_filename")
        scanner_type = rule.get("scanner_type", "oscap")

        # If rule has OVAL definition, use OVAL check system
        if oval_filename:
            check_system = "http://oval.mitre.org/XMLSchema/oval-definitions-5"

            # Read OVAL definition ID from file
            oval_def_id = self._read_oval_definition_id(oval_filename)

            check = ET.SubElement(
                rule_elem, f"{{{self.NAMESPACES['xccdf']}}}check", {"system": check_system}
            )

            # Reference aggregated oval-definitions.xml file
            check_ref_attrs = {"href": "oval-definitions.xml"}

            # Add name attribute if we successfully extracted OVAL ID
            if oval_def_id:
                check_ref_attrs["name"] = oval_def_id

            check_ref = ET.SubElement(
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

            check = ET.SubElement(
                rule_elem, f"{{{self.NAMESPACES['xccdf']}}}check", {"system": check_system}
            )

            check_ref = ET.SubElement(
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
                export = ET.SubElement(
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
            r
            for r in rules
            if framework in r.get("frameworks", {})
            and framework_version in r["frameworks"][framework]
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

            select = ET.SubElement(
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

    def _prettify_xml(self, elem: ET.Element) -> str:
        """Convert ElementTree to pretty-printed XML string"""
        rough_string = ET.tostring(elem, encoding="utf-8")
        reparsed = minidom.parseString(rough_string)
        return reparsed.toprettyxml(indent="  ", encoding="utf-8").decode("utf-8")
