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

import xml.etree.ElementTree as ET
from xml.dom import minidom
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorDatabase
import logging

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
        'xccdf': 'http://checklists.nist.gov/xccdf/1.2',
        'xhtml': 'http://www.w3.org/1999/xhtml',
        'dc': 'http://purl.org/dc/elements/1.1/',
        'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
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
        rule_filter: Optional[Dict] = None
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
        benchmark = self._create_benchmark_element(
            benchmark_id, title, description, version
        )

        # Extract all unique variables across rules
        all_variables = self._extract_all_variables(rules)

        # Add XCCDF Value elements
        for var_id, var_def in all_variables.items():
            value_elem = self._create_xccdf_value(var_def)
            benchmark.append(value_elem)

        # Group rules by category for better organization
        rules_by_category = self._group_rules_by_category(rules)

        # Create Group elements for each category
        for category, category_rules in rules_by_category.items():
            group = self._create_xccdf_group(category, category_rules)
            benchmark.append(group)

        # Create Profile elements (one per framework version)
        profiles = self._create_profiles(rules, framework, framework_version)
        for profile in profiles:
            benchmark.append(profile)

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
        description: Optional[str] = None
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
                'id': tailoring_id,
                f"{{{self.NAMESPACES['xsi']}}}schemaLocation": 
                    "http://checklists.nist.gov/xccdf/1.2 "
                    "http://scap.nist.gov/schema/xccdf/1.2/xccdf_1.2.xsd"
            }
        )

        # Add version
        version_elem = ET.SubElement(
            tailoring,
            f"{{{self.NAMESPACES['xccdf']}}}version",
            {'time': datetime.now(timezone.utc).isoformat()}
        )
        version_elem.text = "1.0"

        # Add benchmark reference
        benchmark_elem = ET.SubElement(
            tailoring,
            f"{{{self.NAMESPACES['xccdf']}}}benchmark",
            {
                'href': benchmark_href,
                'id': benchmark_version
            }
        )

        # Create Profile with variable overrides
        profile = ET.SubElement(
            tailoring,
            f"{{{self.NAMESPACES['xccdf']}}}Profile",
            {
                'id': f"{profile_id}_customized",
                'extends': profile_id
            }
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
                profile,
                f"{{{self.NAMESPACES['xccdf']}}}set-value",
                {'idref': var_id}
            )
            set_value.text = str(var_value)

        return self._prettify_xml(tailoring)

    def _create_benchmark_element(
        self,
        benchmark_id: str,
        title: str,
        description: str,
        version: str
    ) -> ET.Element:
        """Create root Benchmark element with metadata"""
        # XCCDF 1.2 requires benchmark IDs to follow xccdf_<reverse-DNS>_benchmark_<name>
        if not benchmark_id.startswith('xccdf_'):
            benchmark_id = f"xccdf_com.hanalyx.openwatch_benchmark_{benchmark_id}"

        benchmark = ET.Element(
            f"{{{self.NAMESPACES['xccdf']}}}Benchmark",
            {
                'id': benchmark_id,
                'resolved': 'true',
                f"{{{self.NAMESPACES['xsi']}}}schemaLocation":
                    "http://checklists.nist.gov/xccdf/1.2 "
                    "http://scap.nist.gov/schema/xccdf/1.2/xccdf_1.2.xsd"
            }
        )

        # Add status
        status = ET.SubElement(
            benchmark,
            f"{{{self.NAMESPACES['xccdf']}}}status",
            {'date': datetime.now(timezone.utc).strftime('%Y-%m-%d')}
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
            {'time': datetime.now(timezone.utc).isoformat()}
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
        var_type = var_def.get('type', 'string')
        var_id = var_def['id']

        # XCCDF 1.2 requires value IDs to follow xccdf_<reverse-DNS>_value_<name>
        if not var_id.startswith('xccdf_'):
            var_id = f"xccdf_com.hanalyx.openwatch_value_{var_id}"

        value = ET.Element(
            f"{{{self.NAMESPACES['xccdf']}}}Value",
            {
                'id': var_id,
                'type': var_type,
                'interactive': str(var_def.get('interactive', True)).lower()
            }
        )

        # Add title
        title = ET.SubElement(value, f"{{{self.NAMESPACES['xccdf']}}}title")
        title.text = var_def.get('title', var_def['id'])

        # Add description if present
        if var_def.get('description'):
            desc = ET.SubElement(value, f"{{{self.NAMESPACES['xccdf']}}}description")
            desc.text = var_def['description']

        # Add default value
        value_elem = ET.SubElement(value, f"{{{self.NAMESPACES['xccdf']}}}value")
        value_elem.text = str(var_def.get('default_value', ''))

        # Add constraints
        constraints = var_def.get('constraints', {})
        
        if var_type == 'number':
            if 'min_value' in constraints:
                lower = ET.SubElement(value, f"{{{self.NAMESPACES['xccdf']}}}lower-bound")
                lower.text = str(constraints['min_value'])
            
            if 'max_value' in constraints:
                upper = ET.SubElement(value, f"{{{self.NAMESPACES['xccdf']}}}upper-bound")
                upper.text = str(constraints['max_value'])

        elif var_type == 'string':
            if 'choices' in constraints:
                for choice in constraints['choices']:
                    choice_elem = ET.SubElement(value, f"{{{self.NAMESPACES['xccdf']}}}choice")
                    choice_elem.text = str(choice)
            
            if 'pattern' in constraints:
                match = ET.SubElement(value, f"{{{self.NAMESPACES['xccdf']}}}match")
                match.text = constraints['pattern']

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
        rule_id = rule['rule_id']
        if not rule_id.startswith('xccdf_'):
            # Remove 'ow-' prefix if present
            rule_name = rule_id.replace('ow-', '')
            rule_id = f"xccdf_com.hanalyx.openwatch_rule_{rule_name}"

        rule_elem = ET.Element(
            f"{{{self.NAMESPACES['xccdf']}}}Rule",
            {
                'id': rule_id,
                'severity': rule.get('severity', 'medium'),
                'selected': 'true'
            }
        )

        # Add title
        title = ET.SubElement(rule_elem, f"{{{self.NAMESPACES['xccdf']}}}title")
        title.text = rule['metadata'].get('name', rule['rule_id'])

        # Add description
        desc = ET.SubElement(rule_elem, f"{{{self.NAMESPACES['xccdf']}}}description")
        desc.text = rule['metadata'].get('description', '')

        # Add rationale
        if rule['metadata'].get('rationale'):
            rationale = ET.SubElement(rule_elem, f"{{{self.NAMESPACES['xccdf']}}}rationale")
            rationale.text = rule['metadata']['rationale']

        # Add identifiers (CCE, CVE, etc.)
        identifiers = rule.get('identifiers', {})
        for ident_type, ident_value in identifiers.items():
            ident_elem = ET.SubElement(
                rule_elem,
                f"{{{self.NAMESPACES['xccdf']}}}ident",
                {'system': f"http://{ident_type}.mitre.org"}
            )
            ident_elem.text = ident_value

        # Add check reference (OVAL or custom)
        scanner_type = rule.get('scanner_type', 'oscap')
        
        if scanner_type == 'oscap':
            check_system = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
        elif scanner_type == 'kubernetes':
            check_system = "http://openwatch.hanalyx.com/scanner/kubernetes"
        else:
            check_system = f"http://openwatch.hanalyx.com/scanner/{scanner_type}"

        check = ET.SubElement(
            rule_elem,
            f"{{{self.NAMESPACES['xccdf']}}}check",
            {'system': check_system}
        )

        check_ref = ET.SubElement(
            check,
            f"{{{self.NAMESPACES['xccdf']}}}check-content-ref",
            {
                'href': f"{scanner_type}-definitions.xml",
                'name': rule.get('scap_rule_id', rule['rule_id'])
            }
        )

        # Add variable exports if rule has variables
        if rule.get('xccdf_variables'):
            for var_id in rule['xccdf_variables'].keys():
                export = ET.SubElement(
                    check,
                    f"{{{self.NAMESPACES['xccdf']}}}check-export",
                    {
                        'export-name': var_id,
                        'value-id': var_id
                    }
                )

        return rule_elem

    def _create_xccdf_group(
        self,
        category: str,
        rules: List[Dict[str, Any]]
    ) -> ET.Element:
        """Create XCCDF Group element containing related rules"""
        # XCCDF 1.2 requires group IDs to follow xccdf_<reverse-DNS>_group_<name>
        group_id = f"xccdf_com.hanalyx.openwatch_group_{category}"

        group = ET.Element(
            f"{{{self.NAMESPACES['xccdf']}}}Group",
            {'id': group_id}
        )

        # Add title
        title = ET.SubElement(group, f"{{{self.NAMESPACES['xccdf']}}}title")
        title.text = category.replace('_', ' ').title()

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
        framework_version: Optional[str]
    ) -> List[ET.Element]:
        """Create XCCDF Profile elements (one per framework)"""
        profiles = []

        # If specific framework requested, create one profile
        if framework and framework_version:
            profile = self._create_single_profile(
                framework, framework_version, rules
            )
            if profile is not None:
                profiles.append(profile)
        else:
            # Create profiles for all frameworks found in rules
            frameworks_found = set()
            for rule in rules:
                for fw, versions in rule.get('frameworks', {}).items():
                    for version in versions.keys():
                        frameworks_found.add((fw, version))

            for fw, version in frameworks_found:
                profile = self._create_single_profile(fw, version, rules)
                if profile is not None:
                    profiles.append(profile)

        return profiles

    def _create_single_profile(
        self,
        framework: str,
        framework_version: str,
        rules: List[Dict[str, Any]]
    ) -> Optional[ET.Element]:
        """Create a single XCCDF Profile for a framework"""
        # Filter rules that belong to this framework version
        matching_rules = [
            r for r in rules
            if framework in r.get('frameworks', {})
            and framework_version in r['frameworks'][framework]
        ]

        if not matching_rules:
            return None

        # XCCDF 1.2 requires profile IDs to follow xccdf_<reverse-DNS>_profile_<name>
        profile_name = f"{framework}_{framework_version}".replace('-', '_').replace('.', '_')
        profile_id = f"xccdf_com.hanalyx.openwatch_profile_{profile_name}"

        profile = ET.Element(
            f"{{{self.NAMESPACES['xccdf']}}}Profile",
            {'id': profile_id}
        )

        # Add title
        title = ET.SubElement(profile, f"{{{self.NAMESPACES['xccdf']}}}title")
        title.text = f"{framework.upper()} {framework_version}"

        # Add description
        desc = ET.SubElement(profile, f"{{{self.NAMESPACES['xccdf']}}}description")
        desc.text = f"Profile for {framework.upper()} {framework_version} compliance"

        # Select all rules in this profile
        for rule in matching_rules:
            # Format rule ID properly
            rule_id = rule['rule_id']
            if not rule_id.startswith('xccdf_'):
                rule_name = rule_id.replace('ow-', '')
                rule_id = f"xccdf_com.hanalyx.openwatch_rule_{rule_name}"

            select = ET.SubElement(
                profile,
                f"{{{self.NAMESPACES['xccdf']}}}select",
                {
                    'idref': rule_id,
                    'selected': 'true'
                }
            )

        return profile

    def _extract_all_variables(self, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract all unique XCCDF variables across rules"""
        all_variables = {}
        
        for rule in rules:
            if rule.get('xccdf_variables'):
                for var_id, var_def in rule['xccdf_variables'].items():
                    if var_id not in all_variables:
                        all_variables[var_id] = var_def
        
        return all_variables

    def _group_rules_by_category(self, rules: List[Dict[str, Any]]) -> Dict[str, List[Dict]]:
        """Group rules by category for organizational purposes"""
        groups = {}
        
        for rule in rules:
            category = rule.get('category', 'uncategorized')
            if category not in groups:
                groups[category] = []
            groups[category].append(rule)
        
        return groups

    def _prettify_xml(self, elem: ET.Element) -> str:
        """Convert ElementTree to pretty-printed XML string"""
        rough_string = ET.tostring(elem, encoding='utf-8')
        reparsed = minidom.parseString(rough_string)
        return reparsed.toprettyxml(indent="  ", encoding='utf-8').decode('utf-8')
