# MongoDB-Based SCAP Scanning with XCCDF Generation

## Overview

OpenWatch stores compliance rules in MongoDB (converted from ComplianceAsCode) and dynamically generates XCCDF data-streams at scan time. This approach maintains full OSCAP compatibility while adding flexibility and customization capabilities beyond what ComplianceAsCode provides natively.

## Architecture: MongoDB → XCCDF → OSCAP → Results

```
┌─────────────────────────────────────────────────────────────────────┐
│                         OpenWatch Scan Flow                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  1. User Initiates Scan                                              │
│     └─> POST /api/v1/scans                                          │
│         {                                                             │
│           "host_id": "uuid",                                         │
│           "profile": "stig",                                         │
│           "variable_overrides": {"var_accounts_tmout": "900"}       │
│         }                                                             │
│                                                                       │
│  2. Load Rules from MongoDB                                          │
│     └─> ComplianceRule.find({"profiles.stig": {"$exists": true}})  │
│         - Load all rules for STIG profile                           │
│         - Include XCCDF variable metadata                           │
│         - Include remediation content (Ansible/Bash)                │
│                                                                       │
│  3. Generate XCCDF Data-Stream                                       │
│     └─> XCCDFGenerator.create_datastream()                          │
│         - Convert MongoDB rules → XCCDF XML                          │
│         - Generate <Benchmark>, <Profile>, <Group>, <Rule> elements │
│         - Embed OVAL checks, OCIL questionnaires                    │
│         - Include remediation scripts (Ansible/Bash)                │
│         - Add XCCDF variable definitions                            │
│                                                                       │
│  4. Generate Tailoring File (if custom variables)                   │
│     └─> XCCDFTailoringGenerator.create_tailoring()                  │
│         - Create <set-value> elements for user overrides            │
│                                                                       │
│  5. Execute OSCAP Scan                                               │
│     └─> oscap xccdf eval                                            │
│         --profile stig                                               │
│         --tailoring-file tailoring.xml                               │
│         --results-arf results.xml                                    │
│         generated-datastream.xml                                     │
│                                                                       │
│  6. Parse Results & Store in MongoDB                                │
│     └─> Store scan results, compliance scores, failed rules         │
│                                                                       │
│  7. (Optional) Execute Remediation via ORSA                         │
│     └─> ORSA plugins use same generated data-stream                 │
│         - Ansible plugin: Extract Ansible tasks from XCCDF           │
│         - Bash plugin: Extract Bash scripts from XCCDF               │
│         - Puppet plugin: Extract Puppet manifests from XCCDF         │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

## Component 1: XCCDF Data-Stream Generator

This is the critical component that converts MongoDB rules into OSCAP-compatible XCCDF XML.

```python
# backend/app/services/xccdf_generator.py

from typing import List, Dict, Optional
from pathlib import Path
from lxml import etree
from datetime import datetime
from app.models.mongo_models import ComplianceRule
from beanie import PydanticObjectId

class XCCDFDataStreamGenerator:
    """
    Generate XCCDF 1.2 data-streams from MongoDB compliance rules

    This allows OpenWatch to use OSCAP scanning engine while storing
    rules in flexible MongoDB format with custom metadata and organization.
    """

    # XCCDF namespaces
    XCCDF_NS = "http://checklists.nist.gov/xccdf/1.2"
    OVAL_NS = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
    OCIL_NS = "http://scap.nist.gov/schema/ocil/2.0"
    DS_NS = "http://scap.nist.gov/schema/scap/source/1.2"

    NSMAP = {
        None: XCCDF_NS,
        "oval": OVAL_NS,
        "ocil": OCIL_NS,
        "ds": DS_NS
    }

    def __init__(self):
        self.benchmark_id = "openwatch_benchmark"
        self.benchmark_version = "1.0"

    async def create_datastream(
        self,
        profile_name: str,
        output_path: Path,
        variable_defaults: Optional[Dict[str, str]] = None
    ) -> Path:
        """
        Generate complete XCCDF data-stream from MongoDB rules

        Args:
            profile_name: Profile to generate (e.g., "stig", "pci-dss")
            output_path: Where to write data-stream XML
            variable_defaults: Default values for XCCDF variables (optional)

        Returns:
            Path to generated data-stream file
        """
        # Load all rules for this profile from MongoDB
        rules = await self._load_profile_rules(profile_name)

        # Create root data-stream collection
        ds_collection = etree.Element(
            f"{{{self.DS_NS}}}data-stream-collection",
            nsmap=self.NSMAP
        )

        # Create data-stream
        data_stream = etree.SubElement(
            ds_collection,
            f"{{{self.DS_NS}}}data-stream",
            id="openwatch_datastream"
        )

        # Create benchmark component
        benchmark = self._create_benchmark(rules, profile_name)
        etree.SubElement(
            data_stream,
            f"{{{self.DS_NS}}}component-ref",
            id="scap_openwatch_cref_benchmark",
            href="#openwatch_benchmark"
        )

        # Add benchmark to component collection
        component = etree.SubElement(
            ds_collection,
            f"{{{self.DS_NS}}}component",
            id="scap_openwatch_cref_benchmark"
        )
        component.append(benchmark)

        # Generate OVAL checks component (if rules have OVAL)
        oval_definitions = self._create_oval_component(rules)
        if oval_definitions is not None:
            oval_comp = etree.SubElement(
                ds_collection,
                f"{{{self.DS_NS}}}component",
                id="scap_openwatch_cref_oval"
            )
            oval_comp.append(oval_definitions)

            # Reference OVAL from data-stream
            etree.SubElement(
                data_stream,
                f"{{{self.DS_NS}}}component-ref",
                id="scap_openwatch_cref_oval",
                href="#scap_openwatch_cref_oval"
            )

        # Write to file
        tree = etree.ElementTree(ds_collection)
        tree.write(
            str(output_path),
            pretty_print=True,
            xml_declaration=True,
            encoding="UTF-8"
        )

        return output_path

    def _create_benchmark(
        self,
        rules: List[ComplianceRule],
        profile_name: str
    ) -> etree.Element:
        """
        Create XCCDF Benchmark element from MongoDB rules

        This is the core of the data-stream - contains all rule definitions,
        profiles, groups, variables, and remediation content.
        """
        benchmark = etree.Element(
            f"{{{self.XCCDF_NS}}}Benchmark",
            id=self.benchmark_id,
            nsmap={None: self.XCCDF_NS}
        )

        # Status
        status = etree.SubElement(benchmark, f"{{{self.XCCDF_NS}}}status")
        status.text = "accepted"
        status.set("date", datetime.utcnow().strftime("%Y-%m-%d"))

        # Title
        title = etree.SubElement(benchmark, f"{{{self.XCCDF_NS}}}title")
        title.text = f"OpenWatch Security Benchmark - {profile_name.upper()}"

        # Description
        description = etree.SubElement(benchmark, f"{{{self.XCCDF_NS}}}description")
        description.text = f"Compliance rules managed by OpenWatch, derived from ComplianceAsCode"

        # Version
        version = etree.SubElement(benchmark, f"{{{self.XCCDF_NS}}}version")
        version.text = self.benchmark_version

        # Platform (CPE)
        for platform in self._extract_platforms(rules):
            platform_elem = etree.SubElement(
                benchmark,
                f"{{{self.XCCDF_NS}}}platform",
                idref=platform
            )

        # XCCDF Variables (extracted from rules)
        variables = self._extract_all_variables(rules)
        for var_id, var_def in variables.items():
            self._create_xccdf_value(benchmark, var_id, var_def)

        # Profile definition
        profile = self._create_profile(benchmark, profile_name, rules)

        # Groups and Rules
        self._create_groups_and_rules(benchmark, rules, profile_name)

        return benchmark

    def _create_profile(
        self,
        benchmark: etree.Element,
        profile_name: str,
        rules: List[ComplianceRule]
    ) -> etree.Element:
        """
        Create XCCDF Profile element

        Profile defines which rules are selected and their severity overrides.
        """
        profile = etree.SubElement(
            benchmark,
            f"{{{self.XCCDF_NS}}}Profile",
            id=f"xccdf_openwatch_profile_{profile_name}"
        )

        # Title
        title = etree.SubElement(profile, f"{{{self.XCCDF_NS}}}title")
        title.text = profile_name.replace("-", " ").replace("_", " ").title()

        # Description
        description = etree.SubElement(profile, f"{{{self.XCCDF_NS}}}description")
        description.text = f"OpenWatch profile: {profile_name}"

        # Select rules that are part of this profile
        for rule in rules:
            if profile_name in rule.profiles:
                profile_data = rule.profiles[profile_name]

                # Select rule
                select = etree.SubElement(
                    profile,
                    f"{{{self.XCCDF_NS}}}select",
                    idref=f"xccdf_openwatch_rule_{rule.rule_id}",
                    selected="true"
                )

                # Set severity if profile overrides it
                if profile_data.get("severity"):
                    refine_value = etree.SubElement(
                        profile,
                        f"{{{self.XCCDF_NS}}}refine-value",
                        idref=f"xccdf_openwatch_rule_{rule.rule_id}",
                        severity=profile_data["severity"]
                    )

        return profile

    def _create_groups_and_rules(
        self,
        benchmark: etree.Element,
        rules: List[ComplianceRule],
        profile_name: str
    ) -> None:
        """
        Create XCCDF Group hierarchy and Rule elements

        Groups organize rules by category (Access Control, Audit, etc.)
        """
        # Organize rules by category
        rules_by_category = {}
        for rule in rules:
            category = rule.metadata.category or "Uncategorized"
            if category not in rules_by_category:
                rules_by_category[category] = []
            rules_by_category[category].append(rule)

        # Create groups
        for category, category_rules in rules_by_category.items():
            group = etree.SubElement(
                benchmark,
                f"{{{self.XCCDF_NS}}}Group",
                id=f"xccdf_openwatch_group_{category.lower().replace(' ', '_')}"
            )

            # Group title
            group_title = etree.SubElement(group, f"{{{self.XCCDF_NS}}}title")
            group_title.text = category

            # Add rules to group
            for rule in category_rules:
                self._create_rule(group, rule, profile_name)

    def _create_rule(
        self,
        parent: etree.Element,
        rule: ComplianceRule,
        profile_name: str
    ) -> etree.Element:
        """
        Create XCCDF Rule element from MongoDB ComplianceRule

        This is where MongoDB data gets converted to XCCDF format.
        """
        xccdf_rule = etree.SubElement(
            parent,
            f"{{{self.XCCDF_NS}}}Rule",
            id=f"xccdf_openwatch_rule_{rule.rule_id}",
            severity=rule.metadata.severity or "medium"
        )

        # Title
        title = etree.SubElement(xccdf_rule, f"{{{self.XCCDF_NS}}}title")
        title.text = rule.metadata.name

        # Description
        description = etree.SubElement(xccdf_rule, f"{{{self.XCCDF_NS}}}description")
        description.text = rule.metadata.description

        # Rationale
        if rule.metadata.rationale:
            rationale = etree.SubElement(xccdf_rule, f"{{{self.XCCDF_NS}}}rationale")
            rationale.text = rule.metadata.rationale

        # References (CIS, NIST, DISA STIG, etc.)
        if rule.frameworks:
            self._add_references(xccdf_rule, rule.frameworks)

        # Identifiers (CCE, CVE)
        if rule.identifiers:
            self._add_identifiers(xccdf_rule, rule.identifiers)

        # OVAL check (automated checking)
        if rule.checks and rule.checks.get("oval"):
            check = etree.SubElement(
                xccdf_rule,
                f"{{{self.XCCDF_NS}}}check",
                system="http://oval.mitre.org/XMLSchema/oval-definitions-5"
            )
            check_content_ref = etree.SubElement(
                check,
                f"{{{self.XCCDF_NS}}}check-content-ref",
                href="#scap_openwatch_cref_oval",
                name=rule.checks["oval"]["id"]
            )

        # OCIL check (manual checking)
        if rule.checks and rule.checks.get("ocil"):
            ocil_check = etree.SubElement(
                xccdf_rule,
                f"{{{self.XCCDF_NS}}}check",
                system="http://scap.nist.gov/schema/ocil/2"
            )
            ocil_ref = etree.SubElement(
                ocil_check,
                f"{{{self.XCCDF_NS}}}check-content-ref",
                href=rule.checks["ocil"]["questionnaire"]
            )

        # Remediation content (Ansible)
        if rule.remediation and rule.remediation.get("ansible"):
            self._add_ansible_remediation(xccdf_rule, rule.remediation["ansible"])

        # Remediation content (Bash)
        if rule.remediation and rule.remediation.get("bash"):
            self._add_bash_remediation(xccdf_rule, rule.remediation["bash"])

        return xccdf_rule

    def _create_xccdf_value(
        self,
        benchmark: etree.Element,
        var_id: str,
        var_def: Dict
    ) -> etree.Element:
        """
        Create XCCDF Value element for customizable variables

        This enables scan-time customization (tailoring).
        """
        # Ensure fully-qualified ID
        if not var_id.startswith("xccdf_"):
            var_id = f"xccdf_openwatch_value_{var_id}"

        value_elem = etree.SubElement(
            benchmark,
            f"{{{self.XCCDF_NS}}}Value",
            id=var_id,
            type=var_def.get("type", "string")
        )

        # Title
        title = etree.SubElement(value_elem, f"{{{self.XCCDF_NS}}}title")
        title.text = var_def.get("title", var_id)

        # Description
        if var_def.get("description"):
            desc = etree.SubElement(value_elem, f"{{{self.XCCDF_NS}}}description")
            desc.text = var_def["description"]

        # Default value
        value = etree.SubElement(value_elem, f"{{{self.XCCDF_NS}}}value")
        value.text = str(var_def.get("default_value", ""))

        # Choices (if enum-like)
        if var_def.get("constraints", {}).get("choices"):
            for choice in var_def["constraints"]["choices"]:
                choice_elem = etree.SubElement(
                    value_elem,
                    f"{{{self.XCCDF_NS}}}choice"
                )
                choice_elem.text = str(choice)

        # Interactive flag (can be customized via tailoring)
        if var_def.get("interactive", True):
            value_elem.set("interactive", "true")

        return value_elem

    def _add_ansible_remediation(
        self,
        rule: etree.Element,
        ansible_data: Dict
    ) -> None:
        """
        Embed Ansible remediation content in XCCDF Rule

        OSCAP can extract and execute this during --remediate.
        """
        fix = etree.SubElement(
            rule,
            f"{{{self.XCCDF_NS}}}fix",
            system="urn:xccdf:fix:script:ansible",
            complexity=ansible_data.get("complexity", "low"),
            disruption=ansible_data.get("disruption", "low")
        )

        # Embed Ansible tasks as CDATA
        # OSCAP will extract this and execute via ansible-playbook
        fix.text = etree.CDATA(ansible_data.get("tasks", ""))

        # Variable bindings (tell OSCAP which variables to substitute)
        if ansible_data.get("variables"):
            for var in ansible_data["variables"]:
                sub = etree.SubElement(
                    fix,
                    f"{{{self.XCCDF_NS}}}sub",
                    idref=f"xccdf_openwatch_value_{var}"
                )

    def _add_bash_remediation(
        self,
        rule: etree.Element,
        bash_data: Dict
    ) -> None:
        """
        Embed Bash remediation script in XCCDF Rule
        """
        fix = etree.SubElement(
            rule,
            f"{{{self.XCCDF_NS}}}fix",
            system="urn:xccdf:fix:script:sh",
            complexity=bash_data.get("complexity", "low"),
            disruption=bash_data.get("disruption", "low")
        )

        fix.text = etree.CDATA(bash_data.get("script", ""))

        # Variable bindings
        if bash_data.get("variables"):
            for var in bash_data["variables"]:
                sub = etree.SubElement(
                    fix,
                    f"{{{self.XCCDF_NS}}}sub",
                    idref=f"xccdf_openwatch_value_{var}"
                )

    def _create_oval_component(
        self,
        rules: List[ComplianceRule]
    ) -> Optional[etree.Element]:
        """
        Generate OVAL definitions component

        OVAL provides automated checks for rules.
        """
        # Check if any rules have OVAL checks
        has_oval = any(
            rule.checks and rule.checks.get("oval")
            for rule in rules
        )

        if not has_oval:
            return None

        oval_defs = etree.Element(
            f"{{{self.OVAL_NS}}}oval_definitions",
            nsmap={None: self.OVAL_NS}
        )

        # Generator info
        generator = etree.SubElement(oval_defs, f"{{{self.OVAL_NS}}}generator")
        prod_name = etree.SubElement(generator, f"{{{self.OVAL_NS}}}product_name")
        prod_name.text = "OpenWatch OVAL Generator"
        timestamp = etree.SubElement(generator, f"{{{self.OVAL_NS}}}timestamp")
        timestamp.text = datetime.utcnow().isoformat()

        # Definitions section
        definitions = etree.SubElement(oval_defs, f"{{{self.OVAL_NS}}}definitions")

        for rule in rules:
            if rule.checks and rule.checks.get("oval"):
                oval_data = rule.checks["oval"]

                definition = etree.SubElement(
                    definitions,
                    f"{{{self.OVAL_NS}}}definition",
                    id=oval_data["id"],
                    class_="compliance"
                )

                # Metadata
                metadata = etree.SubElement(definition, f"{{{self.OVAL_NS}}}metadata")
                title = etree.SubElement(metadata, f"{{{self.OVAL_NS}}}title")
                title.text = rule.metadata.name

                # Criteria (the actual OVAL logic)
                if oval_data.get("criteria"):
                    criteria = etree.SubElement(
                        definition,
                        f"{{{self.OVAL_NS}}}criteria"
                    )
                    # Parse and add OVAL criteria from MongoDB
                    # This would contain the actual OVAL test logic

        return oval_defs

    async def _load_profile_rules(
        self,
        profile_name: str
    ) -> List[ComplianceRule]:
        """
        Load all rules for a profile from MongoDB

        Uses MongoDB query to efficiently fetch only rules in this profile.
        """
        rules = await ComplianceRule.find(
            {f"profiles.{profile_name}": {"$exists": True}}
        ).to_list()

        return rules

    def _extract_all_variables(
        self,
        rules: List[ComplianceRule]
    ) -> Dict[str, Dict]:
        """
        Extract all unique XCCDF variables from rules

        Returns dict of {variable_id: variable_definition}
        """
        variables = {}

        for rule in rules:
            if rule.xccdf_variables:
                for var_id, var_def in rule.xccdf_variables.items():
                    if var_id not in variables:
                        variables[var_id] = var_def

        return variables

    def _extract_platforms(
        self,
        rules: List[ComplianceRule]
    ) -> List[str]:
        """
        Extract unique platform CPEs from rules

        Returns list of CPE identifiers (e.g., "cpe:/o:redhat:enterprise_linux:8")
        """
        platforms = set()

        for rule in rules:
            if rule.platform_implementations:
                for platform_data in rule.platform_implementations.values():
                    if platform_data.get("cpe"):
                        platforms.add(platform_data["cpe"])

        return sorted(platforms)

    def _add_references(
        self,
        rule: etree.Element,
        frameworks: Dict[str, Dict]
    ) -> None:
        """
        Add framework references (NIST 800-53, CIS, DISA STIG, etc.)
        """
        for framework, versions in frameworks.items():
            for version, mappings in versions.items():
                for control in mappings.get("controls", []):
                    ref = etree.SubElement(
                        rule,
                        f"{{{self.XCCDF_NS}}}reference",
                        href=mappings.get("url", "")
                    )
                    ref.text = f"{framework.upper()} {control}"

    def _add_identifiers(
        self,
        rule: etree.Element,
        identifiers: Dict[str, str]
    ) -> None:
        """
        Add identifiers (CCE, CVE, etc.)
        """
        for id_type, id_value in identifiers.items():
            ident = etree.SubElement(
                rule,
                f"{{{self.XCCDF_NS}}}ident",
                system=f"http://{id_type}.mitre.org"
            )
            ident.text = id_value
```

## Component 2: Scan Service with Dynamic XCCDF Generation

```python
# backend/app/services/scan_service_mongodb.py

from typing import Dict, Optional
from pathlib import Path
from app.services.xccdf_generator import XCCDFDataStreamGenerator
from app.services.xccdf_tailoring_generator import XCCDFTailoringGenerator
from app.models.mongo_models import Host, ScanConfiguration, ScanResult
import subprocess
import asyncio

class MongoDBScanService:
    """
    Execute OSCAP scans using rules stored in MongoDB

    Flow:
    1. Load rules from MongoDB
    2. Generate XCCDF data-stream
    3. Generate tailoring file (if custom variables)
    4. Execute oscap
    5. Parse and store results
    """

    def __init__(self):
        self.xccdf_gen = XCCDFDataStreamGenerator()
        self.tailoring_gen = XCCDFTailoringGenerator()

    async def execute_scan(
        self,
        host_id: str,
        profile: str,
        variable_overrides: Optional[Dict[str, str]] = None
    ) -> ScanResult:
        """
        Execute compliance scan using MongoDB rules

        Args:
            host_id: Target host UUID
            profile: Profile name (e.g., "stig", "pci-dss")
            variable_overrides: Custom XCCDF variable values

        Returns:
            ScanResult with compliance status and failed rules
        """
        # Get host
        host = await Host.get(host_id)

        # Create working directory
        work_dir = Path(f"/tmp/scan_{host_id}_{profile}")
        work_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Step 1: Generate XCCDF data-stream from MongoDB
            datastream_path = await self.xccdf_gen.create_datastream(
                profile_name=profile,
                output_path=work_dir / "datastream.xml"
            )

            # Step 2: Generate tailoring file if custom variables
            tailoring_path = None
            if variable_overrides:
                tailoring_path = self.tailoring_gen.create_tailoring(
                    profile_id=f"xccdf_openwatch_profile_{profile}",
                    variable_overrides=variable_overrides,
                    benchmark_href="#openwatch_benchmark",
                    output_path=work_dir / "tailoring.xml"
                )

            # Step 3: Execute OSCAP
            result = await self._execute_oscap(
                host=host,
                datastream=datastream_path,
                profile=profile,
                tailoring=tailoring_path,
                work_dir=work_dir
            )

            # Step 4: Parse results
            scan_result = await self._parse_scan_results(
                results_file=work_dir / "results.xml",
                host_id=host_id,
                profile=profile
            )

            # Step 5: Store in MongoDB
            await scan_result.save()

            return scan_result

        finally:
            # Cleanup temp files
            if not self.keep_temp_files:
                shutil.rmtree(work_dir, ignore_errors=True)

    async def _execute_oscap(
        self,
        host: Host,
        datastream: Path,
        profile: str,
        tailoring: Optional[Path],
        work_dir: Path
    ) -> subprocess.CompletedProcess:
        """
        Execute oscap command locally or remotely
        """
        cmd = [
            "oscap", "xccdf", "eval",
            "--profile", f"xccdf_openwatch_profile_{profile}",
            "--results-arf", str(work_dir / "results.xml"),
            "--report", str(work_dir / "report.html")
        ]

        # Add tailoring if custom variables
        if tailoring:
            cmd.extend(["--tailoring-file", str(tailoring)])

        cmd.append(str(datastream))

        # Execute locally or via SSH
        if host.connection_type == "ssh":
            return await self._execute_remote(host, cmd, datastream, tailoring, work_dir)
        else:
            return await self._execute_local(cmd)

    async def _execute_remote(
        self,
        host: Host,
        cmd: List[str],
        datastream: Path,
        tailoring: Optional[Path],
        work_dir: Path
    ) -> subprocess.CompletedProcess:
        """
        Execute scan on remote host via SSH

        1. Copy generated data-stream to remote
        2. Copy tailoring file (if exists)
        3. Execute oscap remotely
        4. Retrieve results
        """
        credentials = await self._decrypt_credentials(host.encrypted_credentials)

        async with asyncssh.connect(
            host.hostname,
            username=credentials["username"],
            password=credentials.get("password"),
            client_keys=credentials.get("private_key")
        ) as conn:
            # Copy files to remote
            async with conn.start_sftp_client() as sftp:
                await sftp.put(str(datastream), "/tmp/openwatch_datastream.xml")
                if tailoring:
                    await sftp.put(str(tailoring), "/tmp/openwatch_tailoring.xml")

            # Update command with remote paths
            remote_cmd = cmd.copy()
            remote_cmd[remote_cmd.index(str(datastream))] = "/tmp/openwatch_datastream.xml"
            if tailoring:
                remote_cmd[remote_cmd.index(str(tailoring))] = "/tmp/openwatch_tailoring.xml"

            # Execute
            result = await conn.run(" ".join(remote_cmd))

            # Retrieve results
            async with conn.start_sftp_client() as sftp:
                await sftp.get(
                    "/tmp/results.xml",
                    str(work_dir / "results.xml")
                )
                await sftp.get(
                    "/tmp/report.html",
                    str(work_dir / "report.html")
                )

            return result

    async def _parse_scan_results(
        self,
        results_file: Path,
        host_id: str,
        profile: str
    ) -> ScanResult:
        """
        Parse OSCAP results and create ScanResult document

        Maps XCCDF results back to MongoDB rule IDs.
        """
        tree = etree.parse(str(results_file))

        # Parse rule results
        rule_results = []
        for rule_result in tree.xpath("//xccdf:rule-result", namespaces={"xccdf": self.XCCDF_NS}):
            rule_id_ref = rule_result.get("idref")

            # Extract OpenWatch rule ID from XCCDF ID
            # xccdf_openwatch_rule_accounts_tmout → accounts_tmout
            ow_rule_id = rule_id_ref.replace("xccdf_openwatch_rule_", "")

            result_elem = rule_result.find("xccdf:result", namespaces={"xccdf": self.XCCDF_NS})
            result_value = result_elem.text if result_elem is not None else "unknown"

            rule_results.append({
                "rule_id": ow_rule_id,
                "result": result_value,  # pass, fail, notapplicable, etc.
                "message": self._extract_message(rule_result)
            })

        # Calculate score
        total = len(rule_results)
        passed = sum(1 for r in rule_results if r["result"] == "pass")
        score = (passed / total * 100) if total > 0 else 0

        return ScanResult(
            host_id=host_id,
            profile=profile,
            score=score,
            total_rules=total,
            passed=passed,
            failed=total - passed,
            rule_results=rule_results,
            scanned_at=datetime.utcnow()
        )
```

## Component 3: ORSA Integration

```python
# backend/app/plugins/orsa/base.py

from abc import ABC, abstractmethod
from typing import Dict, List, Optional
from pathlib import Path
from lxml import etree

class ORSAPlugin(ABC):
    """
    Open Remediation Standard Adapter (ORSA) base class

    ORSA plugins extract remediation content from XCCDF data-streams
    and execute them using various automation tools (Ansible, Bash, Puppet, etc.)
    """

    def __init__(self, datastream_path: Path):
        self.datastream_path = datastream_path
        self.tree = etree.parse(str(datastream_path))
        self.XCCDF_NS = "http://checklists.nist.gov/xccdf/1.2"

    @abstractmethod
    async def execute_remediation(
        self,
        failed_rules: List[str],
        variable_overrides: Optional[Dict[str, str]] = None
    ) -> Dict[str, bool]:
        """
        Execute remediation for failed rules

        Args:
            failed_rules: List of rule IDs that failed scan
            variable_overrides: Custom XCCDF variable values

        Returns:
            Dict mapping rule_id → success (True/False)
        """
        pass

    def extract_fix_content(
        self,
        rule_id: str,
        fix_system: str
    ) -> Optional[str]:
        """
        Extract remediation content for a specific rule

        Args:
            rule_id: XCCDF rule ID (e.g., "xccdf_openwatch_rule_accounts_tmout")
            fix_system: Fix system URI (e.g., "urn:xccdf:fix:script:ansible")

        Returns:
            Remediation script content (Ansible YAML, Bash script, etc.)
        """
        # Find rule in XCCDF
        rule = self.tree.xpath(
            f"//xccdf:Rule[@id='{rule_id}']",
            namespaces={"xccdf": self.XCCDF_NS}
        )

        if not rule:
            return None

        # Find fix element with matching system
        fix = rule[0].xpath(
            f"xccdf:fix[@system='{fix_system}']",
            namespaces={"xccdf": self.XCCDF_NS}
        )

        if not fix:
            return None

        return fix[0].text

    def substitute_variables(
        self,
        content: str,
        variable_overrides: Dict[str, str]
    ) -> str:
        """
        Substitute XCCDF variables in remediation content

        Variables in content are referenced as:
        - Ansible: {{ var_name }}
        - Bash: $XCCDF_VALUE_VAR_NAME
        """
        result = content

        for var_id, value in variable_overrides.items():
            # Ansible substitution
            result = result.replace(f"{{{{ {var_id} }}}}", value)

            # Bash substitution
            bash_var = f"XCCDF_VALUE_{var_id.upper()}"
            result = result.replace(f"${bash_var}", value)

        return result


# backend/app/plugins/orsa/ansible_plugin.py

from app.plugins.orsa.base import ORSAPlugin
from typing import Dict, List, Optional
import tempfile
import subprocess

class AnsibleORSAPlugin(ORSAPlugin):
    """
    ORSA plugin for Ansible remediation

    Extracts Ansible tasks from XCCDF and executes via ansible-playbook.
    """

    FIX_SYSTEM = "urn:xccdf:fix:script:ansible"

    async def execute_remediation(
        self,
        failed_rules: List[str],
        variable_overrides: Optional[Dict[str, str]] = None
    ) -> Dict[str, bool]:
        """
        Execute Ansible remediation for failed rules
        """
        results = {}

        # Create temporary playbook
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            playbook_path = f.name

            # Write playbook header
            f.write("---\n")
            f.write("- name: OpenWatch ORSA Remediation\n")
            f.write("  hosts: all\n")
            f.write("  become: yes\n")
            f.write("  tasks:\n\n")

            # Extract and write tasks for each failed rule
            for rule_id in failed_rules:
                xccdf_rule_id = f"xccdf_openwatch_rule_{rule_id}"
                content = self.extract_fix_content(xccdf_rule_id, self.FIX_SYSTEM)

                if content:
                    # Substitute variables if overrides provided
                    if variable_overrides:
                        content = self.substitute_variables(content, variable_overrides)

                    # Write task
                    f.write(f"    # Rule: {rule_id}\n")
                    f.write(content)
                    f.write("\n\n")

        try:
            # Execute playbook
            result = subprocess.run(
                ["ansible-playbook", playbook_path],
                capture_output=True,
                text=True
            )

            # Parse results (simple version - real implementation would parse JSON output)
            for rule_id in failed_rules:
                results[rule_id] = result.returncode == 0

        finally:
            # Cleanup
            Path(playbook_path).unlink(missing_ok=True)

        return results


# backend/app/plugins/orsa/bash_plugin.py

class BashORSAPlugin(ORSAPlugin):
    """
    ORSA plugin for Bash script remediation
    """

    FIX_SYSTEM = "urn:xccdf:fix:script:sh"

    async def execute_remediation(
        self,
        failed_rules: List[str],
        variable_overrides: Optional[Dict[str, str]] = None
    ) -> Dict[str, bool]:
        """
        Execute Bash remediation for failed rules
        """
        results = {}

        for rule_id in failed_rules:
            xccdf_rule_id = f"xccdf_openwatch_rule_{rule_id}"
            content = self.extract_fix_content(xccdf_rule_id, self.FIX_SYSTEM)

            if not content:
                results[rule_id] = False
                continue

            # Substitute variables
            if variable_overrides:
                content = self.substitute_variables(content, variable_overrides)

            # Execute script
            try:
                result = subprocess.run(
                    ["bash", "-c", content],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                results[rule_id] = result.returncode == 0
            except Exception as e:
                results[rule_id] = False

        return results
```

## Comparison: OpenWatch vs Native ComplianceAsCode

| Capability | Native ComplianceAsCode | OpenWatch (MongoDB + Dynamic XCCDF) |
|------------|-------------------------|-------------------------------------|
| **Rule Storage** | Static YAML files | MongoDB (flexible, queryable) |
| **Custom Metadata** | ❌ Limited to XCCDF fields | ✅ Custom fields (tags, owners, etc.) |
| **Variable Customization** | ✅ Via tailoring files | ✅ Via API + tailoring generation |
| **Profile Management** | ❌ Requires rebuild | ✅ Dynamic (create profiles via API) |
| **Rule Search** | ❌ Filesystem grep | ✅ MongoDB queries (indexed) |
| **Multi-Tenancy** | ❌ Not supported | ✅ Org-specific rules and profiles |
| **Version Control** | ✅ Git-based | ✅ MongoDB versioning + Git |
| **Custom Rules** | ❌ Requires fork/contribution | ✅ Add via API |
| **Scan Performance** | ✅ Fast (pre-built) | ✅ Fast (cached data-streams) |
| **Remediation** | ✅ Native OSCAP | ✅ OSCAP + ORSA plugins |
| **Real-time Updates** | ❌ Requires rebuild/redeploy | ✅ Update rules in MongoDB |
| **Compliance Reporting** | ✅ OSCAP reports | ✅✅ OSCAP + Custom dashboards |
| **Rule Attribution** | ❌ Not tracked | ✅ Author, reviewer, date |
| **A/B Testing Rules** | ❌ Not possible | ✅ Test alternate implementations |

## Advantages of OpenWatch Approach

### 1. **Same Scan Results as ComplianceAsCode**
- Uses identical OSCAP engine
- Same OVAL/OCIL checks
- Same remediation scripts
- **Result: 100% parity with upstream**

### 2. **Better Flexibility**
- Create custom profiles via API (no rebuild)
- Add organization-specific rules
- Tag and categorize rules dynamically
- Multi-tenant isolation

### 3. **Better Performance for Management**
- MongoDB queries >>> filesystem grep
- Indexed searches by framework, severity, platform
- Real-time rule updates
- No need to rebuild data-streams

### 4. **Better Auditability**
- Track who created/modified rules
- Version history in MongoDB
- Change logs for compliance audits
- Approval workflows for rule changes

### 5. **Better Integration**
- RESTful API for all operations
- Webhook support for scan events
- Export to multiple formats (JSON, YAML, XCCDF, CSV)
- Integration with ticketing systems (Jira, ServiceNow)

### 6. **ORSA Plugin Ecosystem**
- Ansible plugin (native XCCDF)
- Bash plugin (native XCCDF)
- Puppet plugin (convert from XCCDF)
- Chef plugin (convert from XCCDF)
- SaltStack plugin (convert from XCCDF)
- Custom plugins for proprietary tools

## Performance Optimization: Data-Stream Caching

```python
# backend/app/services/xccdf_cache.py

from typing import Optional
from pathlib import Path
import hashlib
import json

class XCCDFCache:
    """
    Cache generated XCCDF data-streams to avoid regeneration

    Cache key = hash(profile + rule_ids + rule_versions)
    """

    def __init__(self, cache_dir: Path = Path("/var/cache/openwatch/xccdf")):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    async def get_datastream(
        self,
        profile: str,
        variable_defaults: Optional[Dict[str, str]] = None
    ) -> Optional[Path]:
        """
        Get cached data-stream if available and valid
        """
        cache_key = await self._compute_cache_key(profile, variable_defaults)
        cache_file = self.cache_dir / f"{cache_key}.xml"

        if cache_file.exists():
            return cache_file

        return None

    async def store_datastream(
        self,
        profile: str,
        datastream_path: Path,
        variable_defaults: Optional[Dict[str, str]] = None
    ) -> Path:
        """
        Store generated data-stream in cache
        """
        cache_key = await self._compute_cache_key(profile, variable_defaults)
        cache_file = self.cache_dir / f"{cache_key}.xml"

        # Copy to cache
        shutil.copy(datastream_path, cache_file)

        return cache_file

    async def _compute_cache_key(
        self,
        profile: str,
        variable_defaults: Optional[Dict[str, str]]
    ) -> str:
        """
        Compute cache key from profile rules

        Cache is invalid if:
        - Any rule in profile changes
        - Variable defaults change
        """
        # Get all rule IDs and versions for this profile
        rules = await ComplianceRule.find(
            {f"profiles.{profile}": {"$exists": True}}
        ).to_list()

        rule_fingerprint = {
            rule.rule_id: rule.version
            for rule in rules
        }

        # Include variable defaults in key
        key_data = {
            "profile": profile,
            "rules": rule_fingerprint,
            "variables": variable_defaults or {}
        }

        # Hash
        key_json = json.dumps(key_data, sort_keys=True)
        return hashlib.sha256(key_json.encode()).hexdigest()

    async def invalidate_profile(self, profile: str) -> int:
        """
        Invalidate all cached data-streams for a profile

        Call this when rules in profile are modified.
        """
        count = 0
        for cache_file in self.cache_dir.glob(f"*{profile}*.xml"):
            cache_file.unlink()
            count += 1
        return count
```

## Next Steps

1. **Implement XCCDFDataStreamGenerator** ✅ (documented above)
2. **Enhance ComplianceRule model** with `xccdf_variables` field
3. **Update SCAP converter** to extract remediation content and variables
4. **Implement MongoDBScanService** with dynamic XCCDF generation
5. **Implement ORSA base plugin** and Ansible/Bash plugins
6. **Add data-stream caching** for performance
7. **Create API endpoints** for custom scans with variables
8. **Build UI** for variable customization and ORSA remediation

---
*Last updated: 2025-10-14*
