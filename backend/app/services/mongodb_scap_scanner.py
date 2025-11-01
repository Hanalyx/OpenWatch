"""
MongoDB-Integrated SCAP Scanner Service
Enhanced scanner that uses MongoDB compliance rules for scanning operations
"""
import asyncio
import logging
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
import json
import uuid
import shutil

from .scap_scanner import SCAPScanner, ScanExecutionError, SCAPContentError
from .mongo_integration_service import get_mongo_service, MongoIntegrationService
from .rule_service import RuleService
from .platform_capability_service import PlatformCapabilityService
from .remote_scap_executor import RemoteSCAPExecutor, ScanType, RemoteSCAPExecutionError
from .auth_service import get_auth_service
from ..models.mongo_models import ComplianceRule, RuleIntelligence, PlatformImplementation
from ..config import get_settings
from ..database import SessionLocal

logger = logging.getLogger(__name__)


class MongoDBSCAPScanner(SCAPScanner):
    """Enhanced SCAP Scanner that integrates with MongoDB rules"""
    
    def __init__(self, content_dir: Optional[str] = None, results_dir: Optional[str] = None):
        super().__init__(content_dir, results_dir)
        self.mongo_service: Optional[MongoIntegrationService] = None
        self.rule_service: Optional[RuleService] = None
        self.platform_service: Optional[PlatformCapabilityService] = None
        self._initialized = False
        
    async def initialize(self):
        """Initialize MongoDB integration services"""
        if self._initialized:
            return
            
        try:
            # Initialize MongoDB service
            self.mongo_service = await get_mongo_service()
            logger.info("MongoDB service initialized for scanner")
            
            # Initialize rule service
            self.rule_service = RuleService()
            await self.rule_service.initialize()
            logger.info("Rule service initialized for scanner")
            
            # Initialize platform service
            self.platform_service = PlatformCapabilityService()
            await self.platform_service.initialize()
            logger.info("Platform capability service initialized")
            
            self._initialized = True
            logger.info("MongoDB SCAP Scanner fully initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize MongoDB SCAP Scanner: {e}")
            raise SCAPContentError(f"MongoDB integration initialization failed: {str(e)}")
    
    async def select_platform_rules(self, platform: str, platform_version: str,
                                  framework: Optional[str] = None,
                                  severity_filter: Optional[List[str]] = None) -> List[ComplianceRule]:
        """Select MongoDB rules applicable to a specific platform"""
        if not self._initialized:
            await self.initialize()

        try:
            logger.info(f"Selecting rules for platform: {platform} {platform_version}")

            # Use rule service to get platform-specific rules
            rules = await self.rule_service.get_rules_by_platform(
                platform=platform,
                platform_version=platform_version,
                framework=framework,
                severity_filter=severity_filter
            )

            # Convert to ComplianceRule objects if needed
            mongodb_rules = []
            for rule_data in rules:
                if isinstance(rule_data, dict):
                    # Convert dict to ComplianceRule if needed
                    try:
                        rule = ComplianceRule(**rule_data)
                        mongodb_rules.append(rule)
                    except Exception as e:
                        logger.warning(f"Failed to convert rule {rule_data.get('rule_id', 'unknown')}: {e}")
                        continue
                else:
                    mongodb_rules.append(rule_data)

            logger.info(f"Selected {len(mongodb_rules)} rules for {platform} {platform_version}")
            return mongodb_rules

        except Exception as e:
            logger.error(f"Failed to select platform rules: {e}")
            raise SCAPContentError(f"Platform rule selection failed: {str(e)}")

    async def get_rules_by_ids(self, rule_ids: List[str]) -> List[ComplianceRule]:
        """Get specific rules by their MongoDB ObjectIds"""
        if not self._initialized:
            await self.initialize()

        try:
            from bson import ObjectId
            from ..repositories import ComplianceRuleRepository

            logger.info(f"Fetching {len(rule_ids)} specific rules from MongoDB")

            repo = ComplianceRuleRepository()
            rules = []

            for rule_id in rule_ids:
                try:
                    # Query by MongoDB ObjectId using find_one
                    rule = await repo.find_one({"_id": ObjectId(rule_id)})
                    if rule:
                        rules.append(rule)
                    else:
                        logger.warning(f"Rule not found: {rule_id}")
                except Exception as e:
                    logger.warning(f"Failed to fetch rule {rule_id}: {e}")
                    continue

            logger.info(f"Successfully fetched {len(rules)} rules by ID")
            return rules

        except Exception as e:
            logger.error(f"Failed to get rules by IDs: {e}")
            raise SCAPContentError(f"Rule retrieval failed: {str(e)}")
    
    async def resolve_rule_inheritance(self, rules: List[ComplianceRule], 
                                     platform: str) -> List[ComplianceRule]:
        """Resolve rule inheritance and parameter overrides"""
        try:
            logger.info(f"Resolving inheritance for {len(rules)} rules on {platform}")
            
            resolved_rules = []
            for rule in rules:
                # Check if rule has inheritance
                if hasattr(rule, 'inherits_from') and rule.inherits_from:
                    try:
                        # Get parent rule with inheritance resolution
                        parent_data = await self.rule_service.get_rule_with_dependencies(
                            rule_id=rule.inherits_from,
                            resolve_depth=3,
                            include_conflicts=True
                        )
                        
                        # Merge parent and child rule configurations
                        resolved_rule = await self._merge_inherited_rule(rule, parent_data, platform)
                        resolved_rules.append(resolved_rule)
                        
                    except Exception as e:
                        logger.warning(f"Failed to resolve inheritance for rule {rule.rule_id}: {e}")
                        # Use original rule if inheritance resolution fails
                        resolved_rules.append(rule)
                else:
                    resolved_rules.append(rule)
            
            logger.info(f"Resolved inheritance for {len(resolved_rules)} rules")
            return resolved_rules
            
        except Exception as e:
            logger.error(f"Rule inheritance resolution failed: {e}")
            return rules  # Return original rules if resolution fails
    
    async def _merge_inherited_rule(self, child_rule: ComplianceRule, 
                                   parent_data: Dict, platform: str) -> ComplianceRule:
        """Merge child rule with parent rule data"""
        try:
            parent_rule_data = parent_data.get('rule', {})
            
            # Create a copy of the child rule
            merged_data = child_rule.dict()
            
            # Merge platform implementations
            if 'platform_implementations' in parent_rule_data:
                parent_platforms = parent_rule_data['platform_implementations']
                child_platforms = merged_data.get('platform_implementations', {})
                
                # Merge platform-specific configurations
                for p_name, p_impl in parent_platforms.items():
                    if p_name not in child_platforms:
                        child_platforms[p_name] = p_impl
                    elif p_name == platform:
                        # Child overrides parent for specific platform
                        merged_impl = {**p_impl, **child_platforms[p_name]}
                        child_platforms[p_name] = merged_impl
                
                merged_data['platform_implementations'] = child_platforms
            
            # Merge frameworks
            if 'frameworks' in parent_rule_data:
                parent_frameworks = parent_rule_data['frameworks']
                child_frameworks = merged_data.get('frameworks', {})
                
                for framework, versions in parent_frameworks.items():
                    if framework not in child_frameworks:
                        child_frameworks[framework] = versions
                    else:
                        # Merge version mappings
                        child_frameworks[framework].update(versions)
                
                merged_data['frameworks'] = child_frameworks
            
            # Merge tags
            if 'tags' in parent_rule_data:
                parent_tags = set(parent_rule_data['tags'])
                child_tags = set(merged_data.get('tags', []))
                merged_data['tags'] = list(parent_tags.union(child_tags))
            
            # Create new rule with merged data
            return ComplianceRule(**merged_data)
            
        except Exception as e:
            logger.error(f"Failed to merge inherited rule: {e}")
            return child_rule
    
    async def generate_mongodb_scan_profile(self, rules: List[ComplianceRule],
                                          profile_name: str,
                                          platform: str) -> Tuple[str, Optional[str]]:
        """
        Generate SCAP profile XML and OVAL definitions from MongoDB rules

        Returns:
            Tuple of (xccdf_profile_path, oval_definitions_path)
            oval_definitions_path may be None if no OVAL definitions found
        """
        try:
            logger.info(f"Generating SCAP profile '{profile_name}' from {len(rules)} MongoDB rules")

            # Create temporary directory for SCAP content
            temp_dir = Path(tempfile.mkdtemp(prefix='openwatch_scap_'))

            # Generate OVAL definitions document first to get the mapping
            oval_definitions_path, rule_to_oval_id_map = self._generate_oval_definitions(rules, platform, temp_dir)

            if oval_definitions_path:
                logger.info(f"Generated OVAL definitions: {oval_definitions_path}")
            else:
                logger.warning(f"No OVAL definitions generated for {len(rules)} rules")

            # Generate XCCDF profile with OVAL ID mapping
            profile_path = temp_dir / "xccdf-profile.xml"
            xml_content = self._generate_xccdf_profile_xml(rules, profile_name, platform, rule_to_oval_id_map)
            with open(profile_path, 'w', encoding='utf-8') as f:
                f.write(xml_content)

            logger.info(f"Generated SCAP profile: {profile_path}")

            return (str(profile_path), oval_definitions_path)

        except Exception as e:
            logger.error(f"Failed to generate MongoDB scan profile: {e}")
            raise SCAPContentError(f"Profile generation failed: {str(e)}")

    def _generate_oval_definitions(self, rules: List[ComplianceRule],
                                   platform: str,
                                   temp_dir: Path) -> Tuple[Optional[str], Dict[str, str]]:
        """
        Generate OVAL definitions document from MongoDB rules with oval_filename references

        Args:
            rules: List of ComplianceRule objects
            platform: Target platform (e.g., 'rhel8')
            temp_dir: Temporary directory to store generated OVAL file

        Returns:
            Tuple of (path_to_oval_definitions, rule_to_oval_id_mapping)
            - path: Path to generated oval-definitions.xml or None if no OVAL definitions found
            - mapping: Dict mapping rule_id -> actual OVAL definition ID for XCCDF generation
        """
        try:
            oval_storage_base = Path("/app/data/oval_definitions")
            oval_definitions_found = []
            rules_with_oval = 0

            # Collect all OVAL definition files referenced by rules
            for rule in rules:
                if hasattr(rule, 'oval_filename') and rule.oval_filename:
                    # oval_filename format: "platform/filename.xml" (e.g., "rhel8/package_firewalld_installed.xml")
                    oval_file_path = oval_storage_base / rule.oval_filename

                    if oval_file_path.exists():
                        oval_definitions_found.append({
                            'rule_id': rule.rule_id,
                            'oval_path': oval_file_path,
                            'oval_filename': rule.oval_filename
                        })
                        rules_with_oval += 1
                    else:
                        logger.warning(f"OVAL file not found for rule {rule.rule_id}: {oval_file_path}")

            if not oval_definitions_found:
                logger.warning(f"No OVAL definitions found for {len(rules)} rules on platform {platform}")
                return (None, {})

            logger.info(f"Found {len(oval_definitions_found)} OVAL definitions for {rules_with_oval} rules")

            # Generate combined OVAL definitions document
            # Create root element with OVAL namespaces
            oval_ns = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
            oval_common_ns = "http://oval.mitre.org/XMLSchema/oval-common-5"
            linux_ns = "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"
            unix_ns = "http://oval.mitre.org/XMLSchema/oval-definitions-5#unix"
            ind_ns = "http://oval.mitre.org/XMLSchema/oval-definitions-5#independent"

            # Register namespaces
            ET.register_namespace('', oval_ns)
            ET.register_namespace('oval', oval_common_ns)
            ET.register_namespace('linux', linux_ns)
            ET.register_namespace('unix', unix_ns)
            ET.register_namespace('ind', ind_ns)

            # Create root oval_definitions element
            root = ET.Element(f"{{{oval_ns}}}oval_definitions", attrib={
                f"{{{oval_ns}}}schemaVersion": "5.11"
            })

            # Add generator info
            generator = ET.SubElement(root, "generator")
            ET.SubElement(generator, "product_name").text = "OpenWatch MongoDB SCAP Scanner"
            ET.SubElement(generator, "product_version").text = "1.0.0"
            ET.SubElement(generator, "schema_version").text = "5.11"
            ET.SubElement(generator, "timestamp").text = datetime.utcnow().isoformat() + "Z"

            # Create definitions container
            definitions = ET.SubElement(root, "definitions")

            # Create tests, objects, states, and variables containers
            tests = ET.SubElement(root, "tests")
            objects = ET.SubElement(root, "objects")
            states = ET.SubElement(root, "states")
            variables = ET.SubElement(root, "variables")

            # Process each OVAL file and extract definitions
            definition_ids_added = set()
            # Map rule_id -> actual OVAL definition ID for XCCDF generation
            rule_to_oval_id_map = {}

            for oval_info in oval_definitions_found:
                try:
                    # Parse the OVAL file
                    tree = ET.parse(oval_info['oval_path'])
                    oval_root = tree.getroot()

                    # Extract all definition elements
                    for definition in oval_root.findall('.//{http://oval.mitre.org/XMLSchema/oval-definitions-5}definition'):
                        def_id = definition.get('id')
                        if def_id and def_id not in definition_ids_added:
                            definitions.append(definition)
                            definition_ids_added.add(def_id)
                            # Store mapping: rule_id -> OVAL definition ID
                            rule_to_oval_id_map[oval_info['rule_id']] = def_id

                    # Extract tests
                    for test in oval_root.findall('.//{http://oval.mitre.org/XMLSchema/oval-definitions-5}*[@id]'):
                        if 'test' in test.tag.lower():
                            test_id = test.get('id')
                            if test_id:
                                tests.append(test)

                    # Extract objects
                    for obj in oval_root.findall('.//{http://oval.mitre.org/XMLSchema/oval-definitions-5}*[@id]'):
                        if 'object' in obj.tag.lower():
                            obj_id = obj.get('id')
                            if obj_id:
                                objects.append(obj)

                    # Extract states
                    for state in oval_root.findall('.//{http://oval.mitre.org/XMLSchema/oval-definitions-5}*[@id]'):
                        if 'state' in state.tag.lower():
                            state_id = state.get('id')
                            if state_id:
                                states.append(state)

                    # Extract variables
                    for variable in oval_root.findall('.//{http://oval.mitre.org/XMLSchema/oval-definitions-5}*[@id]'):
                        if 'variable' in variable.tag.lower():
                            var_id = variable.get('id')
                            if var_id:
                                variables.append(variable)

                except Exception as e:
                    logger.error(f"Failed to parse OVAL file {oval_info['oval_path']}: {e}")
                    continue

            # Write combined OVAL definitions document
            oval_output_path = temp_dir / "oval-definitions.xml"
            tree = ET.ElementTree(root)
            tree.write(
                oval_output_path,
                encoding='utf-8',
                xml_declaration=True,
                method='xml'
            )

            logger.info(f"Generated OVAL definitions document: {oval_output_path} ({len(definition_ids_added)} definitions)")
            return (str(oval_output_path), rule_to_oval_id_map)

        except Exception as e:
            logger.error(f"Failed to generate OVAL definitions document: {e}", exc_info=True)
            return (None, {})

    def _strip_html_tags(self, text: str) -> str:
        """
        Strip all HTML tags from text for XCCDF compliance.
        XCCDF only allows plain text or properly namespaced XHTML elements.
        For simplicity, we strip all HTML to avoid schema validation errors.
        """
        import re
        if not text:
            return ""

        # Remove all HTML tags (including self-closing tags like <br/>)
        text = re.sub(r'<[^>]+>', '', text)

        # Clean up multiple whitespaces/newlines
        text = re.sub(r'\s+', ' ', text)

        # Escape XML special characters
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        text = text.replace('"', '&quot;')
        text = text.replace("'", '&apos;')

        return text.strip()

    def _generate_xccdf_profile_xml(self, rules: List[ComplianceRule],
                                   profile_name: str, platform: str,
                                   rule_to_oval_id_map: Dict[str, str] = None) -> str:
        """
        Generate XCCDF XML from MongoDB rules

        Args:
            rules: List of ComplianceRule objects
            profile_name: Name of the profile
            platform: Target platform
            rule_to_oval_id_map: Optional mapping of rule_id -> actual OVAL definition ID
        """
        if rule_to_oval_id_map is None:
            rule_to_oval_id_map = {}

        # Debug logging
        logger.info(f"Generating XCCDF for {len(rules)} rules with platform={platform}")
        if rules:
            sample_rule = rules[0]
            logger.info(f"Sample rule platform_implementations keys: {list(sample_rule.platform_implementations.keys()) if hasattr(sample_rule, 'platform_implementations') and sample_rule.platform_implementations else 'None'}")

        # Generate XCCDF-compliant IDs following the pattern: xccdf_<reverse-domain>_<type>_<name>
        benchmark_id = f"xccdf_com.openwatch_benchmark_{platform}"
        profile_id = f"xccdf_com.openwatch_profile_{profile_name.lower().replace(' ', '_')}"

        xml_lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<xccdf:Benchmark xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2" ',
            'xmlns:xhtml="http://www.w3.org/1999/xhtml" ',
            f'id="{benchmark_id}" resolved="1" xml:lang="en-US">',
            f'  <xccdf:status>incomplete</xccdf:status>',
            f'  <xccdf:title>MongoDB Generated Profile - {profile_name}</xccdf:title>',
            f'  <xccdf:description>Profile generated from MongoDB compliance rules</xccdf:description>',
            f'  <xccdf:version>{datetime.now().strftime("%Y.%m.%d")}</xccdf:version>',
            f'  <xccdf:model system="urn:xccdf:scoring:default"/>',
            '',
            f'  <xccdf:Profile id="{profile_id}">',
            f'    <xccdf:title>{profile_name}</xccdf:title>',
            f'    <xccdf:description>MongoDB-based compliance profile for {platform}</xccdf:description>',
        ]
        
        # Add rule selections
        # Note: rules are already filtered for the platform, so no need to check platform_implementations
        rules_added = 0
        for rule in rules:
            # Use scap_rule_id if available (proper XCCDF ID from source), otherwise fall back to rule_id
            rule_id = rule.scap_rule_id or rule.rule_id
            xml_lines.append(f'    <xccdf:select idref="{rule_id}" selected="true"/>')
            rules_added += 1

        logger.info(f"Added {rules_added} rule selections to XCCDF profile")
        xml_lines.append('  </xccdf:Profile>')

        # Add rules
        # Note: rules are already filtered for the platform, so no need to check platform_implementations
        rules_with_checks = 0
        for rule in rules:
                # Use scap_rule_id if available (proper XCCDF ID from source), otherwise fall back to rule_id
                rule_id = rule.scap_rule_id or rule.rule_id

                # Strip HTML tags from description and rationale for XCCDF compliance
                description = self._strip_html_tags(rule.metadata.get("description", "No description"))
                rationale = self._strip_html_tags(rule.metadata.get("rationale", "No rationale provided"))

                xml_lines.extend([
                    '',
                    f'  <xccdf:Rule id="{rule_id}" severity="{rule.severity}">',
                    f'    <xccdf:title>{rule.metadata.get("name", "Unknown Rule")}</xccdf:title>',
                    f'    <xccdf:description>{description}</xccdf:description>',
                    f'    <xccdf:rationale>{rationale}</xccdf:rationale>',
                ])

                # Add OVAL check reference if rule has an OVAL definition
                if hasattr(rule, 'oval_filename') and rule.oval_filename:
                    # Use the actual OVAL definition ID from the mapping (extracted from OVAL file)
                    # Fallback to constructed ID if not in mapping (backwards compatibility)
                    actual_oval_id = rule_to_oval_id_map.get(rule.rule_id)

                    if actual_oval_id:
                        # Use the real OVAL definition ID from the OVAL file
                        xml_lines.extend([
                            '    <xccdf:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">',
                            f'      <xccdf:check-content-ref name="{actual_oval_id}" href="oval-definitions.xml"/>',
                            '    </xccdf:check>',
                        ])
                        rules_with_checks += 1
                    else:
                        # Log warning if mapping is missing
                        logger.warning(f"No OVAL definition ID mapping found for rule {rule.rule_id} with OVAL file {rule.oval_filename}")

                xml_lines.append('  </xccdf:Rule>')

        logger.info(f"Added {len(rules)} XCCDF rules ({rules_with_checks} with OVAL checks)")
        
        xml_lines.append('</xccdf:Benchmark>')
        
        return '\n'.join(xml_lines)
    
    async def scan_with_mongodb_rules(self, host_id: str, hostname: str,
                                    platform: str, platform_version: str,
                                    framework: Optional[str] = None,
                                    connection_params: Optional[Dict] = None,
                                    severity_filter: Optional[List[str]] = None,
                                    rule_ids: Optional[List[str]] = None) -> Dict:
        """Perform SCAP scan using MongoDB rules"""
        if not self._initialized:
            await self.initialize()

        try:
            scan_id = f"mongodb_scan_{host_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            logger.info(f"Starting MongoDB rule-based scan {scan_id} for {hostname}")

            # Step 1: Select rules - either specific IDs or platform-appropriate rules
            if rule_ids:
                logger.info(f"Using {len(rule_ids)} user-selected rules")
                rules = await self.get_rules_by_ids(rule_ids)
            else:
                logger.info(f"Auto-selecting rules for platform {platform} {platform_version}")
                rules = await self.select_platform_rules(
                    platform=platform,
                    platform_version=platform_version,
                    framework=framework,
                    severity_filter=severity_filter
                )

            if not rules:
                return {
                    "success": False,
                    "error": f"No rules found for platform {platform} {platform_version}",
                    "scan_id": scan_id
                }
            
            # Step 2: Resolve rule inheritance
            resolved_rules = await self.resolve_rule_inheritance(rules, platform)
            
            # Step 3: Generate SCAP profile from MongoDB rules
            profile_name = f"MongoDB {framework or 'Standard'} Profile"
            profile_path, oval_path = await self.generate_mongodb_scan_profile(
                resolved_rules, profile_name, platform
            )

            # Step 4: Execute SCAP scan with generated profile
            scan_result = await self._execute_mongodb_scan(
                scan_id=scan_id,
                hostname=hostname,
                profile_path=profile_path,
                profile_name=profile_name,
                connection_params=connection_params,
                platform=platform
            )

            # Step 5: Enrich results with MongoDB rule intelligence
            enriched_result = await self._enrich_scan_results(scan_result, resolved_rules)

            # Cleanup temporary files
            # TODO: Temporarily disabled for debugging - re-enable after XCCDF fix
            try:
                temp_dir = Path(profile_path).parent
                logger.info(f"DEBUG: Preserved local temp directory for inspection: {temp_dir}")
                # shutil.rmtree(temp_dir)
                # logger.debug(f"Cleaned up temporary SCAP content directory: {temp_dir}")
            except Exception as e:
                logger.warning(f"Failed to preserve temp directory: {e}")
            
            logger.info(f"MongoDB scan {scan_id} completed successfully")
            return enriched_result
            
        except Exception as e:
            logger.error(f"MongoDB scan failed: {e}")
            raise ScanExecutionError(f"MongoDB-based scan failed: {str(e)}")
    
    async def _execute_mongodb_scan(self, scan_id: str, hostname: str,
                                   profile_path: str, profile_name: str,
                                   connection_params: Optional[Dict],
                                   platform: str) -> Dict:
        """Execute the actual SCAP scan with generated profile"""
        try:
            # Generate XCCDF-compliant profile ID
            profile_id = f"xccdf_com.openwatch_profile_{profile_name.lower().replace(' ', '_')}"

            # Result file paths
            result_file = self.results_dir / f"{scan_id}_results.xml"

            if connection_params:
                # Remote scan using RemoteSCAPExecutor
                logger.info(f"Executing remote MongoDB scan on {hostname}")

                # Get host and auth_method from database to determine credential resolution strategy
                db = SessionLocal()
                try:
                    from sqlalchemy import text

                    host_result = db.execute(
                        text("SELECT auth_method FROM hosts WHERE id = :host_id"),
                        {"host_id": connection_params.get('host_id')}
                    ).fetchone()

                    if not host_result:
                        raise ScanExecutionError(f"Host {connection_params.get('host_id')} not found")

                    host_auth_method = host_result[0]
                    use_default = host_auth_method in ['system_default', 'default']
                    target_id = None if use_default else connection_params.get('host_id')

                    logger.info(f"Host auth_method: {host_auth_method}, use_default: {use_default}")

                    # Use CentralizedAuthService to resolve credentials
                    auth_service = get_auth_service(db)
                    credential_data = auth_service.resolve_credential(
                        target_id=target_id,
                        use_default=use_default
                    )

                    if not credential_data:
                        raise ScanExecutionError(
                            f"No credentials available for host {connection_params.get('host_id')}"
                        )

                    logger.info(f"Resolved credentials: username={credential_data.username}, "
                               f"auth_method={credential_data.auth_method.value}, "
                               f"source={credential_data.source}")

                    # Update connection_params with resolved credentials
                    connection_params['username'] = credential_data.username
                    connection_params['auth_method'] = credential_data.auth_method.value

                    # Initialize remote executor with database session
                    executor = RemoteSCAPExecutor(db=db)

                    # Execute remote scan with CredentialData object
                    remote_result = executor.execute_scan(
                        xccdf_file=Path(profile_path),
                        profile_id=profile_id,
                        hostname=hostname,
                        connection_params=connection_params,
                        credential_data=credential_data,
                        scan_id=scan_id,
                        results_dir=self.results_dir,
                        scan_type=ScanType.MONGODB_GENERATED,
                        timeout=1800  # 30 minutes timeout for remote scans
                    )

                finally:
                    db.close()

                # Convert RemoteScanResult to dict format
                result_xml = remote_result.result_files.get('xml')
                result_html = remote_result.result_files.get('html')

                return {
                    "success": remote_result.success,
                    "scan_id": scan_id,
                    "return_code": remote_result.exit_code,
                    "stdout": remote_result.stdout,
                    "stderr": remote_result.stderr,
                    "result_file": str(result_xml) if result_xml else str(result_file),
                    "report_file": str(result_html) if result_html else str(result_file).replace('.xml', '.html'),
                    "execution_time": remote_result.execution_time_seconds,
                    "files_transferred": remote_result.files_transferred
                }

            else:
                # Local scan using subprocess
                logger.info(f"Executing local MongoDB scan")

                cmd = [
                    'oscap', 'xccdf', 'eval',
                    '--profile', profile_id,
                    '--results', str(result_file),
                    '--report', str(result_file).replace('.xml', '.html'),
                    profile_path
                ]

                logger.info(f"Executing local command: {' '.join(cmd)}")

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minutes timeout for local scans
                )

                # Log oscap output for debugging
                if result.returncode not in [0, 2]:  # 0=pass, 2=some rules failed
                    logger.error(f"oscap returned non-zero exit code: {result.returncode}")
                    logger.error(f"oscap stderr: {result.stderr}")
                else:
                    logger.info(f"oscap completed successfully (exit code: {result.returncode})")

                return {
                    "success": True,
                    "scan_id": scan_id,
                    "return_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "result_file": str(result_file),
                    "report_file": str(result_file).replace('.xml', '.html')
                }

        except RemoteSCAPExecutionError as e:
            logger.error(f"Remote MongoDB scan execution failed: {e}")
            raise ScanExecutionError(f"Remote scan execution failed: {str(e)}")
        except subprocess.TimeoutExpired:
            raise ScanExecutionError("Local scan execution timeout")
        except Exception as e:
            logger.error(f"MongoDB scan execution failed: {e}", exc_info=True)
            raise ScanExecutionError(f"Scan execution failed: {str(e)}")

    async def _enrich_scan_results(self, scan_result: Dict, 
                                 rules: List[ComplianceRule]) -> Dict:
        """Enrich scan results with MongoDB rule intelligence"""
        try:
            if not scan_result.get("success") or not scan_result.get("result_file"):
                return scan_result
            
            # Parse SCAP results XML
            result_file = scan_result["result_file"]
            if not Path(result_file).exists():
                logger.warning(f"Scan result file not found: {result_file}")
                return scan_result
            
            # Read and parse results
            with open(result_file, 'r') as f:
                results_xml = f.read()
            
            # Create rule lookup for enrichment
            rule_lookup = {rule.scap_rule_id or rule.rule_id: rule for rule in rules}
            
            # Enrich with MongoDB intelligence
            enrichment_data = await self._gather_rule_intelligence(rule_lookup)
            
            # Add enrichment to result
            scan_result["enrichment"] = enrichment_data
            scan_result["mongodb_rules_used"] = len(rules)
            scan_result["enriched_at"] = datetime.utcnow().isoformat()
            
            logger.info(f"Enriched scan results with {len(enrichment_data)} rule intelligence entries")
            return scan_result
            
        except Exception as e:
            logger.error(f"Failed to enrich scan results: {e}")
            # Return original results if enrichment fails
            return scan_result
    
    async def _gather_rule_intelligence(self, rule_lookup: Dict[str, ComplianceRule]) -> Dict[str, Any]:
        """Gather intelligence data for rules"""
        intelligence_data = {}
        
        for rule_id, rule in rule_lookup.items():
            try:
                # Get rule intelligence from MongoDB
                intel_result = await self.mongo_service.get_rule_with_intelligence(rule.rule_id)
                
                if intel_result and "intelligence" in intel_result:
                    intelligence_data[rule_id] = {
                        "rule_id": rule.rule_id,
                        "business_impact": intel_result["intelligence"].get("business_impact"),
                        "compliance_importance": intel_result["intelligence"].get("compliance_importance"),
                        "false_positive_rate": intel_result["intelligence"].get("false_positive_rate"),
                        "remediation_complexity": rule.remediation_complexity,
                        "remediation_risk": rule.remediation_risk,
                        "frameworks": rule.frameworks,
                        "tags": rule.tags
                    }
                
            except Exception as e:
                logger.warning(f"Failed to gather intelligence for rule {rule_id}: {e}")
                continue
        
        return intelligence_data