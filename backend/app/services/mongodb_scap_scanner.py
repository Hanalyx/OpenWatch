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

from .scap_scanner import SCAPScanner, ScanExecutionError, SCAPContentError
from .mongo_integration_service import get_mongo_service, MongoIntegrationService
from .rule_service import RuleService
from .platform_capability_service import PlatformCapabilityService
from ..models.mongo_models import ComplianceRule, RuleIntelligence, PlatformImplementation
from ..config import get_settings

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
                                          platform: str) -> str:
        """Generate SCAP profile XML from MongoDB rules"""
        try:
            logger.info(f"Generating SCAP profile '{profile_name}' from {len(rules)} MongoDB rules")
            
            # Create temporary file for the generated profile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
                profile_path = f.name
                
                # Generate basic XCCDF profile structure
                xml_content = self._generate_xccdf_profile_xml(rules, profile_name, platform)
                f.write(xml_content)
            
            logger.info(f"Generated SCAP profile: {profile_path}")
            return profile_path
            
        except Exception as e:
            logger.error(f"Failed to generate MongoDB scan profile: {e}")
            raise SCAPContentError(f"Profile generation failed: {str(e)}")
    
    def _generate_xccdf_profile_xml(self, rules: List[ComplianceRule], 
                                   profile_name: str, platform: str) -> str:
        """Generate XCCDF XML from MongoDB rules"""
        xml_lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<xccdf:Benchmark xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2" ',
            'xmlns:xhtml="http://www.w3.org/1999/xhtml" ',
            f'id="mongodb-generated-{platform}" resolved="1" xml:lang="en-US">',
            f'  <xccdf:status>incomplete</xccdf:status>',
            f'  <xccdf:title>MongoDB Generated Profile - {profile_name}</xccdf:title>',
            f'  <xccdf:description>Profile generated from MongoDB compliance rules</xccdf:description>',
            f'  <xccdf:version>{datetime.now().strftime("%Y.%m.%d")}</xccdf:version>',
            '',
            f'  <xccdf:Profile id="mongodb_{profile_name.lower().replace(" ", "_")}">',
            f'    <xccdf:title>{profile_name}</xccdf:title>',
            f'    <xccdf:description>MongoDB-based compliance profile for {platform}</xccdf:description>',
        ]
        
        # Add rule selections
        for rule in rules:
            if rule.platform_implementations and platform in rule.platform_implementations:
                xml_lines.append(f'    <xccdf:select idref="{rule.scap_rule_id or rule.rule_id}" selected="true"/>')
        
        xml_lines.append('  </xccdf:Profile>')
        
        # Add rules
        for rule in rules:
            if rule.platform_implementations and platform in rule.platform_implementations:
                platform_impl = rule.platform_implementations[platform]
                
                xml_lines.extend([
                    '',
                    f'  <xccdf:Rule id="{rule.scap_rule_id or rule.rule_id}" severity="{rule.severity}">',
                    f'    <xccdf:title>{rule.metadata.get("name", "Unknown Rule")}</xccdf:title>',
                    f'    <xccdf:description>{rule.metadata.get("description", "No description")}</xccdf:description>',
                    f'    <xccdf:rationale>{rule.metadata.get("rationale", "No rationale provided")}</xccdf:rationale>',
                ])
                
                # Add check if available
                if hasattr(platform_impl, 'check_command') and platform_impl.check_command:
                    xml_lines.extend([
                        '    <xccdf:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">',
                        f'      <xccdf:check-content-ref name="oval:org.openwatch:def:{rule.rule_id}" href="oval-definitions.xml"/>',
                        '    </xccdf:check>',
                    ])
                
                xml_lines.append('  </xccdf:Rule>')
        
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
            profile_path = await self.generate_mongodb_scan_profile(
                resolved_rules, profile_name, platform
            )
            
            # Step 4: Execute SCAP scan with generated profile
            scan_result = await self._execute_mongodb_scan(
                scan_id=scan_id,
                hostname=hostname,
                profile_path=profile_path,
                connection_params=connection_params,
                platform=platform
            )
            
            # Step 5: Enrich results with MongoDB rule intelligence
            enriched_result = await self._enrich_scan_results(scan_result, resolved_rules)
            
            # Cleanup temporary profile
            try:
                Path(profile_path).unlink()
            except Exception as e:
                logger.warning(f"Failed to cleanup temporary profile: {e}")
            
            logger.info(f"MongoDB scan {scan_id} completed successfully")
            return enriched_result
            
        except Exception as e:
            logger.error(f"MongoDB scan failed: {e}")
            raise ScanExecutionError(f"MongoDB-based scan failed: {str(e)}")
    
    async def _execute_mongodb_scan(self, scan_id: str, hostname: str, 
                                   profile_path: str, connection_params: Optional[Dict],
                                   platform: str) -> Dict:
        """Execute the actual SCAP scan with generated profile"""
        try:
            # Use parent class scan method with our generated profile
            result_file = self.results_dir / f"{scan_id}_results.xml"
            
            if connection_params:
                # Remote scan
                cmd = [
                    'oscap-ssh',
                    f"{connection_params.get('username')}@{hostname}",
                    str(connection_params.get('port', 22)),
                    'xccdf', 'eval',
                    '--profile', f"mongodb_{platform.lower()}_profile",
                    '--results', str(result_file),
                    '--report', str(result_file).replace('.xml', '.html'),
                    profile_path
                ]
            else:
                # Local scan
                cmd = [
                    'oscap', 'xccdf', 'eval',
                    '--profile', f"mongodb_{platform.lower()}_profile",
                    '--results', str(result_file),
                    '--report', str(result_file).replace('.xml', '.html'),
                    profile_path
                ]
            
            logger.info(f"Executing MongoDB scan: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            return {
                "success": True,
                "scan_id": scan_id,
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "result_file": str(result_file),
                "report_file": str(result_file).replace('.xml', '.html')
            }
            
        except subprocess.TimeoutExpired:
            raise ScanExecutionError("MongoDB scan execution timeout")
        except Exception as e:
            logger.error(f"MongoDB scan execution failed: {e}")
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