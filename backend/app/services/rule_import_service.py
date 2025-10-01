"""
Rule Import Service
Handles importing and validation of unified compliance rules from JSON definitions
"""
import json
import asyncio
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

from backend.app.models.unified_rule_models import (
    UnifiedComplianceRule, RuleSet, ComplianceProfile,
    RuleType, ComplianceStatus, Platform, PlatformVersionRange,
    ExecutionContext, RuleParameter, RemediationAction, FrameworkMapping
)


class RuleImportService:
    """Service for importing unified compliance rules"""
    
    def __init__(self):
        """Initialize the rule import service"""
        self.unified_rules_path = Path(__file__).parent.parent / "data" / "unified_rules"
        self.imported_rules = {}
    
    async def import_rule_from_file(self, file_path: Path) -> str:
        """
        Import a unified compliance rule from JSON file
        
        Args:
            file_path: Path to the rule definition JSON file
            
        Returns:
            Rule ID of imported rule
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                rule_data = json.load(f)
            
            # Create unified compliance rule
            rule = await self._create_rule_from_data(rule_data)
            
            # Check if rule already exists
            existing = await UnifiedComplianceRule.find_one(
                UnifiedComplianceRule.rule_id == rule.rule_id
            )
            
            if existing:
                # Update existing rule
                for field, value in rule.__dict__.items():
                    if not field.startswith('_') and field != 'id':
                        setattr(existing, field, value)
                existing.updated_at = datetime.utcnow()
                await existing.save()
                rule_id = existing.rule_id
            else:
                # Insert new rule
                await rule.save()
                rule_id = rule.rule_id
            
            # Track imported rule
            self.imported_rules[rule_id] = {
                "file_path": str(file_path),
                "imported_at": datetime.utcnow().isoformat(),
                "rule_type": rule.rule_type,
                "frameworks": [fm.framework_id for fm in rule.framework_mappings]
            }
            
            return rule_id
            
        except Exception as e:
            raise Exception(f"Failed to import rule from {file_path}: {str(e)}")
    
    async def _create_rule_from_data(self, rule_data: Dict[str, Any]) -> UnifiedComplianceRule:
        """
        Create UnifiedComplianceRule from JSON data
        
        Args:
            rule_data: Rule data from JSON
            
        Returns:
            UnifiedComplianceRule instance
        """
        # Validate required fields
        required_fields = ["rule_id", "title", "description", "rule_type", "execution_context"]
        for field in required_fields:
            if field not in rule_data:
                raise ValueError(f"Required field '{field}' missing from rule data")
        
        # Create execution context
        exec_ctx_data = rule_data["execution_context"]
        execution_context = ExecutionContext(**exec_ctx_data)
        
        # Create parameters
        parameters = []
        for param_data in rule_data.get("parameters", []):
            parameters.append(RuleParameter(**param_data))
        
        # Create platform version ranges
        supported_platforms = []
        for platform_data in rule_data.get("supported_platforms", []):
            supported_platforms.append(PlatformVersionRange(**platform_data))
        
        # Create framework mappings
        framework_mappings = []
        for mapping_data in rule_data.get("framework_mappings", []):
            framework_mappings.append(FrameworkMapping(**mapping_data))
        
        # Create remediation if present
        remediation = None
        if "remediation" in rule_data:
            remediation = RemediationAction(**rule_data["remediation"])
        
        # Create the unified compliance rule
        rule = UnifiedComplianceRule(
            rule_id=rule_data["rule_id"],
            title=rule_data["title"],
            description=rule_data["description"],
            version=rule_data.get("version", "1.0"),
            rule_type=RuleType(rule_data["rule_type"]),
            execution_context=execution_context,
            parameters=parameters,
            supported_platforms=supported_platforms,
            framework_mappings=framework_mappings,
            pass_criteria=rule_data.get("pass_criteria", ""),
            severity=rule_data.get("severity", "medium"),
            category=rule_data.get("category", "General"),
            tags=rule_data.get("tags", []),
            remediation=remediation,
            created_by=rule_data.get("created_by", "System"),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            is_active=rule_data.get("is_active", True),
            is_validated=rule_data.get("is_validated", False),
            validation_notes=rule_data.get("validation_notes")
        )
        
        return rule
    
    async def import_all_rules(self) -> Dict[str, Any]:
        """
        Import all unified compliance rules from the rules directory
        
        Returns:
            Dictionary with import results
        """
        results = {
            "imported": [],
            "failed": [],
            "total_rules": 0,
            "total_frameworks": set(),
            "rule_types": {}
        }
        
        # Find all JSON files in unified rules directory
        if not self.unified_rules_path.exists():
            raise Exception(f"Unified rules directory not found: {self.unified_rules_path}")
        
        rule_files = list(self.unified_rules_path.glob("*.json"))
        
        for rule_file in rule_files:
            try:
                rule_id = await self.import_rule_from_file(rule_file)
                results["imported"].append({
                    "rule_id": rule_id,
                    "file": rule_file.name
                })
                
                # Update statistics
                rule_info = self.imported_rules[rule_id]
                results["total_frameworks"].update(rule_info["frameworks"])
                rule_type = rule_info["rule_type"]
                results["rule_types"][rule_type] = results["rule_types"].get(rule_type, 0) + 1
                
            except Exception as e:
                results["failed"].append({
                    "file": rule_file.name,
                    "error": str(e)
                })
        
        results["total_rules"] = len(results["imported"])
        results["total_frameworks"] = list(results["total_frameworks"])
        
        return results
    
    async def create_framework_ruleset(
        self, 
        framework_id: str, 
        ruleset_name: Optional[str] = None
    ) -> str:
        """
        Create a ruleset containing all rules for a specific framework
        
        Args:
            framework_id: Framework to create ruleset for
            ruleset_name: Optional custom name for the ruleset
            
        Returns:
            Ruleset ID
        """
        # Find all rules that map to this framework
        rules = await UnifiedComplianceRule.find(
            UnifiedComplianceRule.framework_mappings.framework_id == framework_id
        ).to_list()
        
        if not rules:
            raise Exception(f"No rules found for framework: {framework_id}")
        
        # Create ruleset
        ruleset_id = f"framework_{framework_id}_ruleset"
        name = ruleset_name or f"{framework_id.upper()} Compliance Ruleset"
        
        # Determine supported platforms
        all_platforms = set()
        for rule in rules:
            for platform_range in rule.supported_platforms:
                all_platforms.add(platform_range.platform)
        
        # Create execution order based on severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_rules = sorted(rules, key=lambda r: severity_order.get(r.severity, 4))
        
        ruleset = RuleSet(
            ruleset_id=ruleset_id,
            name=name,
            description=f"Comprehensive ruleset for {framework_id} compliance requirements",
            rule_ids=[rule.rule_id for rule in rules],
            target_frameworks=[framework_id],
            supported_platforms=list(all_platforms),
            execution_order=[rule.rule_id for rule in sorted_rules],
            parallel_execution=True,
            stop_on_error=False,
            minimum_compliance_percentage=90.0,
            critical_rule_ids=[rule.rule_id for rule in rules if rule.severity == "critical"],
            created_by="RuleImportService",
            is_active=True,
            is_validated=True
        )
        
        # Check if ruleset exists
        existing = await RuleSet.find_one(RuleSet.ruleset_id == ruleset_id)
        if existing:
            # Update existing
            for field, value in ruleset.__dict__.items():
                if not field.startswith('_') and field != 'id':
                    setattr(existing, field, value)
            existing.updated_at = datetime.utcnow()
            await existing.save()
        else:
            await ruleset.save()
        
        return ruleset_id
    
    async def create_multi_framework_profile(
        self, 
        framework_ids: List[str],
        profile_name: str,
        profile_description: str = ""
    ) -> str:
        """
        Create a compliance profile covering multiple frameworks
        
        Args:
            framework_ids: List of framework IDs to include
            profile_name: Name for the compliance profile
            profile_description: Description of the profile
            
        Returns:
            Profile ID
        """
        # Create rulesets for each framework
        ruleset_ids = []
        for framework_id in framework_ids:
            try:
                ruleset_id = await self.create_framework_ruleset(framework_id)
                ruleset_ids.append(ruleset_id)
            except Exception as e:
                print(f"Warning: Could not create ruleset for {framework_id}: {e}")
        
        if not ruleset_ids:
            raise Exception("No valid rulesets could be created for the specified frameworks")
        
        # Calculate framework coverage
        framework_coverage = {}
        for framework_id in framework_ids:
            # Get total framework controls
            from backend.app.models.enhanced_mongo_models import FrameworkControlDefinition
            total_controls = await FrameworkControlDefinition.count(
                FrameworkControlDefinition.framework_id == framework_id
            )
            
            # Get rules covering this framework
            covered_rules = await UnifiedComplianceRule.count(
                UnifiedComplianceRule.framework_mappings.framework_id == framework_id
            )
            
            if total_controls > 0:
                coverage = (covered_rules / total_controls) * 100
                framework_coverage[framework_id] = round(coverage, 2)
            else:
                framework_coverage[framework_id] = 0.0
        
        # Create profile
        profile_id = f"multi_framework_profile_{len(framework_ids)}"
        
        profile = ComplianceProfile(
            profile_id=profile_id,
            name=profile_name,
            description=profile_description or f"Multi-framework compliance profile covering {', '.join(framework_ids)}",
            ruleset_ids=ruleset_ids,
            framework_coverage=framework_coverage,
            overall_compliance_threshold=85.0,
            framework_compliance_thresholds={fid: 80.0 for fid in framework_ids},
            risk_level="high",
            business_criticality="high",
            created_by="RuleImportService",
            is_active=True,
            is_approved=False
        )
        
        # Check if profile exists
        existing = await ComplianceProfile.find_one(ComplianceProfile.profile_id == profile_id)
        if existing:
            # Update existing
            for field, value in profile.__dict__.items():
                if not field.startswith('_') and field != 'id':
                    setattr(existing, field, value)
            existing.updated_at = datetime.utcnow()
            await existing.save()
        else:
            await profile.save()
        
        return profile_id
    
    async def validate_rule_integrity(self, rule_id: str) -> Dict[str, Any]:
        """
        Validate the integrity of an imported rule
        
        Args:
            rule_id: Rule ID to validate
            
        Returns:
            Validation results
        """
        rule = await UnifiedComplianceRule.find_one(UnifiedComplianceRule.rule_id == rule_id)
        if not rule:
            raise Exception(f"Rule not found: {rule_id}")
        
        validation_results = {
            "rule_id": rule_id,
            "is_valid": True,
            "issues": [],
            "warnings": [],
            "framework_mappings_valid": True,
            "platform_support_valid": True,
            "execution_context_valid": True
        }
        
        # Validate framework mappings
        for mapping in rule.framework_mappings:
            # Check if framework exists
            from backend.app.models.enhanced_mongo_models import FrameworkControlDefinition
            framework_exists = await FrameworkControlDefinition.count(
                FrameworkControlDefinition.framework_id == mapping.framework_id
            ) > 0
            
            if not framework_exists:
                validation_results["issues"].append(f"Framework not found: {mapping.framework_id}")
                validation_results["framework_mappings_valid"] = False
                validation_results["is_valid"] = False
            
            # Check if control IDs exist
            for control_id in mapping.control_ids:
                control_exists = await FrameworkControlDefinition.count(
                    FrameworkControlDefinition.framework_id == mapping.framework_id,
                    FrameworkControlDefinition.control_id == control_id
                ) > 0
                
                if not control_exists:
                    validation_results["warnings"].append(
                        f"Control not found: {mapping.framework_id}:{control_id}"
                    )
        
        # Validate platform support
        if not rule.supported_platforms:
            validation_results["issues"].append("No supported platforms specified")
            validation_results["platform_support_valid"] = False
            validation_results["is_valid"] = False
        
        # Validate execution context
        if not rule.execution_context:
            validation_results["issues"].append("No execution context specified")
            validation_results["execution_context_valid"] = False
            validation_results["is_valid"] = False
        elif rule.rule_type == RuleType.COMMAND_EXECUTION and not rule.execution_context.command:
            validation_results["issues"].append("Command execution rule missing command")
            validation_results["execution_context_valid"] = False
            validation_results["is_valid"] = False
        elif rule.rule_type == RuleType.FILE_CHECK and not rule.execution_context.file_path:
            validation_results["issues"].append("File check rule missing file path")
            validation_results["execution_context_valid"] = False
            validation_results["is_valid"] = False
        
        return validation_results
    
    async def get_import_summary(self) -> Dict[str, Any]:
        """
        Get summary of imported rules
        
        Returns:
            Summary of imported rules
        """
        # Get total rules count
        total_rules = await UnifiedComplianceRule.count()
        
        # Get rules by type
        rule_types = {}
        for rule_type in RuleType:
            count = await UnifiedComplianceRule.count(
                UnifiedComplianceRule.rule_type == rule_type
            )
            if count > 0:
                rule_types[rule_type.value] = count
        
        # Get rules by severity
        severity_counts = {}
        for severity in ["critical", "high", "medium", "low"]:
            count = await UnifiedComplianceRule.count(
                UnifiedComplianceRule.severity == severity
            )
            if count > 0:
                severity_counts[severity] = count
        
        # Get framework coverage
        framework_coverage = {}
        rules = await UnifiedComplianceRule.find().to_list()
        for rule in rules:
            for mapping in rule.framework_mappings:
                framework_id = mapping.framework_id
                if framework_id not in framework_coverage:
                    framework_coverage[framework_id] = {
                        "rules": 0,
                        "controls": len(mapping.control_ids)
                    }
                framework_coverage[framework_id]["rules"] += 1
        
        return {
            "total_rules": total_rules,
            "rule_types": rule_types,
            "severity_distribution": severity_counts,
            "framework_coverage": framework_coverage,
            "active_rules": await UnifiedComplianceRule.count(UnifiedComplianceRule.is_active == True),
            "validated_rules": await UnifiedComplianceRule.count(UnifiedComplianceRule.is_validated == True)
        }