"""
Rule Orchestrator Service
Orchestrates execution of multiple rules and rule sets
"""
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime
from collections import defaultdict

from backend.app.models.unified_rule_models import (
    UnifiedComplianceRule, RuleSet, ComplianceProfile, RuleExecution,
    ComplianceStatus, Platform
)
from backend.app.services.rule_parsing_service import RuleParsingService


class RulesetExecutionResult:
    """Result of ruleset execution"""
    
    def __init__(self, ruleset_id: str):
        self.ruleset_id = ruleset_id
        self.execution_id = f"ruleset_exec_{ruleset_id}_{int(datetime.utcnow().timestamp())}"
        self.started_at = datetime.utcnow()
        self.completed_at: Optional[datetime] = None
        self.total_rules = 0
        self.executed_rules = 0
        self.successful_executions = 0
        self.compliant_rules = 0
        self.non_compliant_rules = 0
        self.error_rules = 0
        self.rule_executions: List[RuleExecution] = []
        self.framework_compliance: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.overall_compliance_percentage = 0.0
        self.success = False
        self.error_message: Optional[str] = None


class ProfileExecutionResult:
    """Result of compliance profile execution"""
    
    def __init__(self, profile_id: str):
        self.profile_id = profile_id
        self.execution_id = f"profile_exec_{profile_id}_{int(datetime.utcnow().timestamp())}"
        self.started_at = datetime.utcnow()
        self.completed_at: Optional[datetime] = None
        self.ruleset_results: List[RulesetExecutionResult] = []
        self.overall_compliance_percentage = 0.0
        self.framework_compliance_percentages: Dict[str, float] = {}
        self.meets_thresholds = False
        self.success = False
        self.error_message: Optional[str] = None


class RuleOrchestratorService:
    """Service for orchestrating rule execution across multiple frameworks"""
    
    def __init__(self):
        """Initialize the rule orchestrator service"""
        self.rule_parser = RuleParsingService()
        self.concurrent_executions = 5  # Maximum concurrent rule executions
    
    async def execute_ruleset(
        self,
        ruleset_id: str,
        host_id: str,
        scan_id: Optional[str] = None,
        execution_parameters: Optional[Dict[str, Any]] = None
    ) -> RulesetExecutionResult:
        """
        Execute a complete ruleset
        
        Args:
            ruleset_id: ID of the ruleset to execute
            host_id: Target host identifier
            scan_id: Optional scan identifier
            execution_parameters: Optional global execution parameters
            
        Returns:
            Ruleset execution result
        """
        result = RulesetExecutionResult(ruleset_id)
        
        try:
            # Load ruleset
            ruleset = await RuleSet.find_one(RuleSet.ruleset_id == ruleset_id)
            if not ruleset:
                result.error_message = f"Ruleset not found: {ruleset_id}"
                return result
            
            # Load rules
            rules = []
            for rule_id in ruleset.rule_ids:
                rule = await UnifiedComplianceRule.find_one(
                    UnifiedComplianceRule.rule_id == rule_id,
                    UnifiedComplianceRule.is_active == True
                )
                if rule:
                    rules.append(rule)
            
            result.total_rules = len(rules)
            
            if not rules:
                result.error_message = "No active rules found in ruleset"
                return result
            
            # Check platform compatibility
            platform = await self.rule_parser._detect_platform()
            compatible_rules = self._filter_compatible_rules(rules, platform)
            
            if not compatible_rules:
                result.error_message = f"No rules compatible with platform: {platform.value}"
                return result
            
            # Execute rules
            if ruleset.parallel_execution:
                rule_executions = await self._execute_rules_parallel(
                    compatible_rules, host_id, scan_id, execution_parameters, ruleset.stop_on_error
                )
            else:
                rule_executions = await self._execute_rules_sequential(
                    compatible_rules, host_id, scan_id, execution_parameters, 
                    ruleset.execution_order, ruleset.stop_on_error
                )
            
            result.rule_executions = rule_executions
            result.executed_rules = len(rule_executions)
            
            # Calculate statistics
            self._calculate_ruleset_statistics(result)
            
            # Check critical rules
            self._check_critical_rules(result, ruleset)
            
            # Check compliance threshold
            if result.overall_compliance_percentage >= ruleset.minimum_compliance_percentage:
                result.success = True
            else:
                result.error_message = f"Compliance percentage {result.overall_compliance_percentage:.1f}% below threshold {ruleset.minimum_compliance_percentage}%"
            
            result.completed_at = datetime.utcnow()
            
        except Exception as e:
            result.error_message = str(e)
            result.completed_at = datetime.utcnow()
        
        return result
    
    async def execute_compliance_profile(
        self,
        profile_id: str,
        host_id: str,
        scan_id: Optional[str] = None,
        execution_parameters: Optional[Dict[str, Any]] = None
    ) -> ProfileExecutionResult:
        """
        Execute a complete compliance profile
        
        Args:
            profile_id: ID of the compliance profile to execute
            host_id: Target host identifier
            scan_id: Optional scan identifier
            execution_parameters: Optional global execution parameters
            
        Returns:
            Profile execution result
        """
        result = ProfileExecutionResult(profile_id)
        
        try:
            # Load compliance profile
            profile = await ComplianceProfile.find_one(
                ComplianceProfile.profile_id == profile_id,
                ComplianceProfile.is_active == True
            )
            if not profile:
                result.error_message = f"Compliance profile not found: {profile_id}"
                return result
            
            # Execute each ruleset in the profile
            for ruleset_id in profile.ruleset_ids:
                ruleset_result = await self.execute_ruleset(
                    ruleset_id, host_id, scan_id, execution_parameters
                )
                result.ruleset_results.append(ruleset_result)
            
            # Calculate overall compliance
            self._calculate_profile_compliance(result, profile)
            
            result.completed_at = datetime.utcnow()
            
        except Exception as e:
            result.error_message = str(e)
            result.completed_at = datetime.utcnow()
        
        return result
    
    async def execute_framework_rules(
        self,
        framework_id: str,
        host_id: str,
        scan_id: Optional[str] = None,
        execution_parameters: Optional[Dict[str, Any]] = None
    ) -> RulesetExecutionResult:
        """
        Execute all rules for a specific framework
        
        Args:
            framework_id: Framework to execute rules for
            host_id: Target host identifier
            scan_id: Optional scan identifier
            execution_parameters: Optional execution parameters
            
        Returns:
            Execution result
        """
        result = RulesetExecutionResult(f"framework_{framework_id}")
        
        try:
            # Find all rules that map to this framework
            rules = await UnifiedComplianceRule.find(
                UnifiedComplianceRule.framework_mappings.framework_id == framework_id,
                UnifiedComplianceRule.is_active == True
            ).to_list()
            
            result.total_rules = len(rules)
            
            if not rules:
                result.error_message = f"No active rules found for framework: {framework_id}"
                return result
            
            # Check platform compatibility
            platform = await self.rule_parser._detect_platform()
            compatible_rules = self._filter_compatible_rules(rules, platform)
            
            # Execute rules in parallel
            rule_executions = await self._execute_rules_parallel(
                compatible_rules, host_id, scan_id, execution_parameters, False
            )
            
            result.rule_executions = rule_executions
            result.executed_rules = len(rule_executions)
            
            # Calculate statistics
            self._calculate_ruleset_statistics(result)
            
            result.success = True
            result.completed_at = datetime.utcnow()
            
        except Exception as e:
            result.error_message = str(e)
            result.completed_at = datetime.utcnow()
        
        return result
    
    async def _execute_rules_parallel(
        self,
        rules: List[UnifiedComplianceRule],
        host_id: str,
        scan_id: Optional[str],
        execution_parameters: Optional[Dict[str, Any]],
        stop_on_error: bool
    ) -> List[RuleExecution]:
        """Execute rules in parallel"""
        semaphore = asyncio.Semaphore(self.concurrent_executions)
        
        async def execute_with_semaphore(rule: UnifiedComplianceRule) -> Optional[RuleExecution]:
            async with semaphore:
                try:
                    return await self.rule_parser.execute_rule(
                        rule, host_id, execution_parameters, scan_id
                    )
                except Exception as e:
                    print(f"Error executing rule {rule.rule_id}: {e}")
                    if stop_on_error:
                        raise
                    return None
        
        # Execute all rules concurrently
        tasks = [execute_with_semaphore(rule) for rule in rules]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out None results and exceptions
        executions = []
        for result in results:
            if isinstance(result, RuleExecution):
                executions.append(result)
            elif isinstance(result, Exception) and stop_on_error:
                raise result
        
        return executions
    
    async def _execute_rules_sequential(
        self,
        rules: List[UnifiedComplianceRule],
        host_id: str,
        scan_id: Optional[str],
        execution_parameters: Optional[Dict[str, Any]],
        execution_order: List[str],
        stop_on_error: bool
    ) -> List[RuleExecution]:
        """Execute rules in sequential order"""
        executions = []
        
        # Create rule lookup
        rule_map = {rule.rule_id: rule for rule in rules}
        
        # Execute in specified order, then remaining rules
        ordered_rule_ids = execution_order + [
            rule.rule_id for rule in rules 
            if rule.rule_id not in execution_order
        ]
        
        for rule_id in ordered_rule_ids:
            if rule_id in rule_map:
                try:
                    execution = await self.rule_parser.execute_rule(
                        rule_map[rule_id], host_id, execution_parameters, scan_id
                    )
                    executions.append(execution)
                    
                    # Stop on error if configured
                    if stop_on_error and execution.compliance_status == ComplianceStatus.ERROR:
                        break
                        
                except Exception as e:
                    print(f"Error executing rule {rule_id}: {e}")
                    if stop_on_error:
                        break
        
        return executions
    
    def _filter_compatible_rules(
        self,
        rules: List[UnifiedComplianceRule],
        platform: Platform
    ) -> List[UnifiedComplianceRule]:
        """Filter rules compatible with the target platform"""
        compatible_rules = []
        
        for rule in rules:
            is_compatible = False
            for platform_range in rule.supported_platforms:
                if platform_range.platform == platform:
                    is_compatible = True
                    break
            
            if is_compatible:
                compatible_rules.append(rule)
        
        return compatible_rules
    
    def _calculate_ruleset_statistics(self, result: RulesetExecutionResult):
        """Calculate statistics for ruleset execution"""
        for execution in result.rule_executions:
            if execution.execution_success:
                result.successful_executions += 1
            
            if execution.compliance_status == ComplianceStatus.COMPLIANT:
                result.compliant_rules += 1
            elif execution.compliance_status == ComplianceStatus.NON_COMPLIANT:
                result.non_compliant_rules += 1
            elif execution.compliance_status == ComplianceStatus.ERROR:
                result.error_rules += 1
            
            # Calculate framework compliance
            for framework_result in execution.framework_results:
                framework_id = framework_result["framework_id"]
                status = framework_result["status"]
                result.framework_compliance[framework_id][status] += 1
        
        # Calculate overall compliance percentage
        if result.executed_rules > 0:
            compliant_count = result.compliant_rules
            # Include EXCEEDS status as compliant
            for execution in result.rule_executions:
                if execution.compliance_status == ComplianceStatus.EXCEEDS:
                    compliant_count += 1
            
            result.overall_compliance_percentage = (compliant_count / result.executed_rules) * 100
    
    def _check_critical_rules(self, result: RulesetExecutionResult, ruleset: RuleSet):
        """Check if critical rules passed"""
        if not ruleset.critical_rule_ids:
            return
        
        critical_failures = []
        for execution in result.rule_executions:
            if (execution.rule_id in ruleset.critical_rule_ids and 
                execution.compliance_status not in [ComplianceStatus.COMPLIANT, ComplianceStatus.EXCEEDS]):
                critical_failures.append(execution.rule_id)
        
        if critical_failures:
            result.success = False
            if result.error_message:
                result.error_message += f" Critical rule failures: {', '.join(critical_failures)}"
            else:
                result.error_message = f"Critical rule failures: {', '.join(critical_failures)}"
    
    def _calculate_profile_compliance(
        self,
        result: ProfileExecutionResult,
        profile: ComplianceProfile
    ):
        """Calculate overall compliance for the profile"""
        if not result.ruleset_results:
            return
        
        # Calculate overall compliance percentage
        total_compliance = sum(rs.overall_compliance_percentage for rs in result.ruleset_results)
        result.overall_compliance_percentage = total_compliance / len(result.ruleset_results)
        
        # Calculate framework-specific compliance
        framework_executions = defaultdict(list)
        for ruleset_result in result.ruleset_results:
            for execution in ruleset_result.rule_executions:
                for framework_result in execution.framework_results:
                    framework_id = framework_result["framework_id"]
                    status = framework_result["status"]
                    framework_executions[framework_id].append(status)
        
        for framework_id, statuses in framework_executions.items():
            compliant_count = sum(
                1 for status in statuses 
                if status in ["compliant", "exceeds"]
            )
            total_count = len(statuses)
            if total_count > 0:
                percentage = (compliant_count / total_count) * 100
                result.framework_compliance_percentages[framework_id] = percentage
        
        # Check if thresholds are met
        overall_threshold_met = (
            result.overall_compliance_percentage >= profile.overall_compliance_threshold
        )
        
        framework_thresholds_met = True
        for framework_id, threshold in profile.framework_compliance_thresholds.items():
            actual_percentage = result.framework_compliance_percentages.get(framework_id, 0.0)
            if actual_percentage < threshold:
                framework_thresholds_met = False
                break
        
        result.meets_thresholds = overall_threshold_met and framework_thresholds_met
        result.success = result.meets_thresholds
        
        if not result.meets_thresholds:
            failure_reasons = []
            if not overall_threshold_met:
                failure_reasons.append(
                    f"Overall compliance {result.overall_compliance_percentage:.1f}% "
                    f"below threshold {profile.overall_compliance_threshold}%"
                )
            if not framework_thresholds_met:
                failure_reasons.append("Framework-specific thresholds not met")
            result.error_message = "; ".join(failure_reasons)
    
    async def get_execution_summary(
        self,
        execution_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get summary of a rule execution
        
        Args:
            execution_id: Execution ID to get summary for
            
        Returns:
            Execution summary or None if not found
        """
        execution = await RuleExecution.find_one(
            RuleExecution.execution_id == execution_id
        )
        
        if not execution:
            return None
        
        return {
            "execution_id": execution.execution_id,
            "rule_id": execution.rule_id,
            "host_id": execution.host_id,
            "scan_id": execution.scan_id,
            "executed_at": execution.executed_at,
            "compliance_status": execution.compliance_status.value,
            "execution_success": execution.execution_success,
            "execution_time": execution.execution_time,
            "platform": execution.platform.value,
            "platform_version": execution.platform_version,
            "framework_results": execution.framework_results,
            "evidence_collected": execution.evidence_collected,
            "justification": execution.justification,
            "error_message": execution.error_message
        }