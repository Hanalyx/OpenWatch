"""
Multi-Framework Scanner Engine
Unified scanning engine that can execute compliance checks across multiple frameworks simultaneously
"""
import asyncio
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum

from backend.app.models.unified_rule_models import (
    UnifiedComplianceRule, RuleSet, ComplianceProfile, RuleExecution,
    ComplianceStatus, Platform
)
from backend.app.services.rule_parsing_service import RuleParsingService
from backend.app.services.rule_orchestrator_service import RuleOrchestratorService
from backend.app.services.platform_detection_service import PlatformDetectionService


class ScanType(str, Enum):
    """Types of compliance scans"""
    FRAMEWORK_SPECIFIC = "framework_specific"
    MULTI_FRAMEWORK = "multi_framework"
    UNIFIED_COMPLIANCE = "unified_compliance"
    BASELINE_ASSESSMENT = "baseline_assessment"
    DELTA_SCAN = "delta_scan"
    CONTINUOUS_MONITORING = "continuous_monitoring"


class ScanPriority(str, Enum):
    """Scan execution priorities"""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


@dataclass
class ScanConfiguration:
    """Configuration for multi-framework scanning"""
    scan_id: str
    scan_type: ScanType
    target_frameworks: List[str]
    host_targets: List[str]
    rule_filters: Dict[str, Any] = None
    execution_settings: Dict[str, Any] = None
    compliance_thresholds: Dict[str, float] = None
    priority: ScanPriority = ScanPriority.NORMAL
    timeout: int = 3600  # 1 hour default
    parallel_hosts: int = 5
    parallel_rules: int = 10
    stop_on_error: bool = False
    collect_evidence: bool = True
    generate_reports: bool = True
    
    def __post_init__(self):
        if self.rule_filters is None:
            self.rule_filters = {}
        if self.execution_settings is None:
            self.execution_settings = {}
        if self.compliance_thresholds is None:
            self.compliance_thresholds = {}


@dataclass
class FrameworkResult:
    """Results for a specific framework"""
    framework_id: str
    total_rules: int
    executed_rules: int
    compliant_rules: int
    non_compliant_rules: int
    error_rules: int
    exceeds_rules: int
    compliance_percentage: float
    execution_time: float
    rule_executions: List[RuleExecution] = None
    
    def __post_init__(self):
        if self.rule_executions is None:
            self.rule_executions = []


@dataclass
class HostResult:
    """Results for a specific host"""
    host_id: str
    platform_info: Dict[str, Any]
    framework_results: List[FrameworkResult]
    overall_compliance_percentage: float
    total_execution_time: float
    scan_status: str
    error_message: Optional[str] = None
    
    def __post_init__(self):
        if self.framework_results is None:
            self.framework_results = []


@dataclass
class ScanResult:
    """Complete multi-framework scan results"""
    scan_id: str
    scan_type: ScanType
    started_at: datetime
    completed_at: Optional[datetime]
    total_execution_time: float
    host_results: List[HostResult]
    framework_summary: Dict[str, Dict[str, Any]]
    overall_statistics: Dict[str, Any]
    compliance_gaps: List[Dict[str, Any]]
    recommendations: List[str]
    success: bool
    error_message: Optional[str] = None
    
    def __post_init__(self):
        if self.host_results is None:
            self.host_results = []
        if self.framework_summary is None:
            self.framework_summary = {}
        if self.overall_statistics is None:
            self.overall_statistics = {}
        if self.compliance_gaps is None:
            self.compliance_gaps = []
        if self.recommendations is None:
            self.recommendations = []


class MultiFrameworkScanner:
    """Unified scanning engine for multi-framework compliance assessment"""
    
    def __init__(self):
        """Initialize the multi-framework scanner"""
        self.rule_parser = RuleParsingService()
        self.rule_orchestrator = RuleOrchestratorService()
        self.platform_detector = PlatformDetectionService()
        self.active_scans: Dict[str, ScanResult] = {}
    
    async def execute_unified_scan(
        self,
        scan_config: ScanConfiguration
    ) -> ScanResult:
        """
        Execute a unified compliance scan across multiple frameworks
        
        Args:
            scan_config: Scan configuration
            
        Returns:
            Complete scan results
        """
        scan_result = ScanResult(
            scan_id=scan_config.scan_id,
            scan_type=scan_config.scan_type,
            started_at=datetime.utcnow(),
            completed_at=None,
            total_execution_time=0.0,
            host_results=[],
            framework_summary={},
            overall_statistics={},
            compliance_gaps=[],
            recommendations=[],
            success=False
        )
        
        # Register active scan
        self.active_scans[scan_config.scan_id] = scan_result
        
        try:
            start_time = datetime.utcnow()
            
            # Execute scan based on type
            if scan_config.scan_type == ScanType.FRAMEWORK_SPECIFIC:
                await self._execute_framework_specific_scan(scan_config, scan_result)
            elif scan_config.scan_type == ScanType.MULTI_FRAMEWORK:
                await self._execute_multi_framework_scan(scan_config, scan_result)
            elif scan_config.scan_type == ScanType.UNIFIED_COMPLIANCE:
                await self._execute_unified_compliance_scan(scan_config, scan_result)
            elif scan_config.scan_type == ScanType.BASELINE_ASSESSMENT:
                await self._execute_baseline_assessment(scan_config, scan_result)
            elif scan_config.scan_type == ScanType.DELTA_SCAN:
                await self._execute_delta_scan(scan_config, scan_result)
            elif scan_config.scan_type == ScanType.CONTINUOUS_MONITORING:
                await self._execute_continuous_monitoring(scan_config, scan_result)
            else:
                raise ValueError(f"Unsupported scan type: {scan_config.scan_type}")
            
            # Calculate final results
            end_time = datetime.utcnow()
            scan_result.completed_at = end_time
            scan_result.total_execution_time = (end_time - start_time).total_seconds()
            
            # Generate analytics
            await self._generate_scan_analytics(scan_result)
            await self._identify_compliance_gaps(scan_result)
            await self._generate_recommendations(scan_result)
            
            scan_result.success = True
            
        except Exception as e:
            scan_result.error_message = str(e)
            scan_result.success = False
            scan_result.completed_at = datetime.utcnow()
            scan_result.total_execution_time = (scan_result.completed_at - scan_result.started_at).total_seconds()
        
        finally:
            # Cleanup active scan
            if scan_config.scan_id in self.active_scans:
                del self.active_scans[scan_config.scan_id]
        
        return scan_result
    
    async def _execute_framework_specific_scan(
        self,
        scan_config: ScanConfiguration,
        scan_result: ScanResult
    ):
        """Execute scan for specific frameworks"""
        # Execute each host in parallel (up to configured limit)
        semaphore = asyncio.Semaphore(scan_config.parallel_hosts)
        
        async def scan_host(host_id: str) -> HostResult:
            async with semaphore:
                return await self._scan_host_frameworks(
                    host_id, scan_config.target_frameworks, scan_config
                )
        
        # Execute all host scans
        tasks = [scan_host(host_id) for host_id in scan_config.host_targets]
        scan_result.host_results = await asyncio.gather(*tasks)
    
    async def _execute_multi_framework_scan(
        self,
        scan_config: ScanConfiguration,
        scan_result: ScanResult
    ):
        """Execute multi-framework scan using unified rules"""
        # Find unified rules that cover multiple target frameworks
        unified_rules = await self._find_multi_framework_rules(scan_config.target_frameworks)
        
        # Execute unified rules across all hosts
        semaphore = asyncio.Semaphore(scan_config.parallel_hosts)
        
        async def scan_host_unified(host_id: str) -> HostResult:
            async with semaphore:
                return await self._scan_host_unified_rules(
                    host_id, unified_rules, scan_config
                )
        
        tasks = [scan_host_unified(host_id) for host_id in scan_config.host_targets]
        scan_result.host_results = await asyncio.gather(*tasks)
    
    async def _execute_unified_compliance_scan(
        self,
        scan_config: ScanConfiguration,
        scan_result: ScanResult
    ):
        """Execute comprehensive unified compliance scan"""
        # Combine framework-specific and unified rule approaches
        
        # First, execute unified rules that cover multiple frameworks
        await self._execute_multi_framework_scan(scan_config, scan_result)
        
        # Then, fill gaps with framework-specific rules
        await self._fill_framework_gaps(scan_config, scan_result)
    
    async def _execute_baseline_assessment(
        self,
        scan_config: ScanConfiguration,
        scan_result: ScanResult
    ):
        """Execute baseline security assessment"""
        # Focus on critical and high-severity rules across all frameworks
        scan_config.rule_filters['severity'] = ['critical', 'high']
        await self._execute_multi_framework_scan(scan_config, scan_result)
    
    async def _execute_delta_scan(
        self,
        scan_config: ScanConfiguration,
        scan_result: ScanResult
    ):
        """Execute delta scan (changes since last scan)"""
        # Find previous scan results and identify changes
        # This is a placeholder for future implementation
        await self._execute_multi_framework_scan(scan_config, scan_result)
    
    async def _execute_continuous_monitoring(
        self,
        scan_config: ScanConfiguration,
        scan_result: ScanResult
    ):
        """Execute continuous monitoring scan"""
        # Focus on high-impact rules with frequent execution
        scan_config.rule_filters['tags'] = ['continuous_monitoring', 'high_impact']
        await self._execute_multi_framework_scan(scan_config, scan_result)
    
    async def _scan_host_frameworks(
        self,
        host_id: str,
        target_frameworks: List[str],
        scan_config: ScanConfiguration
    ) -> HostResult:
        """Scan a single host for specific frameworks"""
        host_start_time = datetime.utcnow()
        
        # Detect platform information
        platform_info = await self._get_host_platform_info(host_id)
        
        # Initialize host result
        host_result = HostResult(
            host_id=host_id,
            platform_info=platform_info,
            framework_results=[],
            overall_compliance_percentage=0.0,
            total_execution_time=0.0,
            scan_status="scanning"
        )
        
        try:
            # Execute each framework
            for framework_id in target_frameworks:
                framework_result = await self._scan_framework(
                    host_id, framework_id, scan_config
                )
                host_result.framework_results.append(framework_result)
            
            # Calculate overall compliance
            if host_result.framework_results:
                total_compliance = sum(fr.compliance_percentage for fr in host_result.framework_results)
                host_result.overall_compliance_percentage = total_compliance / len(host_result.framework_results)
            
            host_result.scan_status = "completed"
            
        except Exception as e:
            host_result.scan_status = "error"
            host_result.error_message = str(e)
        
        # Calculate execution time
        host_end_time = datetime.utcnow()
        host_result.total_execution_time = (host_end_time - host_start_time).total_seconds()
        
        return host_result
    
    async def _scan_host_unified_rules(
        self,
        host_id: str,
        unified_rules: List[UnifiedComplianceRule],
        scan_config: ScanConfiguration
    ) -> HostResult:
        """Scan a single host using unified rules"""
        host_start_time = datetime.utcnow()
        
        # Detect platform information
        platform_info = await self._get_host_platform_info(host_id)
        
        # Initialize host result
        host_result = HostResult(
            host_id=host_id,
            platform_info=platform_info,
            framework_results=[],
            overall_compliance_percentage=0.0,
            total_execution_time=0.0,
            scan_status="scanning"
        )
        
        try:
            # Filter rules compatible with this host's platform
            platform = Platform(platform_info.get('platform', 'rhel_9'))
            compatible_rules = await self._filter_platform_compatible_rules(unified_rules, platform)
            
            # Execute rules
            rule_executions = await self._execute_rules_parallel(
                compatible_rules, host_id, scan_config
            )
            
            # Group results by framework
            framework_executions = defaultdict(list)
            for execution in rule_executions:
                for framework_result in execution.framework_results:
                    framework_id = framework_result['framework_id']
                    framework_executions[framework_id].append(execution)
            
            # Create framework results
            for framework_id, executions in framework_executions.items():
                framework_result = self._calculate_framework_result(
                    framework_id, executions
                )
                host_result.framework_results.append(framework_result)
            
            # Calculate overall compliance
            if host_result.framework_results:
                total_compliance = sum(fr.compliance_percentage for fr in host_result.framework_results)
                host_result.overall_compliance_percentage = total_compliance / len(host_result.framework_results)
            
            host_result.scan_status = "completed"
            
        except Exception as e:
            host_result.scan_status = "error"
            host_result.error_message = str(e)
        
        # Calculate execution time
        host_end_time = datetime.utcnow()
        host_result.total_execution_time = (host_end_time - host_start_time).total_seconds()
        
        return host_result
    
    async def _scan_framework(
        self,
        host_id: str,
        framework_id: str,
        scan_config: ScanConfiguration
    ) -> FrameworkResult:
        """Scan a single framework on a host"""
        framework_start_time = datetime.utcnow()
        
        # Execute framework rules
        ruleset_result = await self.rule_orchestrator.execute_framework_rules(
            framework_id, host_id, scan_config.scan_id
        )
        
        # Convert to framework result
        framework_result = FrameworkResult(
            framework_id=framework_id,
            total_rules=ruleset_result.total_rules,
            executed_rules=ruleset_result.executed_rules,
            compliant_rules=ruleset_result.compliant_rules,
            non_compliant_rules=ruleset_result.non_compliant_rules,
            error_rules=ruleset_result.error_rules,
            exceeds_rules=0,  # Count exceeds status
            compliance_percentage=ruleset_result.overall_compliance_percentage,
            execution_time=(datetime.utcnow() - framework_start_time).total_seconds(),
            rule_executions=ruleset_result.rule_executions
        )
        
        # Count exceeds rules
        for execution in ruleset_result.rule_executions:
            if execution.compliance_status == ComplianceStatus.EXCEEDS:
                framework_result.exceeds_rules += 1
        
        return framework_result
    
    async def _find_multi_framework_rules(
        self,
        target_frameworks: List[str]
    ) -> List[UnifiedComplianceRule]:
        """Find unified rules that cover multiple target frameworks"""
        # Find rules that map to at least 2 of the target frameworks
        rules = await UnifiedComplianceRule.find(
            UnifiedComplianceRule.is_active == True
        ).to_list()
        
        multi_framework_rules = []
        for rule in rules:
            # Count how many target frameworks this rule covers
            covered_frameworks = set()
            for mapping in rule.framework_mappings:
                if mapping.framework_id in target_frameworks:
                    covered_frameworks.add(mapping.framework_id)
            
            # Include if it covers at least 2 frameworks or is marked as multi-framework
            if (len(covered_frameworks) >= 2 or 
                'multi_framework' in rule.tags or 
                len(rule.framework_mappings) > 1):
                multi_framework_rules.append(rule)
        
        return multi_framework_rules
    
    async def _filter_platform_compatible_rules(
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
    
    async def _execute_rules_parallel(
        self,
        rules: List[UnifiedComplianceRule],
        host_id: str,
        scan_config: ScanConfiguration
    ) -> List[RuleExecution]:
        """Execute rules in parallel with configured limits"""
        semaphore = asyncio.Semaphore(scan_config.parallel_rules)
        
        async def execute_rule_with_semaphore(rule: UnifiedComplianceRule) -> Optional[RuleExecution]:
            async with semaphore:
                try:
                    return await self.rule_parser.execute_rule(
                        rule, host_id, scan_config.execution_settings, scan_config.scan_id
                    )
                except Exception as e:
                    print(f"Error executing rule {rule.rule_id}: {e}")
                    if scan_config.stop_on_error:
                        raise
                    return None
        
        # Execute all rules
        tasks = [execute_rule_with_semaphore(rule) for rule in rules]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out None results and exceptions
        executions = []
        for result in results:
            if isinstance(result, RuleExecution):
                executions.append(result)
            elif isinstance(result, Exception) and scan_config.stop_on_error:
                raise result
        
        return executions
    
    def _calculate_framework_result(
        self,
        framework_id: str,
        executions: List[RuleExecution]
    ) -> FrameworkResult:
        """Calculate framework result from rule executions"""
        total_rules = len(executions)
        executed_rules = sum(1 for e in executions if e.execution_success)
        compliant_rules = sum(1 for e in executions if e.compliance_status == ComplianceStatus.COMPLIANT)
        non_compliant_rules = sum(1 for e in executions if e.compliance_status == ComplianceStatus.NON_COMPLIANT)
        error_rules = sum(1 for e in executions if e.compliance_status == ComplianceStatus.ERROR)
        exceeds_rules = sum(1 for e in executions if e.compliance_status == ComplianceStatus.EXCEEDS)
        
        # Calculate compliance percentage
        if executed_rules > 0:
            compliant_count = compliant_rules + exceeds_rules  # Exceeds counts as compliant
            compliance_percentage = (compliant_count / executed_rules) * 100
        else:
            compliance_percentage = 0.0
        
        # Calculate execution time
        execution_time = sum(e.execution_time for e in executions)
        
        return FrameworkResult(
            framework_id=framework_id,
            total_rules=total_rules,
            executed_rules=executed_rules,
            compliant_rules=compliant_rules,
            non_compliant_rules=non_compliant_rules,
            error_rules=error_rules,
            exceeds_rules=exceeds_rules,
            compliance_percentage=compliance_percentage,
            execution_time=execution_time,
            rule_executions=executions
        )
    
    async def _get_host_platform_info(self, host_id: str) -> Dict[str, Any]:
        """Get platform information for a host"""
        # For now, assume local host. In production, this would connect to remote hosts
        platform_info = await self.platform_detector.detect_platform_info()
        
        return {
            'platform': platform_info.platform.value,
            'version': platform_info.version,
            'architecture': platform_info.architecture,
            'kernel_version': platform_info.kernel_version,
            'hostname': platform_info.hostname,
            'distribution': platform_info.distribution,
            'capabilities': [cap.value for cap in platform_info.capabilities],
            'package_managers': platform_info.package_managers,
            'init_system': platform_info.init_system,
            'virtualization_type': platform_info.virtualization_type,
            'security_modules': platform_info.security_modules
        }
    
    async def _fill_framework_gaps(
        self,
        scan_config: ScanConfiguration,
        scan_result: ScanResult
    ):
        """Fill gaps in framework coverage with framework-specific rules"""
        # Analyze which framework controls are not covered by unified rules
        # and execute additional framework-specific rules to fill gaps
        
        # This is a placeholder for future implementation
        pass
    
    async def _generate_scan_analytics(self, scan_result: ScanResult):
        """Generate comprehensive scan analytics"""
        if not scan_result.host_results:
            return
        
        # Overall statistics
        total_hosts = len(scan_result.host_results)
        successful_hosts = sum(1 for hr in scan_result.host_results if hr.scan_status == "completed")
        failed_hosts = total_hosts - successful_hosts
        
        # Framework summary
        framework_stats = defaultdict(lambda: {
            'total_rules': 0,
            'executed_rules': 0,
            'compliant_rules': 0,
            'non_compliant_rules': 0,
            'error_rules': 0,
            'exceeds_rules': 0,
            'compliance_percentage': 0.0,
            'host_count': 0
        })
        
        for host_result in scan_result.host_results:
            for framework_result in host_result.framework_results:
                framework_id = framework_result.framework_id
                stats = framework_stats[framework_id]
                
                stats['total_rules'] += framework_result.total_rules
                stats['executed_rules'] += framework_result.executed_rules
                stats['compliant_rules'] += framework_result.compliant_rules
                stats['non_compliant_rules'] += framework_result.non_compliant_rules
                stats['error_rules'] += framework_result.error_rules
                stats['exceeds_rules'] += framework_result.exceeds_rules
                stats['host_count'] += 1
        
        # Calculate average compliance percentages
        for framework_id, stats in framework_stats.items():
            if stats['host_count'] > 0:
                # Get compliance percentages from all hosts for this framework
                compliance_percentages = []
                for host_result in scan_result.host_results:
                    for framework_result in host_result.framework_results:
                        if framework_result.framework_id == framework_id:
                            compliance_percentages.append(framework_result.compliance_percentage)
                
                if compliance_percentages:
                    stats['compliance_percentage'] = sum(compliance_percentages) / len(compliance_percentages)
        
        # Store results
        scan_result.framework_summary = dict(framework_stats)
        scan_result.overall_statistics = {
            'total_hosts': total_hosts,
            'successful_hosts': successful_hosts,
            'failed_hosts': failed_hosts,
            'total_frameworks': len(framework_stats),
            'scan_duration': scan_result.total_execution_time,
            'average_host_compliance': sum(hr.overall_compliance_percentage for hr in scan_result.host_results) / total_hosts if total_hosts > 0 else 0.0
        }
    
    async def _identify_compliance_gaps(self, scan_result: ScanResult):
        """Identify compliance gaps and common failures"""
        gaps = []
        
        # Analyze common failure patterns
        failure_patterns = defaultdict(list)
        
        for host_result in scan_result.host_results:
            for framework_result in host_result.framework_results:
                for execution in framework_result.rule_executions:
                    if execution.compliance_status == ComplianceStatus.NON_COMPLIANT:
                        gap_key = f"{framework_result.framework_id}:{execution.rule_id}"
                        failure_patterns[gap_key].append({
                            'host_id': host_result.host_id,
                            'rule_id': execution.rule_id,
                            'framework_id': framework_result.framework_id,
                            'error_message': execution.error_message
                        })
        
        # Convert to gap analysis
        for gap_key, failures in failure_patterns.items():
            if len(failures) > 1:  # Common failure across multiple hosts
                framework_id, rule_id = gap_key.split(':', 1)
                gaps.append({
                    'type': 'common_failure',
                    'framework_id': framework_id,
                    'rule_id': rule_id,
                    'affected_hosts': len(failures),
                    'total_hosts': len(scan_result.host_results),
                    'failure_rate': len(failures) / len(scan_result.host_results),
                    'description': f"Rule {rule_id} fails on {len(failures)} hosts"
                })
        
        scan_result.compliance_gaps = gaps
    
    async def _generate_recommendations(self, scan_result: ScanResult):
        """Generate compliance recommendations"""
        recommendations = []
        
        # Framework-specific recommendations
        for framework_id, stats in scan_result.framework_summary.items():
            compliance_pct = stats['compliance_percentage']
            
            if compliance_pct < 70:
                recommendations.append(
                    f"Critical: {framework_id} compliance is {compliance_pct:.1f}%. "
                    f"Immediate attention required for {stats['non_compliant_rules']} failing rules."
                )
            elif compliance_pct < 85:
                recommendations.append(
                    f"Warning: {framework_id} compliance is {compliance_pct:.1f}%. "
                    f"Address {stats['non_compliant_rules']} non-compliant rules to improve posture."
                )
            elif compliance_pct >= 95:
                recommendations.append(
                    f"Excellent: {framework_id} compliance is {compliance_pct:.1f}%. "
                    f"Consider implementing advanced security measures."
                )
        
        # Gap-specific recommendations
        for gap in scan_result.compliance_gaps:
            if gap['failure_rate'] > 0.5:  # Affects more than 50% of hosts
                recommendations.append(
                    f"Systematic Issue: Rule {gap['rule_id']} fails on {gap['affected_hosts']} hosts. "
                    f"Review baseline configuration and implement automated remediation."
                )
        
        # Exceeding compliance opportunities
        total_exceeds = sum(
            stats['exceeds_rules'] for stats in scan_result.framework_summary.values()
        )
        if total_exceeds > 0:
            recommendations.append(
                f"Opportunity: {total_exceeds} rules exceed baseline requirements. "
                f"Document enhanced security posture for compliance reporting."
            )
        
        scan_result.recommendations = recommendations
    
    async def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get status of an active scan"""
        if scan_id not in self.active_scans:
            return None
        
        scan_result = self.active_scans[scan_id]
        
        # Calculate progress
        total_hosts = len(scan_result.host_results) if scan_result.host_results else 0
        completed_hosts = sum(
            1 for hr in scan_result.host_results 
            if hr.scan_status in ["completed", "error"]
        ) if scan_result.host_results else 0
        
        progress_percentage = (completed_hosts / total_hosts * 100) if total_hosts > 0 else 0
        
        return {
            'scan_id': scan_id,
            'scan_type': scan_result.scan_type.value,
            'started_at': scan_result.started_at.isoformat(),
            'total_hosts': total_hosts,
            'completed_hosts': completed_hosts,
            'progress_percentage': progress_percentage,
            'success': scan_result.success,
            'error_message': scan_result.error_message
        }
    
    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel an active scan"""
        if scan_id in self.active_scans:
            # In a production implementation, this would signal the scan to stop
            scan_result = self.active_scans[scan_id]
            scan_result.error_message = "Scan cancelled by user"
            scan_result.success = False
            scan_result.completed_at = datetime.utcnow()
            del self.active_scans[scan_id]
            return True
        return False