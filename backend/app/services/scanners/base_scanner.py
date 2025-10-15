#!/usr/bin/env python3
"""
Base Scanner Interface

Abstract base class for all scanner implementations (OSCAP, Kubernetes, Cloud APIs, etc.)
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any
import logging

from app.models.scan_models import RuleResult, ScanTarget, ScanResultSummary

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    """
    Abstract base class for compliance scanners
    
    Each scanner implementation (OSCAP, Kubernetes, AWS, etc.) must implement
    the scan() method to execute compliance checks against a target system.
    """
    
    def __init__(self, scanner_name: str):
        self.scanner_name = scanner_name
        self.version = self._get_version()
    
    @abstractmethod
    async def scan(
        self,
        rules: List[Dict[str, Any]],
        target: ScanTarget,
        variables: Dict[str, str],
        scan_options: Dict[str, Any] = None
    ) -> tuple[List[RuleResult], ScanResultSummary]:
        """
        Execute compliance scan against target
        
        Args:
            rules: List of compliance rules to check (from MongoDB)
            target: Target system to scan (host, cluster, cloud account)
            variables: XCCDF variable overrides
            scan_options: Scanner-specific options
        
        Returns:
            Tuple of (rule_results, summary)
        """
        pass
    
    @abstractmethod
    def _get_version(self) -> str:
        """Get scanner version (e.g., oscap 1.3.7, kubectl 1.28.0)"""
        pass
    
    def _calculate_summary(self, results: List[RuleResult]) -> ScanResultSummary:
        """Calculate summary statistics from rule results"""
        summary = ScanResultSummary(total_rules=len(results))
        
        # Count by status
        for result in results:
            if result.status == "pass":
                summary.passed += 1
            elif result.status == "fail":
                summary.failed += 1
            elif result.status == "error":
                summary.error += 1
            elif result.status == "notapplicable":
                summary.not_applicable += 1
            elif result.status == "notchecked":
                summary.not_checked += 1
            elif result.status == "notselected":
                summary.not_selected += 1
            elif result.status == "informational":
                summary.informational += 1
            elif result.status == "fixed":
                summary.fixed += 1
        
        # Calculate compliance percentage
        evaluated = summary.passed + summary.failed
        if evaluated > 0:
            summary.compliance_percentage = (summary.passed / evaluated) * 100
        
        # Breakdown by severity
        summary.by_severity = self._group_by_severity(results)
        
        # Breakdown by scanner
        summary.by_scanner = self._group_by_scanner(results)
        
        return summary
    
    def _group_by_severity(self, results: List[RuleResult]) -> Dict[str, Dict[str, int]]:
        """Group results by severity level"""
        by_severity = {}
        
        for result in results:
            severity = result.severity
            if severity not in by_severity:
                by_severity[severity] = {
                    "total": 0,
                    "passed": 0,
                    "failed": 0,
                    "error": 0,
                    "not_applicable": 0
                }
            
            by_severity[severity]["total"] += 1
            
            if result.status == "pass":
                by_severity[severity]["passed"] += 1
            elif result.status == "fail":
                by_severity[severity]["failed"] += 1
            elif result.status == "error":
                by_severity[severity]["error"] += 1
            elif result.status == "notapplicable":
                by_severity[severity]["not_applicable"] += 1
        
        return by_severity
    
    def _group_by_scanner(self, results: List[RuleResult]) -> Dict[str, Dict[str, int]]:
        """Group results by scanner type"""
        by_scanner = {}
        
        for result in results:
            scanner = result.scanner_type
            if scanner not in by_scanner:
                by_scanner[scanner] = {
                    "total": 0,
                    "passed": 0,
                    "failed": 0
                }
            
            by_scanner[scanner]["total"] += 1
            
            if result.status == "pass":
                by_scanner[scanner]["passed"] += 1
            elif result.status == "fail":
                by_scanner[scanner]["failed"] += 1
        
        return by_scanner
    
    def validate_target(self, target: ScanTarget) -> bool:
        """
        Validate that target is compatible with this scanner
        
        Override in subclass to add scanner-specific validation
        """
        return True
    
    def get_required_capabilities(self) -> List[str]:
        """
        Return list of required capabilities for this scanner
        
        e.g., ['ssh', 'oscap'], ['kubectl', 'cluster-admin'], ['aws-cli', 'iam:ListUsers']
        """
        return []


class ScannerNotAvailableError(Exception):
    """Raised when required scanner is not available"""
    pass


class ScannerExecutionError(Exception):
    """Raised when scanner execution fails"""
    pass


class UnsupportedTargetError(Exception):
    """Raised when target type is not supported by scanner"""
    pass
