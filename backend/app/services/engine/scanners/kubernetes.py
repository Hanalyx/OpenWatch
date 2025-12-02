"""
Kubernetes Scanner Implementation

This module provides the KubernetesScanner for executing compliance checks
against Kubernetes and OpenShift clusters using kubectl and JSONPath queries.

Key Features:
- Kubernetes API compliance checking via kubectl
- OpenShift-specific resource support
- YAML/JSONPath query evaluation
- Cluster connection validation

Migrated from: backend/app/services/scanners/kubernetes_scanner.py

Design Philosophy:
- Subprocess isolation for kubectl operations
- Security-first command execution (no shell=True)
- Graceful error handling
- Stateless operation for thread safety

Security Notes:
- kubectl commands use argument lists (no shell injection)
- KUBECONFIG paths validated before use
- Resource names sanitized
- Error messages truncated to prevent info disclosure

Usage:
    from backend.app.services.engine.scanners import KubernetesScanner

    scanner = KubernetesScanner()

    # Check scanner availability
    if scanner.is_available():
        # Execute scan
        results = await scanner.scan(
            rules=compliance_rules,
            target=cluster_target,
            variables={},
        )
"""

import asyncio
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..exceptions import ScanExecutionError, ScannerError
from ..models import ScannerCapabilities, ScanProvider, ScanType
from .base import BaseScanner

logger = logging.getLogger(__name__)


# Result status for Kubernetes checks
class KubernetesCheckStatus:
    """Status values for Kubernetes compliance checks."""

    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    NOT_APPLICABLE = "notapplicable"
    UNKNOWN = "unknown"


class KubernetesRuleResult:
    """
    Result of a single Kubernetes rule evaluation.

    Represents the outcome of checking a compliance rule against
    a Kubernetes cluster resource.

    Attributes:
        rule_id: Unique rule identifier
        title: Human-readable rule title
        severity: Rule severity (high, medium, low)
        status: Check status (pass, fail, error)
        message: Detailed result message
        actual_value: Actual value found in cluster
        expected_value: Expected value from rule
        resource_type: Kubernetes resource type checked
        resource_name: Specific resource name checked
        scanner_output: Raw output from kubectl
    """

    def __init__(
        self,
        rule_id: str,
        title: str = "",
        severity: str = "unknown",
        status: str = KubernetesCheckStatus.UNKNOWN,
        message: str = "",
        actual_value: Any = None,
        expected_value: Any = None,
        resource_type: str = "",
        resource_name: str = "",
        scanner_output: str = "",
    ):
        self.rule_id = rule_id
        self.title = title
        self.severity = severity
        self.status = status
        self.message = message
        self.actual_value = actual_value
        self.expected_value = expected_value
        self.resource_type = resource_type
        self.resource_name = resource_name
        self.scanner_output = scanner_output

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "message": self.message,
            "actual_value": self.actual_value,
            "expected_value": self.expected_value,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "scanner_output": self.scanner_output,
        }

    @property
    def is_pass(self) -> bool:
        """Check if result is passing."""
        return self.status == KubernetesCheckStatus.PASS

    @property
    def is_finding(self) -> bool:
        """Check if result is a finding requiring attention."""
        return self.status in (
            KubernetesCheckStatus.FAIL,
            KubernetesCheckStatus.ERROR,
        )


class KubernetesScanSummary:
    """
    Summary statistics for a Kubernetes scan.

    Provides aggregate counts and pass rate for reporting.
    """

    def __init__(
        self,
        total_rules: int = 0,
        passed: int = 0,
        failed: int = 0,
        errors: int = 0,
        not_applicable: int = 0,
    ):
        self.total_rules = total_rules
        self.passed = passed
        self.failed = failed
        self.errors = errors
        self.not_applicable = not_applicable

    @property
    def pass_rate(self) -> float:
        """Calculate pass rate percentage."""
        evaluated = self.total_rules - self.not_applicable
        if evaluated > 0:
            return round((self.passed / evaluated) * 100, 2)
        return 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "total_rules": self.total_rules,
            "passed": self.passed,
            "failed": self.failed,
            "errors": self.errors,
            "not_applicable": self.not_applicable,
            "pass_rate": self.pass_rate,
        }


class KubernetesScanner(BaseScanner):
    """
    Kubernetes scanner for YAML-based compliance checks.

    Executes compliance checks against Kubernetes/OpenShift clusters
    using kubectl and JSONPath queries. Supports various check
    conditions including equals, contains, exists, and more.

    The scanner validates cluster connectivity before scanning and
    handles kubeconfig configuration for multi-cluster environments.

    Attributes:
        kubectl_path: Path to kubectl binary
        kubectl_timeout: Timeout for kubectl commands (seconds)

    Usage:
        scanner = KubernetesScanner()

        if scanner.is_available():
            results, summary = await scanner.scan(
                rules=compliance_rules,
                target=KubernetesTarget(
                    identifier="production-cluster",
                    kubeconfig="/path/to/kubeconfig",
                ),
                variables={},
            )

            print(f"Pass rate: {summary.pass_rate}%")
    """

    def __init__(
        self,
        kubectl_path: str = "kubectl",
        kubectl_timeout: int = 30,
    ):
        """
        Initialize the Kubernetes scanner.

        Args:
            kubectl_path: Path to kubectl binary (default: use PATH).
            kubectl_timeout: Timeout for kubectl commands in seconds.
        """
        super().__init__(name="KubernetesScanner")
        self.kubectl_path = kubectl_path
        self.kubectl_timeout = kubectl_timeout
        self._kubectl_version: Optional[str] = None

    @property
    def provider(self) -> ScanProvider:
        """Return KUBERNETES provider type."""
        return ScanProvider.KUBERNETES

    @property
    def capabilities(self) -> ScannerCapabilities:
        """Return Kubernetes scanner capabilities."""
        return ScannerCapabilities(
            provider=ScanProvider.KUBERNETES,
            supported_scan_types=[ScanType.KUBERNETES_POLICY],
            supported_formats=["yaml", "json"],
            supports_remote=True,
            supports_local=True,
            max_concurrent=5,  # Limit concurrent kubectl calls
        )

    def validate_content(self, content_path: Path) -> bool:
        """
        Validate Kubernetes compliance content.

        For Kubernetes, content is typically YAML rule definitions
        rather than SCAP XML files.

        Args:
            content_path: Path to content file.

        Returns:
            True if content appears valid.
        """
        try:
            if not content_path.exists():
                return False

            # Check for YAML/JSON extension
            valid_extensions = [".yaml", ".yml", ".json"]
            if content_path.suffix.lower() not in valid_extensions:
                return False

            # Quick content check
            with open(content_path, "r", encoding="utf-8") as f:
                header = f.read(1024)

            # Look for rule indicators
            rule_markers = [
                "rule_id",
                "check_content",
                "resource_type",
                "yamlpath",
            ]

            return any(marker in header.lower() for marker in rule_markers)

        except Exception as e:
            self._logger.debug("Content validation error: %s", e)
            return False

    def extract_profiles(self, content_path: Path) -> List[Dict[str, Any]]:
        """
        Extract profiles from Kubernetes content.

        Kubernetes rules don't use profiles in the SCAP sense,
        but this method returns rule categories if defined.

        Args:
            content_path: Path to content file.

        Returns:
            List of category/profile dictionaries.
        """
        # Kubernetes scanner doesn't use traditional profiles
        # Return empty list - rules are executed directly
        return []

    def parse_results(self, result_path: Path, result_format: str = "json") -> Dict[str, Any]:
        """
        Parse Kubernetes scan result file.

        Args:
            result_path: Path to result file.
            result_format: Expected format (json, yaml).

        Returns:
            Dictionary with parsed results.
        """
        try:
            if not result_path.exists():
                raise ScannerError(f"Result file not found: {result_path}")

            with open(result_path, "r", encoding="utf-8") as f:
                content = f.read()

            if result_format == "json":
                return json.loads(content)
            else:
                # For YAML, we'd need yaml library
                # For now, return as raw content
                return {"raw_content": content}

        except json.JSONDecodeError as e:
            raise ScannerError(f"Invalid JSON in result file: {str(e)[:50]}")
        except Exception as e:
            raise ScannerError(f"Failed to parse results: {str(e)[:50]}")

    def is_available(self) -> bool:
        """
        Check if kubectl is available.

        Returns:
            True if kubectl command is accessible.
        """
        try:
            # Use synchronous check for availability
            import subprocess

            result = subprocess.run(
                ["which", self.kubectl_path],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    async def check_availability_async(self) -> bool:
        """
        Async check if kubectl is available.

        Returns:
            True if kubectl command is accessible.
        """
        try:
            process = await asyncio.create_subprocess_exec(
                "which",
                self.kubectl_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(
                process.communicate(),
                timeout=5,
            )
            return process.returncode == 0
        except Exception:
            return False

    async def get_kubectl_version(self) -> str:
        """
        Get kubectl client version.

        Returns:
            Version string or "unknown".
        """
        if self._kubectl_version:
            return self._kubectl_version

        try:
            process = await asyncio.create_subprocess_exec(
                self.kubectl_path,
                "version",
                "--client",
                "--short",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, _ = await asyncio.wait_for(
                process.communicate(),
                timeout=10,
            )

            # Parse version like "Client Version: v1.28.0"
            version_line = stdout.decode().strip()
            if ":" in version_line:
                self._kubectl_version = version_line.split(":")[1].strip()
            else:
                self._kubectl_version = "unknown"

        except Exception as e:
            self._logger.warning("Could not get kubectl version: %s", e)
            self._kubectl_version = "unknown"

        return self._kubectl_version

    async def scan(
        self,
        rules: List[Dict[str, Any]],
        target: Dict[str, Any],
        variables: Optional[Dict[str, str]] = None,
        scan_options: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[KubernetesRuleResult], KubernetesScanSummary]:
        """
        Execute Kubernetes compliance scan.

        Process:
        1. Validate kubectl availability and cluster connection
        2. For each rule:
           - Extract resource type and JSONPath query
           - Query Kubernetes API via kubectl
           - Evaluate condition against actual value
        3. Return structured results with summary

        Args:
            rules: List of compliance rule dictionaries.
            target: Target cluster information with credentials.
            variables: Variable substitutions for rules.
            scan_options: Additional scan configuration.

        Returns:
            Tuple of (rule_results, summary).

        Raises:
            ScanExecutionError: If scan cannot be completed.
        """
        self._logger.info(
            "Kubernetes scan starting: %d rules, cluster=%s",
            len(rules),
            target.get("identifier", "unknown"),
        )

        variables = variables or {}
        scan_options = scan_options or {}

        # Check kubectl availability
        if not await self.check_availability_async():
            raise ScanExecutionError(
                "kubectl command not found",
                scan_id="",
                host_id="",
            )

        try:
            # Validate cluster connection
            await self._validate_connection(target)

            # Execute checks for each rule
            rule_results: List[KubernetesRuleResult] = []
            for rule in rules:
                result = await self._check_rule(rule, target, variables, scan_options)
                rule_results.append(result)

            # Calculate summary
            summary = self._calculate_summary(rule_results)

            self._logger.info(
                "Kubernetes scan completed: %d/%d passed (%.1f%%)",
                summary.passed,
                summary.total_rules,
                summary.pass_rate,
            )

            return rule_results, summary

        except ScanExecutionError:
            raise
        except Exception as e:
            self._logger.error("Kubernetes scan failed: %s", e)
            raise ScanExecutionError(
                f"Kubernetes scan execution failed: {str(e)[:100]}",
                scan_id="",
                host_id="",
            )

    async def _validate_connection(self, target: Dict[str, Any]) -> None:
        """
        Validate connection to Kubernetes cluster.

        Args:
            target: Target cluster information.

        Raises:
            ScanExecutionError: If connection fails.
        """
        # Build environment with kubeconfig
        env = self._build_kubectl_env(target)

        # Test connection with kubectl cluster-info
        try:
            process = await asyncio.create_subprocess_exec(
                self.kubectl_path,
                "cluster-info",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.kubectl_timeout,
            )

            if process.returncode != 0:
                error_msg = stderr.decode()[:200]
                raise ScanExecutionError(
                    f"Cannot connect to cluster: {error_msg}",
                    scan_id="",
                    host_id="",
                )

            self._logger.info(
                "Connected to Kubernetes cluster: %s",
                target.get("identifier", "unknown"),
            )

        except asyncio.TimeoutError:
            raise ScanExecutionError(
                "Timeout connecting to cluster",
                scan_id="",
                host_id="",
            )

    def _build_kubectl_env(self, target: Dict[str, Any]) -> Dict[str, str]:
        """
        Build environment variables for kubectl.

        Args:
            target: Target cluster information.

        Returns:
            Environment dictionary with KUBECONFIG if needed.
        """
        env = dict(os.environ)

        credentials = target.get("credentials", {})
        if credentials and "kubeconfig" in credentials:
            kubeconfig_path = credentials["kubeconfig"]

            # Validate kubeconfig path for security
            # Only allow paths under expected directories
            if self._is_safe_kubeconfig_path(kubeconfig_path):
                env["KUBECONFIG"] = kubeconfig_path
            else:
                self._logger.warning(
                    "Kubeconfig path rejected for security: %s",
                    kubeconfig_path[:50],
                )

        return env

    def _is_safe_kubeconfig_path(self, path: str) -> bool:
        """
        Validate kubeconfig path for security.

        Args:
            path: Path to kubeconfig file.

        Returns:
            True if path appears safe.
        """
        try:
            resolved = Path(path).resolve()
            path_str = str(resolved)

            # Allow common kubeconfig locations
            allowed_prefixes = [
                str(Path.home() / ".kube"),
                "/etc/kubernetes",
                "/app/data/kubeconfig",
                "/tmp",
            ]

            is_allowed = any(path_str.startswith(prefix) for prefix in allowed_prefixes)

            if not is_allowed:
                return False

            # Check for path traversal
            if ".." in path:
                return False

            return True

        except Exception:
            return False

    async def _check_rule(
        self,
        rule: Dict[str, Any],
        target: Dict[str, Any],
        variables: Dict[str, str],
        scan_options: Dict[str, Any],
    ) -> KubernetesRuleResult:
        """
        Execute single rule check against Kubernetes API.

        Rule check_content should contain:
        - resource_type: e.g., "image.config.openshift.io"
        - resource_name: e.g., "cluster"
        - yamlpath: JSONPath query
        - expected_value: Expected result
        - condition: "equals", "not_equals", "exists", etc.

        Args:
            rule: Rule definition dictionary.
            target: Target cluster information.
            variables: Variable substitutions.
            scan_options: Scan configuration.

        Returns:
            KubernetesRuleResult with check outcome.
        """
        rule_id = rule.get("rule_id", "unknown")
        metadata = rule.get("metadata", {})
        title = metadata.get("name", rule_id)
        severity = rule.get("severity", "unknown")
        check_content = rule.get("check_content", {})

        # Extract check parameters
        resource_type = check_content.get("resource_type", "")
        resource_name = check_content.get("resource_name", "")
        yamlpath = check_content.get("yamlpath", "")
        expected = check_content.get("expected_value")
        condition = check_content.get("condition", "equals")

        # Validate required parameters
        if not resource_type or not yamlpath:
            return KubernetesRuleResult(
                rule_id=rule_id,
                title=title,
                severity=severity,
                status=KubernetesCheckStatus.ERROR,
                message="Missing resource_type or yamlpath in check_content",
                resource_type=resource_type,
            )

        # Sanitize resource names for security
        if not self._is_valid_resource_name(resource_type):
            return KubernetesRuleResult(
                rule_id=rule_id,
                title=title,
                severity=severity,
                status=KubernetesCheckStatus.ERROR,
                message="Invalid resource_type format",
                resource_type=resource_type,
            )

        try:
            # Query Kubernetes API
            actual_value, raw_output = await self._query_resource(
                target=target,
                resource_type=resource_type,
                resource_name=resource_name,
                yamlpath=yamlpath,
            )

            # Evaluate condition
            passed = self._evaluate_condition(actual_value, expected, condition)

            status = KubernetesCheckStatus.PASS if passed else KubernetesCheckStatus.FAIL

            message = f"Actual: {actual_value}, Expected: {expected} ({condition})"

            return KubernetesRuleResult(
                rule_id=rule_id,
                title=title,
                severity=severity,
                status=status,
                message=message,
                actual_value=actual_value,
                expected_value=expected,
                resource_type=resource_type,
                resource_name=resource_name,
                scanner_output=raw_output[:500],  # Limit output size
            )

        except Exception as e:
            self._logger.error(
                "Error checking rule %s: %s",
                rule_id[:50],
                str(e)[:50],
            )
            return KubernetesRuleResult(
                rule_id=rule_id,
                title=title,
                severity=severity,
                status=KubernetesCheckStatus.ERROR,
                message=str(e)[:200],
                resource_type=resource_type,
                resource_name=resource_name,
            )

    def _is_valid_resource_name(self, name: str) -> bool:
        """
        Validate Kubernetes resource name format.

        Args:
            name: Resource name to validate.

        Returns:
            True if name appears valid.
        """
        # Resource names should be alphanumeric with dots and hyphens
        # e.g., "image.config.openshift.io", "pods", "configmaps"
        pattern = r"^[a-z0-9][a-z0-9.\-]*$"
        return bool(re.match(pattern, name.lower()))

    async def _query_resource(
        self,
        target: Dict[str, Any],
        resource_type: str,
        resource_name: str,
        yamlpath: str,
    ) -> Tuple[Any, str]:
        """
        Query Kubernetes resource using kubectl and JSONPath.

        Args:
            target: Target cluster information.
            resource_type: Kubernetes resource type.
            resource_name: Specific resource name (optional).
            yamlpath: JSONPath query string.

        Returns:
            Tuple of (parsed_value, raw_output).

        Raises:
            ScanExecutionError: If query fails.
        """
        env = self._build_kubectl_env(target)

        # Build kubectl command as argument list (security: no shell injection)
        cmd = [self.kubectl_path, "get", resource_type]

        if resource_name:
            cmd.append(resource_name)

        # Add JSONPath output format
        cmd.extend(["-o", f"jsonpath={{{yamlpath}}}"])

        self._logger.debug("Executing: %s", " ".join(cmd))

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.kubectl_timeout,
            )

            if process.returncode != 0:
                error_msg = stderr.decode()[:200]
                raise ScanExecutionError(
                    f"kubectl query failed: {error_msg}",
                    scan_id="",
                    host_id="",
                )

            # Parse output
            output = stdout.decode().strip()

            # Try to parse as JSON if it looks like JSON
            parsed_value: Any = output
            if output.startswith("[") or output.startswith("{"):
                try:
                    parsed_value = json.loads(output)
                except json.JSONDecodeError:
                    pass

            return parsed_value, output

        except asyncio.TimeoutError:
            raise ScanExecutionError(
                f"Timeout querying resource: {resource_type}",
                scan_id="",
                host_id="",
            )

    def _evaluate_condition(
        self,
        actual: Any,
        expected: Any,
        condition: str,
    ) -> bool:
        """
        Evaluate condition between actual and expected values.

        Supported conditions:
        - equals: actual == expected
        - not_equals: actual != expected
        - contains: expected in actual
        - not_contains: expected not in actual
        - exists: actual is not None/empty
        - not_exists: actual is None/empty
        - any_exist: len(actual) > 0 (for lists)
        - none_exist: len(actual) == 0 (for lists)
        - greater_than: actual > expected (numeric)
        - less_than: actual < expected (numeric)

        Args:
            actual: Actual value from cluster.
            expected: Expected value from rule.
            condition: Condition type string.

        Returns:
            True if condition is satisfied.
        """
        if condition == "equals":
            return actual == expected

        elif condition == "not_equals":
            return actual != expected

        elif condition == "contains":
            if actual is None:
                return False
            if isinstance(actual, str):
                return str(expected) in actual
            if isinstance(actual, (list, dict)):
                return expected in actual
            return False

        elif condition == "not_contains":
            if actual is None:
                return True
            if isinstance(actual, str):
                return str(expected) not in actual
            if isinstance(actual, (list, dict)):
                return expected not in actual
            return True

        elif condition == "exists":
            return actual is not None and actual != ""

        elif condition == "not_exists":
            return actual is None or actual == ""

        elif condition == "any_exist":
            if isinstance(actual, (list, dict)):
                return len(actual) > 0
            return False

        elif condition == "none_exist":
            if isinstance(actual, (list, dict)):
                return len(actual) == 0
            return True

        elif condition == "greater_than":
            try:
                return float(actual) > float(expected)
            except (ValueError, TypeError):
                return False

        elif condition == "less_than":
            try:
                return float(actual) < float(expected)
            except (ValueError, TypeError):
                return False

        else:
            self._logger.warning(
                "Unknown condition: %s, defaulting to equals",
                condition,
            )
            return actual == expected

    def _calculate_summary(
        self,
        results: List[KubernetesRuleResult],
    ) -> KubernetesScanSummary:
        """
        Calculate summary statistics from rule results.

        Args:
            results: List of rule results.

        Returns:
            KubernetesScanSummary with aggregated counts.
        """
        summary = KubernetesScanSummary(total_rules=len(results))

        for result in results:
            if result.status == KubernetesCheckStatus.PASS:
                summary.passed += 1
            elif result.status == KubernetesCheckStatus.FAIL:
                summary.failed += 1
            elif result.status == KubernetesCheckStatus.ERROR:
                summary.errors += 1
            elif result.status == KubernetesCheckStatus.NOT_APPLICABLE:
                summary.not_applicable += 1

        return summary

    def get_required_capabilities(self) -> List[str]:
        """
        Get required capabilities for Kubernetes scanning.

        Returns:
            List of required capability strings.
        """
        return ["kubectl", "cluster-reader"]
