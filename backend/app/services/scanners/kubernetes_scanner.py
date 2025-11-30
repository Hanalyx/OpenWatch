#!/usr/bin/env python3
"""
Kubernetes Scanner Implementation

Executes YAML-based compliance checks against Kubernetes/OpenShift clusters.
"""

import asyncio
import json
import logging
import os
from typing import Any, Dict, List

from ...models.scan_models import RuleResult, RuleResultStatus, ScanResultSummary, ScanTarget, ScanTargetType
from .base_scanner import BaseScanner, ScannerExecutionError, ScannerNotAvailableError, UnsupportedTargetError

logger = logging.getLogger(__name__)


class KubernetesScanner(BaseScanner):
    """
    Kubernetes scanner for YAML-based compliance checks

    Executes checks against Kubernetes API using yamlpath queries.
    Supports OpenShift-specific resources.
    """

    def __init__(self):
        super().__init__("kubernetes")

    def _get_version(self) -> str:
        """Get kubectl version"""
        try:
            result = asyncio.run(
                asyncio.create_subprocess_exec(
                    "kubectl",
                    "version",
                    "--client",
                    "--short",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            )
            stdout, _ = asyncio.run(result.communicate())
            # Parse version like "Client Version: v1.28.0"
            version_line = stdout.decode().strip()
            if ":" in version_line:
                version = version_line.split(":")[1].strip()
                return version
            return "unknown"
        except Exception as e:
            logger.warning(f"Could not determine kubectl version: {e}")
            return "unknown"

    async def scan(
        self,
        rules: List[Dict[str, Any]],
        target: ScanTarget,
        variables: Dict[str, str],
        scan_options: Dict[str, Any] = None,
    ) -> tuple[List[RuleResult], ScanResultSummary]:
        """
        Execute Kubernetes compliance scan

        Process:
        1. Validate kubeconfig/connection
        2. For each rule:
           - Extract resource type and yamlpath query
           - Query Kubernetes API
           - Evaluate condition against actual value
        3. Return structured results
        """
        logger.info(f"Kubernetes scan starting: {len(rules)} rules, cluster={target.identifier}")

        # Validate target type
        if target.type != ScanTargetType.KUBERNETES:
            raise UnsupportedTargetError("Kubernetes scanner only supports KUBERNETES target type")

        # Check kubectl availability
        if not await self._check_kubectl_available():
            raise ScannerNotAvailableError("kubectl command not found")

        scan_options = scan_options or {}

        try:
            # Validate cluster connection
            await self._validate_connection(target)

            # Execute checks for each rule
            rule_results = []
            for rule in rules:
                result = await self._check_rule(rule, target, variables, scan_options)
                rule_results.append(result)

            # Calculate summary
            summary = self._calculate_summary(rule_results)

            logger.info(f"Kubernetes scan completed: {summary.passed}/{summary.total_rules} passed")

            return rule_results, summary

        except Exception as e:
            logger.error(f"Kubernetes scan failed: {e}")
            raise ScannerExecutionError(f"Kubernetes scan execution failed: {str(e)}")

    async def _check_kubectl_available(self) -> bool:
        """Check if kubectl command is available"""
        try:
            process = await asyncio.create_subprocess_exec(
                "which",
                "kubectl",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            return process.returncode == 0
        except Exception:
            return False

    async def _validate_connection(self, target: ScanTarget):
        """Validate connection to Kubernetes cluster"""
        # Set KUBECONFIG if provided
        env = {}
        if target.credentials and "kubeconfig" in target.credentials:
            env["KUBECONFIG"] = target.credentials["kubeconfig"]

        # Test connection with kubectl cluster-info
        process = await asyncio.create_subprocess_exec(
            "kubectl",
            "cluster-info",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, **env} if env else None,
        )

        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            raise ScannerExecutionError(f"Cannot connect to cluster: {stderr.decode()}")

        logger.info(f"Connected to Kubernetes cluster: {target.identifier}")

    async def _check_rule(
        self,
        rule: Dict[str, Any],
        target: ScanTarget,
        variables: Dict[str, str],
        scan_options: Dict[str, Any],
    ) -> RuleResult:
        """
        Execute single rule check against Kubernetes API

        Rule check_content should contain:
        - resource_type: e.g., "image.config.openshift.io"
        - resource_name: e.g., "cluster"
        - yamlpath: JSONPath query
        - expected_value: Expected result
        - condition: "equals", "not_equals", "exists", etc.
        """
        check_content = rule.get("check_content", {})

        # Extract check parameters
        resource_type = check_content.get("resource_type")
        resource_name = check_content.get("resource_name", "")
        yamlpath = check_content.get("yamlpath", "")
        expected = check_content.get("expected_value")
        condition = check_content.get("condition", "equals")

        if not resource_type or not yamlpath:
            return RuleResult(
                rule_id=rule["rule_id"],
                title=rule["metadata"].get("name", rule["rule_id"]),
                severity=rule.get("severity", "unknown"),
                status=RuleResultStatus.ERROR,
                message="Missing resource_type or yamlpath in check_content",
                scanner_type="kubernetes",
            )

        try:
            # Query Kubernetes API
            actual_value = await self._query_resource(
                target=target,
                resource_type=resource_type,
                resource_name=resource_name,
                yamlpath=yamlpath,
            )

            # Evaluate condition
            passed = self._evaluate_condition(actual_value, expected, condition)

            status = RuleResultStatus.PASS if passed else RuleResultStatus.FAIL
            message = f"Actual: {actual_value}, Expected: {expected} ({condition})"

            return RuleResult(
                rule_id=rule["rule_id"],
                scap_rule_id=rule.get("scap_rule_id"),
                title=rule["metadata"].get("name", rule["rule_id"]),
                severity=rule.get("severity", "unknown"),
                status=status,
                message=message,
                scanner_output=json.dumps({"actual": actual_value, "expected": expected}),
                scanner_type="kubernetes",
            )

        except Exception as e:
            logger.error(f"Error checking rule {rule['rule_id']}: {e}")
            return RuleResult(
                rule_id=rule["rule_id"],
                title=rule["metadata"].get("name", rule["rule_id"]),
                severity=rule.get("severity", "unknown"),
                status=RuleResultStatus.ERROR,
                message=str(e),
                scanner_type="kubernetes",
            )

    async def _query_resource(self, target: ScanTarget, resource_type: str, resource_name: str, yamlpath: str) -> Any:
        """
        Query Kubernetes resource using kubectl and JSONPath

        Example:
            resource_type: "image.config.openshift.io"
            resource_name: "cluster"
            yamlpath: ".spec.allowedRegistriesForImport[:].insecure"
        """
        # Set KUBECONFIG if provided
        env = {}
        if target.credentials and "kubeconfig" in target.credentials:
            env["KUBECONFIG"] = target.credentials["kubeconfig"]

        # Build kubectl command
        # kubectl get <resource_type> <resource_name> -o jsonpath='{<yamlpath>}'
        cmd = ["kubectl", "get", resource_type]

        if resource_name:
            cmd.append(resource_name)

        cmd.extend(["-o", f"jsonpath={{{yamlpath}}}"])

        logger.debug(f"Executing: {' '.join(cmd)}")

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, **env} if env else None,
        )

        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            raise ScannerExecutionError(f"kubectl query failed: {stderr.decode()}")

        # Parse output
        output = stdout.decode().strip()

        # Try to parse as JSON if it looks like JSON
        if output.startswith("[") or output.startswith("{"):
            try:
                return json.loads(output)
            except json.JSONDecodeError:
                pass

        return output

    def _evaluate_condition(self, actual: Any, expected: Any, condition: str) -> bool:
        """
        Evaluate condition between actual and expected values

        Supported conditions:
        - equals: actual == expected
        - not_equals: actual != expected
        - contains: expected in actual
        - not_contains: expected not in actual
        - exists: actual is not None
        - not_exists: actual is None
        - any_exist: len(actual) > 0 (for lists)
        - none_exist: len(actual) == 0 (for lists)
        """
        if condition == "equals":
            return actual == expected
        elif condition == "not_equals":
            return actual != expected
        elif condition == "contains":
            return expected in actual if actual else False
        elif condition == "not_contains":
            return expected not in actual if actual else True
        elif condition == "exists":
            return actual is not None and actual != ""
        elif condition == "not_exists":
            return actual is None or actual == ""
        elif condition == "any_exist":
            return len(actual) > 0 if isinstance(actual, (list, dict)) else False
        elif condition == "none_exist":
            return len(actual) == 0 if isinstance(actual, (list, dict)) else True
        else:
            logger.warning(f"Unknown condition: {condition}, defaulting to equals")
            return actual == expected

    def get_required_capabilities(self) -> List[str]:
        """Required capabilities for Kubernetes scanner"""
        return ["kubectl", "cluster-reader"]  # cluster-reader RBAC role or higher
