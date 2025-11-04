#!/usr/bin/env python3
"""
OSCAP Scanner Implementation

Executes OVAL-based compliance checks using OpenSCAP tools.
"""

import asyncio
import logging
import os
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional

from ...models.scan_models import (
    RuleResult,
    RuleResultStatus,
    ScanResultSummary,
    ScanTarget,
    ScanTargetType,
)
from ..xccdf_generator_service import XCCDFGeneratorService
from .base_scanner import (
    BaseScanner,
    ScannerExecutionError,
    ScannerNotAvailableError,
    UnsupportedTargetError,
)

logger = logging.getLogger(__name__)


class OSCAPScanner(BaseScanner):
    """
    OpenSCAP scanner for traditional OVAL-based compliance checks

    Supports:
    - SSH-based remote scanning (oscap-ssh)
    - Local scanning (oscap)
    - XCCDF variable customization via tailoring files
    """

    # XCCDF namespaces
    XCCDF_NS = {"xccdf": "http://checklists.nist.gov/xccdf/1.2"}

    def __init__(self):
        super().__init__("oscap")

    def _get_version(self) -> str:
        """Get OpenSCAP version"""
        try:
            result = asyncio.run(
                asyncio.create_subprocess_exec(
                    "oscap",
                    "--version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            )
            stdout, _ = asyncio.run(result.communicate())
            # Parse version from output like "OpenSCAP command line tool (oscap) 1.3.7"
            version_line = stdout.decode().split("\n")[0]
            version = version_line.split()[-1]
            return version
        except Exception as e:
            logger.warning(f"Could not determine oscap version: {e}")
            return "unknown"

    async def scan(
        self,
        rules: List[Dict[str, Any]],
        target: ScanTarget,
        variables: Dict[str, str],
        scan_options: Dict[str, Any] = None,
    ) -> tuple[List[RuleResult], ScanResultSummary]:
        """
        Execute OSCAP scan

        Process:
        1. Generate XCCDF benchmark from rules
        2. Generate tailoring file with variable overrides
        3. Execute oscap (local or remote via SSH)
        4. Parse XCCDF results XML
        5. Return structured results
        """
        logger.info(f"OSCAP scan starting: {len(rules)} rules, target={target.identifier}")

        # Validate target type
        if target.type not in [ScanTargetType.SSH_HOST, ScanTargetType.LOCAL]:
            raise UnsupportedTargetError(
                f"OSCAP scanner does not support target type: {target.type}"
            )

        # Check oscap availability
        if not await self._check_oscap_available():
            raise ScannerNotAvailableError("oscap command not found")

        scan_options = scan_options or {}

        try:
            # 1. Generate XCCDF benchmark
            benchmark_xml, profile_id = await self._generate_benchmark(rules, scan_options)

            # 2. Generate tailoring file if variables provided
            tailoring_xml = None
            if variables:
                tailoring_xml = await self._generate_tailoring(
                    benchmark_id=scan_options.get("benchmark_id", "openwatch-benchmark"),
                    profile_id=profile_id,
                    variables=variables,
                )

            # 3. Execute oscap scan
            results_xml = await self._execute_oscap(
                target=target,
                benchmark_xml=benchmark_xml,
                tailoring_xml=tailoring_xml,
                profile_id=profile_id,
                scan_options=scan_options,
            )

            # 4. Parse results
            rule_results = self._parse_results(results_xml, rules)

            # 5. Calculate summary
            summary = self._calculate_summary(rule_results)

            logger.info(f"OSCAP scan completed: {summary.passed}/{summary.total_rules} passed")

            return rule_results, summary

        except Exception as e:
            logger.error(f"OSCAP scan failed: {e}")
            raise ScannerExecutionError(f"OSCAP execution failed: {str(e)}")

    async def _check_oscap_available(self) -> bool:
        """Check if oscap command is available"""
        try:
            process = await asyncio.create_subprocess_exec(
                "which",
                "oscap",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            return process.returncode == 0
        except Exception:
            return False

    async def _generate_benchmark(
        self, rules: List[Dict[str, Any]], scan_options: Dict[str, Any]
    ) -> tuple[str, str]:
        """
        Generate XCCDF benchmark from rules

        Returns: (benchmark_xml, profile_id)
        """
        # This would use XCCDFGeneratorService, but since we don't have db here,
        # we'll create a simplified benchmark for now
        # In production, pass db instance to scanner or use service locator pattern

        benchmark_id = scan_options.get("benchmark_id", "openwatch-benchmark")
        profile_id = scan_options.get("profile_id", "default_profile")

        # Simplified benchmark generation (placeholder)
        # Real implementation would call XCCDFGeneratorService
        benchmark_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<xccdf:Benchmark xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2"
                  id="xccdf_com.hanalyx.openwatch_benchmark_{benchmark_id}">
  <xccdf:status>draft</xccdf:status>
  <xccdf:title>OpenWatch Compliance Benchmark</xccdf:title>
  <xccdf:version>1.0</xccdf:version>

  <!-- Rules would be inserted here -->

  <xccdf:Profile id="{profile_id}">
    <xccdf:title>Default Profile</xccdf:title>
  </xccdf:Profile>
</xccdf:Benchmark>
"""

        return benchmark_xml, profile_id

    async def _generate_tailoring(
        self, benchmark_id: str, profile_id: str, variables: Dict[str, str]
    ) -> str:
        """Generate XCCDF tailoring file with variable overrides"""

        # Build set-value elements
        set_values = "\n".join(
            [
                f'    <xccdf:set-value idref="{var_id}">{var_value}</xccdf:set-value>'
                for var_id, var_value in variables.items()
            ]
        )

        tailoring_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<xccdf:Tailoring xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2"
                  id="openwatch_tailoring">
  <xccdf:version>1.0</xccdf:version>
  <xccdf:benchmark href="{benchmark_id}.xml"/>

  <xccdf:Profile id="{profile_id}_customized" extends="{profile_id}">
    <xccdf:title>Customized Profile</xccdf:title>
{set_values}
  </xccdf:Profile>
</xccdf:Tailoring>
"""

        return tailoring_xml

    async def _execute_oscap(
        self,
        target: ScanTarget,
        benchmark_xml: str,
        tailoring_xml: Optional[str],
        profile_id: str,
        scan_options: Dict[str, Any],
    ) -> str:
        """
        Execute oscap command (local or remote)

        Returns: XCCDF results XML string
        """
        # Write benchmark to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(benchmark_xml)
            benchmark_file = f.name

        tailoring_file = None
        if tailoring_xml:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
                f.write(tailoring_xml)
                tailoring_file = f.name

        results_file = tempfile.mktemp(suffix=".xml")

        try:
            if target.type == ScanTargetType.SSH_HOST:
                # Remote scan via oscap-ssh
                results_xml = await self._scan_remote(
                    target=target,
                    benchmark_file=benchmark_file,
                    tailoring_file=tailoring_file,
                    profile_id=profile_id,
                    results_file=results_file,
                    scan_options=scan_options,
                )
            else:
                # Local scan
                results_xml = await self._scan_local(
                    benchmark_file=benchmark_file,
                    tailoring_file=tailoring_file,
                    profile_id=profile_id,
                    results_file=results_file,
                    scan_options=scan_options,
                )

            return results_xml

        finally:
            # Cleanup temp files
            for temp_file in [benchmark_file, tailoring_file, results_file]:
                if temp_file and os.path.exists(temp_file):
                    os.unlink(temp_file)

    async def _scan_remote(
        self,
        target: ScanTarget,
        benchmark_file: str,
        tailoring_file: Optional[str],
        profile_id: str,
        results_file: str,
        scan_options: Dict[str, Any],
    ) -> str:
        """Execute remote scan via oscap-ssh"""

        # Build oscap-ssh command
        credentials = target.credentials or {}
        username = credentials.get("username", "root")
        ssh_target = f"{username}@{target.identifier}"

        cmd = [
            "oscap-ssh",
            ssh_target,
            "xccdf",
            "eval",
            "--profile",
            profile_id,
            "--results",
            results_file,
        ]

        if tailoring_file:
            cmd.extend(["--tailoring-file", tailoring_file])

        cmd.append(benchmark_file)

        logger.info(f"Executing: {' '.join(cmd)}")

        process = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        # oscap returns non-zero if there are failures, which is expected
        if process.returncode not in [0, 2]:  # 0=all pass, 2=some fail
            raise ScannerExecutionError(f"oscap-ssh failed: {stderr.decode()}")

        # Read results file
        if os.path.exists(results_file):
            with open(results_file, "r") as f:
                return f.read()
        else:
            raise ScannerExecutionError("Results file not created")

    async def _scan_local(
        self,
        benchmark_file: str,
        tailoring_file: Optional[str],
        profile_id: str,
        results_file: str,
        scan_options: Dict[str, Any],
    ) -> str:
        """Execute local scan"""

        cmd = [
            "oscap",
            "xccdf",
            "eval",
            "--profile",
            profile_id,
            "--results",
            results_file,
        ]

        if tailoring_file:
            cmd.extend(["--tailoring-file", tailoring_file])

        cmd.append(benchmark_file)

        logger.info(f"Executing: {' '.join(cmd)}")

        process = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        if process.returncode not in [0, 2]:
            raise ScannerExecutionError(f"oscap failed: {stderr.decode()}")

        if os.path.exists(results_file):
            with open(results_file, "r") as f:
                return f.read()
        else:
            raise ScannerExecutionError("Results file not created")

    def _parse_results(self, results_xml: str, rules: List[Dict[str, Any]]) -> List[RuleResult]:
        """
        Parse XCCDF results XML into RuleResult objects

        XCCDF results XML structure:
        <TestResult>
          <rule-result idref="xccdf_...rule_..." time="...">
            <result>pass|fail|error|notapplicable</result>
            <message>...</message>
          </rule-result>
        </TestResult>
        """
        rule_results = []

        try:
            root = ET.fromstring(results_xml)

            # Find all rule-result elements
            for rule_result_elem in root.findall(".//xccdf:rule-result", self.XCCDF_NS):
                rule_id = rule_result_elem.get("idref", "")

                # Get result status
                result_elem = rule_result_elem.find("xccdf:result", self.XCCDF_NS)
                status = result_elem.text if result_elem is not None else "error"

                # Get message
                message_elem = rule_result_elem.find("xccdf:message", self.XCCDF_NS)
                message = message_elem.text if message_elem is not None else None

                # Find corresponding rule from input rules
                matching_rule = next(
                    (
                        r
                        for r in rules
                        if r["rule_id"] in rule_id or r.get("scap_rule_id") == rule_id
                    ),
                    None,
                )

                if matching_rule:
                    rule_results.append(
                        RuleResult(
                            rule_id=matching_rule["rule_id"],
                            scap_rule_id=matching_rule.get("scap_rule_id"),
                            title=matching_rule["metadata"].get("name", rule_id),
                            severity=matching_rule.get("severity", "unknown"),
                            status=RuleResultStatus(status.lower()),
                            message=message,
                            scanner_type="oscap",
                        )
                    )

        except ET.ParseError as e:
            logger.error(f"Failed to parse XCCDF results: {e}")
            raise ScannerExecutionError(f"Invalid XCCDF results XML: {str(e)}")

        return rule_results

    def get_required_capabilities(self) -> List[str]:
        """Required capabilities for OSCAP scanner"""
        return ["oscap", "ssh"]  # ssh only for remote scans
