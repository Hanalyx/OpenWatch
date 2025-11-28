"""
Rule-Specific Scanner Service
Enables targeted scanning of specific SCAP rules for efficient remediation verification
"""

import asyncio
import functools
import json
import logging
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, cast

from .compliance_framework_mapper import ComplianceFrameworkMapper
from .scap_scanner import ScanExecutionError, SCAPScanner

logger = logging.getLogger(__name__)


class RuleSpecificScanner:
    """Service for scanning specific SCAP rules"""

    def __init__(self, results_dir: str = "/app/data/results/rule_scans"):
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.scanner = SCAPScanner()
        self.framework_mapper = ComplianceFrameworkMapper()
        self.executor = ThreadPoolExecutor(max_workers=5)

    def _sanitize_identifier(self, identifier: str) -> str:
        """
        Security Fix: Sanitize identifiers to prevent path injection
        Only allow alphanumeric characters, hyphens, and underscores
        """
        import re

        # Remove any characters that aren't alphanumeric, hyphens, or underscores
        sanitized = re.sub(r"[^a-zA-Z0-9\-_]", "_", identifier)
        # Limit length to prevent excessively long paths
        return sanitized[:50]

    async def scan_specific_rules(
        self,
        host_id: str,
        content_path: str,
        profile_id: str,
        rule_ids: List[str],
        connection_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Scan specific rules on a host"""
        try:
            # Security Fix: Sanitize host_id to prevent path injection
            sanitized_host_id = self._sanitize_identifier(host_id)
            scan_id = f"rule_scan_{sanitized_host_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            logger.info(f"Starting rule-specific scan {scan_id} for {len(rule_ids)} rules")

            # Create scan results structure
            results: Dict[str, Any] = {
                "scan_id": scan_id,
                "host_id": host_id,
                "timestamp": datetime.now().isoformat(),
                "profile_id": profile_id,
                "total_rules": len(rule_ids),
                "scanned_rules": 0,
                "passed_rules": 0,
                "failed_rules": 0,
                "error_rules": 0,
                "rule_results": [],
                "scan_type": "rule_specific",
                "duration_seconds": 0,
            }

            start_time = datetime.now()

            # Determine if local or remote scan
            if connection_params:
                results["scan_mode"] = "remote"
                scan_results = await self._scan_rules_remote(
                    scan_id, content_path, profile_id, rule_ids, connection_params
                )
            else:
                results["scan_mode"] = "local"
                scan_results = await self._scan_rules_local(scan_id, content_path, profile_id, rule_ids)

            # Process results
            for rule_id, rule_result in scan_results.items():
                results["scanned_rules"] += 1

                # Get compliance framework mappings
                framework_info = self.framework_mapper.get_unified_control(rule_id)

                rule_entry = {
                    "rule_id": rule_id,
                    "result": rule_result.get("result", "error"),
                    "title": rule_result.get("title", ""),
                    "severity": rule_result.get("severity", "unknown"),
                    "scan_output": rule_result.get("output", ""),
                    "error": rule_result.get("error", None),
                    "compliance_frameworks": [],
                }

                # Add framework mappings
                if framework_info:
                    for mapping in framework_info.frameworks:
                        rule_entry["compliance_frameworks"].append(
                            {
                                "framework": mapping.framework.value,
                                "control_id": mapping.control_id,
                                "control_title": mapping.control_title,
                            }
                        )
                    rule_entry["automated_remediation_available"] = framework_info.automated_remediation
                    rule_entry["aegis_rule_id"] = framework_info.aegis_rule_id

                # Count results
                if rule_result.get("result") == "pass":
                    results["passed_rules"] += 1
                elif rule_result.get("result") == "fail":
                    results["failed_rules"] += 1
                else:
                    results["error_rules"] += 1

                results["rule_results"].append(rule_entry)

            # Calculate duration
            end_time = datetime.now()
            results["duration_seconds"] = (end_time - start_time).total_seconds()

            # Calculate compliance score
            if results["scanned_rules"] > 0:
                results["compliance_score"] = (results["passed_rules"] / results["scanned_rules"]) * 100
            else:
                results["compliance_score"] = 0

            # Save results
            await self._save_scan_results(results)

            logger.info(f"Rule-specific scan completed: {scan_id}")
            return results

        except Exception as e:
            logger.error(f"Error in rule-specific scan: {e}")
            raise ScanExecutionError(f"Rule scan failed: {str(e)}")

    async def scan_failed_rules_from_previous_scan(
        self,
        previous_scan_id: str,
        content_path: str,
        connection_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Re-scan only failed rules from a previous scan"""
        try:
            # Load previous scan results
            previous_results = await self._load_scan_results(previous_scan_id)

            if not previous_results:
                raise ValueError(f"Previous scan {previous_scan_id} not found")

            # Extract failed rule IDs
            failed_rules = []
            for rule in previous_results.get("failed_rules", []):
                failed_rules.append(rule["rule_id"])

            if not failed_rules:
                return {
                    "message": "No failed rules to re-scan",
                    "previous_scan_id": previous_scan_id,
                }

            logger.info(f"Re-scanning {len(failed_rules)} failed rules from scan {previous_scan_id}")

            # Perform targeted scan - get values with defaults for type safety
            host_id = previous_results.get("host_id", "")
            profile_id = previous_results.get("profile_id", "")
            if not host_id or not profile_id:
                raise ValueError("Previous scan missing host_id or profile_id")
            return await self.scan_specific_rules(
                host_id=host_id,
                content_path=content_path,
                profile_id=profile_id,
                rule_ids=failed_rules,
                connection_params=connection_params,
            )

        except Exception as e:
            logger.error(f"Error re-scanning failed rules: {e}")
            raise

    async def verify_remediation(
        self,
        host_id: str,
        content_path: str,
        aegis_remediation_id: str,
        remediated_rules: List[str],
        connection_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Verify specific rules after AEGIS remediation"""
        try:
            logger.info(f"Verifying remediation {aegis_remediation_id} for {len(remediated_rules)} rules")

            # Create verification scan
            scan_results = await self.scan_specific_rules(
                host_id=host_id,
                content_path=content_path,
                profile_id="remediation_verification",
                rule_ids=remediated_rules,
                connection_params=connection_params,
            )

            # Analyze remediation effectiveness
            verification_report = {
                "remediation_id": aegis_remediation_id,
                "verification_scan_id": scan_results["scan_id"],
                "timestamp": datetime.now().isoformat(),
                "total_rules_remediated": len(remediated_rules),
                "successfully_remediated": scan_results["passed_rules"],
                "failed_remediation": scan_results["failed_rules"],
                "remediation_success_rate": 0,
                "failed_rules": [],
                "successful_rules": [],
            }

            # Calculate success rate
            if verification_report["total_rules_remediated"] > 0:
                verification_report["remediation_success_rate"] = (
                    verification_report["successfully_remediated"] / verification_report["total_rules_remediated"]
                ) * 100

            # Categorize results
            for rule_result in scan_results["rule_results"]:
                if rule_result["result"] == "pass":
                    verification_report["successful_rules"].append(
                        {
                            "rule_id": rule_result["rule_id"],
                            "title": rule_result["title"],
                        }
                    )
                else:
                    verification_report["failed_rules"].append(
                        {
                            "rule_id": rule_result["rule_id"],
                            "title": rule_result["title"],
                            "error": rule_result.get("error", "Remediation not effective"),
                        }
                    )

            return verification_report

        except Exception as e:
            logger.error(f"Error verifying remediation: {e}")
            raise

    async def get_rule_scan_history(
        self, rule_id: str, host_id: Optional[str] = None, limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Get scan history for a specific rule"""
        try:
            history = []

            # Search through recent scan results
            scan_files = sorted(self.results_dir.glob("*.json"), reverse=True)[:100]

            for scan_file in scan_files:
                try:
                    with open(scan_file, "r") as f:
                        scan_data = json.load(f)

                    # Filter by host if specified
                    if host_id and scan_data.get("host_id") != host_id:
                        continue

                    # Look for the rule in results
                    for rule_result in scan_data.get("rule_results", []):
                        if rule_result["rule_id"] == rule_id:
                            history.append(
                                {
                                    "scan_id": scan_data["scan_id"],
                                    "timestamp": scan_data["timestamp"],
                                    "host_id": scan_data["host_id"],
                                    "result": rule_result["result"],
                                    "severity": rule_result["severity"],
                                }
                            )
                            break

                    if len(history) >= limit:
                        break

                except Exception as e:
                    logger.warning(f"Error reading scan file {scan_file}: {e}")
                    continue

            return history

        except Exception as e:
            logger.error(f"Error getting rule scan history: {e}")
            return []

    async def _scan_rules_local(
        self, scan_id: str, content_path: str, profile_id: str, rule_ids: List[str]
    ) -> Dict[str, Dict[str, Any]]:
        """Scan specific rules locally"""
        results = {}

        # Create temporary directory for individual rule scans
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Scan each rule individually for detailed results
            tasks = []
            for rule_id in rule_ids:
                task = self._scan_single_rule_local(scan_id, content_path, profile_id, rule_id, temp_path)
                tasks.append(task)

            # Execute scans concurrently
            rule_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results
            for rule_id, result in zip(rule_ids, rule_results):
                if isinstance(result, Exception):
                    results[rule_id] = {"result": "error", "error": str(result)}
                elif isinstance(result, dict):
                    results[rule_id] = result
                else:
                    results[rule_id] = {"result": "error", "error": "Unknown result type"}

        return results

    async def _scan_single_rule_local(
        self,
        scan_id: str,
        content_path: str,
        profile_id: str,
        rule_id: str,
        temp_dir: Path,
    ) -> Dict[str, Any]:
        """Scan a single rule locally"""
        try:
            # Create unique result files for this rule
            rule_scan_id = f"{scan_id}_{rule_id.replace(':', '_')}"
            xml_result = temp_dir / f"{rule_scan_id}.xml"

            # Run oscap with specific rule
            cmd = [
                "oscap",
                "xccdf",
                "eval",
                "--profile",
                profile_id,
                "--rule",
                rule_id,
                "--results",
                str(xml_result),
                content_path,
            ]

            # Execute in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            run_subprocess = functools.partial(
                subprocess.run,
                cmd,
                capture_output=True,
                timeout=300,
            )
            result = await loop.run_in_executor(self.executor, run_subprocess)

            # Parse result
            if xml_result.exists():
                scan_result = self.scanner._parse_scan_results(str(xml_result))

                # Extract rule-specific result
                for rule_detail in scan_result.get("rule_details", []):
                    if rule_detail["rule_id"] == rule_id:
                        return {
                            "result": rule_detail["result"],
                            "title": rule_detail.get("title", ""),
                            "severity": rule_detail.get("severity", "unknown"),
                            "output": result.stdout,
                        }

            # If we couldn't find the result, check exit code
            if result.returncode == 0:
                return {"result": "pass", "output": result.stdout}
            else:
                return {
                    "result": "fail",
                    "output": result.stdout,
                    "error": result.stderr,
                }

        except subprocess.TimeoutExpired:
            return {"result": "error", "error": "Scan timeout"}
        except Exception as e:
            return {"result": "error", "error": str(e)}

    async def _scan_rules_remote(
        self,
        scan_id: str,
        content_path: str,
        profile_id: str,
        rule_ids: List[str],
        connection_params: Dict[str, Any],
    ) -> Dict[str, Dict[str, Any]]:
        """Scan specific rules on remote host"""
        results = {}

        # For remote scanning, we'll batch rules for efficiency
        # but still provide individual results
        batch_size = 10

        for i in range(0, len(rule_ids), batch_size):
            batch_rules = rule_ids[i : i + batch_size]

            try:
                # Perform batch scan
                batch_results = await self._scan_rule_batch_remote(
                    scan_id, content_path, profile_id, batch_rules, connection_params
                )

                results.update(batch_results)

            except Exception as e:
                # If batch fails, mark all rules in batch as error
                for rule_id in batch_rules:
                    results[rule_id] = {
                        "result": "error",
                        "error": f"Batch scan failed: {str(e)}",
                    }

        return results

    async def _scan_rule_batch_remote(
        self,
        scan_id: str,
        content_path: str,
        profile_id: str,
        rule_ids: List[str],
        connection_params: Dict[str, Any],
    ) -> Dict[str, Dict[str, Any]]:
        """Scan a batch of rules on remote host"""
        try:
            # Use the main scanner for remote execution
            # This will use oscap-ssh or paramiko depending on auth method

            batch_scan_id = f"{scan_id}_batch_{datetime.now().strftime('%H%M%S%f')}"

            # Create a custom command that includes all rules
            # Note: OpenSCAP doesn't support multiple --rule flags,
            # so we need to run separate scans or use a custom profile

            results = {}

            for rule_id in rule_ids:
                result = self.scanner.execute_remote_scan(
                    hostname=connection_params["hostname"],
                    port=connection_params.get("port", 22),
                    username=connection_params["username"],
                    auth_method=connection_params["auth_method"],
                    credential=connection_params["credential"],
                    content_path=content_path,
                    profile_id=profile_id,
                    scan_id=f"{batch_scan_id}_{rule_id.replace(':', '_')}",
                    rule_id=rule_id,
                )

                # Extract rule-specific result
                if "rule_details" in result:
                    for rule_detail in result["rule_details"]:
                        if rule_detail["rule_id"] == rule_id:
                            results[rule_id] = {
                                "result": rule_detail["result"],
                                "title": rule_detail.get("title", ""),
                                "severity": rule_detail.get("severity", "unknown"),
                                "output": result.get("stdout", ""),
                            }
                            break
                else:
                    # Fallback based on exit code
                    results[rule_id] = {
                        "result": "pass" if result.get("exit_code") == 0 else "fail",
                        "output": result.get("stdout", ""),
                    }

            return results

        except Exception as e:
            logger.error(f"Error in remote rule batch scan: {e}")
            raise

    async def _save_scan_results(self, results: Dict[str, Any]) -> None:
        """Save scan results to file"""
        try:
            result_file = self.results_dir / f"{results['scan_id']}.json"

            async with asyncio.Lock():
                with open(result_file, "w") as f:
                    json.dump(results, f, indent=2)

            logger.info(f"Saved scan results to {result_file}")

        except Exception as e:
            logger.error(f"Error saving scan results: {e}")

    async def _load_scan_results(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Load scan results from file"""
        try:
            # Security Fix: Sanitize scan_id to prevent path injection
            sanitized_scan_id = self._sanitize_identifier(scan_id)
            # First try exact match
            result_file = self.results_dir / f"{sanitized_scan_id}.json"

            if not result_file.exists():
                # Try searching in main results directory
                main_results = Path("/app/data/results") / sanitized_scan_id
                if main_results.exists():
                    # Look for results.json in scan directory
                    result_file = main_results / "results.json"

            if result_file.exists():
                with open(result_file, "r") as f:
                    return cast(Dict[str, Any], json.load(f))

            return None

        except Exception as e:
            logger.error(f"Error loading scan results: {e}")
            return None

    def get_rule_remediation_guidance(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Get remediation guidance for a specific rule"""
        try:
            # Get framework mappings
            control = self.framework_mapper.get_unified_control(rule_id)

            if not control:
                return None

            guidance: Dict[str, Any] = {
                "rule_id": rule_id,
                "title": control.title,
                "automated_remediation": control.automated_remediation,
                "aegis_rule_id": control.aegis_rule_id,
                "implementation_guidance": [],
                "assessment_objectives": [],
                "references": [],
            }

            # Collect guidance from all frameworks
            for mapping in control.frameworks:
                guidance["implementation_guidance"].append(
                    {
                        "framework": mapping.framework.value,
                        "guidance": mapping.implementation_guidance,
                    }
                )

                guidance["assessment_objectives"].extend(mapping.assessment_objectives)

                if mapping.related_controls:
                    guidance["references"].extend(
                        [f"{mapping.framework.value}: {ctrl}" for ctrl in mapping.related_controls]
                    )

            # Remove duplicates
            guidance["assessment_objectives"] = list(set(guidance["assessment_objectives"]))
            guidance["references"] = list(set(guidance["references"]))

            return guidance

        except Exception as e:
            logger.error(f"Error getting remediation guidance: {e}")
            return None
