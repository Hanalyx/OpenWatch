"""
OpenWatch CLI SCAP Scanner Service - Refactored
Enhanced SCAP scanning engine for command-line operations using base scanner architecture
"""

import os
import asyncio
import concurrent.futures
import uuid
import logging
from typing import Dict, List, Optional, AsyncGenerator
from datetime import datetime
from pathlib import Path
import json

from .base_scap_scanner import BaseSCAPScanner, SCAPBaseError
from .scap_scanner_refactored import ScanExecutionError

logger = logging.getLogger(__name__)


class CLIScannerError(SCAPBaseError):
    """Exception raised for CLI scanner specific errors"""

    pass


class SCAPCLIScanner(BaseSCAPScanner):
    """
    Enhanced SCAP scanner optimized for CLI operations and parallel scanning

    This refactored version uses the base scanner architecture to eliminate
    code duplication while providing CLI-specific functionality.
    """

    def __init__(
        self,
        content_dir: str = "/app/data/scap",
        results_dir: str = "/app/data/results",
        max_parallel_scans: int = 100,
    ):
        # Initialize base class
        super().__init__(content_dir, results_dir)

        self.max_parallel_scans = max_parallel_scans

        logger.info(f"CLI SCAP Scanner initialized with max {max_parallel_scans} parallel scans")

    async def scan_single_host(
        self, host_config: Dict, profile_id: str, content_path: str, rule_id: str = None
    ) -> Dict:
        """
        Scan a single host with given configuration

        Args:
            host_config: Host configuration dict with keys: hostname, port, username, auth_method, credential
            profile_id: SCAP profile identifier
            content_path: Path to SCAP content file
            rule_id: Optional specific rule to scan

        Returns:
            Scan results dictionary
        """
        try:
            scan_id = str(uuid.uuid4())

            logger.info(f"Starting scan {scan_id} for {host_config.get('hostname', 'localhost')}")

            # Determine if this is a local or remote scan
            hostname = host_config.get("hostname", "localhost")

            if hostname in ["localhost", "127.0.0.1", "::1"]:
                # Local scan
                return await self._execute_local_scan_async(
                    content_path, profile_id, scan_id, rule_id
                )
            else:
                # Remote scan
                return await self._execute_remote_scan_async(
                    hostname,
                    host_config.get("port", 22),
                    host_config.get("username", "root"),
                    host_config.get("auth_method", "password"),
                    host_config.get("credential", ""),
                    content_path,
                    profile_id,
                    scan_id,
                    rule_id,
                )

        except Exception as e:
            logger.error(f"Scan failed for {host_config.get('hostname', 'unknown')}: {e}")
            return {
                "scan_id": scan_id if "scan_id" in locals() else str(uuid.uuid4()),
                "hostname": host_config.get("hostname", "unknown"),
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            }

    async def scan_multiple_hosts(
        self,
        hosts_configs: List[Dict],
        profile_id: str,
        content_path: str,
        rule_id: str = None,
        progress_callback=None,
    ) -> AsyncGenerator[Dict, None]:
        """
        Scan multiple hosts in parallel with configurable concurrency

        Args:
            hosts_configs: List of host configuration dictionaries
            profile_id: SCAP profile identifier
            content_path: Path to SCAP content file
            rule_id: Optional specific rule to scan
            progress_callback: Optional callback function for progress updates

        Yields:
            Individual scan results as they complete
        """
        try:
            logger.info(f"Starting parallel scan of {len(hosts_configs)} hosts")

            # Create semaphore to limit concurrent scans
            semaphore = asyncio.Semaphore(self.max_parallel_scans)

            async def scan_with_semaphore(host_config):
                async with semaphore:
                    return await self.scan_single_host(
                        host_config, profile_id, content_path, rule_id
                    )

            # Create tasks for all hosts
            tasks = [scan_with_semaphore(host_config) for host_config in hosts_configs]

            # Process results as they complete
            completed = 0
            async for task in asyncio.as_completed(tasks):
                result = await task
                completed += 1

                # Call progress callback if provided
                if progress_callback:
                    progress_callback(
                        {
                            "completed": completed,
                            "total": len(hosts_configs),
                            "progress": (completed / len(hosts_configs)) * 100,
                            "current_result": result,
                        }
                    )

                yield result

        except Exception as e:
            logger.error(f"Multi-host scan failed: {e}")
            # Yield error result
            yield {
                "scan_id": str(uuid.uuid4()),
                "hostname": "batch_scan",
                "status": "error",
                "error": f"Batch scan failed: {str(e)}",
                "timestamp": datetime.now().isoformat(),
            }

    async def _execute_local_scan_async(
        self, content_path: str, profile_id: str, scan_id: str, rule_id: str = None
    ) -> Dict:
        """Execute local scan asynchronously using base class methods"""
        try:
            # Run the synchronous scan in a thread pool
            loop = asyncio.get_event_loop()

            with concurrent.futures.ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self.execute_local_scan,
                    content_path,
                    profile_id,
                    scan_id,
                    rule_id,
                )

            return result

        except Exception as e:
            logger.error(f"Async local scan failed: {e}")
            return {
                "scan_id": scan_id,
                "hostname": "localhost",
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            }

    async def _execute_remote_scan_async(
        self,
        hostname: str,
        port: int,
        username: str,
        auth_method: str,
        credential: str,
        content_path: str,
        profile_id: str,
        scan_id: str,
        rule_id: str = None,
    ) -> Dict:
        """Execute remote scan asynchronously using base class methods"""
        try:
            # Run the synchronous scan in a thread pool
            loop = asyncio.get_event_loop()

            with concurrent.futures.ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self.execute_remote_scan,
                    hostname,
                    port,
                    username,
                    auth_method,
                    credential,
                    content_path,
                    profile_id,
                    scan_id,
                    rule_id,
                )

            return result

        except Exception as e:
            logger.error(f"Async remote scan failed: {e}")
            return {
                "scan_id": scan_id,
                "hostname": hostname,
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            }

    def execute_local_scan(
        self, content_path: str, profile_id: str, scan_id: str, rule_id: str = None
    ) -> Dict:
        """Execute SCAP scan on local system - delegates to base implementation"""
        try:
            logger.info(f"CLI local scan: {scan_id}")

            # Create scan directory and get file paths using base class methods
            scan_dir = self.create_scan_directory(scan_id)
            xml_result, html_report, arf_result = self.get_scan_file_paths(scan_dir)

            # Build command using base class method
            cmd = self.build_oscap_command(
                profile_id, xml_result, html_report, arf_result, content_path, rule_id
            )

            logger.info(f"CLI executing: {' '.join(cmd)}")

            import subprocess

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=1800  # 30 minutes timeout
            )

            # Basic result structure for CLI scanner
            scan_results = {
                "scan_id": scan_id,
                "hostname": "localhost",
                "scan_type": "local_cli",
                "status": "completed" if result.returncode in [0, 2] else "error",
                "exit_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "xml_result": str(xml_result) if xml_result.exists() else None,
                "html_report": str(html_report) if html_report.exists() else None,
                "arf_result": str(arf_result) if arf_result.exists() else None,
                "timestamp": datetime.now().isoformat(),
            }

            # Add basic rule counts if XML exists
            if xml_result.exists():
                try:
                    # Simple XML parsing for rule counts
                    import xml.etree.ElementTree as ET

                    tree = ET.parse(str(xml_result))
                    root = tree.getroot()

                    # Count rules by result type (simplified)
                    rule_results = root.findall(
                        ".//{http://checklists.nist.gov/xccdf/1.2}rule-result"
                    )
                    rules_total = len(rule_results)

                    rules_passed = len(
                        [
                            r
                            for r in rule_results
                            if r.find("{http://checklists.nist.gov/xccdf/1.2}result") is not None
                            and r.find("{http://checklists.nist.gov/xccdf/1.2}result").text
                            == "pass"
                        ]
                    )

                    rules_failed = len(
                        [
                            r
                            for r in rule_results
                            if r.find("{http://checklists.nist.gov/xccdf/1.2}result") is not None
                            and r.find("{http://checklists.nist.gov/xccdf/1.2}result").text
                            == "fail"
                        ]
                    )

                    scan_results.update(
                        {
                            "rules_total": rules_total,
                            "rules_passed": rules_passed,
                            "rules_failed": rules_failed,
                            "score": (rules_passed / max(rules_total, 1)) * 100,
                        }
                    )

                except Exception as e:
                    logger.warning(f"Failed to parse XML results for basic counts: {e}")

            logger.info(f"CLI local scan completed: {scan_id}")
            return scan_results

        except subprocess.TimeoutExpired:
            logger.error(f"CLI scan timeout: {scan_id}")
            raise ScanExecutionError("CLI scan execution timeout")
        except Exception as e:
            logger.error(f"CLI local scan failed: {e}")
            raise ScanExecutionError(f"CLI scan execution failed: {str(e)}")

    def execute_remote_scan(
        self,
        hostname: str,
        port: int,
        username: str,
        auth_method: str,
        credential: str,
        content_path: str,
        profile_id: str,
        scan_id: str,
        rule_id: str = None,
    ) -> Dict:
        """Execute SCAP scan on remote system - uses base class connection management"""
        try:
            logger.info(f"CLI remote scan: {scan_id} on {hostname}")

            # Test connection first using base class method
            connection_test = self.test_ssh_connection(
                hostname, port, username, auth_method, credential
            )
            if not connection_test["success"]:
                raise ScanExecutionError(f"SSH connection failed: {connection_test['message']}")

            # Create scan directory and get file paths using base class methods
            scan_dir = self.create_scan_directory(scan_id)
            xml_result, html_report, arf_result = self.get_scan_file_paths(scan_dir)

            # Use base class connection manager for SSH operations
            ssh = self.connection_manager.create_ssh_client()

            # Connect using base class connection management
            if auth_method == "password":
                ssh.connect(
                    hostname,
                    port=port,
                    username=username,
                    password=credential,
                    timeout=30,
                )
            elif auth_method in ["ssh-key", "ssh_key"]:
                key = self.connection_manager.validate_and_parse_key(credential)
                ssh.connect(hostname, port=port, username=username, pkey=key, timeout=30)
            else:
                raise ScanExecutionError(f"Unsupported auth method: {auth_method}")

            # Execute simplified remote scan
            remote_results_dir = f"/tmp/openwatch_cli_scan_{scan_id}"
            remote_xml = f"{remote_results_dir}/results.xml"

            # Create remote directory and transfer content
            ssh.exec_command(f"mkdir -p {remote_results_dir}")

            sftp = ssh.open_sftp()
            remote_content_path = f"{remote_results_dir}/content.xml"
            sftp.put(content_path, remote_content_path)
            sftp.close()

            # Build and execute command
            cmd = f"oscap xccdf eval --profile {profile_id} --results {remote_xml}"
            if rule_id:
                cmd += f" --rule {rule_id}"
            cmd += f" {remote_content_path}"

            logger.info(f"CLI executing remote command: {cmd}")

            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=1800)
            exit_code = stdout.channel.recv_exit_status()
            stdout_data = stdout.read().decode()
            stderr_data = stderr.read().decode()

            # Download results if available
            try:
                sftp = ssh.open_sftp()
                sftp.get(remote_xml, str(xml_result))
                sftp.close()
            except:
                logger.warning("Could not download remote XML results")

            # Clean up and close connection
            ssh.exec_command(f"rm -rf {remote_results_dir}")
            ssh.close()

            # Build result structure
            scan_results = {
                "scan_id": scan_id,
                "hostname": hostname,
                "scan_type": "remote_cli",
                "status": "completed" if exit_code in [0, 2] else "error",
                "exit_code": exit_code,
                "stdout": stdout_data,
                "stderr": stderr_data,
                "xml_result": str(xml_result) if xml_result.exists() else None,
                "timestamp": datetime.now().isoformat(),
            }

            logger.info(f"CLI remote scan completed: {scan_id}")
            return scan_results

        except Exception as e:
            logger.error(f"CLI remote scan failed: {e}")
            raise ScanExecutionError(f"CLI remote scan execution failed: {str(e)}")

    def generate_scan_report(self, scan_results: List[Dict]) -> Dict:
        """Generate summary report from multiple scan results"""
        try:
            total_scans = len(scan_results)
            successful_scans = len([r for r in scan_results if r.get("status") == "completed"])
            failed_scans = total_scans - successful_scans

            # Aggregate rule statistics
            total_rules = sum(r.get("rules_total", 0) for r in scan_results)
            total_passed = sum(r.get("rules_passed", 0) for r in scan_results)
            total_failed = sum(r.get("rules_failed", 0) for r in scan_results)

            overall_score = (total_passed / max(total_rules, 1)) * 100 if total_rules > 0 else 0

            report = {
                "report_id": str(uuid.uuid4()),
                "generated_at": datetime.now().isoformat(),
                "scan_summary": {
                    "total_hosts": total_scans,
                    "successful_scans": successful_scans,
                    "failed_scans": failed_scans,
                    "success_rate": (successful_scans / max(total_scans, 1)) * 100,
                },
                "compliance_summary": {
                    "total_rules_evaluated": total_rules,
                    "rules_passed": total_passed,
                    "rules_failed": total_failed,
                    "overall_compliance_score": overall_score,
                },
                "detailed_results": scan_results,
            }

            logger.info(f"Generated CLI scan report: {report['report_id']}")
            return report

        except Exception as e:
            logger.error(f"Failed to generate scan report: {e}")
            return {"error": str(e), "generated_at": datetime.now().isoformat()}
