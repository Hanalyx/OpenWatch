"""
OpenWatch CLI SCAP Scanner Service
Enhanced SCAP scanning engine for command-line operations supporting 100+ parallel hosts
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

from .scap_scanner import SCAPScanner, SCAPContentError, ScanExecutionError

logger = logging.getLogger(__name__)


class CLIScannerError(Exception):
    """Exception raised for CLI scanner specific errors"""

    pass


class SCAPCLIScanner:
    """Enhanced SCAP scanner optimized for CLI operations and parallel scanning"""

    def __init__(
        self,
        content_dir: str = "/app/data/scap",
        results_dir: str = "/app/data/results",
        max_parallel_scans: int = 100,
    ):
        self.base_scanner = SCAPScanner(content_dir, results_dir)
        self.content_dir = Path(content_dir)
        self.results_dir = Path(results_dir)
        self.max_parallel_scans = max_parallel_scans

        # Ensure directories exist
        self.content_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)

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
        total_hosts = len(hosts_configs)
        completed_scans = 0

        logger.info(
            f"Starting parallel scan of {total_hosts} hosts (max parallel: {self.max_parallel_scans})"
        )

        # Create semaphore to limit concurrent scans
        semaphore = asyncio.Semaphore(self.max_parallel_scans)

        async def scan_with_semaphore(host_config: Dict) -> Dict:
            async with semaphore:
                return await self.scan_single_host(host_config, profile_id, content_path, rule_id)

        # Create all scan tasks
        scan_tasks = [scan_with_semaphore(host_config) for host_config in hosts_configs]

        # Process results as they complete
        for coro in asyncio.as_completed(scan_tasks):
            result = await coro
            completed_scans += 1

            # Call progress callback if provided
            if progress_callback:
                progress_callback(completed_scans, total_hosts, result)

            # Log progress
            logger.info(f"Scan progress: {completed_scans}/{total_hosts} completed")

            yield result

    async def batch_scan_from_targets(
        self,
        targets: List[str],
        profile_id: str,
        content_path: str,
        rule_id: str = None,
        default_credentials: Dict = None,
    ) -> List[Dict]:
        """
        Perform batch scan from a list of target hostnames/IPs

        Args:
            targets: List of hostnames or IP addresses
            profile_id: SCAP profile identifier
            content_path: Path to SCAP content file
            rule_id: Optional specific rule to scan
            default_credentials: Default SSH credentials to use

        Returns:
            List of all scan results
        """
        # Convert targets to host configs
        hosts_configs = []

        for target in targets:
            host_config = {
                "hostname": target,
                "port": 22,
                "username": (
                    default_credentials.get("username", "root") if default_credentials else "root"
                ),
                "auth_method": (
                    default_credentials.get("auth_method", "password")
                    if default_credentials
                    else "password"
                ),
                "credential": (
                    default_credentials.get("credential", "") if default_credentials else ""
                ),
            }
            hosts_configs.append(host_config)

        # Collect all results
        results = []

        def progress_callback(completed, total, result):
            print(
                f"[OpenWatch] Progress: {completed}/{total} - {result.get('hostname', 'unknown')} completed"
            )

        async for result in self.scan_multiple_hosts(
            hosts_configs, profile_id, content_path, rule_id, progress_callback
        ):
            results.append(result)

        return results

    def get_available_profiles(self, content_path: str) -> List[Dict]:
        """Get available SCAP profiles from content file"""
        try:
            return self.base_scanner.extract_profiles(content_path)
        except Exception as e:
            logger.error(f"Failed to extract profiles: {e}")
            return []

    def validate_content_file(self, content_path: str) -> bool:
        """Validate SCAP content file"""
        try:
            self.base_scanner.validate_scap_content(content_path)
            return True
        except SCAPContentError:
            return False

    def get_default_content_path(self) -> str:
        """Get path to default SCAP content file"""
        # Look for common SCAP content files
        potential_files = [
            self.content_dir / "ssg-rhel8-ds.xml",
            self.content_dir / "ssg-ubuntu2004-ds.xml",
            self.content_dir / "default-content.xml",
            self.content_dir / "scap-content.xml",
        ]

        for file_path in potential_files:
            if file_path.exists():
                logger.info(f"Using default content file: {file_path}")
                return str(file_path)

        # If no content found, log warning
        logger.warning("No default SCAP content file found")
        return str(self.content_dir / "default-content.xml")

    async def _execute_local_scan_async(
        self, content_path: str, profile_id: str, scan_id: str, rule_id: str = None
    ) -> Dict:
        """Execute local scan asynchronously"""
        loop = asyncio.get_event_loop()

        # Run the blocking scan in a thread pool
        with concurrent.futures.ThreadPoolExecutor() as executor:
            result = await loop.run_in_executor(
                executor,
                self.base_scanner.execute_local_scan,
                content_path,
                profile_id,
                scan_id,
                rule_id,
            )

        # Add CLI-specific metadata
        result.update(
            {
                "hostname": "localhost",
                "status": "completed" if result.get("exit_code") == 0 else "failed",
                "cli_scan": True,
            }
        )

        return result

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
        """Execute remote scan asynchronously"""
        loop = asyncio.get_event_loop()

        # Run the blocking scan in a thread pool
        with concurrent.futures.ThreadPoolExecutor() as executor:
            result = await loop.run_in_executor(
                executor,
                self.base_scanner.execute_remote_scan,
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

        # Add CLI-specific metadata
        result.update(
            {
                "hostname": hostname,
                "status": "completed" if result.get("exit_code") == 0 else "failed",
                "cli_scan": True,
            }
        )

        return result

    def generate_scan_summary(self, results: List[Dict]) -> Dict:
        """Generate summary statistics from scan results"""
        if not results:
            return {"error": "No scan results provided"}

        total_hosts = len(results)
        successful_scans = len([r for r in results if r.get("status") == "completed"])
        failed_scans = len([r for r in results if r.get("status") == "failed"])
        error_scans = len([r for r in results if r.get("status") == "error"])

        # Aggregate rule statistics
        total_rules = sum(r.get("rules_total", 0) for r in results if "rules_total" in r)
        total_passed = sum(r.get("rules_passed", 0) for r in results if "rules_passed" in r)
        total_failed = sum(r.get("rules_failed", 0) for r in results if "rules_failed" in r)

        # Calculate average score
        scores = [r.get("score", 0) for r in results if "score" in r and r.get("score") is not None]
        avg_score = sum(scores) / len(scores) if scores else 0

        return {
            "scan_summary": {
                "total_hosts": total_hosts,
                "successful_scans": successful_scans,
                "failed_scans": failed_scans,
                "error_scans": error_scans,
                "success_rate": (successful_scans / total_hosts * 100) if total_hosts > 0 else 0,
            },
            "compliance_summary": {
                "total_rules_checked": total_rules,
                "total_rules_passed": total_passed,
                "total_rules_failed": total_failed,
                "average_compliance_score": avg_score,
                "overall_compliance_rate": (
                    (total_passed / total_rules * 100) if total_rules > 0 else 0
                ),
            },
            "timestamp": datetime.now().isoformat(),
        }

    def export_results_json(self, results: List[Dict], output_file: str) -> bool:
        """Export scan results to JSON file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Include summary in export
            export_data = {
                "scan_results": results,
                "summary": self.generate_scan_summary(results),
                "exported_at": datetime.now().isoformat(),
                "total_scans": len(results),
            }

            with open(output_path, "w") as f:
                json.dump(export_data, f, indent=2)

            logger.info(f"Scan results exported to: {output_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to export results: {e}")
            return False
