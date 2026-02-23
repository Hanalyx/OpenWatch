"""
Kensa Scanner - OpenWatch Integration

Thin wrapper that registers Kensa with OpenWatch's ScannerFactory.
The actual scanning logic is handled by the Kensa runner package.

This module provides:
    - KensaScanner: BaseScanner implementation for ScannerFactory
    - register_kensa_scanner: Registration function called on startup

Note: Kensa is installed via pip. The runner module is in site-packages.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.services.engine.models import ScannerCapabilities, ScanProvider, ScanType
from app.services.engine.scanners.base import BaseScanner

from .config import KensaConfig, get_kensa_config
from .executor import KensaSessionFactory

logger = logging.getLogger(__name__)


def _get_rules_path() -> str:
    """Get the Kensa rules path using runner.paths discovery."""
    try:
        from runner.paths import get_rules_path

        return str(get_rules_path())
    except ImportError:
        logger.warning("runner.paths not available, falling back to config")
        config = get_kensa_config()
        return config.rules_path or "rules"


class KensaScanner(BaseScanner):
    """
    Kensa compliance scanner - OpenWatch integration wrapper.

    This is a thin wrapper that:
    1. Implements the BaseScanner interface for ScannerFactory
    2. Retrieves credentials from OpenWatch
    3. Delegates actual scanning to the Kensa runner package

    Kensa provides:
    - 338 canonical YAML rules
    - SSH-based check execution
    - Capability-gated implementations
    - Framework mappings (CIS, STIG, NIST)
    """

    def __init__(self, config: Optional[KensaConfig] = None):
        """
        Initialize Kensa scanner wrapper.

        Args:
            config: Optional Kensa configuration.
        """
        super().__init__(name="KensaScanner")
        self.config = config or get_kensa_config()
        self._initialized = False

    async def initialize(self) -> None:
        """
        Initialize the scanner.

        Verifies that the Kensa runner package is available.
        """
        if self._initialized:
            return

        # Check if Kensa runner is available
        try:
            from runner.paths import get_version

            version = get_version()
            logger.info("Kensa runner package found: %s", version)
        except ImportError:
            logger.warning("Kensa runner package not installed. Install with: pip install kensa")

        self._initialized = True
        logger.info("KensaScanner initialized")

    # =========================================================================
    # BaseScanner Interface Implementation
    # =========================================================================

    @property
    def provider(self) -> ScanProvider:
        """Return the scanner's provider type."""
        return ScanProvider.CUSTOM

    @property
    def capabilities(self) -> ScannerCapabilities:
        """Return the scanner's capabilities."""
        return ScannerCapabilities(
            provider=ScanProvider.CUSTOM,
            supported_scan_types=[
                ScanType.COMPLIANCE,
                ScanType.VULNERABILITY,
            ],
            supported_formats=["yaml", "kensa"],
            supports_remote=True,
            supports_local=False,
            max_concurrent=self.config.max_concurrent_checks,
        )

    def validate_content(self, content_path: Path) -> bool:
        """
        Validate Kensa rules content.

        For Kensa, content validation is handled by the runner package.
        This method checks if the runner package is available.
        """
        try:
            from runner.paths import get_version  # noqa: F401

            return True
        except ImportError:
            logger.error("Kensa runner package not installed")
            return False

    def extract_profiles(self, content_path: Path) -> List[Dict[str, Any]]:
        """
        Extract available profiles/frameworks from Kensa.

        Kensa uses frameworks instead of XCCDF profiles.
        """
        return [
            {
                "id": "kensa_all",
                "title": "All Kensa Rules",
                "description": "All 338 canonical Kensa rules",
            },
            {
                "id": "cis-rhel9-v2.0.0",
                "title": "CIS RHEL 9 v2.0.0",
                "description": "CIS Benchmark for RHEL 9 (95.1% coverage)",
            },
            {
                "id": "stig-rhel9-v2r7",
                "title": "STIG RHEL 9 V2R7",
                "description": "DISA STIG for RHEL 9 (75.8% coverage)",
            },
            {
                "id": "nist-800-53",
                "title": "NIST 800-53",
                "description": "NIST 800-53 control mappings",
            },
        ]

    def parse_results(
        self,
        result_path: Path,
        result_format: str = "json",
    ) -> Dict[str, Any]:
        """
        Parse Kensa scan results.

        Kensa produces JSON results directly.
        """
        import json

        try:
            with open(result_path) as f:
                data = json.load(f)

            return {
                "pass_count": data.get("passed", 0),
                "fail_count": data.get("failed", 0),
                "error_count": data.get("errors", 0),
                "findings": data.get("results", []),
                "metadata": {
                    "scanner": "kensa",
                    "version": data.get("kensa_version", "unknown"),
                    "timestamp": data.get("timestamp"),
                },
            }

        except Exception as e:
            logger.error("Failed to parse Kensa results: %s", e)
            return {
                "pass_count": 0,
                "fail_count": 0,
                "error_count": 1,
                "findings": [],
                "metadata": {"error": str(e)},
            }

    def can_handle_content(self, content_path: str) -> bool:
        """Check if this scanner can handle the given content."""
        try:
            from runner.paths import get_version  # noqa: F401

            return True
        except ImportError:
            return False

    # =========================================================================
    # Kensa-Specific Methods
    # =========================================================================

    async def scan(
        self,
        host_id: str,
        db: Any,
        framework: Optional[str] = None,
        rule_ids: Optional[List[str]] = None,
        category: Optional[str] = None,
        severity: Optional[List[str]] = None,
        dry_run: bool = False,
        collect_system_info: bool = False,
        collect_packages: bool = False,
        collect_services: bool = False,
        collect_users: bool = False,
        collect_network: bool = False,
        collect_firewall: bool = False,
        collect_routes: bool = False,
        collect_audit_events: bool = False,
        collect_metrics: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute Kensa compliance scan on target host.

        This method:
        1. Retrieves credentials from OpenWatch
        2. Passes them to Kensa for scanning
        3. Optionally collects system information, packages, services, users, network, audit, metrics
        4. Returns results in OpenWatch format

        Args:
            host_id: OpenWatch host UUID.
            db: Database session for credential lookup.
            framework: Optional framework filter (cis-rhel9-v2.0.0, stig-rhel9-v2r7).
            rule_ids: Optional specific rule IDs to check.
            category: Optional category filter.
            severity: Optional severity filter (list of severity levels).
            dry_run: If True, only show what would be checked.
            collect_system_info: If True, collect system information during scan.
            collect_packages: If True, collect installed packages during scan.
            collect_services: If True, collect running services during scan.
            collect_users: If True, collect user accounts during scan.
            collect_network: If True, collect network interfaces during scan.
            collect_firewall: If True, collect firewall rules during scan.
            collect_routes: If True, collect routing table during scan.
            collect_audit_events: If True, collect security audit events during scan.
            collect_metrics: If True, collect resource metrics during scan.

        Returns:
            Scan results dictionary.
        """
        try:
            from runner.engine import check_rules_from_path
            from runner.paths import get_version

            kensa_version = get_version()

        except ImportError as e:
            logger.error("Kensa runner package not available: %s", e)
            return {
                "status": "error",
                "error": "Kensa runner package not available. Install with: pip install kensa",
            }

        rules_path = _get_rules_path()

        # Get credentials from OpenWatch
        factory = KensaSessionFactory(db)

        try:
            # Use the session factory's context manager for secure key handling
            async with factory.create_session(host_id) as session:
                # Run Kensa check
                results = check_rules_from_path(
                    session,
                    rules_path,
                    severity=severity,
                    category=category,
                )

                # Calculate totals
                total = len(results)
                passed = sum(1 for r in results if r.passed and not r.skipped)
                failed = sum(1 for r in results if not r.passed and not r.skipped)
                skipped = sum(1 for r in results if r.skipped)
                score = (passed / (passed + failed) * 100) if (passed + failed) > 0 else 0.0

                # Get hostname from credentials
                credentials = await factory.get_credentials(host_id)
                hostname = credentials["hostname"]

                # Collect system information if requested
                system_info = None
                packages = None
                services = None
                users = None
                network = None
                firewall = None
                routes = None
                audit_events = None
                metrics = None

                collect_any = (
                    collect_system_info
                    or collect_packages
                    or collect_services
                    or collect_users
                    or collect_network
                    or collect_firewall
                    or collect_routes
                    or collect_audit_events
                    or collect_metrics
                )

                if collect_any:
                    try:
                        from app.services.system_info import SystemInfoCollector

                        # Create a non-sudo session for collection commands
                        async with factory.create_session(host_id, use_sudo=False) as collection_session:
                            collector = SystemInfoCollector(collection_session)

                            if collect_system_info:
                                system_info = collector.collect()
                                logger.debug("Collected system info for host %s", host_id)

                            if collect_packages:
                                packages = collector.collect_packages()
                                logger.debug(
                                    "Collected %d packages for host %s",
                                    len(packages) if packages else 0,
                                    host_id,
                                )

                            if collect_services:
                                services = collector.collect_services()
                                logger.debug(
                                    "Collected %d services for host %s",
                                    len(services) if services else 0,
                                    host_id,
                                )

                            if collect_users:
                                users = collector.collect_users()
                                logger.debug(
                                    "Collected %d users for host %s",
                                    len(users) if users else 0,
                                    host_id,
                                )

                            if collect_network:
                                network = collector.collect_network()
                                logger.debug(
                                    "Collected %d network interfaces for host %s",
                                    len(network) if network else 0,
                                    host_id,
                                )

                            if collect_firewall:
                                firewall = collector.collect_firewall_rules()
                                logger.debug(
                                    "Collected %d firewall rules for host %s",
                                    len(firewall) if firewall else 0,
                                    host_id,
                                )

                        if collect_routes:
                            routes = collector.collect_routes()
                            logger.debug(
                                "Collected %d routes for host %s",
                                len(routes) if routes else 0,
                                host_id,
                            )

                        if collect_audit_events:
                            audit_events = collector.collect_audit_events()
                            logger.debug(
                                "Collected %d audit events for host %s",
                                len(audit_events) if audit_events else 0,
                                host_id,
                            )

                        if collect_metrics:
                            metrics = collector.collect_metrics()
                            logger.debug(
                                "Collected metrics for host %s",
                                host_id,
                            )
                    except Exception as e:
                        logger.warning("Failed to collect server intelligence: %s", e)

                return {
                    "status": "completed",
                    "host_id": host_id,
                    "hostname": hostname,
                    "passed": passed,
                    "failed": failed,
                    "skipped": skipped,
                    "total": total,
                    "compliance_score": score,
                    "results": [
                        {
                            "rule_id": r.rule_id,
                            "title": r.title,
                            "severity": r.severity,
                            "passed": r.passed,
                            "skipped": r.skipped,
                            "skip_reason": r.skip_reason,
                            "detail": r.detail,
                        }
                        for r in results
                    ],
                    "kensa_version": kensa_version,
                    "system_info": system_info,
                    "packages": packages,
                    "services": services,
                    "users": users,
                    "network": network,
                    "firewall": firewall,
                    "routes": routes,
                    "audit_events": audit_events,
                    "metrics": metrics,
                }

        except Exception as e:
            logger.exception("Kensa scan failed: %s", e)
            return {
                "status": "error",
                "host_id": host_id,
                "error": str(e),
            }


# =============================================================================
# Registration
# =============================================================================


def register_kensa_scanner() -> None:
    """
    Register Kensa scanner with the ScannerFactory.

    Call this on application startup to make Kensa available as a scanner type.
    """
    from app.services.engine.scanners import ScannerFactory

    if not ScannerFactory.is_registered("kensa"):
        ScannerFactory.register_scanner("kensa", KensaScanner)
        logger.info("Registered KensaScanner with ScannerFactory")


__all__ = [
    "KensaScanner",
    "register_kensa_scanner",
]
