"""
Aegis Scanner - OpenWatch Integration

Thin wrapper that registers Aegis with OpenWatch's ScannerFactory.
The actual scanning logic is handled by the aegis package.

This module provides:
    - AegisScanner: BaseScanner implementation for ScannerFactory
    - register_aegis_scanner: Registration function called on startup

Note: This requires the aegis package (backend/aegis/) to be available.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.services.engine.models import ScannerCapabilities, ScanProvider, ScanType
from app.services.engine.scanners.base import BaseScanner

from .config import AegisConfig, get_aegis_config
from .executor import AegisSessionFactory

logger = logging.getLogger(__name__)

# Path to Aegis rules directory (relative to backend/)
# __file__ = backend/app/plugins/aegis/scanner.py
# .parent x4 = backend/
# + aegis/rules = backend/aegis/rules
AEGIS_RULES_PATH = Path(__file__).parent.parent.parent.parent / "aegis" / "rules"


class AegisScanner(BaseScanner):
    """
    Aegis compliance scanner - OpenWatch integration wrapper.

    This is a thin wrapper that:
    1. Implements the BaseScanner interface for ScannerFactory
    2. Retrieves credentials from OpenWatch
    3. Delegates actual scanning to the aegis package

    The aegis package provides:
    - 338 canonical YAML rules
    - SSH-based check execution
    - Capability-gated implementations
    - Framework mappings (CIS, STIG, NIST)
    """

    def __init__(self, config: Optional[AegisConfig] = None):
        """
        Initialize Aegis scanner wrapper.

        Args:
            config: Optional Aegis configuration.
        """
        super().__init__(name="AegisScanner")
        self.config = config or get_aegis_config()
        self._initialized = False

    async def initialize(self) -> None:
        """
        Initialize the scanner.

        Verifies that the aegis package is available.
        """
        if self._initialized:
            return

        # Check if aegis package is available
        try:
            import aegis  # noqa: F401

            logger.info("Aegis package found: %s", getattr(aegis, "__version__", "unknown"))
        except ImportError:
            logger.warning("Aegis package not installed. Install with: pip install aegis")

        self._initialized = True
        logger.info("AegisScanner initialized")

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
            supported_formats=["yaml", "aegis"],
            supports_remote=True,
            supports_local=False,
            max_concurrent=self.config.max_concurrent_checks,
        )

    def validate_content(self, content_path: Path) -> bool:
        """
        Validate Aegis rules content.

        For Aegis, content validation is handled by the aegis package.
        This method checks if the aegis package is available.
        """
        try:
            import aegis  # noqa: F401

            return True
        except ImportError:
            logger.error("Aegis package not installed")
            return False

    def extract_profiles(self, content_path: Path) -> List[Dict[str, Any]]:
        """
        Extract available profiles/frameworks from Aegis.

        Aegis uses frameworks instead of XCCDF profiles.
        """
        return [
            {
                "id": "aegis_all",
                "title": "All Aegis Rules",
                "description": "All 338 canonical Aegis rules",
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
        Parse Aegis scan results.

        Aegis produces JSON results directly.
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
                    "scanner": "aegis",
                    "version": data.get("aegis_version", "unknown"),
                    "timestamp": data.get("timestamp"),
                },
            }

        except Exception as e:
            logger.error("Failed to parse Aegis results: %s", e)
            return {
                "pass_count": 0,
                "fail_count": 0,
                "error_count": 1,
                "findings": [],
                "metadata": {"error": str(e)},
            }

    def can_handle_content(self, content_path: str) -> bool:
        """Check if this scanner can handle the given content."""
        # Aegis handles its own rules from the aegis package
        try:
            import aegis  # noqa: F401

            return True
        except ImportError:
            return False

    # =========================================================================
    # Aegis-Specific Methods
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
    ) -> Dict[str, Any]:
        """
        Execute Aegis compliance scan on target host.

        This method:
        1. Retrieves credentials from OpenWatch
        2. Passes them to Aegis for scanning
        3. Optionally collects system information, packages, services, users, and network
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

        Returns:
            Scan results dictionary.
        """
        try:
            from aegis import __version__ as aegis_version
            from aegis import check_rules_from_path

        except ImportError as e:
            logger.error("Aegis package not available: %s", e)
            return {
                "status": "error",
                "error": "Aegis package not available. Check backend/aegis/ directory.",
            }

        # Get credentials from OpenWatch
        factory = AegisSessionFactory(db)

        try:
            # Use the session factory's context manager for secure key handling
            async with factory.create_session(host_id) as session:
                # Run Aegis check
                results = check_rules_from_path(
                    session,
                    str(AEGIS_RULES_PATH),
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

                collect_any = (
                    collect_system_info
                    or collect_packages
                    or collect_services
                    or collect_users
                    or collect_network
                    or collect_firewall
                    or collect_routes
                )

                if collect_any:
                    try:
                        from app.services.system_info import SystemInfoCollector

                        # Create a non-sudo session for collection commands
                        # Most collection commands don't need sudo and work better without it
                        # (especially on Ubuntu where passwordless sudo may not be configured)
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
                    "aegis_version": aegis_version,
                    "system_info": system_info,
                    "packages": packages,
                    "services": services,
                    "users": users,
                    "network": network,
                    "firewall": firewall,
                    "routes": routes,
                }

        except Exception as e:
            logger.exception("Aegis scan failed: %s", e)
            return {
                "status": "error",
                "host_id": host_id,
                "error": str(e),
            }


# =============================================================================
# Registration
# =============================================================================


def register_aegis_scanner() -> None:
    """
    Register Aegis scanner with the ScannerFactory.

    Call this on application startup to make Aegis available as a scanner type.
    """
    from app.services.engine.scanners import ScannerFactory

    if not ScannerFactory.is_registered("aegis"):
        ScannerFactory.register_scanner("aegis", AegisScanner)
        logger.info("Registered AegisScanner with ScannerFactory")


__all__ = [
    "AegisScanner",
    "register_aegis_scanner",
]
