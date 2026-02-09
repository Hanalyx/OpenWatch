"""
Aegis Plugin Implementation

Implements the OpenWatch plugin interfaces (ScannerPlugin + RemediationPlugin)
for the Aegis compliance engine.

This is the full plugin implementation that can be registered with the
OpenWatch plugin manager for lifecycle management.

Note: This requires the aegis package (backend/aegis/) to be available.
"""

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.plugins.interface import (
    PluginMetadata,
    PluginType,
    RemediationPlugin,
    ScanContext,
    ScannerPlugin,
    ScanResult,
    create_plugin_metadata,
    create_scan_result,
)

from .config import get_aegis_config
from .exceptions import AegisLicenseError
from .executor import AegisSessionFactory

logger = logging.getLogger(__name__)

# Path to Aegis rules directory (relative to backend/)
# __file__ = backend/app/plugins/aegis/plugin.py
# .parent x4 = backend/
# + aegis/rules = backend/aegis/rules
AEGIS_RULES_PATH = Path(__file__).parent.parent.parent.parent / "aegis" / "rules"


class AegisPlugin(ScannerPlugin, RemediationPlugin):
    """
    Aegis compliance plugin for OpenWatch.

    Implements both ScannerPlugin and RemediationPlugin interfaces.
    Delegates actual scanning/remediation to the aegis package.

    The aegis package provides:
    - 338 canonical YAML rules
    - SSH-based check execution
    - Capability-gated implementations
    - Framework mappings (CIS, STIG, NIST)
    - Remediation with rollback support

    This plugin provides:
    - OpenWatch plugin lifecycle management
    - Credential bridge to aegis
    - License validation for remediation
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize Aegis plugin.

        Args:
            config: Optional configuration dictionary.
        """
        super().__init__(config)

        self._aegis_config = get_aegis_config()
        self._initialized = False
        self._aegis_available = False

    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return create_plugin_metadata(
            name="Aegis Compliance Engine",
            version="1.0.0",
            description=(
                "SSH-based compliance scanning with 338 canonical YAML rules. "
                "Provides native checks for CIS RHEL 9 (95.1% coverage), "
                "STIG RHEL 9 (75.8% coverage), and NIST 800-53 mappings. "
                "Remediation requires OpenWatch+ subscription."
            ),
            author="Hanalyx",
            plugin_type=PluginType.SCANNER,
            supported_api_version="1.0.0",
            dependencies=["aegis>=0.1.0"],
            config_schema={
                "type": "object",
                "properties": {
                    "max_concurrent_checks": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 50,
                        "default": 10,
                    },
                    "check_timeout": {
                        "type": "integer",
                        "minimum": 5,
                        "maximum": 300,
                        "default": 60,
                    },
                },
            },
        )

    async def initialize(self) -> bool:
        """
        Initialize the plugin.

        Verifies aegis package is available.
        """
        if self._initialized:
            return True

        try:
            import aegis

            self._aegis_available = True
            logger.info("Aegis plugin initialized (aegis v%s)", getattr(aegis, "__version__", "unknown"))
        except ImportError:
            logger.warning("Aegis package not installed. Install with: pip install aegis")
            self._aegis_available = False

        self._initialized = True
        return self._aegis_available

    async def cleanup(self) -> bool:
        """Cleanup plugin resources."""
        self._initialized = False
        logger.info("Aegis plugin cleaned up")
        return True

    # =========================================================================
    # ScannerPlugin Interface
    # =========================================================================

    async def can_scan_host(self, host_config: Dict[str, Any]) -> bool:
        """
        Check if this plugin can scan the specified host.

        Aegis supports RHEL family distributions.
        """
        if not self._aegis_available:
            return False

        platform = host_config.get("platform", "").lower()
        supported = ["rhel", "centos", "fedora", "rocky", "alma"]

        return any(p in platform for p in supported)

    async def execute_scan(self, context: ScanContext) -> ScanResult:
        """
        Execute a scan using the Aegis plugin.

        Uses aegis.check_rules_from_path() to run all rules against the host.
        """
        if not self._aegis_available:
            return create_scan_result(
                scan_id=context.scan_id,
                hostname=context.target_host,
                status="error",
                timestamp=datetime.now(timezone.utc).isoformat(),
                metadata={"error": "Aegis package not installed"},
            )

        start_time = datetime.now(timezone.utc)

        try:
            from aegis import __version__ as aegis_version
            from aegis import check_rules_from_path

            # Get credentials from OpenWatch
            host_id = context.scan_parameters.get("host_id", "")
            db = context.scan_parameters.get("db")

            if not db:
                raise RuntimeError("Database session required for credential lookup")

            factory = AegisSessionFactory(db)

            # Use the session factory's context manager for secure key handling
            async with factory.create_session(host_id) as session:
                # Run Aegis check on all rules
                framework = context.scan_parameters.get("framework")
                severity_filter = context.scan_parameters.get("severity")

                # Check rules from Aegis rules directory
                results = check_rules_from_path(
                    session,
                    str(AEGIS_RULES_PATH),
                    severity=severity_filter,
                )

                end_time = datetime.now(timezone.utc)
                duration_ms = int((end_time - start_time).total_seconds() * 1000)

                # Calculate totals
                total = len(results)
                passed = sum(1 for r in results if r.passed and not r.skipped)
                failed = sum(1 for r in results if not r.passed and not r.skipped)
                skipped = sum(1 for r in results if r.skipped)
                score = (passed / (passed + failed) * 100) if (passed + failed) > 0 else 0.0

                # Get hostname from credentials
                credentials = await factory.get_credentials(host_id)
                hostname = credentials["hostname"]

                return create_scan_result(
                    scan_id=context.scan_id,
                    hostname=hostname,
                    status="completed",
                    timestamp=start_time.isoformat(),
                    rules_total=total,
                    rules_passed=passed,
                    rules_failed=failed,
                    rules_error=skipped,
                    score=score,
                    failed_rules=[
                        {
                            "rule_id": r.rule_id,
                            "title": r.title,
                            "severity": r.severity,
                            "detail": r.detail,
                        }
                        for r in results
                        if not r.passed and not r.skipped
                    ],
                    metadata={
                        "scanner": "aegis",
                        "version": aegis_version,
                        "duration_ms": duration_ms,
                        "framework": framework,
                        "rules_skipped": skipped,
                    },
                )

        except Exception as e:
            logger.exception("Aegis scan failed: %s", e)
            return create_scan_result(
                scan_id=context.scan_id,
                hostname=context.target_host,
                status="failed",
                timestamp=start_time.isoformat(),
                metadata={"error": str(e)},
            )

    async def validate_content(self, content_path: str) -> bool:
        """Validate content. Aegis uses its bundled rules."""
        return self._aegis_available

    def get_supported_profiles(self, content_path: str) -> List[Dict[str, Any]]:
        """Get supported frameworks (Aegis uses frameworks, not profiles)."""
        return [
            {
                "id": "cis-rhel9-v2.0.0",
                "title": "CIS RHEL 9 v2.0.0",
                "description": "95.1% coverage (271/285 controls)",
            },
            {
                "id": "stig-rhel9-v2r7",
                "title": "STIG RHEL 9 V2R7",
                "description": "75.8% coverage (338/446 controls)",
            },
            {
                "id": "nist-800-53",
                "title": "NIST 800-53",
                "description": "NIST 800-53 control mappings",
            },
        ]

    # =========================================================================
    # RemediationPlugin Interface
    # =========================================================================

    async def can_remediate_rule(
        self,
        rule_id: str,
        host_config: Dict[str, Any],
    ) -> bool:
        """Check if remediation is available for rule."""
        if not self._aegis_available:
            return False

        try:
            from aegis import load_rules

            # Load the specific rule and check if it has remediation steps
            rule_path = AEGIS_RULES_PATH
            rules = load_rules(str(rule_path))

            for rule in rules:
                if rule.get("id") == rule_id:
                    return bool(rule.get("remediation"))
            return False
        except Exception:
            return False

    async def execute_remediation(
        self,
        rule_id: str,
        host_config: Dict[str, Any],
        scan_result: ScanResult,
    ) -> Dict[str, Any]:
        """
        Execute remediation. Requires OpenWatch+ license.
        """
        if not await self._check_remediation_license():
            raise AegisLicenseError(
                feature="remediation",
                detail="Remediation requires OpenWatch+ subscription",
            )

        if not self._aegis_available:
            return {
                "status": "error",
                "error": "Aegis package not installed",
            }

        try:
            from aegis import detect_capabilities, load_rules, remediate_rule

            # Get credentials
            host_id = host_config.get("host_id", "")
            db = host_config.get("db")

            factory = AegisSessionFactory(db)

            async with factory.create_session(host_id) as session:
                # Load the rule
                rules = load_rules(str(AEGIS_RULES_PATH))
                target_rule = None
                for rule in rules:
                    if rule.get("id") == rule_id:
                        target_rule = rule
                        break

                if not target_rule:
                    return {
                        "status": "error",
                        "rule_id": rule_id,
                        "error": f"Rule not found: {rule_id}",
                    }

                # Detect capabilities
                capabilities = detect_capabilities(session)

                # Run remediation
                result = remediate_rule(
                    session,
                    target_rule,
                    capabilities,
                    dry_run=self._aegis_config.dry_run_default,
                )

                return {
                    "status": "completed" if result.remediated else "failed",
                    "rule_id": rule_id,
                    "remediated": result.remediated,
                    "detail": result.remediation_detail,
                    "rolled_back": result.rolled_back,
                }

        except Exception as e:
            logger.exception("Remediation failed: %s", e)
            return {
                "status": "error",
                "rule_id": rule_id,
                "error": str(e),
            }

    async def get_remediation_plan(
        self,
        failed_rules: List[str],
        host_config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Get remediation plan. Requires OpenWatch+ license."""
        if not await self._check_remediation_license():
            raise AegisLicenseError(
                feature="remediation",
                detail="Remediation planning requires OpenWatch+ subscription",
            )

        # TODO: Implement remediation planning via aegis
        return {
            "status": "not_implemented",
            "rules": failed_rules,
        }

    def validate_remediation(
        self,
        rule_id: str,
        host_config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Validate remediation was successful."""
        # TODO: Re-run check via aegis
        return {"status": "not_implemented", "validated": False}

    # =========================================================================
    # Helper Methods
    # =========================================================================

    async def _check_remediation_license(self) -> bool:
        """Check if remediation is licensed (OpenWatch+)."""
        # TODO: Integrate with OpenWatch license service
        return False
