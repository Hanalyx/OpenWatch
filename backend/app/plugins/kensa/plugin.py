"""
Kensa Plugin Implementation

Implements the OpenWatch plugin interfaces (ScannerPlugin + RemediationPlugin)
for the Kensa compliance engine.

This is the full plugin implementation that can be registered with the
OpenWatch plugin manager for lifecycle management.

Note: Kensa is installed via pip. The runner module is in site-packages.
"""

import logging
from datetime import datetime, timezone
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

from .config import get_kensa_config
from .exceptions import KensaLicenseError
from .executor import KensaSessionFactory

logger = logging.getLogger(__name__)


def _get_rules_path() -> str:
    """Get the Kensa rules path using runner.paths discovery."""
    try:
        from runner.paths import get_rules_path

        return str(get_rules_path())
    except ImportError:
        config = get_kensa_config()
        return config.rules_path or "rules"


class KensaPlugin(ScannerPlugin, RemediationPlugin):
    """
    Kensa compliance plugin for OpenWatch.

    Implements both ScannerPlugin and RemediationPlugin interfaces.
    Delegates actual scanning/remediation to the Kensa runner package.

    Kensa provides:
    - 338 canonical YAML rules
    - SSH-based check execution
    - Capability-gated implementations
    - Framework mappings (CIS, STIG, NIST)
    - Remediation with rollback support

    This plugin provides:
    - OpenWatch plugin lifecycle management
    - Credential bridge to Kensa
    - License validation for remediation
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize Kensa plugin.

        Args:
            config: Optional configuration dictionary.
        """
        super().__init__(config)

        self._kensa_config = get_kensa_config()
        self._initialized = False
        self._runner_available = False

    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return create_plugin_metadata(
            name="Kensa Compliance Engine",
            version="1.1.0",
            description=(
                "SSH-based compliance scanning with 338 canonical YAML rules. "
                "Provides native checks for CIS RHEL 9 (95.1% coverage), "
                "STIG RHEL 9 (75.8% coverage), and NIST 800-53 mappings. "
                "Remediation requires OpenWatch+ subscription."
            ),
            author="Hanalyx",
            plugin_type=PluginType.SCANNER,
            supported_api_version="1.0.0",
            dependencies=["kensa>=1.1.0"],
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

        Verifies Kensa runner package is available.
        """
        if self._initialized:
            return True

        try:
            from runner.paths import get_version

            version = get_version()
            self._runner_available = True
            logger.info("Kensa plugin initialized (kensa v%s)", version)
        except ImportError:
            logger.warning("Kensa runner package not installed. Install with: pip install kensa")
            self._runner_available = False

        self._initialized = True
        return self._runner_available

    async def cleanup(self) -> bool:
        """Cleanup plugin resources."""
        self._initialized = False
        logger.info("Kensa plugin cleaned up")
        return True

    # =========================================================================
    # ScannerPlugin Interface
    # =========================================================================

    async def can_scan_host(self, host_config: Dict[str, Any]) -> bool:
        """
        Check if this plugin can scan the specified host.

        Kensa supports RHEL family distributions.
        """
        if not self._runner_available:
            return False

        platform = host_config.get("platform", "").lower()
        supported = ["rhel", "centos", "fedora", "rocky", "alma"]

        return any(p in platform for p in supported)

    async def execute_scan(self, context: ScanContext) -> ScanResult:
        """
        Execute a scan using the Kensa plugin.

        Uses runner.engine.check_rules_from_path() to run all rules against the host.
        """
        if not self._runner_available:
            return create_scan_result(
                scan_id=context.scan_id,
                hostname=context.target_host,
                status="error",
                timestamp=datetime.now(timezone.utc).isoformat(),
                metadata={"error": "Kensa runner package not installed"},
            )

        start_time = datetime.now(timezone.utc)

        try:
            from runner.engine import check_rules_from_path
            from runner.paths import get_version

            kensa_version = get_version()
            rules_path = _get_rules_path()

            # Get credentials from OpenWatch
            host_id = context.scan_parameters.get("host_id", "")
            db = context.scan_parameters.get("db")

            if not db:
                raise RuntimeError("Database session required for credential lookup")

            factory = KensaSessionFactory(db)

            # Use the session factory's context manager for secure key handling
            async with factory.create_session(host_id) as session:
                # Run Kensa check on all rules
                framework = context.scan_parameters.get("framework")
                severity_filter = context.scan_parameters.get("severity")

                # Check rules from Kensa rules directory
                results = check_rules_from_path(
                    session,
                    rules_path,
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
                        "scanner": "kensa",
                        "version": kensa_version,
                        "duration_ms": duration_ms,
                        "framework": framework,
                        "rules_skipped": skipped,
                    },
                )

        except Exception as e:
            logger.exception("Kensa scan failed: %s", e)
            return create_scan_result(
                scan_id=context.scan_id,
                hostname=context.target_host,
                status="failed",
                timestamp=start_time.isoformat(),
                metadata={"error": str(e)},
            )

    async def validate_content(self, content_path: str) -> bool:
        """Validate content. Kensa uses its bundled rules."""
        return self._runner_available

    def get_supported_profiles(self, content_path: str) -> List[Dict[str, Any]]:
        """Get supported frameworks (Kensa uses frameworks, not profiles)."""
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
        if not self._runner_available:
            return False

        try:
            from runner._loading import load_rules

            rules_path = _get_rules_path()
            rules = load_rules(rules_path)

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
            raise KensaLicenseError(
                feature="remediation",
                detail="Remediation requires OpenWatch+ subscription",
            )

        if not self._runner_available:
            return {
                "status": "error",
                "error": "Kensa runner package not installed",
            }

        try:
            from runner._loading import load_rules
            from runner._orchestration import remediate_rule
            from runner.detect import detect_capabilities

            rules_path = _get_rules_path()

            # Get credentials
            host_id = host_config.get("host_id", "")
            db = host_config.get("db")

            factory = KensaSessionFactory(db)

            async with factory.create_session(host_id) as session:
                # Load the rule
                rules = load_rules(rules_path)
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
                    dry_run=self._kensa_config.dry_run_default,
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
            raise KensaLicenseError(
                feature="remediation",
                detail="Remediation planning requires OpenWatch+ subscription",
            )

        # TODO: Implement remediation planning via Kensa
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
        # TODO: Re-run check via Kensa
        return {"status": "not_implemented", "validated": False}

    # =========================================================================
    # Helper Methods
    # =========================================================================

    async def _check_remediation_license(self) -> bool:
        """Check if remediation is licensed (OpenWatch+)."""
        # TODO: Integrate with OpenWatch license service
        return False
