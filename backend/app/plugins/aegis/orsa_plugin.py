"""
Aegis ORSA Plugin Implementation

ORSA v2.0 compliant wrapper for the Aegis compliance engine.

This module provides:
- AegisORSAPlugin: Full ORSAPlugin implementation
- Automatic registration with ORSAPluginRegistry

Usage:
    from app.plugins.aegis.orsa_plugin import AegisORSAPlugin

    # Create and register
    plugin = AegisORSAPlugin()
    registry = ORSAPluginRegistry.instance()
    await registry.register(plugin)

    # Execute scans
    results = await plugin.check(host_id="...")

Features:
- Compliance checking (always available)
- Remediation (requires OpenWatch+ license)
- Rollback (requires OpenWatch+ license)
- Framework mappings (CIS, STIG, NIST)
"""

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.services.licensing import LicenseRequiredError, requires_license
from app.services.plugins.orsa import (
    CanonicalRule,
    Capability,
    CheckResult,
    HostCapabilities,
    HostMetadata,
    ORSAPlugin,
    ORSAPluginRegistry,
    PluginInfo,
    RemediationResult,
    RemediationStepResult,
    RollbackResult,
)

from .config import get_aegis_config
from .executor import AegisSessionFactory

logger = logging.getLogger(__name__)

# Path to Aegis rules directory
AEGIS_RULES_PATH = Path(__file__).parent.parent.parent.parent / "aegis" / "rules"

# Aegis version from the package
try:
    from aegis import __version__ as AEGIS_VERSION
except ImportError:
    AEGIS_VERSION = "0.1.0"


class AegisORSAPlugin(ORSAPlugin):
    """
    Aegis compliance plugin implementing ORSA v2.0 interface.

    This plugin provides:
    - 338 canonical YAML compliance rules
    - SSH-based check execution
    - Capability-gated implementations
    - Framework mappings (CIS, STIG, NIST)
    - Remediation with rollback support (OpenWatch+ only)

    Free Tier:
        - check(): Execute compliance scans
        - get_rules(): Browse available rules
        - detect_capabilities(): Detect host capabilities
        - get_framework_mappings(): Query framework coverage

    OpenWatch+ (Licensed):
        - remediate(): Execute automated remediation
        - rollback(): Rollback previous remediations
    """

    PLUGIN_ID = "aegis"
    PLUGIN_NAME = "Aegis Compliance Engine"
    PLUGIN_VERSION = AEGIS_VERSION
    PLUGIN_VENDOR = "Hanalyx"

    def __init__(self, db: Optional[Any] = None) -> None:
        """
        Initialize Aegis ORSA plugin.

        Args:
            db: Optional database session. Required for scanning.
        """
        self._db = db
        self._config = get_aegis_config()
        self._aegis_available = False
        self._rules_cache: Optional[List[Dict[str, Any]]] = None

        # Check if Aegis is available
        try:
            import aegis  # noqa: F401

            self._aegis_available = True
        except ImportError:
            logger.warning("Aegis package not available")

    # =========================================================================
    # Required ORSAPlugin Methods
    # =========================================================================

    async def get_info(self) -> PluginInfo:
        """Return plugin metadata and capabilities."""
        return PluginInfo(
            plugin_id=self.PLUGIN_ID,
            name=self.PLUGIN_NAME,
            version=self.PLUGIN_VERSION,
            description=(
                "SSH-based compliance scanning with 338 canonical YAML rules. "
                "Provides native checks for CIS RHEL 9 (95.1% coverage), "
                "STIG RHEL 9 (75.8% coverage), and NIST 800-53 mappings. "
                "Remediation requires OpenWatch+ subscription."
            ),
            vendor=self.PLUGIN_VENDOR,
            capabilities=[
                Capability.COMPLIANCE_CHECK,
                Capability.REMEDIATION,
                Capability.ROLLBACK,
                Capability.CAPABILITY_DETECTION,
                Capability.DRY_RUN,
                Capability.PARALLEL_EXECUTION,
                Capability.FRAMEWORK_MAPPING,
            ],
            supported_platforms=["rhel8", "rhel9", "centos8", "rocky8", "rocky9", "alma8", "alma9"],
            supported_frameworks=["cis", "stig", "nist_800_53", "pci_dss", "srg"],
            documentation_url="https://github.com/Hanalyx/aegis",
            license_type="open_source",
            requires_license=True,  # Remediation requires OpenWatch+
            orsa_version="2.0.0",
        )

    async def get_capabilities(self) -> List[Capability]:
        """Return list of plugin capabilities."""
        return [
            Capability.COMPLIANCE_CHECK,
            Capability.REMEDIATION,
            Capability.ROLLBACK,
            Capability.CAPABILITY_DETECTION,
            Capability.DRY_RUN,
            Capability.PARALLEL_EXECUTION,
            Capability.FRAMEWORK_MAPPING,
        ]

    async def get_rules(
        self,
        platform: Optional[str] = None,
        framework: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> List[CanonicalRule]:
        """
        Get available compliance rules.

        Args:
            platform: Filter by platform (rhel8, rhel9, etc.)
            framework: Filter by framework (cis, stig, nist_800_53)
            category: Filter by category (access-control, audit, etc.)
            severity: Filter by severity (critical, high, medium, low)
            tags: Filter by tags

        Returns:
            List of CanonicalRule matching filters.
        """
        if not self._aegis_available:
            return []

        # Load rules from Aegis
        rules = await self._load_rules()

        # Apply filters
        filtered = []
        for rule_dict in rules:
            # Platform filter
            if platform:
                platforms = rule_dict.get("platforms", [])
                platform_match = any(p.get("family", "").lower() in platform.lower() for p in platforms)
                if not platform_match:
                    continue

            # Category filter
            if category and rule_dict.get("category", "").lower() != category.lower():
                continue

            # Severity filter
            if severity and rule_dict.get("severity", "").lower() != severity.lower():
                continue

            # Framework filter
            if framework:
                refs = rule_dict.get("framework_refs", {})
                if framework.lower() not in [k.lower() for k in refs.keys()]:
                    continue

            # Tags filter
            if tags:
                rule_tags = rule_dict.get("tags", [])
                if not any(t in rule_tags for t in tags):
                    continue

            # Convert to CanonicalRule
            filtered.append(
                CanonicalRule(
                    id=rule_dict.get("id", ""),
                    title=rule_dict.get("title", ""),
                    description=rule_dict.get("description", ""),
                    rationale=rule_dict.get("rationale", ""),
                    severity=rule_dict.get("severity", "medium"),
                    category=rule_dict.get("category", ""),
                    tags=rule_dict.get("tags", []),
                    references=rule_dict.get("framework_refs", {}),
                    platforms=rule_dict.get("platforms", []),
                    implementations=rule_dict.get("implementations", []),
                    depends_on=rule_dict.get("depends_on", []),
                    conflicts_with=rule_dict.get("conflicts_with", []),
                )
            )

        return filtered

    async def detect_capabilities(self, host_id: str) -> HostCapabilities:
        """
        Detect capabilities of target host.

        Args:
            host_id: OpenWatch host ID

        Returns:
            HostCapabilities with detected platform and capabilities.
        """
        if not self._aegis_available or not self._db:
            return HostCapabilities(
                platform_family="unknown",
                platform_version="unknown",
                capabilities=[],
            )

        try:
            from aegis import detect_capabilities

            factory = AegisSessionFactory(self._db)

            async with factory.create_session(host_id) as session:
                caps = detect_capabilities(session)

                return HostCapabilities(
                    platform_family=caps.platform_family,
                    platform_version=caps.platform_version,
                    capabilities=caps.capabilities,
                    detected_at=datetime.now(timezone.utc),
                )

        except Exception as e:
            logger.exception("Failed to detect capabilities for host %s: %s", host_id, e)
            return HostCapabilities(
                platform_family="unknown",
                platform_version="unknown",
                capabilities=[],
            )

    async def check(
        self,
        host_id: str,
        rule_ids: Optional[List[str]] = None,
        framework: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[CheckResult]:
        """
        Execute compliance checks on target host.

        This is the core scanning functionality. Always available without license.

        Args:
            host_id: OpenWatch host ID
            rule_ids: Specific rules to check (optional)
            framework: Filter rules by framework
            category: Filter rules by category
            severity: Filter rules by minimum severity

        Returns:
            List of CheckResult for each evaluated rule.
        """
        if not self._aegis_available:
            return [
                CheckResult(
                    rule_id="aegis.error",
                    title="Aegis Not Available",
                    severity="critical",
                    category="system",
                    passed=False,
                    detail="Aegis package not installed",
                )
            ]

        if not self._db:
            return [
                CheckResult(
                    rule_id="aegis.error",
                    title="Database Session Required",
                    severity="critical",
                    category="system",
                    passed=False,
                    detail="Database session not provided to plugin",
                )
            ]

        try:
            from aegis import check_rules_from_path

            factory = AegisSessionFactory(self._db)

            # Get credentials to build HostMetadata
            credentials = await factory.get_credentials(host_id)

            async with factory.create_session(host_id) as session:
                # Execute Aegis checks
                results = check_rules_from_path(
                    session,
                    str(AEGIS_RULES_PATH),
                    severity=[severity] if severity else None,
                    category=category,
                )

                # Convert to CheckResult
                check_results = []
                for r in results:
                    # Filter by rule_ids if specified
                    if rule_ids and r.rule_id not in rule_ids:
                        continue

                    check_results.append(
                        CheckResult(
                            rule_id=r.rule_id,
                            title=r.title,
                            severity=r.severity,
                            category=getattr(r, "category", "unknown"),
                            passed=r.passed,
                            detail=r.detail,
                            actual_value=getattr(r, "actual_value", None),
                            expected_value=getattr(r, "expected_value", None),
                            implementation_used=getattr(r, "implementation_used", None),
                            check_method=getattr(r, "check_method", None),
                            check_duration_ms=getattr(r, "check_duration_ms", None),
                            framework_refs=getattr(r, "framework_refs", {}),
                            host_metadata=HostMetadata(
                                hostname=credentials["hostname"],
                                platform_family="rhel",  # TODO: Get from detection
                                platform_version="9",  # TODO: Get from detection
                            ),
                        )
                    )

                logger.info(
                    "Aegis check completed for host %s: %d passed, %d failed",
                    host_id,
                    sum(1 for r in check_results if r.passed),
                    sum(1 for r in check_results if not r.passed),
                )

                return check_results

        except Exception as e:
            logger.exception("Aegis check failed for host %s: %s", host_id, e)
            return [
                CheckResult(
                    rule_id="aegis.error",
                    title="Scan Failed",
                    severity="critical",
                    category="system",
                    passed=False,
                    detail=str(e),
                )
            ]

    @requires_license("remediation")
    async def remediate(
        self,
        host_id: str,
        rule_ids: List[str],
        dry_run: bool = True,
        framework: Optional[str] = None,
    ) -> List[RemediationResult]:
        """
        Execute remediation on target host.

        Requires OpenWatch+ license.

        Args:
            host_id: OpenWatch host ID
            rule_ids: Rules to remediate
            dry_run: If True, simulate without making changes
            framework: Framework context

        Returns:
            List of RemediationResult for each rule.
        """
        if not self._aegis_available:
            raise RuntimeError("Aegis package not available")

        if not self._db:
            raise RuntimeError("Database session not provided")

        try:
            from aegis import detect_capabilities, load_rules, remediate_rule

            factory = AegisSessionFactory(self._db)

            async with factory.create_session(host_id) as session:
                # Load rules
                rules = load_rules(str(AEGIS_RULES_PATH))

                # Detect host capabilities
                capabilities = detect_capabilities(session)

                results = []
                for rule_id in rule_ids:
                    # Find the rule
                    target_rule = None
                    for rule in rules:
                        if rule.get("id") == rule_id:
                            target_rule = rule
                            break

                    if not target_rule:
                        results.append(
                            RemediationResult(
                                rule_id=rule_id,
                                title="Unknown",
                                severity="unknown",
                                success=False,
                                changes_made=False,
                                detail=f"Rule not found: {rule_id}",
                                dry_run=dry_run,
                            )
                        )
                        continue

                    # Execute remediation
                    try:
                        result = remediate_rule(
                            session,
                            target_rule,
                            capabilities,
                            dry_run=dry_run,
                        )

                        results.append(
                            RemediationResult(
                                rule_id=rule_id,
                                title=target_rule.get("title", ""),
                                severity=target_rule.get("severity", "medium"),
                                success=result.remediated,
                                changes_made=result.changes_made,
                                detail=result.remediation_detail,
                                step_results=(
                                    [
                                        RemediationStepResult(
                                            step_index=i,
                                            mechanism=step.get("mechanism", "unknown"),
                                            success=step.get("success", False),
                                            detail=step.get("detail", ""),
                                            pre_state=step.get("pre_state"),
                                            post_state=step.get("post_state"),
                                            verified=step.get("verified", False),
                                        )
                                        for i, step in enumerate(result.steps)
                                    ]
                                    if hasattr(result, "steps")
                                    else []
                                ),
                                rollback_available=result.rolled_back is not None,
                                rollback_data=result.rollback_data if hasattr(result, "rollback_data") else None,
                                dry_run=dry_run,
                                reboot_required=result.reboot_required if hasattr(result, "reboot_required") else False,
                            )
                        )

                    except Exception as e:
                        logger.exception("Remediation failed for rule %s: %s", rule_id, e)
                        results.append(
                            RemediationResult(
                                rule_id=rule_id,
                                title=target_rule.get("title", ""),
                                severity=target_rule.get("severity", "medium"),
                                success=False,
                                changes_made=False,
                                detail=str(e),
                                dry_run=dry_run,
                            )
                        )

                return results

        except LicenseRequiredError:
            raise
        except Exception as e:
            logger.exception("Remediation failed for host %s: %s", host_id, e)
            raise

    @requires_license("remediation")
    async def rollback(
        self,
        host_id: str,
        job_id: str,
    ) -> RollbackResult:
        """
        Rollback a previous remediation job.

        Requires OpenWatch+ license.

        Args:
            host_id: OpenWatch host ID
            job_id: Remediation job ID to rollback

        Returns:
            RollbackResult with rollback status.
        """
        # TODO: Implement rollback via Aegis
        # This requires storing rollback data from remediation jobs

        return RollbackResult(
            job_id=job_id,
            success=False,
            detail="Rollback not yet implemented",
            rule_results=[],
        )

    # =========================================================================
    # Optional ORSAPlugin Methods
    # =========================================================================

    async def health_check(self) -> Dict[str, Any]:
        """Check plugin health status."""
        return {
            "healthy": self._aegis_available,
            "message": "Aegis package available" if self._aegis_available else "Aegis package not installed",
            "version": self.PLUGIN_VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    async def get_framework_mappings(
        self,
        framework: str,
        version: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Get framework mapping data."""
        # Query from PostgreSQL aegis_rules and framework_mappings tables
        if not self._db:
            return None

        try:
            from sqlalchemy import text

            # Get mapping counts
            query = text(
                """
                SELECT
                    COUNT(DISTINCT rule_id) as rule_count,
                    COUNT(*) as mapping_count
                FROM framework_mappings
                WHERE framework = :framework
            """
            )
            result = self._db.execute(query, {"framework": framework}).fetchone()

            if not result:
                return None

            return {
                "framework": framework,
                "version": version,
                "rule_count": result.rule_count,
                "mapping_count": result.mapping_count,
            }

        except Exception as e:
            logger.exception("Failed to get framework mappings: %s", e)
            return None

    async def validate_rules(self) -> Dict[str, Any]:
        """Validate all rules against schema."""
        if not self._aegis_available:
            return {"valid": False, "errors": ["Aegis package not installed"]}

        try:
            from aegis import load_rules

            rules = load_rules(str(AEGIS_RULES_PATH))

            errors = []
            for rule in rules:
                if not rule.get("id"):
                    errors.append(f"Rule missing id: {rule}")
                if not rule.get("title"):
                    errors.append(f"Rule {rule.get('id')} missing title")
                if not rule.get("check"):
                    errors.append(f"Rule {rule.get('id')} missing check definition")

            return {
                "valid": len(errors) == 0,
                "rule_count": len(rules),
                "errors": errors[:10],  # Limit errors shown
                "error_count": len(errors),
            }

        except Exception as e:
            return {"valid": False, "errors": [str(e)]}

    # =========================================================================
    # Private Methods
    # =========================================================================

    async def _load_rules(self) -> List[Dict[str, Any]]:
        """Load rules from Aegis with caching."""
        if self._rules_cache is not None:
            return self._rules_cache

        if not self._aegis_available:
            return []

        try:
            from aegis import load_rules

            rules = load_rules(str(AEGIS_RULES_PATH))
            self._rules_cache = rules
            return rules

        except Exception as e:
            logger.exception("Failed to load Aegis rules: %s", e)
            return []


# =============================================================================
# Registration Functions
# =============================================================================


async def register_aegis_orsa_plugin(db: Any = None) -> PluginInfo:
    """
    Register Aegis plugin with the ORSA Plugin Registry.

    Args:
        db: Database session for plugin initialization.

    Returns:
        PluginInfo for the registered plugin.
    """
    registry = ORSAPluginRegistry.instance()

    if registry.is_registered(AegisORSAPlugin.PLUGIN_ID):
        logger.info("Aegis ORSA plugin already registered")
        info = await registry.get_info(AegisORSAPlugin.PLUGIN_ID)
        if info:
            return info

    plugin = AegisORSAPlugin(db=db)
    info = await registry.register(plugin)

    logger.info(
        "Registered Aegis ORSA plugin v%s with %d capabilities",
        info.version,
        len(info.capabilities),
    )

    return info


__all__ = [
    "AegisORSAPlugin",
    "register_aegis_orsa_plugin",
]
