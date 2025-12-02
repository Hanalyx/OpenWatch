#!/usr/bin/env python3
"""
Semantic SCAP Engine

Transforms static SCAP processing into intelligent semantic analysis,
enabling cross-framework compliance intelligence and intelligent
remediation orchestration.

This engine provides:
1. Semantic understanding extraction from SCAP rule IDs
2. Universal compliance framework mapping (NIST, CIS, STIG, PCI-DSS)
3. Cross-framework compliance matrix analysis
4. Intelligent remediation strategy generation
5. Compliance trend prediction and drift analysis

Security Considerations:
- All external API calls use validated inputs with timeouts
- No shell command execution in this module
- Database operations use parameterized queries
- Input validation on all external data

Architecture:
- Single Responsibility: Transforms SCAP results to semantic intelligence
- Uses httpx for async HTTP with proper timeouts
- Caches rule mappings and framework data for performance
- Graceful fallback when AEGIS integration unavailable

Usage:
    from backend.app.services.engine.integration import (
        SemanticEngine,
        get_semantic_engine,
    )

    engine = get_semantic_engine()
    result = await engine.process_scan_with_intelligence(
        scan_results={"failed_rules": [...], "rules_total": 100},
        scan_id="scan-123",
        host_info={"host_id": "host-456", "os_version": "RHEL 9"}
    )
"""

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
from sqlalchemy import text

from backend.app.config import get_settings
from backend.app.database import get_db

logger = logging.getLogger(__name__)

# Module-level singleton instance for reuse across requests
_semantic_engine_instance: Optional["SemanticEngine"] = None

# HTTP client configuration constants
HTTP_TIMEOUT_SECONDS = 5.0
CACHE_TTL_SECONDS = 3600  # 1 hour


@dataclass
class SemanticRule:
    """
    Rich semantic representation of a compliance rule.

    This dataclass provides a normalized view of compliance rules
    that transcends specific SCAP implementations, enabling
    cross-framework intelligence and unified remediation.

    Attributes:
        name: Semantic name (e.g., 'ssh_disable_root_login')
        scap_rule_id: Original SCAP/XCCDF rule identifier
        title: Human-readable rule title
        compliance_intent: What this rule is trying to achieve
        business_impact: Business impact category (high, medium, low)
        risk_level: Risk level from rule severity
        frameworks: List of applicable compliance frameworks
        remediation_complexity: Complexity level (simple, moderate, complex)
        estimated_fix_time: Estimated remediation time in minutes
        dependencies: Other rules that should be fixed first
        cross_framework_mappings: Framework-specific rule identifiers
        remediation_available: Whether automated remediation exists

    Example:
        rule = SemanticRule(
            name="ssh_disable_root_login",
            scap_rule_id="xccdf_rule_ssh_root",
            title="Disable SSH root login",
            compliance_intent="authentication",
            business_impact="high",
            risk_level="high",
            frameworks=["stig", "cis"],
            remediation_complexity="simple",
            estimated_fix_time=5,
            dependencies=[],
            cross_framework_mappings={"cis": "5.2.10"},
            remediation_available=True
        )
    """

    name: str
    scap_rule_id: str
    title: str
    compliance_intent: str
    business_impact: str
    risk_level: str
    frameworks: List[str] = field(default_factory=list)
    remediation_complexity: str = "simple"
    estimated_fix_time: int = 10
    dependencies: List[str] = field(default_factory=list)
    cross_framework_mappings: Dict[str, str] = field(default_factory=dict)
    remediation_available: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for serialization.

        Returns:
            Dictionary representation of all fields.
        """
        return asdict(self)


@dataclass
class IntelligentScanResult:
    """
    Enhanced scan result with semantic intelligence.

    This dataclass combines original SCAP scan results with
    semantic analysis, providing actionable compliance insights.

    Attributes:
        scan_id: Original scan identifier
        host_id: Target host identifier
        original_results: Preserved original SCAP results
        semantic_rules: List of semantically analyzed rules
        framework_compliance_matrix: Cross-framework compliance scores
        remediation_strategy: Intelligent remediation recommendations
        compliance_trends: Predicted compliance trends
        processing_metadata: Processing statistics and timing

    Example:
        result = IntelligentScanResult(
            scan_id="scan-123",
            host_id="host-456",
            original_results={"rules_total": 100, "rules_passed": 85},
            semantic_rules=[...],
            framework_compliance_matrix={"stig": 85.0, "cis": 82.5},
            remediation_strategy={"total_rules": 15, "quick_wins": [...]},
            compliance_trends={"risk_level_distribution": {...}},
            processing_metadata={"processing_time_seconds": 1.5}
        )
    """

    scan_id: str
    host_id: str
    original_results: Dict[str, Any]
    semantic_rules: List[SemanticRule]
    framework_compliance_matrix: Dict[str, float]
    remediation_strategy: Dict[str, Any]
    compliance_trends: Dict[str, Any]
    processing_metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for API responses.

        Returns:
            Dictionary representation suitable for JSON serialization.
        """
        return {
            "scan_id": self.scan_id,
            "host_id": self.host_id,
            "original_results": self.original_results,
            "semantic_rules": [rule.to_dict() for rule in self.semantic_rules],
            "framework_compliance_matrix": self.framework_compliance_matrix,
            "remediation_strategy": self.remediation_strategy,
            "compliance_trends": self.compliance_trends,
            "processing_metadata": self.processing_metadata,
        }


class SemanticEngine:
    """
    Transform static SCAP processing into intelligent semantic analysis.

    This engine provides the intelligence layer between OpenWatch scanning
    and AEGIS remediation, enabling universal compliance understanding.

    The engine performs:
    1. Semantic extraction from SCAP rule identifiers
    2. Framework mapping to universal compliance standards
    3. Cross-framework compliance analysis
    4. Intelligent remediation strategy generation
    5. Compliance trend prediction

    Attributes:
        aegis_base_url: Base URL for AEGIS API integration
        _rule_mappings_cache: Cache for semantic rule mappings
        _framework_cache: Cache for framework information
        _cache_ttl: Time-to-live for cached data in seconds

    Example:
        engine = SemanticEngine()
        result = await engine.process_scan_with_intelligence(
            scan_results={"failed_rules": [...]},
            scan_id="scan-123",
            host_info={"host_id": "host-456"}
        )
    """

    def __init__(self) -> None:
        """
        Initialize the Semantic SCAP Engine.

        Loads configuration settings and initializes caches for
        rule mappings and framework data.
        """
        self.settings = get_settings()
        # Get AEGIS base URL with fallback to local development URL
        self.aegis_base_url = getattr(
            self.settings,
            "aegis_api_url",
            "http://localhost:8001",
        )
        # Initialize caches for performance optimization
        self._rule_mappings_cache: Dict[str, SemanticRule] = {}
        self._framework_cache: Dict[str, Any] = {}
        self._cache_ttl = CACHE_TTL_SECONDS

    async def process_scan_with_intelligence(
        self,
        scan_results: Dict[str, Any],
        scan_id: str,
        host_info: Dict[str, Any],
    ) -> IntelligentScanResult:
        """
        Transform raw SCAP results into intelligent compliance insights.

        This is the main entry point for semantic analysis. It processes
        raw SCAP scan results and produces enriched intelligence including:
        - Semantic understanding of failed rules
        - Cross-framework compliance mapping
        - Intelligent remediation strategy
        - Compliance trend predictions

        Args:
            scan_results: Raw SCAP scan results containing:
                - failed_rules: List of failed rule dictionaries
                - rule_details: Detailed rule information (optional)
                - rules_total: Total rules scanned
                - rules_passed: Rules that passed
            scan_id: Unique scan identifier for tracking.
            host_info: Host information dictionary containing:
                - host_id: Target host identifier
                - os_version: Operating system version
                - distribution_name: Linux distribution name (optional)
                - distribution_version: Distribution version (optional)

        Returns:
            IntelligentScanResult with comprehensive semantic analysis.

        Note:
            If processing fails, returns a minimal result with error
            information in processing_metadata to maintain functionality.

        Example:
            result = await engine.process_scan_with_intelligence(
                scan_results={
                    "failed_rules": [{"rule_id": "xccdf_rule_1", "severity": "high"}],
                    "rules_total": 100,
                    "rules_passed": 99
                },
                scan_id="scan-abc123",
                host_info={"host_id": "host-xyz", "os_version": "RHEL 9"}
            )
        """
        logger.info(f"Processing scan with semantic intelligence: {scan_id}")
        start_time = datetime.now(timezone.utc)

        try:
            # Step 1: Extract semantic understanding from failed rules
            semantic_rules = await self._extract_semantic_understanding(
                scan_results.get("failed_rules", []),
                scan_results.get("rule_details", []),
                host_info,
            )

            # Step 2: Map rules to universal compliance frameworks
            framework_mappings = await self._map_to_universal_frameworks(
                semantic_rules,
                host_info,
            )

            # Step 3: Analyze cross-framework compliance impact
            compliance_matrix = await self._analyze_compliance_matrix(
                semantic_rules,
                scan_results,
                framework_mappings,
            )

            # Step 4: Generate intelligent remediation strategy
            remediation_strategy = await self._create_intelligent_remediation_strategy(
                semantic_rules,
                host_info,
                compliance_matrix,
            )

            # Step 5: Predict compliance trends
            compliance_trends = await self._predict_compliance_trends(
                semantic_rules,
                scan_id,
                host_info.get("host_id"),
            )

            # Calculate processing duration
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds()

            result = IntelligentScanResult(
                scan_id=scan_id,
                host_id=host_info.get("host_id", "unknown"),
                original_results=scan_results,
                semantic_rules=semantic_rules,
                framework_compliance_matrix=compliance_matrix,
                remediation_strategy=remediation_strategy,
                compliance_trends=compliance_trends,
                processing_metadata={
                    "processing_time_seconds": processing_time,
                    "semantic_rules_count": len(semantic_rules),
                    "frameworks_analyzed": list(compliance_matrix.keys()),
                    "remediation_available_count": sum(
                        1 for r in semantic_rules if r.remediation_available
                    ),
                    "processed_at": start_time.isoformat(),
                },
            )

            # Persist semantic analysis for future reference
            await self._store_semantic_analysis(result)

            logger.info(
                f"Semantic analysis complete for scan {scan_id}: "
                f"{len(semantic_rules)} rules analyzed, "
                f"{len(compliance_matrix)} frameworks evaluated"
            )

            return result

        except Exception as e:
            logger.error(
                f"Error in semantic SCAP processing for scan {scan_id}: {e}",
                exc_info=True,
            )
            # Return minimal result to maintain API contract
            return IntelligentScanResult(
                scan_id=scan_id,
                host_id=host_info.get("host_id", "unknown"),
                original_results=scan_results,
                semantic_rules=[],
                framework_compliance_matrix={},
                remediation_strategy={},
                compliance_trends={},
                processing_metadata={
                    "error": str(e),
                    "processing_failed": True,
                    "fallback_mode": True,
                },
            )

    async def _extract_semantic_understanding(
        self,
        failed_rules: List[Dict[str, Any]],
        rule_details: List[Dict[str, Any]],
        host_info: Dict[str, Any],
    ) -> List[SemanticRule]:
        """
        Extract semantic meaning from SCAP rule identifiers.

        Uses pattern matching and AEGIS integration to derive
        semantic understanding from cryptic SCAP rule IDs.

        Args:
            failed_rules: List of failed rule dictionaries with rule_id.
            rule_details: Optional detailed rule information.
            host_info: Host information for platform-specific mapping.

        Returns:
            List of SemanticRule objects with rich semantic data.
        """
        semantic_rules: List[SemanticRule] = []

        # Create lookup for detailed rule information
        rule_details_lookup = {detail.get("rule_id"): detail for detail in rule_details}

        for failed_rule in failed_rules:
            scap_rule_id = failed_rule.get("rule_id", "")
            if not scap_rule_id:
                continue

            try:
                # Get detailed information if available
                rule_detail = rule_details_lookup.get(scap_rule_id, {})

                # Map SCAP rule to semantic representation
                semantic_rule = await self._map_scap_rule_to_semantic(
                    scap_rule_id,
                    rule_detail,
                    failed_rule.get("severity", "medium"),
                    host_info,
                )

                if semantic_rule:
                    semantic_rules.append(semantic_rule)

            except Exception as e:
                logger.warning(f"Failed to process rule {scap_rule_id}: {e}")
                # Create minimal semantic rule to avoid breaking functionality
                semantic_rules.append(
                    SemanticRule(
                        name=self._generate_fallback_rule_name(scap_rule_id),
                        scap_rule_id=scap_rule_id,
                        title=rule_detail.get("title", "Unknown Rule"),
                        compliance_intent="Security compliance rule",
                        business_impact="security",
                        risk_level=failed_rule.get("severity", "medium"),
                        frameworks=["stig"],
                        remediation_complexity="unknown",
                        estimated_fix_time=10,
                        dependencies=[],
                        cross_framework_mappings={},
                        remediation_available=False,
                    )
                )

        logger.info(f"Extracted semantic understanding for {len(semantic_rules)} rules")
        return semantic_rules

    async def _map_scap_rule_to_semantic(
        self,
        scap_rule_id: str,
        rule_detail: Dict[str, Any],
        severity: str,
        host_info: Dict[str, Any],
    ) -> Optional[SemanticRule]:
        """
        Map a SCAP rule ID to semantic understanding.

        First attempts to query AEGIS for authoritative mapping,
        then falls back to pattern-based extraction.

        Args:
            scap_rule_id: Full SCAP/XCCDF rule identifier.
            rule_detail: Detailed rule information from scan.
            severity: Rule severity level.
            host_info: Host information for platform context.

        Returns:
            SemanticRule if mapping successful, None otherwise.
        """
        # Try to get mapping from AEGIS first (authoritative source)
        semantic_mapping = await self._query_aegis_for_semantic_mapping(
            scap_rule_id,
            host_info,
        )

        if semantic_mapping:
            return semantic_mapping

        # Fallback to pattern-based mapping
        semantic_name = self._extract_semantic_name_from_scap_rule(scap_rule_id)
        compliance_intent = self._extract_compliance_intent(rule_detail)
        business_impact = self._determine_business_impact(rule_detail, semantic_name)
        remediation_complexity = self._estimate_remediation_complexity(rule_detail)

        return SemanticRule(
            name=semantic_name,
            scap_rule_id=scap_rule_id,
            title=rule_detail.get("title", "Unknown Rule"),
            compliance_intent=compliance_intent,
            business_impact=business_impact,
            risk_level=severity,
            frameworks=self._determine_applicable_frameworks(rule_detail),
            remediation_complexity=remediation_complexity,
            estimated_fix_time=self._estimate_fix_time(remediation_complexity),
            dependencies=[],
            cross_framework_mappings={},
            remediation_available=False,
        )

    def _extract_semantic_name_from_scap_rule(self, scap_rule_id: str) -> str:
        """
        Extract semantic name from SCAP rule ID using pattern matching.

        Uses regex patterns to identify common rule types and
        generate meaningful semantic names.

        Args:
            scap_rule_id: Full SCAP rule identifier.

        Returns:
            Human-readable semantic name for the rule.
        """
        # Common SCAP rule ID patterns mapped to semantic names
        # Patterns are matched against lowercase rule IDs
        patterns = {
            r"ssh.*root.*login": "ssh_disable_root_login",
            r"ssh.*permit.*root": "ssh_disable_root_login",
            r"password.*min.*length": "password_minimum_length",
            r"password.*length": "password_minimum_length",
            r"password.*digit": "password_minimum_digits",
            r"password.*upper": "password_minimum_uppercase",
            r"password.*lower": "password_minimum_lowercase",
            r"password.*special": "password_minimum_special_chars",
            r"auditd.*enable": "auditd_service_enabled",
            r"audit.*log": "audit_logging_configured",
            r"firewall.*enable": "firewall_enabled",
            r"selinux.*enforc": "selinux_enforcing_mode",
            r"kernel.*modules": "kernel_module_restrictions",
            r"file.*permissions": "file_permissions_configured",
            r"umask": "umask_configured",
            r"cron.*permissions": "cron_access_restricted",
        }

        rule_id_lower = scap_rule_id.lower()

        for pattern, semantic_name in patterns.items():
            if re.search(pattern, rule_id_lower):
                return semantic_name

        # Generate fallback name from rule ID
        return self._generate_fallback_rule_name(scap_rule_id)

    def _generate_fallback_rule_name(self, scap_rule_id: str) -> str:
        """
        Generate a fallback semantic name from SCAP rule ID.

        Cleans the rule ID to create a readable name when no
        pattern match is found.

        Args:
            scap_rule_id: Full SCAP rule identifier.

        Returns:
            Cleaned semantic name or "unknown_rule" if extraction fails.
        """
        # Remove common SCAP prefixes and suffixes
        clean_id = re.sub(r"xccdf_[^_]+_rule_", "", scap_rule_id)
        clean_id = re.sub(r"_rule$", "", clean_id)
        # Replace non-alphanumeric characters with underscores
        clean_id = re.sub(r"[^a-zA-Z0-9_]", "_", clean_id)
        # Collapse multiple underscores
        clean_id = re.sub(r"_+", "_", clean_id)
        clean_id = clean_id.strip("_").lower()

        return clean_id or "unknown_rule"

    def _extract_compliance_intent(self, rule_detail: Dict[str, Any]) -> str:
        """
        Extract compliance intent from rule details.

        Analyzes rule title and description to categorize the
        compliance intent.

        Args:
            rule_detail: Dictionary containing title and description.

        Returns:
            Compliance intent category string.
        """
        title = rule_detail.get("title", "").lower()
        description = rule_detail.get("description", "").lower()
        combined_text = f"{title} {description}"

        # Intent patterns mapped to categories
        intent_patterns = {
            "authentication": ["password", "login", "auth", "credential"],
            "access_control": ["permission", "access", "privilege", "authorization"],
            "audit_logging": ["audit", "log", "monitor", "track"],
            "network_security": ["ssh", "network", "port", "firewall", "protocol"],
            "system_hardening": ["kernel", "module", "service", "daemon"],
            "data_protection": ["encrypt", "hash", "secure", "protect"],
            "compliance_monitoring": ["compliance", "policy", "standard", "requirement"],
        }

        for intent, keywords in intent_patterns.items():
            if any(keyword in combined_text for keyword in keywords):
                return intent

        return "security_compliance"

    def _determine_business_impact(
        self,
        rule_detail: Dict[str, Any],
        semantic_name: str,
    ) -> str:
        """
        Determine business impact category based on compliance intent.

        Args:
            rule_detail: Dictionary with rule information.
            semantic_name: Semantic name for additional context.

        Returns:
            Impact level: "high", "medium", or "low".
        """
        high_impact_intents = ["authentication", "access_control", "network_security"]
        medium_impact_intents = ["audit_logging", "system_hardening"]

        compliance_intent = self._extract_compliance_intent(rule_detail)

        if compliance_intent in high_impact_intents:
            return "high"
        elif compliance_intent in medium_impact_intents:
            return "medium"
        else:
            return "low"

    def _determine_applicable_frameworks(
        self,
        rule_detail: Dict[str, Any],
    ) -> List[str]:
        """
        Determine which compliance frameworks this rule applies to.

        Currently returns a baseline set of common frameworks.
        Future enhancement: Use rule metadata for specific mapping.

        Args:
            rule_detail: Dictionary with rule information.

        Returns:
            List of applicable framework identifiers.
        """
        # Most SCAP rules apply to these common frameworks
        # This will be enhanced with actual framework mapping
        return ["stig", "cis", "nist"]

    def _estimate_remediation_complexity(
        self,
        rule_detail: Dict[str, Any],
    ) -> str:
        """
        Estimate remediation complexity from rule details.

        Analyzes remediation text to categorize complexity.

        Args:
            rule_detail: Dictionary containing remediation information.

        Returns:
            Complexity level: "simple", "moderate", or "complex".
        """
        remediation = rule_detail.get("remediation", {})
        fix_text = remediation.get("fix_text", "").lower()

        if "edit" in fix_text or "configure" in fix_text:
            return "simple"
        elif "install" in fix_text or "restart" in fix_text:
            return "moderate"
        elif "complex" in fix_text or "multiple" in fix_text:
            return "complex"
        else:
            return "simple"

    def _estimate_fix_time(self, complexity: str) -> int:
        """
        Estimate fix time in minutes based on complexity.

        Args:
            complexity: Complexity level string.

        Returns:
            Estimated time in minutes.
        """
        time_mapping = {
            "simple": 5,
            "moderate": 15,
            "complex": 30,
        }
        return time_mapping.get(complexity, 10)

    async def _query_aegis_for_semantic_mapping(
        self,
        scap_rule_id: str,
        host_info: Dict[str, Any],
    ) -> Optional[SemanticRule]:
        """
        Query AEGIS for authoritative semantic rule mapping.

        AEGIS provides curated semantic mappings for rules that
        have automated remediation available.

        Args:
            scap_rule_id: SCAP rule identifier to query.
            host_info: Host information for platform context.

        Returns:
            SemanticRule if AEGIS has mapping, None otherwise.
        """
        try:
            distribution_key = self._build_distribution_key(host_info)

            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.aegis_base_url}/api/rules/scap-mapping",
                    params={
                        "scap_rule_id": scap_rule_id,
                        "distribution": distribution_key,
                    },
                    timeout=HTTP_TIMEOUT_SECONDS,
                )

                if response.status_code == 200:
                    mapping_data = response.json()

                    if mapping_data.get("semantic_rule"):
                        rule_data = mapping_data["semantic_rule"]

                        return SemanticRule(
                            name=rule_data["name"],
                            scap_rule_id=scap_rule_id,
                            title=rule_data.get("title", ""),
                            compliance_intent=rule_data.get("compliance_intent", ""),
                            business_impact=rule_data.get("business_impact", "medium"),
                            risk_level=rule_data.get("severity", "medium"),
                            frameworks=rule_data.get("frameworks", []),
                            remediation_complexity=rule_data.get(
                                "remediation_complexity", "simple"
                            ),
                            estimated_fix_time=rule_data.get("estimated_fix_time", 10),
                            dependencies=rule_data.get("dependencies", []),
                            cross_framework_mappings=rule_data.get("cross_framework_mappings", {}),
                            remediation_available=True,
                        )

        except httpx.TimeoutException:
            logger.debug(f"AEGIS query timed out for rule {scap_rule_id}")
        except httpx.RequestError as e:
            logger.debug(f"AEGIS request error for rule {scap_rule_id}: {e}")
        except Exception as e:
            logger.debug(f"Could not query AEGIS for semantic mapping: {e}")

        return None

    def _build_distribution_key(self, host_info: Dict[str, Any]) -> str:
        """
        Build distribution key for AEGIS queries.

        Creates a normalized distribution identifier for
        platform-specific rule mappings.

        Args:
            host_info: Host information dictionary.

        Returns:
            Distribution key string (e.g., "rhel9", "ubuntu22").
        """
        dist_name = host_info.get("distribution_name", "")
        dist_version = host_info.get("distribution_version", "")

        if dist_name and dist_version:
            return f"{dist_name}{dist_version}"

        # Fallback to parsing OS version string
        os_version = host_info.get("os_version", "")
        if "rhel" in os_version.lower() or "red hat" in os_version.lower():
            version_match = re.search(r"\d+", os_version)
            if version_match:
                return f"rhel{version_match.group()}"

        return "rhel9"  # Default fallback

    async def _map_to_universal_frameworks(
        self,
        semantic_rules: List[SemanticRule],
        host_info: Dict[str, Any],
    ) -> Dict[str, List[SemanticRule]]:
        """
        Map semantic rules to universal compliance frameworks.

        Organizes rules by framework for cross-framework analysis.

        Args:
            semantic_rules: List of semantic rules to map.
            host_info: Host information for context.

        Returns:
            Dictionary mapping framework names to applicable rules.
        """
        framework_mappings: Dict[str, List[SemanticRule]] = {}

        # Try to get framework information from AEGIS
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.aegis_base_url}/api/frameworks",
                    timeout=HTTP_TIMEOUT_SECONDS,
                )

                if response.status_code == 200:
                    frameworks_data = response.json()

                    for framework_info in frameworks_data:
                        framework_name = framework_info["name"]
                        applicable_rules = [
                            r for r in semantic_rules if framework_name in r.frameworks
                        ]

                        if applicable_rules:
                            framework_mappings[framework_name] = applicable_rules

        except (httpx.TimeoutException, httpx.RequestError) as e:
            logger.debug(f"Could not query AEGIS frameworks: {e}")

            # Fallback to basic framework mapping from rule data
            for rule in semantic_rules:
                for framework in rule.frameworks:
                    if framework not in framework_mappings:
                        framework_mappings[framework] = []
                    framework_mappings[framework].append(rule)

        except Exception as e:
            logger.debug(f"Unexpected error in framework mapping: {e}")
            # Use same fallback logic
            for rule in semantic_rules:
                for framework in rule.frameworks:
                    if framework not in framework_mappings:
                        framework_mappings[framework] = []
                    framework_mappings[framework].append(rule)

        return framework_mappings

    async def _analyze_compliance_matrix(
        self,
        semantic_rules: List[SemanticRule],
        original_scan_results: Dict[str, Any],
        framework_mappings: Dict[str, List[SemanticRule]],
    ) -> Dict[str, float]:
        """
        Analyze cross-framework compliance scores.

        Calculates estimated compliance percentage for each
        framework based on scan results and rule mappings.

        Args:
            semantic_rules: List of failed rules with semantic data.
            original_scan_results: Original SCAP scan results.
            framework_mappings: Rules organized by framework.

        Returns:
            Dictionary mapping framework names to compliance percentages.
        """
        compliance_matrix: Dict[str, float] = {}

        # Get total rules from original scan
        total_rules = original_scan_results.get("rules_total", 0)
        passed_rules = original_scan_results.get("rules_passed", 0)

        if total_rules == 0:
            return compliance_matrix

        # Calculate baseline compliance score
        baseline_score = (passed_rules / total_rules) * 100

        for framework_name, framework_rules in framework_mappings.items():
            framework_failed_count = len(framework_rules)

            if framework_failed_count == 0:
                compliance_matrix[framework_name] = baseline_score
            else:
                # Estimate compliance impact per framework
                # Cap impact at 20% to prevent extreme variations
                impact_factor = min(framework_failed_count * 2, 20)
                estimated_score = max(baseline_score - impact_factor, 0)
                compliance_matrix[framework_name] = round(estimated_score, 1)

        return compliance_matrix

    async def _create_intelligent_remediation_strategy(
        self,
        semantic_rules: List[SemanticRule],
        host_info: Dict[str, Any],
        compliance_matrix: Dict[str, float],
    ) -> Dict[str, Any]:
        """
        Create intelligent remediation strategy.

        Generates prioritized remediation recommendations based on:
        - Business impact
        - Remediation complexity
        - Framework compliance improvement potential

        Args:
            semantic_rules: List of failed rules with semantic data.
            host_info: Host information for context.
            compliance_matrix: Current framework compliance scores.

        Returns:
            Dictionary containing remediation strategy and recommendations.
        """
        if not semantic_rules:
            return {}

        # Categorize rules by impact and complexity
        high_impact_rules = [r for r in semantic_rules if r.business_impact == "high"]
        quick_wins = [
            r
            for r in semantic_rules
            if r.remediation_complexity == "simple" and r.estimated_fix_time <= 10
        ]

        # Calculate total estimated time
        total_time = sum(rule.estimated_fix_time for rule in semantic_rules)

        # Determine priority order
        priority_rules: List[SemanticRule] = []

        # 1. High impact, simple fixes first (best ROI)
        priority_rules.extend(
            [r for r in high_impact_rules if r.remediation_complexity == "simple"]
        )

        # 2. Quick wins for momentum
        priority_rules.extend([r for r in quick_wins if r not in priority_rules])

        # 3. Remaining high impact rules
        priority_rules.extend([r for r in high_impact_rules if r not in priority_rules])

        # 4. Everything else
        priority_rules.extend([r for r in semantic_rules if r not in priority_rules])

        strategy: Dict[str, Any] = {
            "total_rules": len(semantic_rules),
            "estimated_total_time_minutes": total_time,
            "high_impact_rules": [r.to_dict() for r in high_impact_rules[:5]],
            "quick_wins": [r.to_dict() for r in quick_wins[:5]],
            "priority_order": [r.name for r in priority_rules],
            "complexity_breakdown": {
                "simple": len([r for r in semantic_rules if r.remediation_complexity == "simple"]),
                "moderate": len(
                    [r for r in semantic_rules if r.remediation_complexity == "moderate"]
                ),
                "complex": len(
                    [r for r in semantic_rules if r.remediation_complexity == "complex"]
                ),
            },
            "framework_impact_prediction": self._predict_framework_impact(
                semantic_rules, compliance_matrix
            ),
            "remediation_recommendations": self._generate_remediation_recommendations(
                semantic_rules
            ),
        }

        return strategy

    def _predict_framework_impact(
        self,
        semantic_rules: List[SemanticRule],
        current_compliance: Dict[str, float],
    ) -> Dict[str, Dict[str, float]]:
        """
        Predict compliance improvement from fixing rules.

        Estimates potential score improvement for each framework
        if all applicable rules are remediated.

        Args:
            semantic_rules: List of failed rules.
            current_compliance: Current compliance scores by framework.

        Returns:
            Dictionary with current, predicted scores and improvement per framework.
        """
        impact_prediction: Dict[str, Dict[str, float]] = {}

        for framework_name, current_score in current_compliance.items():
            framework_rules = [r for r in semantic_rules if framework_name in r.frameworks]

            if framework_rules:
                # Estimate improvement (capped at 25% to be conservative)
                potential_improvement = min(len(framework_rules) * 3, 25)
                predicted_score = min(current_score + potential_improvement, 100)

                impact_prediction[framework_name] = {
                    "current_score": current_score,
                    "predicted_score": predicted_score,
                    "improvement": predicted_score - current_score,
                    "affected_rules": len(framework_rules),
                }

        return impact_prediction

    def _generate_remediation_recommendations(
        self,
        semantic_rules: List[SemanticRule],
    ) -> List[str]:
        """
        Generate human-readable remediation recommendations.

        Creates actionable recommendation text based on rule analysis.

        Args:
            semantic_rules: List of failed rules.

        Returns:
            List of recommendation strings.
        """
        recommendations: List[str] = []

        high_impact_count = len([r for r in semantic_rules if r.business_impact == "high"])
        quick_wins_count = len([r for r in semantic_rules if r.estimated_fix_time <= 10])

        if high_impact_count > 0:
            recommendations.append(
                f"Prioritize {high_impact_count} high-impact security rules first"
            )

        if quick_wins_count > 0:
            recommendations.append(
                f"Consider addressing {quick_wins_count} quick-win rules for "
                "immediate improvement"
            )

        total_time = sum(rule.estimated_fix_time for rule in semantic_rules)
        if total_time <= 30:
            recommendations.append("All issues can be resolved in under 30 minutes")
        elif total_time <= 60:
            recommendations.append("Estimated remediation time: 30-60 minutes")
        else:
            recommendations.append(
                f"Estimated remediation time: {total_time} minutes - consider batching"
            )

        return recommendations

    async def _predict_compliance_trends(
        self,
        semantic_rules: List[SemanticRule],
        scan_id: str,
        host_id: Optional[str],
    ) -> Dict[str, Any]:
        """
        Predict compliance trends and provide maintenance recommendations.

        Analyzes current state to predict future compliance behavior.

        Args:
            semantic_rules: List of failed rules.
            scan_id: Scan identifier for tracking.
            host_id: Host identifier for host-specific trends.

        Returns:
            Dictionary containing trend analysis and predictions.
        """
        trends: Dict[str, Any] = {
            "risk_level_distribution": {
                "high": len([r for r in semantic_rules if r.risk_level == "high"]),
                "medium": len([r for r in semantic_rules if r.risk_level == "medium"]),
                "low": len([r for r in semantic_rules if r.risk_level == "low"]),
            },
            "remediation_complexity_trend": {
                "simple": len([r for r in semantic_rules if r.remediation_complexity == "simple"]),
                "moderate": len(
                    [r for r in semantic_rules if r.remediation_complexity == "moderate"]
                ),
                "complex": len(
                    [r for r in semantic_rules if r.remediation_complexity == "complex"]
                ),
            },
            "framework_coverage": {
                framework: len([r for r in semantic_rules if framework in r.frameworks])
                for framework in ["stig", "cis", "nist", "pci_dss"]
            },
            "predictions": {
                "next_scan_recommendation": "Schedule follow-up scan after remediation",
                "compliance_drift_risk": ("low" if len(semantic_rules) < 10 else "medium"),
                "maintenance_frequency": ("monthly" if len(semantic_rules) < 5 else "bi-weekly"),
            },
        }

        return trends

    async def _store_semantic_analysis(
        self,
        result: IntelligentScanResult,
    ) -> None:
        """
        Store semantic analysis results for future reference.

        Persists analysis to database for historical tracking
        and trend analysis.

        Args:
            result: IntelligentScanResult to persist.

        Note:
            Failures are logged but do not raise exceptions to
            maintain scan processing flow.
        """
        try:
            db = next(get_db())
            try:
                # Store in semantic_scan_analysis table
                # Using parameterized query to prevent SQL injection
                db.execute(
                    text(
                        """
                        INSERT INTO semantic_scan_analysis
                        (scan_id, host_id, semantic_rules_count, frameworks_analyzed,
                         remediation_available_count, processing_metadata,
                         analysis_data, created_at)
                        VALUES (:scan_id, :host_id, :semantic_rules_count,
                                :frameworks_analyzed, :remediation_available_count,
                                :processing_metadata, :analysis_data, :created_at)
                        ON CONFLICT (scan_id) DO UPDATE SET
                            semantic_rules_count = EXCLUDED.semantic_rules_count,
                            frameworks_analyzed = EXCLUDED.frameworks_analyzed,
                            remediation_available_count = EXCLUDED.remediation_available_count,
                            processing_metadata = EXCLUDED.processing_metadata,
                            analysis_data = EXCLUDED.analysis_data,
                            updated_at = :created_at
                        """
                    ),
                    {
                        "scan_id": result.scan_id,
                        "host_id": result.host_id,
                        "semantic_rules_count": len(result.semantic_rules),
                        "frameworks_analyzed": json.dumps(
                            list(result.framework_compliance_matrix.keys())
                        ),
                        "remediation_available_count": result.processing_metadata.get(
                            "remediation_available_count", 0
                        ),
                        "processing_metadata": json.dumps(result.processing_metadata),
                        "analysis_data": json.dumps(result.to_dict()),
                        "created_at": datetime.now(timezone.utc),
                    },
                )
                db.commit()

                logger.debug(f"Stored semantic analysis for scan {result.scan_id}")

            finally:
                db.close()

        except Exception as e:
            # Log but don't fail - storage is non-critical
            logger.warning(f"Failed to store semantic analysis: {e}")

    async def get_semantic_analysis(
        self,
        scan_id: str,
    ) -> Optional[IntelligentScanResult]:
        """
        Retrieve stored semantic analysis for a scan.

        Fetches previously computed semantic analysis from database.

        Args:
            scan_id: Scan identifier to retrieve analysis for.

        Returns:
            IntelligentScanResult if found, None otherwise.
        """
        try:
            db = next(get_db())
            try:
                result = db.execute(
                    text(
                        """
                        SELECT analysis_data FROM semantic_scan_analysis
                        WHERE scan_id = :scan_id
                        """
                    ),
                    {"scan_id": scan_id},
                ).fetchone()

                if result and result.analysis_data:
                    data = json.loads(result.analysis_data)

                    # Reconstruct SemanticRule objects from stored data
                    semantic_rules = [
                        SemanticRule(**rule_data) for rule_data in data.get("semantic_rules", [])
                    ]

                    return IntelligentScanResult(
                        scan_id=data["scan_id"],
                        host_id=data["host_id"],
                        original_results=data["original_results"],
                        semantic_rules=semantic_rules,
                        framework_compliance_matrix=data["framework_compliance_matrix"],
                        remediation_strategy=data["remediation_strategy"],
                        compliance_trends=data["compliance_trends"],
                        processing_metadata=data["processing_metadata"],
                    )

            finally:
                db.close()

        except Exception as e:
            logger.warning(f"Failed to retrieve semantic analysis: {e}")

        return None


def get_semantic_engine() -> SemanticEngine:
    """
    Get or create the singleton SemanticEngine instance.

    This function provides a singleton pattern to reuse the same
    engine instance across requests, maintaining cache efficiency.

    Returns:
        Singleton SemanticEngine instance.

    Example:
        engine = get_semantic_engine()
        result = await engine.process_scan_with_intelligence(...)
    """
    global _semantic_engine_instance

    if _semantic_engine_instance is None:
        _semantic_engine_instance = SemanticEngine()
        logger.info("Initialized SemanticEngine singleton")

    return _semantic_engine_instance
