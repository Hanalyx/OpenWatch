"""
Semantic SCAP Engine - Transform static SCAP processing into intelligent compliance analysis

This engine transforms traditional SCAP rule processing into semantic understanding,
enabling cross-framework intelligence and intelligent remediation orchestration.
"""

import asyncio
import json
import logging
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..config import get_settings
from ..database import get_db

logger = logging.getLogger(__name__)


@dataclass
class SemanticRule:
    """Rich semantic representation of a compliance rule"""

    name: str  # Semantic name (e.g., 'ssh_disable_root_login')
    scap_rule_id: str  # Original SCAP rule ID
    title: str  # Human-readable title
    compliance_intent: str  # What this rule is trying to achieve
    business_impact: str  # Business impact category
    risk_level: str  # high, medium, low
    frameworks: List[str]  # Which frameworks this rule applies to
    remediation_complexity: str  # simple, moderate, complex
    estimated_fix_time: int  # Estimated time in minutes
    dependencies: List[str]  # Other rules that should be fixed first
    cross_framework_mappings: Dict[str, str]  # Framework-specific rule IDs
    remediation_available: bool  # Whether AEGIS can remediate this

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return asdict(self)


@dataclass
class IntelligentScanResult:
    """Enhanced scan result with semantic intelligence"""

    scan_id: str
    host_id: str
    original_results: Dict[str, Any]  # Original SCAP results (preserved)
    semantic_rules: List[SemanticRule]  # Semantic analysis
    framework_compliance_matrix: Dict[str, float]  # Cross-framework compliance scores
    remediation_strategy: Dict[str, Any]  # Intelligent remediation recommendations
    compliance_trends: Dict[str, Any]  # Predicted compliance trends
    processing_metadata: Dict[str, Any]  # Processing information

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses"""
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


class SemanticSCAPEngine:
    """
    Transform static SCAP processing into intelligent semantic analysis

    This engine provides the intelligence layer between OpenWatch scanning
    and AEGIS remediation, enabling universal compliance understanding.
    """

    def __init__(self):
        self.settings = get_settings()
        self.aegis_base_url = getattr(self.settings, "aegis_api_url", "http://localhost:8001")
        self._rule_mappings_cache: Dict[str, SemanticRule] = {}
        self._framework_cache: Dict[str, Any] = {}
        self._cache_ttl = 3600  # 1 hour cache TTL

    async def process_scan_with_intelligence(
        self, scan_results: Dict[str, Any], scan_id: str, host_info: Dict[str, Any]
    ) -> IntelligentScanResult:
        """
        Transform raw SCAP results into intelligent compliance insights

        Args:
            scan_results: Raw SCAP scan results
            scan_id: Scan identifier
            host_info: Host information including OS details

        Returns:
            IntelligentScanResult with semantic analysis
        """
        logger.info(f"Processing scan with semantic intelligence: {scan_id}")
        start_time = datetime.utcnow()

        try:
            # 1. Extract semantic understanding from failed rules
            semantic_rules = await self._extract_semantic_understanding(
                scan_results.get("failed_rules", []),
                scan_results.get("rule_details", []),
                host_info,
            )

            # 2. Map to universal compliance frameworks
            framework_mappings = await self._map_to_universal_frameworks(semantic_rules, host_info)

            # 3. Analyze cross-framework compliance impact
            compliance_matrix = await self._analyze_compliance_matrix(
                semantic_rules, scan_results, framework_mappings
            )

            # 4. Generate intelligent remediation strategy
            remediation_strategy = await self._create_intelligent_remediation_strategy(
                semantic_rules, host_info, compliance_matrix
            )

            # 5. Predict compliance trends (simplified for initial implementation)
            compliance_trends = await self._predict_compliance_trends(
                semantic_rules, scan_id, host_info.get("host_id")
            )

            processing_time = (datetime.utcnow() - start_time).total_seconds()

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

            # Store semantic analysis results
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
            # Return minimal result to maintain functionality
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
        self, failed_rules: List[Dict], rule_details: List[Dict], host_info: Dict
    ) -> List[SemanticRule]:
        """Extract semantic meaning from SCAP rule IDs"""

        semantic_rules = []

        # Create lookup for detailed rule information
        rule_details_lookup = {detail.get("rule_id"): detail for detail in rule_details}

        for failed_rule in failed_rules:
            scap_rule_id = failed_rule.get("rule_id", "")

            try:
                # Get detailed information if available
                rule_detail = rule_details_lookup.get(scap_rule_id, {})

                # Extract semantic information using rule pattern matching
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
                        frameworks=["stig"],  # Default to STIG
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
        self, scap_rule_id: str, rule_detail: Dict, severity: str, host_info: Dict
    ) -> Optional[SemanticRule]:
        """Map a SCAP rule ID to semantic understanding"""

        # Try to get mapping from AEGIS first
        semantic_mapping = await self._query_aegis_for_semantic_mapping(scap_rule_id, host_info)

        if semantic_mapping:
            return semantic_mapping

        # Fallback to pattern-based mapping
        semantic_name = self._extract_semantic_name_from_scap_rule(scap_rule_id)

        # Extract compliance intent from rule title/description
        compliance_intent = self._extract_compliance_intent(rule_detail)

        # Determine business impact from rule characteristics
        business_impact = self._determine_business_impact(rule_detail, semantic_name)

        # Estimate remediation complexity
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
            remediation_available=False,  # Will be updated later
        )

    def _extract_semantic_name_from_scap_rule(self, scap_rule_id: str) -> str:
        """Extract semantic name from SCAP rule ID using pattern matching"""

        # Common SCAP rule ID patterns and their semantic mappings
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

        # Convert rule ID to lowercase for pattern matching
        rule_id_lower = scap_rule_id.lower()

        for pattern, semantic_name in patterns.items():
            if re.search(pattern, rule_id_lower):
                return semantic_name

        # Generate a fallback name
        return self._generate_fallback_rule_name(scap_rule_id)

    def _generate_fallback_rule_name(self, scap_rule_id: str) -> str:
        """Generate a fallback semantic name from SCAP rule ID"""
        # Extract meaningful parts from the rule ID
        # Remove common prefixes and suffixes
        clean_id = re.sub(r"xccdf_[^_]+_rule_", "", scap_rule_id)
        clean_id = re.sub(r"_rule$", "", clean_id)
        clean_id = re.sub(r"[^a-zA-Z0-9_]", "_", clean_id)
        clean_id = re.sub(r"_+", "_", clean_id)
        clean_id = clean_id.strip("_").lower()

        return clean_id or "unknown_rule"

    def _extract_compliance_intent(self, rule_detail: Dict) -> str:
        """Extract compliance intent from rule details"""
        title = rule_detail.get("title", "").lower()
        description = rule_detail.get("description", "").lower()

        intent_patterns = {
            "authentication": ["password", "login", "auth", "credential"],
            "access_control": ["permission", "access", "privilege", "authorization"],
            "audit_logging": ["audit", "log", "monitor", "track"],
            "network_security": ["ssh", "network", "port", "firewall", "protocol"],
            "system_hardening": ["kernel", "module", "service", "daemon"],
            "data_protection": ["encrypt", "hash", "secure", "protect"],
            "compliance_monitoring": [
                "compliance",
                "policy",
                "standard",
                "requirement",
            ],
        }

        text = f"{title} {description}"

        for intent, keywords in intent_patterns.items():
            if any(keyword in text for keyword in keywords):
                return intent

        return "security_compliance"

    def _determine_business_impact(self, rule_detail: Dict, semantic_name: str) -> str:
        """Determine business impact category"""
        high_impact = ["authentication", "access_control", "network_security"]
        medium_impact = ["audit_logging", "system_hardening"]

        compliance_intent = self._extract_compliance_intent(rule_detail)

        if compliance_intent in high_impact:
            return "high"
        elif compliance_intent in medium_impact:
            return "medium"
        else:
            return "low"

    def _determine_applicable_frameworks(self, rule_detail: Dict) -> List[str]:
        """Determine which compliance frameworks this rule applies to"""
        # For now, assume most rules apply to common frameworks
        # This will be enhanced with actual framework mapping
        return ["stig", "cis", "nist"]

    def _estimate_remediation_complexity(self, rule_detail: Dict) -> str:
        """Estimate remediation complexity"""
        remediation = rule_detail.get("remediation", {})
        fix_text = remediation.get("fix_text", "").lower()

        if "edit" in fix_text or "configure" in fix_text:
            return "simple"
        elif "install" in fix_text or "restart" in fix_text:
            return "moderate"
        elif "complex" in fix_text or "multiple" in fix_text:
            return "complex"
        else:
            return "simple"  # Default to simple

    def _estimate_fix_time(self, complexity: str) -> int:
        """Estimate fix time in minutes based on complexity"""
        time_mapping = {"simple": 5, "moderate": 15, "complex": 30}
        return time_mapping.get(complexity, 10)

    async def _query_aegis_for_semantic_mapping(
        self, scap_rule_id: str, host_info: Dict
    ) -> Optional[SemanticRule]:
        """Query AEGIS for semantic rule mapping"""

        try:
            # Build distribution key for AEGIS query
            distribution_key = self._build_distribution_key(host_info)

            # Query AEGIS for rule mapping
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.aegis_base_url}/api/rules/scap-mapping",
                    params={
                        "scap_rule_id": scap_rule_id,
                        "distribution": distribution_key,
                    },
                    timeout=5.0,
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

        except Exception as e:
            logger.debug(f"Could not query AEGIS for semantic mapping: {e}")

        return None

    def _build_distribution_key(self, host_info: Dict) -> str:
        """Build distribution key for AEGIS queries"""
        dist_name = host_info.get("distribution_name", "")
        dist_version = host_info.get("distribution_version", "")

        if dist_name and dist_version:
            return f"{dist_name}{dist_version}"

        # Fallback to legacy OS version
        os_version = host_info.get("os_version", "")
        if "rhel" in os_version.lower() or "red hat" in os_version.lower():
            version = re.search(r"\d+", os_version)
            if version:
                return f"rhel{version.group()}"

        return "rhel9"  # Default fallback

    async def _map_to_universal_frameworks(
        self, semantic_rules: List[SemanticRule], host_info: Dict
    ) -> Dict[str, List[SemanticRule]]:
        """Map semantic rules to universal compliance frameworks"""

        framework_mappings = {}

        # Query AEGIS for framework information
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{self.aegis_base_url}/api/frameworks", timeout=5.0)

                if response.status_code == 200:
                    frameworks_data = response.json()

                    for framework_info in frameworks_data:
                        framework_name = framework_info["name"]
                        applicable_rules = []

                        for rule in semantic_rules:
                            if framework_name in rule.frameworks:
                                applicable_rules.append(rule)

                        if applicable_rules:
                            framework_mappings[framework_name] = applicable_rules

        except Exception as e:
            logger.debug(f"Could not query AEGIS frameworks: {e}")

            # Fallback to basic framework mapping
            for rule in semantic_rules:
                for framework in rule.frameworks:
                    if framework not in framework_mappings:
                        framework_mappings[framework] = []
                    framework_mappings[framework].append(rule)

        return framework_mappings

    async def _analyze_compliance_matrix(
        self,
        semantic_rules: List[SemanticRule],
        original_scan_results: Dict,
        framework_mappings: Dict[str, List[SemanticRule]],
    ) -> Dict[str, float]:
        """Analyze cross-framework compliance scores"""

        compliance_matrix = {}

        # Get total rules from original scan
        total_rules = original_scan_results.get("rules_total", 0)
        passed_rules = original_scan_results.get("rules_passed", 0)

        if total_rules == 0:
            return compliance_matrix

        # Calculate baseline compliance score
        baseline_score = (passed_rules / total_rules) * 100

        for framework_name, framework_rules in framework_mappings.items():
            # For now, use baseline score with slight variations
            # This will be enhanced with actual framework-specific analysis
            framework_failed_count = len(framework_rules)

            if framework_failed_count == 0:
                compliance_matrix[framework_name] = baseline_score
            else:
                # Estimate compliance impact
                impact_factor = min(framework_failed_count * 2, 20)  # Cap at 20% impact
                estimated_score = max(baseline_score - impact_factor, 0)
                compliance_matrix[framework_name] = round(estimated_score, 1)

        return compliance_matrix

    async def _create_intelligent_remediation_strategy(
        self,
        semantic_rules: List[SemanticRule],
        host_info: Dict,
        compliance_matrix: Dict[str, float],
    ) -> Dict[str, Any]:
        """Create intelligent remediation strategy"""

        if not semantic_rules:
            return {}

        # Categorize rules by impact and complexity
        high_impact_rules = [r for r in semantic_rules if r.business_impact == "high"]
        quick_wins = [
            r
            for r in semantic_rules
            if r.remediation_complexity == "simple" and r.estimated_fix_time <= 10
        ]
        complex_rules = [r for r in semantic_rules if r.remediation_complexity == "complex"]

        # Calculate total estimated time
        total_time = sum(rule.estimated_fix_time for rule in semantic_rules)

        # Determine priority order
        priority_rules = []

        # 1. High impact, simple fixes first
        priority_rules.extend(
            [r for r in high_impact_rules if r.remediation_complexity == "simple"]
        )

        # 2. Quick wins
        priority_rules.extend([r for r in quick_wins if r not in priority_rules])

        # 3. Remaining high impact rules
        priority_rules.extend([r for r in high_impact_rules if r not in priority_rules])

        # 4. Everything else
        priority_rules.extend([r for r in semantic_rules if r not in priority_rules])

        strategy = {
            "total_rules": len(semantic_rules),
            "estimated_total_time_minutes": total_time,
            "high_impact_rules": [r.to_dict() for r in high_impact_rules[:5]],  # Top 5
            "quick_wins": [r.to_dict() for r in quick_wins[:5]],  # Top 5
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
        self, semantic_rules: List[SemanticRule], current_compliance: Dict[str, float]
    ) -> Dict[str, Dict[str, float]]:
        """Predict compliance improvement from fixing rules"""

        impact_prediction = {}

        for framework_name, current_score in current_compliance.items():
            framework_rules = [r for r in semantic_rules if framework_name in r.frameworks]

            if framework_rules:
                # Estimate improvement (simplified calculation)
                potential_improvement = min(len(framework_rules) * 3, 25)  # Cap at 25%
                predicted_score = min(current_score + potential_improvement, 100)

                impact_prediction[framework_name] = {
                    "current_score": current_score,
                    "predicted_score": predicted_score,
                    "improvement": predicted_score - current_score,
                    "affected_rules": len(framework_rules),
                }

        return impact_prediction

    def _generate_remediation_recommendations(
        self, semantic_rules: List[SemanticRule]
    ) -> List[str]:
        """Generate human-readable remediation recommendations"""

        recommendations = []

        high_impact_count = len([r for r in semantic_rules if r.business_impact == "high"])
        quick_wins_count = len([r for r in semantic_rules if r.estimated_fix_time <= 10])

        if high_impact_count > 0:
            recommendations.append(
                f"Prioritize {high_impact_count} high-impact security rules first"
            )

        if quick_wins_count > 0:
            recommendations.append(
                f"Consider addressing {quick_wins_count} quick-win rules for immediate improvement"
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
        self, semantic_rules: List[SemanticRule], scan_id: str, host_id: Optional[str]
    ) -> Dict[str, Any]:
        """Predict compliance trends (simplified initial implementation)"""

        # For initial implementation, provide basic trend analysis
        trends = {
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

    async def _store_semantic_analysis(self, result: IntelligentScanResult):
        """Store semantic analysis results for future reference"""

        try:
            db = next(get_db())
            try:
                # Store in semantic_scan_analysis table
                db.execute(
                    text(
                        """
                    INSERT INTO semantic_scan_analysis
                    (scan_id, host_id, semantic_rules_count, frameworks_analyzed,
                     remediation_available_count, processing_metadata, analysis_data, created_at)
                    VALUES (:scan_id, :host_id, :semantic_rules_count, :frameworks_analyzed,
                            :remediation_available_count, :processing_metadata, :analysis_data, :created_at)
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
                        "created_at": datetime.utcnow(),
                    },
                )
                db.commit()

                logger.debug(f"Stored semantic analysis for scan {result.scan_id}")

            finally:
                db.close()

        except Exception as e:
            logger.warning(f"Failed to store semantic analysis: {e}")

    async def get_semantic_analysis(self, scan_id: str) -> Optional[IntelligentScanResult]:
        """Retrieve stored semantic analysis"""

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

                    # Reconstruct SemanticRule objects
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


# Singleton instance
_semantic_scap_engine = None


def get_semantic_scap_engine() -> SemanticSCAPEngine:
    """Get the global semantic SCAP engine instance"""
    global _semantic_scap_engine
    if _semantic_scap_engine is None:
        _semantic_scap_engine = SemanticSCAPEngine()
    return _semantic_scap_engine
