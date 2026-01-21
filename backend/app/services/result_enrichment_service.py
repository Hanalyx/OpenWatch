"""
Result Enrichment Service for OpenWatch
Enhances SCAP scan results with MongoDB rule intelligence and compliance framework data
"""

import logging
import xml.etree.ElementTree as ET  # nosec B405  # SCAP content from trusted sources only
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from ..services.owca import get_owca_service
from ..services.owca.models import SeverityBreakdown
from .mongo_integration_service import MongoIntegrationService, get_mongo_service
from .rules import RuleService

logger = logging.getLogger(__name__)


class ScanResultEnrichmentError(Exception):
    """Exception raised for scan result enrichment errors"""


class ResultEnrichmentService:
    """
    Service for enriching SCAP scan results with MongoDB intelligence.

    Uses OWCA (OpenWatch Compliance Algorithm) as the single source of truth
    for all compliance score calculations, ensuring consistency across the platform.
    """

    def __init__(self, db: Session):
        """
        Initialize result enrichment service.

        Args:
            db: SQLAlchemy database session for OWCA integration
        """
        self.db = db
        self.mongo_service: Optional[MongoIntegrationService] = None
        self.rule_service: Optional[RuleService] = None
        self._initialized = False
        self.enrichment_stats = {
            "total_enrichments": 0,
            "successful_enrichments": 0,
            "failed_enrichments": 0,
            "avg_enrichment_time": 0.0,
        }

        # Initialize OWCA service for compliance calculations
        self.owca = get_owca_service(db)

    async def initialize(self):
        """Initialize the enrichment service and all dependencies"""
        if self._initialized:
            return

        try:
            self.mongo_service = await get_mongo_service()
            self.rule_service = RuleService()
            await self.rule_service.initialize()

            self._initialized = True
            logger.info("Result Enrichment Service initialized successfully with OWCA integration")

        except Exception as e:
            logger.error(f"Failed to initialize Result Enrichment Service: {e}")
            raise ScanResultEnrichmentError(f"Service initialization failed: {str(e)}")

    async def enrich_scan_results(
        self, result_file_path: str, scan_metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Main method to enrich SCAP scan results with MongoDB intelligence

        Args:
            result_file_path: Path to SCAP XML results file
            scan_metadata: Additional metadata about the scan

        Returns:
            Enriched results dictionary with intelligence data
        """
        if not self._initialized:
            await self.initialize()

        start_time = datetime.utcnow()

        try:
            logger.info(f"Starting scan result enrichment for: {result_file_path}")

            # Parse SCAP results
            scan_results = await self._parse_scap_results(result_file_path)

            # Extract rule results
            rule_results = await self._extract_rule_results(scan_results)

            # Gather MongoDB intelligence for each rule
            intelligence_data = await self._gather_rule_intelligence(rule_results)

            # Generate compliance framework mapping
            framework_mapping = await self._generate_framework_mapping(rule_results, scan_metadata)

            # Create remediation guidance
            remediation_guidance = await self._generate_remediation_guidance(rule_results)

            # Calculate compliance scores
            compliance_scores = await self._calculate_compliance_scores(
                rule_results, framework_mapping
            )

            # Generate executive summary
            executive_summary = await self._generate_executive_summary(
                rule_results, compliance_scores, scan_metadata
            )

            # Compile enriched results
            enriched_results = {
                "scan_metadata": scan_metadata or {},
                "original_result_file": result_file_path,
                "enrichment_timestamp": datetime.utcnow().isoformat(),
                "rule_count": len(rule_results),
                "enriched_rules": rule_results,
                "intelligence_data": intelligence_data,
                "framework_mapping": framework_mapping,
                "remediation_guidance": remediation_guidance,
                "compliance_scores": compliance_scores,
                "executive_summary": executive_summary,
                "enrichment_stats": await self._calculate_enrichment_stats(
                    rule_results, intelligence_data
                ),
            }

            # Update service statistics
            enrichment_time = (datetime.utcnow() - start_time).total_seconds()
            await self._update_service_stats(True, enrichment_time)

            logger.info(f"Scan result enrichment completed in {enrichment_time:.2f}s")
            return enriched_results

        except Exception as e:
            await self._update_service_stats(False, 0)
            logger.error(f"Scan result enrichment failed: {e}")
            raise ScanResultEnrichmentError(f"Result enrichment failed: {str(e)}")

    async def _parse_scap_results(self, result_file_path: str) -> ET.Element:
        """
        Parse SCAP XML results file.

        Security: XML parsing from trusted SCAP result files only.
        SCAP content is generated by oscap scanner on managed hosts.
        """
        try:
            if not Path(result_file_path).exists():
                raise FileNotFoundError(f"Result file not found: {result_file_path}")

            tree = ET.parse(result_file_path)  # nosec B314  # SCAP results from trusted sources
            root = tree.getroot()

            logger.debug(f"Parsed SCAP results XML: {root.tag}")
            return root

        except ET.ParseError as e:
            raise ScanResultEnrichmentError(f"Failed to parse SCAP results XML: {e}")
        except Exception as e:
            raise ScanResultEnrichmentError(f"Error reading result file: {e}")

    async def _extract_rule_results(self, scan_results: ET.Element) -> List[Dict[str, Any]]:
        """Extract individual rule results from SCAP XML"""
        rule_results = []

        try:
            # Handle different SCAP result formats
            namespaces = {
                "xccdf": "http://checklists.nist.gov/xccdf/1.2",
                "cpe": "http://cpe.mitre.org/language/2.0",
                "oval": "http://oval.mitre.org/XMLSchema/oval-results-5",
            }

            # Find rule results in XCCDF format
            rule_result_elements = scan_results.findall(".//xccdf:rule-result", namespaces)

            for rule_elem in rule_result_elements:
                rule_id = rule_elem.get("idref", "unknown")
                result_status = rule_elem.find("xccdf:result", namespaces)

                if result_status is not None:
                    rule_result = {
                        "rule_id": rule_id,
                        "result": result_status.text,
                        "severity": rule_elem.get("severity", "unknown"),
                        "weight": rule_elem.get("weight", "1.0"),
                        "check_content": await self._extract_check_content(rule_elem, namespaces),
                        "fix_content": await self._extract_fix_content(rule_elem, namespaces),
                        "timestamp": datetime.utcnow().isoformat(),
                    }

                    rule_results.append(rule_result)

            logger.info(f"Extracted {len(rule_results)} rule results")
            return rule_results

        except Exception as e:
            logger.error(f"Failed to extract rule results: {e}")
            return []

    async def _extract_check_content(
        self, rule_elem: ET.Element, namespaces: Dict[str, str]
    ) -> Dict[str, Any]:
        """Extract check information from rule element"""
        check_content: Dict[str, Any] = {}

        try:
            check_elem = rule_elem.find(".//xccdf:check", namespaces)
            if check_elem is not None:
                check_content = {
                    "system": check_elem.get("system", "unknown"),
                    "selector": check_elem.get("selector", ""),
                    "content_ref": [],
                }

                # Extract check content references
                for ref_elem in check_elem.findall("xccdf:check-content-ref", namespaces):
                    check_content["content_ref"].append(
                        {
                            "name": ref_elem.get("name", ""),
                            "href": ref_elem.get("href", ""),
                        }
                    )

        except Exception as e:
            logger.warning(f"Failed to extract check content: {e}")

        return check_content

    async def _extract_fix_content(
        self, rule_elem: ET.Element, namespaces: Dict[str, str]
    ) -> Dict[str, Any]:
        """Extract fix/remediation information from rule element"""
        fix_content = {}

        try:
            fix_elem = rule_elem.find(".//xccdf:fix", namespaces)
            if fix_elem is not None:
                fix_content = {
                    "system": fix_elem.get("system", "unknown"),
                    "complexity": fix_elem.get("complexity", "unknown"),
                    "disruption": fix_elem.get("disruption", "unknown"),
                    "reboot": fix_elem.get("reboot", "false") == "true",
                    "content": fix_elem.text or "",
                }

        except Exception as e:
            logger.warning(f"Failed to extract fix content: {e}")

        return fix_content

    async def _gather_rule_intelligence(self, rule_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Gather MongoDB intelligence data for each rule"""
        intelligence_data: Dict[str, Any] = {}

        if not self.mongo_service:
            logger.warning("MongoDB service not available, skipping rule intelligence gathering")
            return intelligence_data

        for rule_result in rule_results:
            rule_id = rule_result["rule_id"]

            try:
                # Get MongoDB rule intelligence
                intel_data = await self.mongo_service.get_rule_with_intelligence(rule_id)

                if intel_data and "intelligence" in intel_data:
                    intelligence_info = intel_data["intelligence"]
                    rule_info = intel_data.get("rule", {})

                    intelligence_data[rule_id] = {
                        "business_impact": intelligence_info.get("business_impact"),
                        "compliance_importance": intelligence_info.get("compliance_importance", 5),
                        "false_positive_rate": intelligence_info.get("false_positive_rate", 0.0),
                        "common_exceptions": intelligence_info.get("common_exceptions", []),
                        "implementation_notes": intelligence_info.get("implementation_notes"),
                        "testing_guidance": intelligence_info.get("testing_guidance"),
                        "rollback_procedure": intelligence_info.get("rollback_procedure"),
                        "scan_duration_avg_ms": intelligence_info.get("scan_duration_avg_ms", 0),
                        "success_rate": intelligence_info.get("success_rate", 0.0),
                        "usage_count": intelligence_info.get("usage_count", 0),
                        "rule_metadata": rule_info.get("metadata", {}),
                        "frameworks": rule_info.get("frameworks", {}),
                        "platform_implementations": rule_info.get("platform_implementations", {}),
                        "remediation_scripts": intel_data.get("remediation_scripts", []),
                    }
                else:
                    # Create basic intelligence entry for rules without MongoDB data
                    intelligence_data[rule_id] = {
                        "business_impact": "Unknown impact - MongoDB rule data not available",
                        "compliance_importance": 3,
                        "false_positive_rate": 0.1,
                        "implementation_notes": "No specific implementation guidance available",
                        "frameworks": {},
                        "remediation_scripts": [],
                    }

            except Exception as e:
                logger.warning(f"Failed to gather intelligence for rule {rule_id}: {e}")
                continue

        return intelligence_data

    async def _generate_framework_mapping(
        self, rule_results: List[Dict[str, Any]], scan_metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Generate compliance framework mapping for the scan"""
        framework_mapping: Dict[str, Any] = {
            "nist": {"controls": {}, "coverage": 0.0, "compliance_rate": 0.0},
            "cis": {"controls": {}, "coverage": 0.0, "compliance_rate": 0.0},
            "stig": {"controls": {}, "coverage": 0.0, "compliance_rate": 0.0},
            "pci": {"controls": {}, "coverage": 0.0, "compliance_rate": 0.0},
        }

        if not self.mongo_service:
            logger.warning("MongoDB service not available, skipping framework mapping")
            return framework_mapping

        try:
            # Get framework mappings from MongoDB rules
            for rule_result in rule_results:
                rule_id = rule_result["rule_id"]
                rule_status = rule_result["result"]

                # Get MongoDB rule data to extract framework mappings
                try:
                    rule_data = await self.mongo_service.get_rule_with_intelligence(rule_id)
                    if rule_data and "rule" in rule_data:
                        frameworks = rule_data["rule"].get("frameworks", {})

                        for framework_name, framework_versions in frameworks.items():
                            if framework_name.lower() in framework_mapping:
                                fw_mapping = framework_mapping[framework_name.lower()]

                                for version, controls in framework_versions.items():
                                    for control in controls:
                                        if control not in fw_mapping["controls"]:
                                            fw_mapping["controls"][control] = {
                                                "rules": [],
                                                "passed": 0,
                                                "failed": 0,
                                                "status": "unknown",
                                            }

                                        fw_mapping["controls"][control]["rules"].append(rule_id)

                                        if rule_status == "pass":
                                            fw_mapping["controls"][control]["passed"] += 1
                                            fw_mapping["controls"][control]["status"] = "compliant"
                                        elif rule_status == "fail":
                                            fw_mapping["controls"][control]["failed"] += 1
                                            fw_mapping["controls"][control][
                                                "status"
                                            ] = "non_compliant"

                except Exception as e:
                    logger.warning(f"Failed to get framework mapping for rule {rule_id}: {e}")
                    continue

            # Calculate coverage and compliance rates
            for framework_name, fw_data in framework_mapping.items():
                total_controls = len(fw_data["controls"])
                if total_controls > 0:
                    compliant_controls = sum(
                        1
                        for control in fw_data["controls"].values()
                        if control["status"] == "compliant"
                    )
                    fw_data["coverage"] = total_controls  # This would need baseline data
                    fw_data["compliance_rate"] = (compliant_controls / total_controls) * 100

        except Exception as e:
            logger.error(f"Failed to generate framework mapping: {e}")

        return framework_mapping

    async def _generate_remediation_guidance(
        self, rule_results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate remediation guidance for failed rules"""
        remediation_guidance: Dict[str, List[Any]] = {
            "critical_failures": [],
            "high_priority": [],
            "medium_priority": [],
            "low_priority": [],
            "automated_fixes_available": [],
            "manual_intervention_required": [],
        }

        if not self.mongo_service:
            logger.warning("MongoDB service not available, skipping remediation guidance")
            return remediation_guidance

        try:
            for rule_result in rule_results:
                if rule_result["result"] == "fail":
                    rule_id = rule_result["rule_id"]
                    severity = rule_result.get("severity", "medium")

                    # Get remediation scripts from MongoDB
                    try:
                        rule_data = await self.mongo_service.get_rule_with_intelligence(rule_id)
                        if rule_data and "remediation_scripts" in rule_data:
                            scripts = rule_data["remediation_scripts"]

                            guidance_item = {
                                "rule_id": rule_id,
                                "severity": severity,
                                "remediation_scripts": scripts,
                                "automated_available": len(scripts) > 0,
                                "estimated_time": self._estimate_remediation_time(scripts),
                                "risk_level": rule_data.get("rule", {}).get(
                                    "remediation_risk", "medium"
                                ),
                            }

                            # Categorize by severity
                            if severity == "high":
                                if any(script.get("approved", False) for script in scripts):
                                    remediation_guidance["automated_fixes_available"].append(
                                        guidance_item
                                    )
                                else:
                                    remediation_guidance["manual_intervention_required"].append(
                                        guidance_item
                                    )
                                remediation_guidance["high_priority"].append(guidance_item)
                            elif severity == "medium":
                                remediation_guidance["medium_priority"].append(guidance_item)
                            else:
                                remediation_guidance["low_priority"].append(guidance_item)

                    except Exception as e:
                        logger.warning(
                            f"Failed to get remediation guidance for rule {rule_id}: {e}"
                        )
                        continue

        except Exception as e:
            logger.error(f"Failed to generate remediation guidance: {e}")

        return remediation_guidance

    def _estimate_remediation_time(self, scripts: List[Dict[str, Any]]) -> int:
        """Estimate remediation time based on available scripts"""
        if not scripts:
            return 30  # Default 30 minutes for manual fixes

        total_time = 0
        for script in scripts:
            total_time += script.get("estimated_duration_seconds", 300)  # Default 5 minutes

        return total_time // 60  # Return minutes

    async def _calculate_compliance_scores(
        self, rule_results: List[Dict[str, Any]], framework_mapping: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Calculate overall compliance scores using OWCA.

        Uses OWCA (OpenWatch Compliance Algorithm) as the single source of truth
        for all compliance calculations. This ensures consistency across the entire
        platform and eliminates duplicate calculation logic.

        Args:
            rule_results: List of rule results from SCAP scan
            framework_mapping: Framework control mapping data

        Returns:
            Dict with overall, severity, and framework scores
        """
        # Count passed/failed rules for overall score
        total_rules = len(rule_results)
        passed_rules = sum(1 for rule in rule_results if rule["result"] == "pass")
        failed_rules = sum(1 for rule in rule_results if rule["result"] == "fail")

        # Use OWCA's canonical score calculation
        overall_score = self.owca.score_calculator.calculate_score(passed_rules, total_rules)
        compliance_tier = self.owca.score_calculator.get_compliance_tier(overall_score)

        # Overall scores using OWCA
        scores = {
            "overall": {
                "score": overall_score,  # OWCA canonical calculation
                "total_rules": total_rules,
                "passed": passed_rules,
                "failed": failed_rules,
                "tier": compliance_tier.value,  # OWCA tier (excellent/good/fair/poor)
            },
            "by_severity": self._calculate_severity_scores_with_owca(rule_results),
            "by_framework": {},
        }

        # Add framework scores using OWCA
        for framework_name, fw_data in framework_mapping.items():
            fw_score = fw_data["compliance_rate"]
            fw_tier = self.owca.score_calculator.get_compliance_tier(fw_score)

            scores["by_framework"][framework_name] = {
                "compliance_rate": fw_score,
                "controls_tested": len(fw_data["controls"]),
                "tier": fw_tier.value,  # OWCA tier instead of letter grade
            }

        return scores

    def _build_severity_breakdown(self, rule_results: List[Dict[str, Any]]) -> SeverityBreakdown:
        """
        Build OWCA SeverityBreakdown from rule results.

        Aggregates rule results by severity level (critical/high/medium/low)
        and creates a validated SeverityBreakdown model.

        Args:
            rule_results: List of rule results from SCAP scan

        Returns:
            SeverityBreakdown model with validated totals
        """
        # Initialize counters for each severity level
        severity_counts = {
            "critical": {"passed": 0, "failed": 0},
            "high": {"passed": 0, "failed": 0},
            "medium": {"passed": 0, "failed": 0},
            "low": {"passed": 0, "failed": 0},
        }

        # Aggregate results by severity
        for rule in rule_results:
            severity = rule.get("severity", "medium").lower()

            # Map "info" to "low" for OWCA compatibility
            if severity == "info":
                severity = "low"

            if severity in severity_counts:
                if rule["result"] == "pass":
                    severity_counts[severity]["passed"] += 1
                elif rule["result"] == "fail":
                    severity_counts[severity]["failed"] += 1

        # Create OWCA SeverityBreakdown model (includes automatic validation)
        return SeverityBreakdown(
            critical_passed=severity_counts["critical"]["passed"],
            critical_failed=severity_counts["critical"]["failed"],
            critical_total=severity_counts["critical"]["passed"]
            + severity_counts["critical"]["failed"],
            high_passed=severity_counts["high"]["passed"],
            high_failed=severity_counts["high"]["failed"],
            high_total=severity_counts["high"]["passed"] + severity_counts["high"]["failed"],
            medium_passed=severity_counts["medium"]["passed"],
            medium_failed=severity_counts["medium"]["failed"],
            medium_total=severity_counts["medium"]["passed"] + severity_counts["medium"]["failed"],
            low_passed=severity_counts["low"]["passed"],
            low_failed=severity_counts["low"]["failed"],
            low_total=severity_counts["low"]["passed"] + severity_counts["low"]["failed"],
        )

    def _calculate_severity_scores_with_owca(
        self, rule_results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Calculate scores broken down by severity using OWCA.

        Uses OWCA's canonical score calculation for each severity level,
        ensuring consistency with platform-wide compliance calculations.

        Args:
            rule_results: List of rule results from SCAP scan

        Returns:
            Dict with scores and tiers for each severity level
        """
        # Build severity breakdown using OWCA model
        severity_breakdown = self._build_severity_breakdown(rule_results)

        # Calculate OWCA scores for each severity level
        severity_scores = {}
        for severity in ["critical", "high", "medium", "low"]:
            passed = getattr(severity_breakdown, f"{severity}_passed")
            failed = getattr(severity_breakdown, f"{severity}_failed")
            total = getattr(severity_breakdown, f"{severity}_total")

            # Use OWCA's canonical score calculation
            score = self.owca.score_calculator.calculate_score(passed, total)
            tier = self.owca.score_calculator.get_compliance_tier(score)

            severity_scores[severity] = {
                "passed": passed,
                "failed": failed,
                "total": total,
                "score": score,  # OWCA canonical calculation
                "tier": tier.value,  # OWCA tier (excellent/good/fair/poor)
            }

        # Add "info" as alias for "low" for backwards compatibility
        severity_scores["info"] = severity_scores["low"].copy()

        return severity_scores

    async def _generate_executive_summary(
        self,
        rule_results: List[Dict[str, Any]],
        compliance_scores: Dict[str, Any],
        scan_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Generate executive summary of the scan using OWCA compliance tiers.

        Provides high-level overview with OWCA tier classifications
        instead of letter grades for consistency across the platform.

        Args:
            rule_results: List of rule results from SCAP scan
            compliance_scores: Calculated compliance scores from OWCA
            scan_metadata: Optional scan metadata

        Returns:
            Dict with executive summary including OWCA tier and recommendations
        """
        total_rules = len(rule_results)
        failed_rules = [rule for rule in rule_results if rule["result"] == "fail"]
        high_severity_failures = [rule for rule in failed_rules if rule.get("severity") == "high"]
        critical_severity_failures = [
            rule for rule in failed_rules if rule.get("severity") == "critical"
        ]

        summary = {
            "scan_date": datetime.utcnow().isoformat(),
            "overall_score": compliance_scores["overall"]["score"],
            "overall_tier": compliance_scores["overall"]["tier"],  # OWCA tier
            "total_rules_tested": total_rules,
            "rules_passed": compliance_scores["overall"]["passed"],
            "rules_failed": compliance_scores["overall"]["failed"],
            "critical_issues": len(critical_severity_failures),
            "high_severity_issues": len(high_severity_failures),
            "recommendation": self._generate_recommendation(
                compliance_scores["overall"]["score"], compliance_scores["overall"]["tier"]
            ),
            "top_priority_fixes": [
                rule["rule_id"]
                for rule in (critical_severity_failures + high_severity_failures)[:5]
            ],
            "framework_compliance": {
                name: data["compliance_rate"]
                for name, data in compliance_scores["by_framework"].items()
            },
        }

        return summary

    def _generate_recommendation(self, overall_score: float, tier: str) -> str:
        """
        Generate recommendation based on OWCA compliance tier.

        Uses OWCA tier classifications (excellent/good/fair/poor) for
        consistent recommendations across the platform.

        Args:
            overall_score: Numerical compliance score (0-100)
            tier: OWCA compliance tier (excellent/good/fair/poor)

        Returns:
            Recommendation string based on tier
        """
        # Use OWCA tier for recommendations instead of arbitrary score ranges
        if tier == "excellent":
            return "Excellent compliance posture. Continue monitoring and maintain current security practices."
        elif tier == "good":
            return "Good compliance posture. Address remaining medium and high severity issues."
        elif tier == "fair":
            return "Fair compliance posture. Focus on high and critical severity failures first."
        else:  # poor
            return (
                "Poor compliance posture. Urgent remediation required across all severity levels."
            )

    async def _calculate_enrichment_stats(
        self, rule_results: List[Dict[str, Any]], intelligence_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Calculate statistics about the enrichment process"""
        return {
            "rules_processed": len(rule_results),
            "rules_enriched": len(intelligence_data),
            "enrichment_coverage": (
                (len(intelligence_data) / len(rule_results) * 100) if rule_results else 0
            ),
            "mongodb_data_available": sum(
                1
                for data in intelligence_data.values()
                if data.get("business_impact") != "Unknown impact - MongoDB rule data not available"
            ),
            "remediation_scripts_found": sum(
                len(data.get("remediation_scripts", [])) for data in intelligence_data.values()
            ),
        }

    async def _update_service_stats(self, success: bool, enrichment_time: float):
        """Update service performance statistics"""
        self.enrichment_stats["total_enrichments"] += 1

        if success:
            self.enrichment_stats["successful_enrichments"] += 1
        else:
            self.enrichment_stats["failed_enrichments"] += 1

        # Update average enrichment time
        total_time = self.enrichment_stats["avg_enrichment_time"] * (
            self.enrichment_stats["total_enrichments"] - 1
        )
        self.enrichment_stats["avg_enrichment_time"] = (
            total_time + enrichment_time
        ) / self.enrichment_stats["total_enrichments"]

    async def get_enrichment_statistics(self) -> Dict[str, Any]:
        """Get service performance statistics"""
        return self.enrichment_stats.copy()
