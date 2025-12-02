"""
Compliance Framework Reporting Service
Generates detailed compliance reports based on MongoDB rules and scan results
"""

import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from jinja2 import Template

from .mongo_integration_service import MongoIntegrationService, get_mongo_service
from .result_enrichment_service import ResultEnrichmentService

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class ComplianceFrameworkReporter:
    """Service for generating compliance framework reports"""

    def __init__(self) -> None:
        """Initialize the compliance framework reporter."""
        self.mongo_service: Optional[MongoIntegrationService] = None
        self.enrichment_service: Optional[ResultEnrichmentService] = None
        self._initialized = False

        # Framework definitions
        self.frameworks = {
            "nist": {
                "full_name": "NIST Cybersecurity Framework",
                "version": "800-53r5",
                "categories": [
                    "AC",
                    "AU",
                    "CA",
                    "CM",
                    "CP",
                    "IA",
                    "IR",
                    "MA",
                    "MP",
                    "PE",
                    "PL",
                    "PS",
                    "RA",
                    "SA",
                    "SC",
                    "SI",
                    "SR",
                ],
                "description": "National Institute of Standards and Technology security controls",
            },
            "cis": {
                "full_name": "Center for Internet Security Controls",
                "version": "v8",
                "categories": ["IG1", "IG2", "IG3"],
                "description": "Critical Security Controls for effective cyber defense",
            },
            "stig": {
                "full_name": "Security Technical Implementation Guide",
                "version": "Latest",
                "categories": ["CAT I", "CAT II", "CAT III"],
                "description": "DoD security configuration standards",
            },
            "pci": {
                "full_name": "Payment Card Industry Data Security Standard",
                "version": "v4.0",
                "categories": ["Requirement 1-12"],
                "description": "Security standards for payment card data protection",
            },
        }

    async def initialize(self, db: Optional["Session"] = None) -> None:
        """
        Initialize the reporting service.

        Args:
            db: Optional SQLAlchemy database session for enrichment service.
                If not provided, enrichment service functionality will be limited.
        """
        if self._initialized:
            return

        try:
            self.mongo_service = await get_mongo_service()
            # ResultEnrichmentService requires db session - only initialize if provided
            if db is not None:
                self.enrichment_service = ResultEnrichmentService(db)
                # Type ignore: ResultEnrichmentService.initialize is async but
                # mypy may not have visibility into its typing
                await self.enrichment_service.initialize()

            self._initialized = True
            logger.info("Compliance Framework Reporter initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize Compliance Framework Reporter: {e}")
            raise Exception(f"Reporter initialization failed: {str(e)}")

    async def generate_compliance_report(
        self,
        enriched_results: Dict[str, Any],
        target_frameworks: Optional[List[str]] = None,
        report_format: str = "json",
    ) -> Dict[str, Any]:
        """
        Generate comprehensive compliance framework report

        Args:
            enriched_results: Results from ResultEnrichmentService
            target_frameworks: Specific frameworks to report on
            report_format: Output format (json, html, pdf)

        Returns:
            Compliance report data
        """
        if not self._initialized:
            await self.initialize()

        try:
            logger.info("Generating compliance framework report")

            # Default to all frameworks if none specified
            if not target_frameworks:
                target_frameworks = list(self.frameworks.keys())

            # Extract framework mapping from enriched results
            framework_mapping = enriched_results.get("framework_mapping", {})
            enriched_results.get("compliance_scores", {})

            # Generate detailed framework analysis
            framework_analysis = await self._analyze_frameworks(framework_mapping, target_frameworks)

            # Generate gap analysis
            gap_analysis = await self._generate_gap_analysis(enriched_results, target_frameworks)

            # Create remediation roadmap
            remediation_roadmap = await self._create_remediation_roadmap(enriched_results, target_frameworks)

            # Generate executive dashboard data
            executive_dashboard = await self._generate_executive_dashboard(enriched_results, framework_analysis)

            # Compile final report
            compliance_report = {
                "metadata": {
                    "report_generated": datetime.utcnow().isoformat(),
                    "scan_timestamp": enriched_results.get("enrichment_timestamp"),
                    "frameworks_analyzed": target_frameworks,
                    "report_format": report_format,
                    "openwatch_version": "1.0.0",
                },
                "executive_summary": enriched_results.get("executive_summary", {}),
                "executive_dashboard": executive_dashboard,
                "framework_analysis": framework_analysis,
                "gap_analysis": gap_analysis,
                "remediation_roadmap": remediation_roadmap,
                "detailed_findings": await self._compile_detailed_findings(enriched_results),
                "appendix": {
                    "framework_definitions": {
                        fw: self.frameworks[fw] for fw in target_frameworks if fw in self.frameworks
                    },
                    "methodology": await self._get_methodology_notes(),
                    "glossary": await self._get_glossary(),
                },
            }

            # Format output based on requested format
            if report_format == "html":
                compliance_report["html_content"] = await self._generate_html_report(compliance_report)
            elif report_format == "pdf":
                compliance_report["pdf_path"] = await self._generate_pdf_report(compliance_report)

            logger.info(f"Compliance report generated for {len(target_frameworks)} frameworks")
            return compliance_report

        except Exception as e:
            logger.error(f"Failed to generate compliance report: {e}")
            raise Exception(f"Compliance report generation failed: {str(e)}")

    async def _analyze_frameworks(
        self, framework_mapping: Dict[str, Any], target_frameworks: List[str]
    ) -> Dict[str, Any]:
        """Analyze compliance posture for each framework"""
        analysis: Dict[str, Any] = {}

        for framework in target_frameworks:
            if framework not in self.frameworks:
                continue

            fw_data = framework_mapping.get(framework, {})
            fw_definition = self.frameworks[framework]

            controls = fw_data.get("controls", {})
            total_controls = len(controls)

            if total_controls == 0:
                analysis[framework] = {
                    "status": "no_data",
                    "message": f"No {framework.upper()} controls tested in this scan",
                }
                continue

            # Calculate detailed statistics
            compliant_controls = sum(1 for control in controls.values() if control["status"] == "compliant")
            non_compliant_controls = sum(1 for control in controls.values() if control["status"] == "non_compliant")

            # Categorize by severity/importance
            critical_failures = []
            high_failures = []
            medium_failures = []

            for control_id, control_data in controls.items():
                if control_data["status"] == "non_compliant":
                    failure_severity = await self._assess_control_criticality(framework, control_id)

                    failure_info = {
                        "control": control_id,
                        "failed_rules": control_data.get("failed", 0),
                        "total_rules": control_data.get("failed", 0) + control_data.get("passed", 0),
                    }

                    if failure_severity == "critical":
                        critical_failures.append(failure_info)
                    elif failure_severity == "high":
                        high_failures.append(failure_info)
                    else:
                        medium_failures.append(failure_info)

            compliance_rate = fw_data.get("compliance_rate", 0)

            analysis[framework] = {
                "framework_info": fw_definition,
                "compliance_rate": compliance_rate,
                "grade": self._calculate_grade_from_rate(compliance_rate),
                "total_controls_tested": total_controls,
                "compliant_controls": compliant_controls,
                "non_compliant_controls": non_compliant_controls,
                "critical_failures": critical_failures,
                "high_priority_failures": high_failures,
                "medium_priority_failures": medium_failures,
                "status": self._determine_framework_status(compliance_rate),
                "recommendations": await self._generate_framework_recommendations(
                    framework, compliance_rate, critical_failures
                ),
            }

        return analysis

    async def _assess_control_criticality(self, framework: str, control_id: str) -> str:
        """Assess the criticality of a failed control"""
        # Framework-specific criticality assessment
        critical_controls = {
            "nist": ["AC-2", "AC-3", "AU-2", "AU-3", "IA-2", "IA-5", "SC-7", "SI-2"],
            "cis": ["1.1", "1.2", "2.1", "3.1", "4.1", "5.1"],
            "stig": ["V-", "SV-"],  # STIG vulnerabilities
            "pci": ["1.", "2.", "3.", "4."],  # PCI requirements
        }

        if framework in critical_controls:
            for critical_pattern in critical_controls[framework]:
                if control_id.startswith(critical_pattern):
                    return "critical"

        return "high"  # Default to high for unknown controls

    def _calculate_grade_from_rate(self, rate: float) -> str:
        """Calculate letter grade from compliance rate"""
        if rate >= 90:
            return "A"
        elif rate >= 80:
            return "B"
        elif rate >= 70:
            return "C"
        elif rate >= 60:
            return "D"
        else:
            return "F"

    def _determine_framework_status(self, compliance_rate: float) -> str:
        """Determine overall status for framework"""
        if compliance_rate >= 90:
            return "excellent"
        elif compliance_rate >= 80:
            return "good"
        elif compliance_rate >= 70:
            return "acceptable"
        elif compliance_rate >= 60:
            return "needs_improvement"
        else:
            return "critical"

    async def _generate_framework_recommendations(
        self, framework: str, compliance_rate: float, critical_failures: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate framework-specific recommendations"""
        recommendations = []

        # Generic recommendations based on compliance rate
        if compliance_rate < 60:
            recommendations.append(
                f"Urgent: {framework.upper()} compliance is critically low. Immediate remediation required."
            )
        elif compliance_rate < 80:
            recommendations.append(f"Priority: Focus on {framework.upper()} critical controls to improve compliance.")

        # Framework-specific recommendations
        if framework == "nist":
            if critical_failures:
                recommendations.append(
                    "NIST: Review access controls (AC) and identification/authentication (IA) implementations."
                )
        elif framework == "cis":
            if critical_failures:
                recommendations.append(
                    "CIS: Focus on basic security hygiene controls (inventory, configuration management)."
                )
        elif framework == "stig":
            if critical_failures:
                recommendations.append("STIG: Address Category I (critical) findings immediately for DoD compliance.")
        elif framework == "pci":
            if critical_failures:
                recommendations.append(
                    "PCI DSS: Critical for payment processing - address network security and access controls."
                )

        # Add remediation timeline
        if critical_failures:
            recommendations.append(
                f"Recommended timeline: Address {len(critical_failures)} critical failures within 30 days."
            )

        return recommendations

    async def _generate_gap_analysis(
        self, enriched_results: Dict[str, Any], target_frameworks: List[str]
    ) -> Dict[str, Any]:
        """Generate gap analysis showing missing controls"""
        gap_analysis = {}

        for framework in target_frameworks:
            if framework not in self.frameworks:
                continue

            # Get expected controls for this framework (this would ideally come from a baseline)
            expected_controls = await self._get_expected_controls(framework)

            # Get actual controls tested
            framework_mapping = enriched_results.get("framework_mapping", {})
            tested_controls = set(framework_mapping.get(framework, {}).get("controls", {}).keys())

            # Calculate gaps
            missing_controls = expected_controls - tested_controls

            gap_analysis[framework] = {
                "expected_controls_count": len(expected_controls),
                "tested_controls_count": len(tested_controls),
                "missing_controls_count": len(missing_controls),
                "coverage_percentage": (
                    (len(tested_controls) / len(expected_controls) * 100) if expected_controls else 0
                ),
                "missing_controls": list(missing_controls),
                "recommendations": (
                    [
                        f"Expand rule coverage to include {len(missing_controls)} missing {framework.upper()} controls",
                        f"Current coverage: {len(tested_controls)}/{len(expected_controls)} controls",
                    ]
                    if missing_controls
                    else ["Full control coverage achieved"]
                ),
            }

        return gap_analysis

    async def _get_expected_controls(self, framework: str) -> set[str]:
        """Get expected controls for a framework (mock implementation)"""
        # This would ideally come from a comprehensive baseline database
        expected_controls = {
            "nist": {
                "AC-2",
                "AC-3",
                "AC-6",
                "AC-17",
                "AU-2",
                "AU-3",
                "AU-12",
                "CA-2",
                "CA-7",
                "CM-2",
                "CM-6",
                "CM-8",
                "CP-1",
                "IA-2",
                "IA-5",
                "IR-4",
                "PE-2",
                "PS-1",
                "RA-5",
                "SA-4",
                "SC-7",
                "SC-8",
                "SI-2",
                "SI-4",
            },
            "cis": {
                "1.1",
                "1.2",
                "2.1",
                "2.2",
                "3.1",
                "3.2",
                "4.1",
                "4.2",
                "5.1",
                "5.2",
                "6.1",
                "6.2",
                "7.1",
                "8.1",
                "9.1",
                "10.1",
            },
            "stig": {"V-1", "V-2", "V-3", "V-4", "V-5"},  # Simplified
            "pci": {
                "1.1",
                "1.2",
                "2.1",
                "2.2",
                "3.1",
                "3.2",
                "4.1",
                "4.2",
                "5.1",
                "6.1",
                "7.1",
                "8.1",
                "9.1",
                "10.1",
                "11.1",
                "12.1",
            },
        }

        return expected_controls.get(framework, set())

    async def _create_remediation_roadmap(
        self, enriched_results: Dict[str, Any], target_frameworks: List[str]
    ) -> Dict[str, Any]:
        """Create prioritized remediation roadmap"""
        remediation_guidance = enriched_results.get("remediation_guidance", {})

        # Create timeline-based roadmap
        roadmap = {
            "immediate": {  # 0-30 days
                "timeframe": "0-30 days",
                "priority": "Critical",
                "items": remediation_guidance.get("critical_failures", [])
                + remediation_guidance.get("high_priority", [])[:3],
                "estimated_effort": "40-80 hours",
                "business_impact": "High security risk reduction",
            },
            "short_term": {  # 30-90 days
                "timeframe": "30-90 days",
                "priority": "High",
                "items": remediation_guidance.get("high_priority", [])[3:]
                + remediation_guidance.get("medium_priority", [])[:5],
                "estimated_effort": "60-120 hours",
                "business_impact": "Compliance improvement",
            },
            "medium_term": {  # 90-180 days
                "timeframe": "90-180 days",
                "priority": "Medium",
                "items": remediation_guidance.get("medium_priority", [])[5:]
                + remediation_guidance.get("low_priority", [])[:3],
                "estimated_effort": "40-80 hours",
                "business_impact": "Operational efficiency",
            },
            "long_term": {  # 180+ days
                "timeframe": "180+ days",
                "priority": "Low",
                "items": remediation_guidance.get("low_priority", [])[3:],
                "estimated_effort": "20-40 hours",
                "business_impact": "Comprehensive coverage",
            },
        }

        # Add framework-specific priorities
        framework_priorities = {}
        for framework in target_frameworks:
            framework_priorities[framework] = await self._get_framework_remediation_priorities(
                framework, enriched_results
            )

        roadmap["framework_priorities"] = framework_priorities

        return roadmap

    async def _get_framework_remediation_priorities(
        self, framework: str, enriched_results: Dict[str, Any]
    ) -> List[str]:
        """Get framework-specific remediation priorities"""
        priorities = {
            "nist": [
                "Access Control (AC) violations",
                "Identification and Authentication (IA) issues",
                "System and Communications Protection (SC) gaps",
                "Audit and Accountability (AU) deficiencies",
            ],
            "cis": [
                "Asset inventory and control",
                "Secure configuration management",
                "Vulnerability management",
                "Administrative privileges control",
            ],
            "stig": [
                "Category I (Critical) findings",
                "Category II (High) findings",
                "System hardening requirements",
                "Network security configurations",
            ],
            "pci": [
                "Network security controls",
                "Cardholder data protection",
                "Access control measures",
                "Monitoring and testing procedures",
            ],
        }

        return priorities.get(framework, ["General security improvements"])

    async def _generate_executive_dashboard(
        self, enriched_results: Dict[str, Any], framework_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate executive dashboard data"""
        compliance_scores = enriched_results.get("compliance_scores", {})

        # Explicit type annotation to allow heterogeneous dict values
        dashboard: Dict[str, Any] = {
            "key_metrics": {
                "overall_compliance_score": compliance_scores.get("overall", {}).get("score", 0),
                "overall_grade": compliance_scores.get("overall", {}).get("grade", "F"),
                "critical_issues": len(enriched_results.get("remediation_guidance", {}).get("critical_failures", [])),
                "total_rules_tested": compliance_scores.get("overall", {}).get("total_rules", 0),
            },
            "framework_overview": {},
            "trend_indicators": {
                "compliance_direction": "stable",  # This would come from historical data
                "risk_level": self._assess_overall_risk_level(compliance_scores),
                "remediation_progress": "pending",  # This would track remediation completion
            },
            "recommendations": [
                "Address critical security findings immediately",
                "Implement systematic remediation process",
                "Schedule regular compliance scans",
                "Review and update security policies",
            ],
        }

        # Add framework overview
        for framework, analysis in framework_analysis.items():
            if analysis.get("status") != "no_data":
                dashboard["framework_overview"][framework] = {
                    "compliance_rate": analysis["compliance_rate"],
                    "grade": analysis["grade"],
                    "status": analysis["status"],
                    "critical_issues": len(analysis.get("critical_failures", [])),
                }

        return dashboard

    def _assess_overall_risk_level(self, compliance_scores: Dict[str, Any]) -> str:
        """Assess overall risk level based on compliance scores"""
        overall_score = compliance_scores.get("overall", {}).get("score", 0)
        critical_count = compliance_scores.get("overall", {}).get("failed", 0)

        if overall_score < 60 or critical_count > 10:
            return "high"
        elif overall_score < 80 or critical_count > 5:
            return "medium"
        else:
            return "low"

    async def _compile_detailed_findings(self, enriched_results: Dict[str, Any]) -> Dict[str, Any]:
        """Compile detailed findings section"""
        return {
            "rule_results_summary": {
                "total_rules": len(enriched_results.get("enriched_rules", [])),
                "passed": len([r for r in enriched_results.get("enriched_rules", []) if r.get("result") == "pass"]),
                "failed": len([r for r in enriched_results.get("enriched_rules", []) if r.get("result") == "fail"]),
                "not_applicable": len(
                    [r for r in enriched_results.get("enriched_rules", []) if r.get("result") == "notapplicable"]
                ),
            },
            "intelligence_coverage": enriched_results.get("enrichment_stats", {}),
            "remediation_availability": {
                "automated_fixes": len(
                    enriched_results.get("remediation_guidance", {}).get("automated_fixes_available", [])
                ),
                "manual_intervention": len(
                    enriched_results.get("remediation_guidance", {}).get("manual_intervention_required", [])
                ),
            },
        }

    async def _get_methodology_notes(self) -> List[str]:
        """Get methodology notes for the appendix"""
        return [
            "Compliance assessment based on MongoDB rule definitions and SCAP scanning",
            "Rule inheritance and platform-specific configurations applied",
            "Results enriched with business impact and remediation guidance",
            "Framework mappings derived from rule metadata and control associations",
            "Compliance scores calculated based on pass/fail ratios with severity weighting",
        ]

    async def _get_glossary(self) -> Dict[str, str]:
        """Get glossary terms for the appendix"""
        return {
            "Compliance Rate": "Percentage of controls/rules that passed testing",
            "Critical Finding": "High-severity security issue requiring immediate attention",
            "Framework": "Structured set of security controls and guidelines",
            "Remediation": "Process of fixing or mitigating identified security issues",
            "Rule Intelligence": "Enhanced metadata about security rules including business impact",
            "SCAP": "Security Content Automation Protocol for standardized security testing",
            "Inheritance Resolution": "Process of applying parent rule configurations to derived rules",
        }

    async def _generate_html_report(self, report_data: Dict[str, Any]) -> str:
        """Generate HTML version of the compliance report"""
        # This would use a proper HTML template
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>OpenWatch Compliance Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background: #2c5aa0; color: white; padding: 20px; }
                .metric { display: inline-block; margin: 10px; padding: 15px; border: 1px solid #ccc; }
                .critical { background: #ffebee; border-color: #f44336; }
                .good { background: #e8f5e8; border-color: #4caf50; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>OpenWatch Compliance Report</h1>
                <p>Generated: {{ metadata.report_generated }}</p>
            </div>
            <div class="metrics">
                <div class="metric">
                    <h3>Overall Score</h3>
                    <p>{{ executive_dashboard.key_metrics.overall_compliance_score }}%</p>
                </div>
                <div class="metric">
                    <h3>Grade</h3>
                    <p>{{ executive_dashboard.key_metrics.overall_grade }}</p>
                </div>
            </div>
        </body>
        </html>
        """

        template = Template(html_template)
        return template.render(**report_data)

    async def _generate_pdf_report(self, report_data: Dict[str, Any]) -> str:
        """Generate PDF version of the compliance report"""
        # This would use a PDF generation library like ReportLab or WeasyPrint
        pdf_path = f"/tmp/compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

        # Mock PDF generation
        with open(pdf_path, "w") as f:
            f.write("PDF Report Generated - Implementation needed")

        return pdf_path
