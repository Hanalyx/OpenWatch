#!/usr/bin/env python3
"""
CLI tool for remediation recommendation operations
Provides command-line interface for analyzing compliance gaps and generating remediation recommendations
"""
import argparse
import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from backend.app.models.unified_rule_models import UnifiedComplianceRule
from backend.app.services.multi_framework_scanner import ScanResult
from backend.app.services.remediation_recommendation_engine import (
    ComplianceGap,
    RemediationCategory,
    RemediationComplexity,
    RemediationPriority,
    RemediationRecommendation,
    RemediationRecommendationEngine,
)


async def load_scan_results(file_path: str) -> ScanResult:
    """Load scan results from JSON file"""
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
        return ScanResult.parse_obj(data)
    except Exception as e:
        print(f"Error loading scan results from {file_path}: {e}")
        return None


async def load_unified_rules(rules_directory: str) -> Dict[str, UnifiedComplianceRule]:
    """Load unified rules from directory"""
    rules = {}
    rules_path = Path(rules_directory)

    if not rules_path.exists():
        print(f"Rules directory not found: {rules_directory}")
        return rules

    for rule_file in rules_path.glob("*.json"):
        try:
            with open(rule_file, "r") as f:
                rule_data = json.load(f)
                rule = UnifiedComplianceRule.parse_obj(rule_data)
                rules[rule.rule_id] = rule
        except Exception as e:
            print(f"Error loading rule from {rule_file}: {e}")
            continue

    return rules


async def analyze_gaps(args):
    """Analyze compliance gaps from scan results"""
    engine = RemediationRecommendationEngine()

    # Load scan results
    print(f"Loading scan results from {args.scan_results}...")
    scan_result = await load_scan_results(args.scan_results)

    if not scan_result:
        print("Failed to load scan results.")
        return 1

    # Load unified rules
    print(f"Loading unified rules from {args.rules_directory}...")
    unified_rules = await load_unified_rules(args.rules_directory)

    if not unified_rules:
        print("No unified rules loaded.")
        return 1

    print(f"Loaded {len(unified_rules)} unified rules")

    # Analyze compliance gaps
    print("Analyzing compliance gaps...")
    target_frameworks = args.frameworks.split(",") if args.frameworks else None

    compliance_gaps = await engine.analyze_compliance_gaps(
        scan_result, unified_rules, target_frameworks
    )

    if not compliance_gaps:
        print("No compliance gaps found.")
        return 0

    # Display gap analysis
    print(f"\nCOMPLIANCE GAP ANALYSIS")
    print("=" * 80)
    print(f"Total compliance gaps identified: {len(compliance_gaps)}")

    # Group by priority
    gaps_by_priority = {}
    for gap in compliance_gaps:
        priority = gap.priority.value
        if priority not in gaps_by_priority:
            gaps_by_priority[priority] = []
        gaps_by_priority[priority].append(gap)

    # Display by priority
    priority_order = ["critical", "high", "medium", "low", "info"]
    for priority in priority_order:
        if priority in gaps_by_priority:
            gaps = gaps_by_priority[priority]
            print(f"\n{priority.upper()} PRIORITY ({len(gaps)} gaps):")
            print("-" * 60)

            for gap in gaps[: args.max_display]:
                print(f"  {gap.framework_id}:{gap.control_id} on {gap.host_id}")
                print(f"    Rule: {gap.title}")
                print(f"    Status: {gap.current_status.value}")
                print(f"    Platform: {gap.platform}")
                if args.verbose:
                    print(f"    Business Impact: {gap.business_impact}")
                    print(f"    Security Implications: {len(gap.security_implications)} identified")
                    if gap.compliance_deadline:
                        print(f"    Deadline: {gap.compliance_deadline.strftime('%Y-%m-%d')}")
                    print()

    # Framework breakdown
    gaps_by_framework = {}
    for gap in compliance_gaps:
        framework = gap.framework_id
        if framework not in gaps_by_framework:
            gaps_by_framework[framework] = []
        gaps_by_framework[framework].append(gap)

    print(f"\nFRAMEWORK BREAKDOWN:")
    print("-" * 40)
    for framework, gaps in gaps_by_framework.items():
        print(f"{framework:20} {len(gaps):3} gaps")

    # Platform breakdown
    gaps_by_platform = {}
    for gap in compliance_gaps:
        platform = gap.platform
        if platform not in gaps_by_platform:
            gaps_by_platform[platform] = []
        gaps_by_platform[platform].append(gap)

    print(f"\nPLATFORM BREAKDOWN:")
    print("-" * 40)
    for platform, gaps in gaps_by_platform.items():
        print(f"{platform:20} {len(gaps):3} gaps")

    # Export if requested
    if args.export:
        output_file = (
            args.output_file
            or f"compliance_gaps_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        )

        export_data = {
            "gap_analysis_metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "scan_id": scan_result.scan_id,
                "total_gaps": len(compliance_gaps),
                "target_frameworks": target_frameworks,
                "priority_distribution": {
                    priority: len(gaps) for priority, gaps in gaps_by_priority.items()
                },
                "framework_distribution": {
                    framework: len(gaps) for framework, gaps in gaps_by_framework.items()
                },
                "platform_distribution": {
                    platform: len(gaps) for platform, gaps in gaps_by_platform.items()
                },
            },
            "compliance_gaps": [
                {
                    "gap_id": gap.gap_id,
                    "rule_id": gap.rule_id,
                    "framework_id": gap.framework_id,
                    "control_id": gap.control_id,
                    "host_id": gap.host_id,
                    "title": gap.title,
                    "description": gap.description,
                    "current_status": gap.current_status.value,
                    "expected_status": gap.expected_status.value,
                    "priority": gap.priority.value,
                    "risk_level": gap.risk_level,
                    "business_impact": gap.business_impact,
                    "security_implications": gap.security_implications,
                    "platform": gap.platform,
                    "failed_checks": gap.failed_checks,
                    "error_details": gap.error_details,
                    "last_scan_time": gap.last_scan_time.isoformat(),
                    "regulatory_requirements": gap.regulatory_requirements,
                    "compliance_deadline": (
                        gap.compliance_deadline.isoformat() if gap.compliance_deadline else None
                    ),
                }
                for gap in compliance_gaps
            ],
        }

        with open(output_file, "w") as f:
            json.dump(export_data, f, indent=2)

        print(f"\nCompliance gaps exported to: {output_file}")

    return 0


async def generate_recommendations(args):
    """Generate remediation recommendations from compliance gaps"""
    engine = RemediationRecommendationEngine()

    # Load scan results and rules
    scan_result = await load_scan_results(args.scan_results)
    unified_rules = await load_unified_rules(args.rules_directory)

    if not scan_result or not unified_rules:
        print("Failed to load required data.")
        return 1

    # Analyze compliance gaps
    target_frameworks = args.frameworks.split(",") if args.frameworks else None
    compliance_gaps = await engine.analyze_compliance_gaps(
        scan_result, unified_rules, target_frameworks
    )

    if not compliance_gaps:
        print("No compliance gaps found to remediate.")
        return 0

    # Filter by priority if specified
    if args.min_priority:
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        min_priority_value = priority_order.get(args.min_priority, 4)
        compliance_gaps = [
            gap
            for gap in compliance_gaps
            if priority_order.get(gap.priority.value, 4) <= min_priority_value
        ]

    print(f"Generating remediation recommendations for {len(compliance_gaps)} gaps...")

    # Generate recommendations
    recommendations = await engine.generate_remediation_recommendations(
        compliance_gaps, unified_rules
    )

    if not recommendations:
        print("No remediation recommendations could be generated.")
        return 0

    # Display recommendations
    print(f"\nREMEDIATION RECOMMENDATIONS")
    print("=" * 80)
    print(f"Generated {len(recommendations)} remediation recommendations")

    # Group by priority
    recommendations_by_priority = {}
    for rec in recommendations:
        priority = rec.compliance_gap.priority.value
        if priority not in recommendations_by_priority:
            recommendations_by_priority[priority] = []
        recommendations_by_priority[priority].append(rec)

    # Display by priority
    priority_order = ["critical", "high", "medium", "low", "info"]
    for priority in priority_order:
        if priority in recommendations_by_priority:
            recs = recommendations_by_priority[priority]
            print(f"\n{priority.upper()} PRIORITY RECOMMENDATIONS ({len(recs)}):")
            print("-" * 60)

            for rec in recs[: args.max_display]:
                gap = rec.compliance_gap
                procedure = rec.primary_procedure

                print(f"  {gap.framework_id}:{gap.control_id} on {gap.host_id}")
                print(f"    Gap: {gap.title}")
                print(f"    Remediation: {procedure.title}")
                print(f"    Complexity: {procedure.complexity.value}")
                print(f"    Category: {procedure.category.value}")
                print(f"    Estimated Time: {procedure.estimated_time_minutes} minutes")
                print(f"    Requires Reboot: {'Yes' if procedure.requires_reboot else 'No'}")
                print(f"    Confidence Score: {rec.confidence_score:.2f}")

                if args.verbose:
                    print(f"    Steps: {len(procedure.steps)}")
                    print(
                        f"    Rollback Available: {'Yes' if procedure.rollback_available else 'No'}"
                    )
                    print(f"    Business Justification: {rec.business_justification[:100]}...")
                    print(f"    Testing Recommendations: {len(rec.testing_recommendations)}")
                    print()

    # Complexity analysis
    complexity_analysis = {}
    for rec in recommendations:
        complexity = rec.primary_procedure.complexity.value
        if complexity not in complexity_analysis:
            complexity_analysis[complexity] = 0
        complexity_analysis[complexity] += 1

    print(f"\nCOMPLEXITY ANALYSIS:")
    print("-" * 40)
    for complexity, count in complexity_analysis.items():
        print(f"{complexity:15} {count:3} recommendations")

    # Category analysis
    category_analysis = {}
    for rec in recommendations:
        category = rec.primary_procedure.category.value
        if category not in category_analysis:
            category_analysis[category] = 0
        category_analysis[category] += 1

    print(f"\nCATEGORY ANALYSIS:")
    print("-" * 40)
    for category, count in category_analysis.items():
        print(f"{category:20} {count:3} recommendations")

    # Export if requested
    if args.export:
        output_file = (
            args.output_file
            or f"remediation_recommendations_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        )

        export_data = {
            "recommendation_metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "scan_id": scan_result.scan_id,
                "total_recommendations": len(recommendations),
                "target_frameworks": target_frameworks,
                "min_priority_filter": args.min_priority,
                "complexity_distribution": complexity_analysis,
                "category_distribution": category_analysis,
            },
            "remediation_recommendations": [
                {
                    "recommendation_id": rec.recommendation_id,
                    "compliance_gap": {
                        "gap_id": rec.compliance_gap.gap_id,
                        "rule_id": rec.compliance_gap.rule_id,
                        "framework_id": rec.compliance_gap.framework_id,
                        "control_id": rec.compliance_gap.control_id,
                        "host_id": rec.compliance_gap.host_id,
                        "title": rec.compliance_gap.title,
                        "priority": rec.compliance_gap.priority.value,
                        "risk_level": rec.compliance_gap.risk_level,
                        "platform": rec.compliance_gap.platform,
                    },
                    "primary_procedure": {
                        "procedure_id": rec.primary_procedure.procedure_id,
                        "title": rec.primary_procedure.title,
                        "description": rec.primary_procedure.description,
                        "category": rec.primary_procedure.category.value,
                        "complexity": rec.primary_procedure.complexity.value,
                        "estimated_time_minutes": rec.primary_procedure.estimated_time_minutes,
                        "requires_reboot": rec.primary_procedure.requires_reboot,
                        "rollback_available": rec.primary_procedure.rollback_available,
                        "steps": rec.primary_procedure.steps,
                        "pre_conditions": rec.primary_procedure.pre_conditions,
                        "post_validation": rec.primary_procedure.post_validation,
                        "rollback_steps": rec.primary_procedure.rollback_steps,
                    },
                    "analysis": {
                        "root_cause_analysis": rec.root_cause_analysis,
                        "business_justification": rec.business_justification,
                        "compliance_benefit": rec.compliance_benefit,
                        "confidence_score": rec.confidence_score,
                    },
                    "guidance": {
                        "recommended_approach": rec.recommended_approach,
                        "testing_recommendations": rec.testing_recommendations,
                        "monitoring_recommendations": rec.monitoring_recommendations,
                    },
                    "orsa_integration": {
                        "compatible_rules_count": len(rec.orsa_compatible_rules),
                        "job_template_available": rec.remediation_job_template is not None,
                    },
                    "metadata": {
                        "created_at": rec.created_at.isoformat(),
                        "framework_citations": rec.framework_citations,
                        "related_controls": rec.related_controls,
                    },
                }
                for rec in recommendations
            ],
        }

        with open(output_file, "w") as f:
            json.dump(export_data, f, indent=2)

        print(f"\nRemediation recommendations exported to: {output_file}")

    return 0


async def generate_orsa_mapping(args):
    """Generate ORSA-compatible rule mappings"""
    engine = RemediationRecommendationEngine()

    # Load data
    scan_result = await load_scan_results(args.scan_results)
    unified_rules = await load_unified_rules(args.rules_directory)

    if not scan_result or not unified_rules:
        print("Failed to load required data.")
        return 1

    # Generate recommendations
    target_frameworks = args.frameworks.split(",") if args.frameworks else None
    compliance_gaps = await engine.analyze_compliance_gaps(
        scan_result, unified_rules, target_frameworks
    )

    recommendations = await engine.generate_remediation_recommendations(
        compliance_gaps, unified_rules
    )

    if not recommendations:
        print("No recommendations available for ORSA mapping.")
        return 0

    # Generate ORSA mappings
    print("Generating ORSA-compatible rule mappings...")
    orsa_mappings = await engine.map_to_orsa_format(recommendations)

    # Display ORSA mappings
    print(f"\nORSA RULE MAPPINGS")
    print("=" * 80)

    total_rules = sum(len(rules) for rules in orsa_mappings.values())
    print(f"Generated {total_rules} ORSA-compatible rules across {len(orsa_mappings)} platforms")

    for platform, rules in orsa_mappings.items():
        print(f"\n{platform.upper()} PLATFORM ({len(rules)} rules):")
        print("-" * 60)

        for rule in rules[: args.max_display]:
            print(f"  Semantic Name: {rule.semantic_name}")
            print(f"  Title: {rule.title}")
            print(f"  Category: {rule.category}")
            print(f"  Severity: {rule.severity}")
            print(f"  Reversible: {'Yes' if rule.reversible else 'No'}")
            print(f"  Requires Reboot: {'Yes' if rule.requires_reboot else 'No'}")
            print(f"  Framework Mappings: {len(rule.framework_mappings)}")

            if args.verbose:
                print(f"  Tags: {', '.join(rule.tags)}")
                print(f"  Prerequisites: {len(rule.prerequisites)}")
                print(f"  Side Effects: {len(rule.side_effects)}")
                print()

    # Export ORSA mappings
    output_file = (
        args.output_file or f"orsa_mappings_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    )

    export_data = {
        "orsa_mapping_metadata": {
            "generated_at": datetime.utcnow().isoformat(),
            "scan_id": scan_result.scan_id,
            "total_platforms": len(orsa_mappings),
            "total_rules": total_rules,
            "platform_distribution": {
                platform: len(rules) for platform, rules in orsa_mappings.items()
            },
        },
        "orsa_rules_by_platform": {
            platform: [
                {
                    "semantic_name": rule.semantic_name,
                    "title": rule.title,
                    "description": rule.description,
                    "category": rule.category,
                    "severity": rule.severity,
                    "tags": rule.tags,
                    "framework_mappings": rule.framework_mappings,
                    "implementations": rule.implementations,
                    "reversible": rule.reversible,
                    "requires_reboot": rule.requires_reboot,
                    "prerequisites": rule.prerequisites,
                    "side_effects": rule.side_effects,
                }
                for rule in rules
            ]
            for platform, rules in orsa_mappings.items()
        },
    }

    with open(output_file, "w") as f:
        json.dump(export_data, f, indent=2)

    print(f"\nORSA mappings exported to: {output_file}")

    return 0


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Remediation recommendation analysis and ORSA integration tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze compliance gaps
  python -m backend.app.cli.remediation_recommendations analyze-gaps \\
    --scan-results scan_results.json \\
    --rules-directory backend/app/data/unified_rules \\
    --frameworks nist_800_53_r5,cis_v8 \\
    --verbose

  # Generate remediation recommendations
  python -m backend.app.cli.remediation_recommendations generate \\
    --scan-results scan_results.json \\
    --rules-directory backend/app/data/unified_rules \\
    --min-priority high \\
    --export

  # Generate ORSA-compatible mappings
  python -m backend.app.cli.remediation_recommendations orsa-mapping \\
    --scan-results scan_results.json \\
    --rules-directory backend/app/data/unified_rules \\
    --output-file orsa_rules.json
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Analyze gaps command
    gaps_parser = subparsers.add_parser("analyze-gaps", help="Analyze compliance gaps")
    gaps_parser.add_argument(
        "--scan-results", required=True, help="JSON file containing scan results"
    )
    gaps_parser.add_argument(
        "--rules-directory",
        required=True,
        help="Directory containing unified rules JSON files",
    )
    gaps_parser.add_argument("--frameworks", help="Comma-separated list of target frameworks")
    gaps_parser.add_argument("--verbose", action="store_true", help="Show detailed gap information")
    gaps_parser.add_argument(
        "--max-display",
        type=int,
        default=10,
        help="Maximum gaps to display per priority",
    )
    gaps_parser.add_argument("--export", action="store_true", help="Export compliance gaps to JSON")
    gaps_parser.add_argument("--output-file", help="Output file for exported data")

    # Generate recommendations command
    gen_parser = subparsers.add_parser("generate", help="Generate remediation recommendations")
    gen_parser.add_argument(
        "--scan-results", required=True, help="JSON file containing scan results"
    )
    gen_parser.add_argument(
        "--rules-directory",
        required=True,
        help="Directory containing unified rules JSON files",
    )
    gen_parser.add_argument("--frameworks", help="Comma-separated list of target frameworks")
    gen_parser.add_argument(
        "--min-priority",
        choices=["critical", "high", "medium", "low", "info"],
        help="Minimum priority level for recommendations",
    )
    gen_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed recommendation information",
    )
    gen_parser.add_argument(
        "--max-display",
        type=int,
        default=10,
        help="Maximum recommendations to display per priority",
    )
    gen_parser.add_argument("--export", action="store_true", help="Export recommendations to JSON")
    gen_parser.add_argument("--output-file", help="Output file for exported data")

    # ORSA mapping command
    orsa_parser = subparsers.add_parser(
        "orsa-mapping", help="Generate ORSA-compatible rule mappings"
    )
    orsa_parser.add_argument(
        "--scan-results", required=True, help="JSON file containing scan results"
    )
    orsa_parser.add_argument(
        "--rules-directory",
        required=True,
        help="Directory containing unified rules JSON files",
    )
    orsa_parser.add_argument("--frameworks", help="Comma-separated list of target frameworks")
    orsa_parser.add_argument(
        "--verbose", action="store_true", help="Show detailed ORSA rule information"
    )
    orsa_parser.add_argument(
        "--max-display",
        type=int,
        default=10,
        help="Maximum rules to display per platform",
    )
    orsa_parser.add_argument("--output-file", help="Output file for ORSA mappings (JSON)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    try:
        if args.command == "analyze-gaps":
            return asyncio.run(analyze_gaps(args))
        elif args.command == "generate":
            return asyncio.run(generate_recommendations(args))
        elif args.command == "orsa-mapping":
            return asyncio.run(generate_orsa_mapping(args))

        return 0

    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
