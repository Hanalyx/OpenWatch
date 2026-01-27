#!/usr/bin/env python3
"""
CLI tool for compliance justification operations
Provides command-line interface for generating compliance justifications and audit documentation
"""

import argparse
import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.app.models.unified_rule_models import UnifiedComplianceRule
from backend.app.services.compliance_justification_engine import ComplianceJustificationEngine
from backend.app.services.multi_framework_scanner import ScanResult


async def load_scan_results(file_path: str) -> Optional[ScanResult]:
    """Load scan results from JSON file."""
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
        return ScanResult.parse_obj(data)
    except Exception as e:
        print(f"Error loading scan results from {file_path}: {e}")
        return None


async def load_unified_rules(rules_directory: str) -> Dict[str, UnifiedComplianceRule]:
    """Load unified rules from directory."""
    rules: Dict[str, UnifiedComplianceRule] = {}
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


async def generate_justifications(args: argparse.Namespace) -> int:
    """Generate compliance justifications from scan results."""
    engine = ComplianceJustificationEngine()

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

    # Generate batch justifications
    print("Generating compliance justifications...")
    batch_justifications = await engine.generate_batch_justifications(scan_result, unified_rules)

    # Display summary
    total_justifications = sum(len(justifications) for justifications in batch_justifications.values())
    print(f"\nGenerated {total_justifications} compliance justifications")
    print("=" * 80)

    # Group by justification type
    justification_types: Dict[str, List[Any]] = {}
    for host_justifications in batch_justifications.values():
        for justification in host_justifications:
            jtype = justification.justification_type.value
            if jtype not in justification_types:
                justification_types[jtype] = []
            justification_types[jtype].append(justification)

    # Display by type
    for jtype, justifications in justification_types.items():
        print(f"\n{jtype.upper().replace('_', ' ')} ({len(justifications)} justifications):")
        print("-" * 60)

        for justification in justifications[: args.max_display]:
            print(f"  {justification.framework_id}:{justification.control_id} " f"on {justification.host_id}")
            print(f"    {justification.summary}")
            if args.verbose:
                print(f"    Evidence: {len(justification.evidence)} items")
                print(f"    Risk: {justification.risk_assessment[:100]}...")
                print()

    # Show exceeding compliance details
    exceeding_justifications = justification_types.get("exceeds", [])
    if exceeding_justifications:
        print("\nEXCEEDING COMPLIANCE HIGHLIGHTS:")
        print("-" * 60)

        for justification in exceeding_justifications:
            print(f"  {justification.framework_id}:{justification.control_id}")
            print(f"    Enhancement: {justification.enhancement_details}")
            if justification.exceeding_rationale:
                print(f"    Rationale: {justification.exceeding_rationale}")
            print()

    # Export if requested
    if args.export:
        all_justifications = []
        for host_justifications in batch_justifications.values():
            all_justifications.extend(host_justifications)

        # Group by framework for export
        framework_justifications: Dict[str, List[Any]] = {}
        for justification in all_justifications:
            framework_id = justification.framework_id
            if framework_id not in framework_justifications:
                framework_justifications[framework_id] = []
            framework_justifications[framework_id].append(justification)

        # Export each framework
        for framework_id, justifications in framework_justifications.items():
            export_data = await engine.export_audit_package(justifications, framework_id, args.export_format)

            if args.output_dir:
                output_dir = Path(args.output_dir)
                output_dir.mkdir(exist_ok=True)
                output_file = output_dir / f"{framework_id}_justifications.{args.export_format}"

                with open(output_file, "w") as f:
                    f.write(export_data)
                print(f"Exported {framework_id} justifications to {output_file}")
            else:
                print(f"\n{framework_id.upper()} JUSTIFICATIONS ({args.export_format.upper()}):")
                print("=" * 80)
                print(export_data)

    return 0


async def analyze_evidence(args: argparse.Namespace) -> int:
    """Analyze evidence quality and completeness."""
    engine = ComplianceJustificationEngine()

    # Load scan results and rules
    scan_result = await load_scan_results(args.scan_results)
    unified_rules = await load_unified_rules(args.rules_directory)

    if not scan_result or not unified_rules:
        print("Failed to load required data.")
        return 1

    # Generate justifications
    batch_justifications = await engine.generate_batch_justifications(scan_result, unified_rules)

    print("EVIDENCE QUALITY ANALYSIS")
    print("=" * 80)

    # Analyze evidence by type
    total_justifications = 0
    evidence_by_type: Dict[str, int] = {}
    confidence_distribution: Dict[str, int] = {"high": 0, "medium": 0, "low": 0}

    all_justifications: List[Any] = []
    for host_justifications in batch_justifications.values():
        all_justifications.extend(host_justifications)

    total_justifications = len(all_justifications)

    for justification in all_justifications:
        # Analyze evidence types
        for evidence in justification.evidence:
            evidence_type = evidence.evidence_type.value
            if evidence_type not in evidence_by_type:
                evidence_by_type[evidence_type] = 0
            evidence_by_type[evidence_type] += 1

            # Analyze confidence levels
            confidence = evidence.confidence_level
            if confidence in confidence_distribution:
                confidence_distribution[confidence] += 1

    # Display evidence analysis
    print(f"Total Justifications: {total_justifications}")
    print("Evidence by Type:")
    for evidence_type, count in evidence_by_type.items():
        print(f"  {evidence_type:15} {count:6} items")

    print("\nConfidence Distribution:")
    total_evidence = sum(confidence_distribution.values())
    for confidence, count in confidence_distribution.items():
        percentage = (count / total_evidence * 100) if total_evidence > 0 else 0
        print(f"  {confidence:10} {count:6} ({percentage:5.1f}%)")

    # Identify gaps
    print("\nEVIDENCE QUALITY RECOMMENDATIONS:")
    print("-" * 60)

    if confidence_distribution["low"] > total_evidence * 0.2:
        print("[WARNING] High proportion of low-confidence evidence - consider additional validation")

    if "monitoring" not in evidence_by_type:
        print("[INFO] No continuous monitoring evidence found - consider adding monitoring capabilities")

    if "policy" not in evidence_by_type:
        print("[INFO] No policy evidence found - consider documenting policy compliance")

    # Framework coverage
    framework_evidence: Dict[str, Dict[str, Any]] = {}
    for justification in all_justifications:
        framework_id = justification.framework_id
        if framework_id not in framework_evidence:
            framework_evidence[framework_id] = {
                "justifications": 0,
                "evidence_items": 0,
                "avg_evidence_per_justification": 0.0,
            }

        framework_evidence[framework_id]["justifications"] += 1
        framework_evidence[framework_id]["evidence_items"] += len(justification.evidence)

    # Calculate averages
    for framework_id, data in framework_evidence.items():
        if data["justifications"] > 0:
            data["avg_evidence_per_justification"] = data["evidence_items"] / data["justifications"]

    print("\nFRAMEWORK EVIDENCE COVERAGE:")
    print("-" * 60)
    for framework_id, data in framework_evidence.items():
        print(
            f"{framework_id:20} {data['justifications']:3} justifications, "
            f"{data['avg_evidence_per_justification']:.1f} avg evidence/justification"
        )

    return 0


async def validate_justifications(args: argparse.Namespace) -> int:
    """Validate justification completeness and quality."""
    engine = ComplianceJustificationEngine()

    # Load data
    scan_result = await load_scan_results(args.scan_results)
    unified_rules = await load_unified_rules(args.rules_directory)

    if not scan_result or not unified_rules:
        print("Failed to load required data.")
        return 1

    # Generate justifications
    batch_justifications = await engine.generate_batch_justifications(scan_result, unified_rules)

    print("JUSTIFICATION VALIDATION REPORT")
    print("=" * 80)

    total_justifications = 0
    complete_justifications = 0
    missing_components: Dict[str, int] = {}
    quality_issues: List[str] = []
    framework_validation: Dict[str, Dict[str, Any]] = {}

    all_justifications: List[Any] = []
    for host_justifications in batch_justifications.values():
        all_justifications.extend(host_justifications)

    total_justifications = len(all_justifications)

    for justification in all_justifications:
        is_complete = True

        # Check required components
        required_components = [
            ("summary", justification.summary),
            ("detailed_explanation", justification.detailed_explanation),
            ("implementation_description", justification.implementation_description),
            ("risk_assessment", justification.risk_assessment),
            ("business_justification", justification.business_justification),
            ("evidence", justification.evidence),
        ]

        for component_name, component_value in required_components:
            if not component_value or (isinstance(component_value, str) and len(component_value.strip()) < 10):
                is_complete = False
                if component_name not in missing_components:
                    missing_components[component_name] = 0
                missing_components[component_name] += 1

        # Check evidence quality
        if len(justification.evidence) < 2:
            quality_issues.append(
                f"{justification.justification_id}: Insufficient evidence ({len(justification.evidence)} items)"
            )
            is_complete = False

        # Check regulatory citations
        if not justification.regulatory_citations:
            quality_issues.append(f"{justification.justification_id}: Missing regulatory citations")
            is_complete = False

        if is_complete:
            complete_justifications += 1

        # Framework-specific validation
        framework_id = justification.framework_id
        if framework_id not in framework_validation:
            framework_validation[framework_id] = {
                "total": 0,
                "complete": 0,
                "issues": [],
            }

        framework_validation[framework_id]["total"] += 1
        if is_complete:
            framework_validation[framework_id]["complete"] += 1

    # Display validation results
    complete_percentage = (complete_justifications / total_justifications * 100) if total_justifications > 0 else 0

    print(f"Total Justifications: {total_justifications}")
    print(f"Complete Justifications: {complete_justifications} ({complete_percentage:.1f}%)")

    if missing_components:
        print("\nMissing Components:")
        for component, count in missing_components.items():
            print(f"  {component:25} {count:3} justifications")

    if quality_issues:
        print(f"\nQuality Issues ({len(quality_issues)} total):")
        for issue in quality_issues[:10]:  # Show first 10
            print(f"  {issue}")
        if len(quality_issues) > 10:
            print(f"  ... and {len(quality_issues) - 10} more issues")

    print("\nFramework Validation:")
    print("-" * 60)
    for framework_id, data in framework_validation.items():
        framework_percentage = (data["complete"] / data["total"] * 100) if data["total"] > 0 else 0
        print(f"{framework_id:20} {data['complete']:3}/{data['total']:3} complete ({framework_percentage:5.1f}%)")

    # Recommendations
    print("\nRECOMMENDATIONS:")
    print("-" * 40)

    if complete_percentage < 90:
        print("[ACTION] Improve justification completeness by addressing missing components")

    if missing_components.get("evidence", 0) > 0:
        print("[ACTION] Add more comprehensive evidence collection")

    if missing_components.get("risk_assessment", 0) > 0:
        print("[ACTION] Enhance risk assessment documentation")

    if complete_percentage >= 95:
        print("[PASS] Excellent justification quality - audit ready")

    return 0


async def export_audit_package(args: argparse.Namespace) -> int:
    """Export comprehensive audit package."""
    engine = ComplianceJustificationEngine()

    # Load data
    scan_result = await load_scan_results(args.scan_results)
    unified_rules = await load_unified_rules(args.rules_directory)

    if not scan_result or not unified_rules:
        print("Failed to load required data.")
        return 1

    # Generate justifications
    print("Generating comprehensive audit package...")
    batch_justifications = await engine.generate_batch_justifications(scan_result, unified_rules)

    # Group by framework
    framework_justifications: Dict[str, List[Any]] = {}
    for host_justifications in batch_justifications.values():
        for justification in host_justifications:
            framework_id = justification.framework_id
            if framework_id not in framework_justifications:
                framework_justifications[framework_id] = []
            framework_justifications[framework_id].append(justification)

    print(f"Preparing audit packages for {len(framework_justifications)} frameworks...")

    # Export packages
    output_dir = Path(args.output_dir) if args.output_dir else Path("audit_packages")
    output_dir.mkdir(exist_ok=True)

    for framework_id, justifications in framework_justifications.items():
        print(f"Exporting {framework_id} audit package ({len(justifications)} justifications)...")

        # Export in both JSON and CSV formats
        for format_type in ["json", "csv"]:
            export_data = await engine.export_audit_package(justifications, framework_id, format_type)

            output_file = output_dir / f"{framework_id}_audit_package.{format_type}"
            with open(output_file, "w") as f:
                f.write(export_data)

            print(f"  Created: {output_file}")

    # Create summary report
    summary_file = output_dir / "audit_summary.json"
    summary_data = {
        "audit_package_summary": {
            "generated_at": datetime.utcnow().isoformat(),
            "scan_id": scan_result.scan_id,
            "total_frameworks": len(framework_justifications),
            "total_justifications": sum(len(justifications) for justifications in framework_justifications.values()),
            "frameworks": {
                framework_id: {
                    "justification_count": len(justifications),
                    "compliance_summary": {
                        "compliant": len([j for j in justifications if j.compliance_status.value == "compliant"]),
                        "exceeds": len([j for j in justifications if j.compliance_status.value == "exceeds"]),
                        "partial": len([j for j in justifications if j.compliance_status.value == "partial"]),
                        "non_compliant": len(
                            [j for j in justifications if j.compliance_status.value == "non_compliant"]
                        ),
                    },
                }
                for framework_id, justifications in framework_justifications.items()
            },
        }
    }

    with open(summary_file, "w") as f:
        json.dump(summary_data, f, indent=2)

    print("\nAudit package export complete!")
    print(f"Output directory: {output_dir.absolute()}")
    print(f"Summary report: {summary_file}")

    return 0


def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Compliance justification generation and audit documentation tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate justifications from scan results
  python -m backend.app.cli.compliance_justification generate \\
    --scan-results scan_results.json \\
    --rules-directory backend/app/data/unified_rules \\
    --verbose

  # Export audit packages
  python -m backend.app.cli.compliance_justification generate \\
    --scan-results scan_results.json \\
    --rules-directory backend/app/data/unified_rules \\
    --export --export-format json \\
    --output-dir audit_packages

  # Analyze evidence quality
  python -m backend.app.cli.compliance_justification analyze-evidence \\
    --scan-results scan_results.json \\
    --rules-directory backend/app/data/unified_rules

  # Validate justification completeness
  python -m backend.app.cli.compliance_justification validate \\
    --scan-results scan_results.json \\
    --rules-directory backend/app/data/unified_rules

  # Export comprehensive audit package
  python -m backend.app.cli.compliance_justification export-audit \\
    --scan-results scan_results.json \\
    --rules-directory backend/app/data/unified_rules \\
    --output-dir compliance_audit_2024
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Generate justifications command
    generate_parser = subparsers.add_parser("generate", help="Generate compliance justifications")
    generate_parser.add_argument("--scan-results", required=True, help="JSON file containing scan results")
    generate_parser.add_argument(
        "--rules-directory",
        required=True,
        help="Directory containing unified rules JSON files",
    )
    generate_parser.add_argument("--verbose", action="store_true", help="Show detailed justification information")
    generate_parser.add_argument(
        "--max-display",
        type=int,
        default=5,
        help="Maximum justifications to display per type",
    )
    generate_parser.add_argument("--export", action="store_true", help="Export justifications as audit packages")
    generate_parser.add_argument(
        "--export-format",
        choices=["json", "csv"],
        default="json",
        help="Export format for audit packages",
    )
    generate_parser.add_argument("--output-dir", help="Output directory for exported packages")

    # Analyze evidence command
    evidence_parser = subparsers.add_parser("analyze-evidence", help="Analyze evidence quality")
    evidence_parser.add_argument("--scan-results", required=True, help="JSON file containing scan results")
    evidence_parser.add_argument(
        "--rules-directory",
        required=True,
        help="Directory containing unified rules JSON files",
    )

    # Validate justifications command
    validate_parser = subparsers.add_parser("validate", help="Validate justification completeness")
    validate_parser.add_argument("--scan-results", required=True, help="JSON file containing scan results")
    validate_parser.add_argument(
        "--rules-directory",
        required=True,
        help="Directory containing unified rules JSON files",
    )

    # Export audit package command
    export_parser = subparsers.add_parser("export-audit", help="Export comprehensive audit package")
    export_parser.add_argument("--scan-results", required=True, help="JSON file containing scan results")
    export_parser.add_argument(
        "--rules-directory",
        required=True,
        help="Directory containing unified rules JSON files",
    )
    export_parser.add_argument(
        "--output-dir",
        default="audit_packages",
        help="Output directory for audit packages",
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    try:
        if args.command == "generate":
            return asyncio.run(generate_justifications(args))
        elif args.command == "analyze-evidence":
            return asyncio.run(analyze_evidence(args))
        elif args.command == "validate":
            return asyncio.run(validate_justifications(args))
        elif args.command == "export-audit":
            return asyncio.run(export_audit_package(args))

        return 0

    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
