#!/usr/bin/env python3
"""
CLI tool for framework mapping operations
Provides command-line interface for cross-framework control mapping and analysis
"""
import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import List, Optional

from backend.app.models.unified_rule_models import Platform, UnifiedComplianceRule
from backend.app.services.framework_mapping_engine import (
    FrameworkMappingEngine,
    MappingConfidence,
    MappingType,
)


async def load_unified_rules(rules_directory: str) -> List[UnifiedComplianceRule]:
    """Load unified rules from directory"""
    rules = []
    rules_path = Path(rules_directory)

    if not rules_path.exists():
        print(f"Rules directory not found: {rules_directory}")
        return rules

    for rule_file in rules_path.glob("*.json"):
        try:
            with open(rule_file, "r") as f:
                rule_data = json.load(f)
                rule = UnifiedComplianceRule.parse_obj(rule_data)
                rules.append(rule)
        except Exception as e:
            print(f"Error loading rule from {rule_file}: {e}")
            continue

    return rules


async def load_predefined_mappings(args):
    """Load predefined framework mappings"""
    mapping_engine = FrameworkMappingEngine()

    mappings_file = (
        args.mappings_file or "backend/app/data/framework_mappings/predefined_mappings.json"
    )

    print(f"Loading predefined mappings from {mappings_file}...")

    try:
        loaded_count = await mapping_engine.load_predefined_mappings(mappings_file)
        print(f"Successfully loaded {loaded_count} predefined mappings")

        if args.verbose:
            print("\nLoaded mappings:")
            for mapping_key, mappings in mapping_engine.control_mappings.items():
                for mapping in mappings:
                    print(
                        f"  {mapping.source_framework}:{mapping.source_control} -> "
                        f"{mapping.target_framework}:{mapping.target_control} "
                        f"({mapping.mapping_type.value}, {mapping.confidence.value})"
                    )

    except Exception as e:
        print(f"Error loading predefined mappings: {e}")
        return 1

    return 0


async def discover_mappings(args):
    """Discover framework mappings from unified rules"""
    mapping_engine = FrameworkMappingEngine()

    # Load unified rules
    print(f"Loading unified rules from {args.rules_directory}...")
    unified_rules = await load_unified_rules(args.rules_directory)

    if not unified_rules:
        print("No unified rules loaded. Cannot discover mappings.")
        return 1

    print(f"Loaded {len(unified_rules)} unified rules")

    # Discover mappings between specified frameworks
    source_framework = args.source_framework
    target_framework = args.target_framework

    print(f"Discovering mappings: {source_framework} -> {target_framework}")

    mappings = await mapping_engine.discover_control_mappings(
        source_framework, target_framework, unified_rules
    )

    print(f"\nDiscovered {len(mappings)} control mappings:")
    print("=" * 80)

    # Group by confidence level
    confidence_groups = {}
    for mapping in mappings:
        confidence = mapping.confidence.value
        if confidence not in confidence_groups:
            confidence_groups[confidence] = []
        confidence_groups[confidence].append(mapping)

    # Display by confidence level
    for confidence in ["high", "medium", "low", "uncertain"]:
        if confidence in confidence_groups:
            group_mappings = confidence_groups[confidence]
            print(f"\n{confidence.upper()} CONFIDENCE ({len(group_mappings)} mappings):")
            print("-" * 40)

            for mapping in group_mappings:
                print(
                    f"{mapping.source_control:15} -> {mapping.target_control:15} "
                    f"({mapping.mapping_type.value})"
                )
                if args.verbose:
                    print(f"    Rationale: {mapping.rationale}")
                    if mapping.evidence:
                        print(f"    Evidence: {', '.join(mapping.evidence[:2])}")
                    print()

    # Export if requested
    if args.export:
        export_data = {
            "source_framework": source_framework,
            "target_framework": target_framework,
            "discovered_at": mappings[0].created_at.isoformat() if mappings else None,
            "total_mappings": len(mappings),
            "mappings": [
                {
                    "source_control": m.source_control,
                    "target_control": m.target_control,
                    "mapping_type": m.mapping_type.value,
                    "confidence": m.confidence.value,
                    "rationale": m.rationale,
                    "evidence": m.evidence,
                }
                for m in mappings
            ],
        }

        if args.output:
            with open(args.output, "w") as f:
                json.dump(export_data, f, indent=2)
            print(f"\nMappings exported to {args.output}")
        else:
            print(f"\nExported mappings:")
            print(json.dumps(export_data, indent=2))

    return 0


async def analyze_relationships(args):
    """Analyze relationships between frameworks"""
    mapping_engine = FrameworkMappingEngine()

    # Load predefined mappings if available
    if args.load_predefined:
        mappings_file = "backend/app/data/framework_mappings/predefined_mappings.json"
        try:
            await mapping_engine.load_predefined_mappings(mappings_file)
            print(f"Loaded predefined mappings from {mappings_file}")
        except Exception as e:
            print(f"Warning: Could not load predefined mappings: {e}")

    # Load unified rules
    print(f"Loading unified rules from {args.rules_directory}...")
    unified_rules = await load_unified_rules(args.rules_directory)

    if not unified_rules:
        print("No unified rules loaded. Cannot analyze relationships.")
        return 1

    print(f"Loaded {len(unified_rules)} unified rules")

    # Analyze relationships
    frameworks = args.frameworks

    print(f"\nAnalyzing relationships between frameworks: {', '.join(frameworks)}")
    print("=" * 80)

    relationships = []

    # Analyze all framework pairs
    for i, framework_a in enumerate(frameworks):
        for framework_b in frameworks[i + 1 :]:
            print(f"\nAnalyzing: {framework_a} ↔ {framework_b}")
            print("-" * 50)

            relationship = await mapping_engine.analyze_framework_relationship(
                framework_a, framework_b, unified_rules
            )

            relationships.append(relationship)

            # Display relationship summary
            print(f"Relationship Type: {relationship.relationship_type}")
            print(f"Strength: {relationship.strength:.2f}")
            print(f"Overlap: {relationship.overlap_percentage:.1f}%")
            print(f"Common Controls: {relationship.common_controls}")
            print(f"Unique to {framework_a}: {relationship.framework_a_unique}")
            print(f"Unique to {framework_b}: {relationship.framework_b_unique}")
            print(f"Bidirectional Mappings: {len(relationship.bidirectional_mappings)}")

            if args.verbose:
                if relationship.implementation_synergies:
                    print("\nImplementation Synergies:")
                    for synergy in relationship.implementation_synergies:
                        print(f"  • {synergy}")

                if relationship.conflict_areas:
                    print("\nConflict Areas:")
                    for conflict in relationship.conflict_areas:
                        print(f"  ⚠ {conflict}")

    # Generate coverage analysis
    if args.coverage_analysis:
        print(f"\n\nFRAMEWORK COVERAGE ANALYSIS")
        print("=" * 80)

        coverage = await mapping_engine.get_framework_coverage_analysis(frameworks, unified_rules)

        print(
            f"Total Unique Controls: {coverage['cross_framework_analysis']['total_unique_controls']}"
        )

        print(f"\nPer-Framework Details:")
        for framework in frameworks:
            if framework in coverage["framework_details"]:
                details = coverage["framework_details"][framework]
                print(
                    f"  {framework:20} {details['total_controls']:3} controls, "
                    f"{details['total_rules']:3} rules "
                    f"({details['coverage_percentage']:.1f}% coverage)"
                )

        if coverage["coverage_gaps"]:
            print(f"\nCoverage Gaps:")
            for gap in coverage["coverage_gaps"]:
                print(
                    f"  {gap['framework']:20} {gap['gap_percentage']:.1f}% gap "
                    f"({gap['missing_controls']} missing controls)"
                )

        if coverage["optimization_opportunities"]:
            print(f"\nOptimization Opportunities:")
            for opportunity in coverage["optimization_opportunities"]:
                print(f"  • {opportunity['description']}")

    # Export if requested
    if args.export:
        export_data = {
            "frameworks_analyzed": frameworks,
            "analysis_timestamp": (
                relationships[0].bidirectional_mappings[0].created_at.isoformat()
                if relationships and relationships[0].bidirectional_mappings
                else None
            ),
            "relationships": [
                {
                    "framework_a": rel.framework_a,
                    "framework_b": rel.framework_b,
                    "relationship_type": rel.relationship_type,
                    "strength": rel.strength,
                    "overlap_percentage": rel.overlap_percentage,
                    "common_controls": rel.common_controls,
                    "implementation_synergies": rel.implementation_synergies,
                    "conflict_areas": rel.conflict_areas,
                }
                for rel in relationships
            ],
        }

        if args.coverage_analysis:
            export_data["coverage_analysis"] = coverage

        if args.output:
            with open(args.output, "w") as f:
                json.dump(export_data, f, indent=2)
            print(f"\nAnalysis exported to {args.output}")
        else:
            print(f"\nExported analysis:")
            print(json.dumps(export_data, indent=2))

    return 0


async def generate_unified_implementation(args):
    """Generate unified implementation for control objective"""
    mapping_engine = FrameworkMappingEngine()

    # Load unified rules
    print(f"Loading unified rules from {args.rules_directory}...")
    unified_rules = await load_unified_rules(args.rules_directory)

    print(f"Loaded {len(unified_rules)} unified rules")

    # Generate unified implementation
    control_objective = args.objective
    target_frameworks = args.frameworks
    platform = Platform(args.platform)

    print(f"\nGenerating unified implementation:")
    print(f"  Objective: {control_objective}")
    print(f"  Frameworks: {', '.join(target_frameworks)}")
    print(f"  Platform: {platform.value}")
    print("=" * 80)

    implementation = await mapping_engine.generate_unified_implementation(
        control_objective, target_frameworks, platform, unified_rules
    )

    # Display implementation details
    print(f"Implementation ID: {implementation.implementation_id}")
    print(f"Description: {implementation.description}")
    print(f"Frameworks Satisfied: {', '.join(implementation.frameworks_satisfied)}")

    if implementation.exceeds_frameworks:
        print(f"Exceeds Requirements: {', '.join(implementation.exceeds_frameworks)}")

    print(f"Effort Estimate: {implementation.effort_estimate}")
    print(f"Risk Assessment: {implementation.risk_assessment}")

    if args.verbose:
        print(f"\nControl Mappings:")
        for framework, controls in implementation.control_mappings.items():
            print(f"  {framework}: {', '.join(controls)}")

        print(f"\nCompliance Justification:")
        print(f"  {implementation.compliance_justification}")

        if implementation.platform_specifics:
            print(f"\nPlatform-Specific Implementation ({platform.value}):")
            platform_impl = implementation.platform_specifics.get(platform)
            if platform_impl:
                print(f"  Type: {platform_impl.implementation_type}")
                if platform_impl.commands:
                    print(f"  Commands: {', '.join(platform_impl.commands[:2])}...")
                if platform_impl.files_modified:
                    print(f"  Files: {', '.join(platform_impl.files_modified[:2])}...")

    # Export if requested
    if args.export:
        export_data = {
            "implementation_id": implementation.implementation_id,
            "objective": control_objective,
            "description": implementation.description,
            "frameworks_satisfied": implementation.frameworks_satisfied,
            "exceeds_frameworks": implementation.exceeds_frameworks,
            "control_mappings": implementation.control_mappings,
            "effort_estimate": implementation.effort_estimate,
            "risk_assessment": implementation.risk_assessment,
            "compliance_justification": implementation.compliance_justification,
            "platform": platform.value,
            "implementation_details": implementation.implementation_details,
        }

        if args.output:
            with open(args.output, "w") as f:
                json.dump(export_data, f, indent=2)
            print(f"\nImplementation exported to {args.output}")
        else:
            print(f"\nExported implementation:")
            print(json.dumps(export_data, indent=2))

    return 0


async def export_mapping_data(args):
    """Export all mapping data"""
    mapping_engine = FrameworkMappingEngine()

    # Load predefined mappings
    mappings_file = (
        args.mappings_file or "backend/app/data/framework_mappings/predefined_mappings.json"
    )

    try:
        loaded_count = await mapping_engine.load_predefined_mappings(mappings_file)
        print(f"Loaded {loaded_count} predefined mappings")
    except Exception as e:
        print(f"Warning: Could not load predefined mappings: {e}")

    # Export in requested format
    export_format = args.format
    print(f"Exporting mapping data in {export_format} format...")

    try:
        export_data = await mapping_engine.export_mapping_data(export_format)

        if args.output:
            with open(args.output, "w") as f:
                f.write(export_data)
            print(f"Mapping data exported to {args.output}")
        else:
            print("Exported mapping data:")
            print("=" * 80)
            print(export_data)

    except Exception as e:
        print(f"Error exporting mapping data: {e}")
        return 1

    return 0


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Framework mapping and cross-framework analysis tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Load predefined mappings
  python -m backend.app.cli.framework_mapping load-mappings \\
    --mappings-file mappings.json --verbose

  # Discover mappings between frameworks
  python -m backend.app.cli.framework_mapping discover \\
    --source-framework nist_800_53_r5 --target-framework cis_v8 \\
    --rules-directory backend/app/data/unified_rules

  # Analyze framework relationships
  python -m backend.app.cli.framework_mapping analyze \\
    --frameworks nist_800_53_r5 cis_v8 iso_27001_2022 \\
    --rules-directory backend/app/data/unified_rules \\
    --coverage-analysis --verbose

  # Generate unified implementation
  python -m backend.app.cli.framework_mapping implement \\
    --objective "session timeout" \\
    --frameworks nist_800_53_r5 cis_v8 \\
    --platform rhel_9 \\
    --rules-directory backend/app/data/unified_rules

  # Export mapping data
  python -m backend.app.cli.framework_mapping export \\
    --format json --output mappings_export.json
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Load mappings command
    load_parser = subparsers.add_parser("load-mappings", help="Load predefined framework mappings")
    load_parser.add_argument("--mappings-file", help="JSON file containing predefined mappings")
    load_parser.add_argument(
        "--verbose", action="store_true", help="Show detailed mapping information"
    )

    # Discover mappings command
    discover_parser = subparsers.add_parser(
        "discover", help="Discover framework mappings from unified rules"
    )
    discover_parser.add_argument("--source-framework", required=True, help="Source framework ID")
    discover_parser.add_argument("--target-framework", required=True, help="Target framework ID")
    discover_parser.add_argument(
        "--rules-directory",
        required=True,
        help="Directory containing unified rules JSON files",
    )
    discover_parser.add_argument(
        "--verbose", action="store_true", help="Show detailed mapping information"
    )
    discover_parser.add_argument("--export", action="store_true", help="Export discovered mappings")
    discover_parser.add_argument("--output", help="Output file for exported mappings")

    # Analyze relationships command
    analyze_parser = subparsers.add_parser(
        "analyze", help="Analyze relationships between frameworks"
    )
    analyze_parser.add_argument(
        "--frameworks", nargs="+", required=True, help="Framework IDs to analyze"
    )
    analyze_parser.add_argument(
        "--rules-directory",
        required=True,
        help="Directory containing unified rules JSON files",
    )
    analyze_parser.add_argument(
        "--load-predefined",
        action="store_true",
        help="Load predefined mappings before analysis",
    )
    analyze_parser.add_argument(
        "--coverage-analysis", action="store_true", help="Include coverage analysis"
    )
    analyze_parser.add_argument(
        "--verbose", action="store_true", help="Show detailed analysis information"
    )
    analyze_parser.add_argument("--export", action="store_true", help="Export analysis results")
    analyze_parser.add_argument("--output", help="Output file for exported analysis")

    # Generate implementation command
    implement_parser = subparsers.add_parser("implement", help="Generate unified implementation")
    implement_parser.add_argument(
        "--objective", required=True, help="Control objective description"
    )
    implement_parser.add_argument(
        "--frameworks", nargs="+", required=True, help="Target framework IDs"
    )
    implement_parser.add_argument(
        "--platform",
        required=True,
        choices=["rhel_8", "rhel_9", "ubuntu_20_04", "ubuntu_22_04", "ubuntu_24_04"],
        help="Target platform",
    )
    implement_parser.add_argument(
        "--rules-directory",
        required=True,
        help="Directory containing unified rules JSON files",
    )
    implement_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed implementation information",
    )
    implement_parser.add_argument(
        "--export", action="store_true", help="Export implementation details"
    )
    implement_parser.add_argument("--output", help="Output file for exported implementation")

    # Export command
    export_parser = subparsers.add_parser("export", help="Export mapping data")
    export_parser.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Export format (default: json)",
    )
    export_parser.add_argument("--mappings-file", help="JSON file containing predefined mappings")
    export_parser.add_argument("--output", help="Output file for exported data")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    try:
        if args.command == "load-mappings":
            return asyncio.run(load_predefined_mappings(args))
        elif args.command == "discover":
            return asyncio.run(discover_mappings(args))
        elif args.command == "analyze":
            return asyncio.run(analyze_relationships(args))
        elif args.command == "implement":
            return asyncio.run(generate_unified_implementation(args))
        elif args.command == "export":
            return asyncio.run(export_mapping_data(args))

        return 0

    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
