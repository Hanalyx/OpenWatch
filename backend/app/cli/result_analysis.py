#!/usr/bin/env python3
"""
CLI tool for compliance result analysis and aggregation
Provides command-line interface for analyzing scan results and generating reports
"""

import argparse
import asyncio
import json
import sys
from typing import List

from app.services.multi_framework_scanner import ScanResult
from app.services.result_aggregation_service import (
    AggregationLevel,
    ResultAggregationService,
)


async def load_scan_results(file_paths: List[str]) -> List[ScanResult]:
    """Load scan results from JSON files"""
    scan_results = []

    for file_path in file_paths:
        try:
            with open(file_path, "r") as f:
                data = json.load(f)

            # Convert JSON data to ScanResult objects
            # This would typically involve deserializing from your actual scan result format
            scan_result = ScanResult.parse_obj(data)
            scan_results.append(scan_result)

        except Exception as e:
            print(f"Error loading scan result from {file_path}: {e}")
            continue

    return scan_results


async def analyze_results(args):
    """Analyze compliance scan results"""
    aggregation_service = ResultAggregationService()

    # Load scan results
    if args.scan_files:
        scan_results = await load_scan_results(args.scan_files)
    else:
        print("No scan files provided. Use --scan-files to specify input files.")
        return

    if not scan_results:
        print("No valid scan results loaded.")
        return

    print(f"Loaded {len(scan_results)} scan results")

    # Determine aggregation level
    aggregation_level = AggregationLevel(args.level)

    # Perform aggregation
    print(f"Performing {aggregation_level.value} aggregation...")
    aggregated_results = await aggregation_service.aggregate_scan_results(
        scan_results, aggregation_level, args.time_period
    )

    # Display summary
    print("\n" + "=" * 80)
    print("COMPLIANCE ANALYSIS SUMMARY")
    print("=" * 80)

    print(f"Aggregation Level: {aggregated_results.aggregation_level.value}")
    print(f"Time Period: {aggregated_results.time_period}")
    print(f"Generated At: {aggregated_results.generated_at}")

    # Overall metrics
    metrics = aggregated_results.overall_metrics
    print(f"\nOverall Compliance: {metrics.compliance_percentage:.1f}%")
    print(f"Total Rules: {metrics.total_rules}")
    print(f"Executed Rules: {metrics.executed_rules}")
    print(f"Compliant Rules: {metrics.compliant_rules}")
    print(f"Exceeds Rules: {metrics.exceeds_rules}")
    print(f"Non-Compliant Rules: {metrics.non_compliant_rules}")
    print(f"Error Rules: {metrics.error_rules}")
    print(f"Execution Success Rate: {metrics.execution_success_rate:.1f}%")

    # Framework breakdown
    if aggregated_results.framework_metrics:
        print("\nFramework Breakdown:")
        print("-" * 60)
        for (
            framework_id,
            framework_metrics,
        ) in aggregated_results.framework_metrics.items():
            print(
                f"{framework_id:20} {framework_metrics.compliance_percentage:6.1f}% "
                f"({framework_metrics.compliant_rules + framework_metrics.exceeds_rules}/"
                f"{framework_metrics.total_rules})"
            )

    # Host breakdown (if available and requested)
    if args.show_hosts and aggregated_results.host_metrics:
        print("\nHost Breakdown:")
        print("-" * 60)
        for host_id, host_metrics in aggregated_results.host_metrics.items():
            print(
                f"{host_id:20} {host_metrics.compliance_percentage:6.1f}% "
                f"({host_metrics.compliant_rules + host_metrics.exceeds_rules}/"
                f"{host_metrics.total_rules})"
            )

    # Platform distribution
    if aggregated_results.platform_distribution:
        print("\nPlatform Distribution:")
        print("-" * 40)
        for platform, count in aggregated_results.platform_distribution.items():
            print(f"{platform:20} {count:6} hosts")

    # Compliance gaps
    if aggregated_results.compliance_gaps:
        print("\nTop Compliance Gaps:")
        print("-" * 80)
        for gap in sorted(aggregated_results.compliance_gaps, key=lambda g: g.remediation_priority)[: args.max_gaps]:
            print(f"{gap.gap_id} [{gap.severity.upper()}] {gap.description}")
            print(f"    Affected hosts: {len(gap.affected_hosts)}")
            print(f"    Framework: {gap.framework_id}")
            print(f"    Priority: {gap.remediation_priority}")
            print()

    # Recommendations
    if aggregated_results.priority_recommendations:
        print("Priority Recommendations:")
        print("-" * 80)
        for i, rec in enumerate(aggregated_results.priority_recommendations[:5], 1):
            print(f"{i}. {rec}")
        print()

    if args.show_strategic and aggregated_results.strategic_recommendations:
        print("Strategic Recommendations:")
        print("-" * 80)
        for i, rec in enumerate(aggregated_results.strategic_recommendations[:5], 1):
            print(f"{i}. {rec}")
        print()

    # Framework comparisons
    if args.show_comparisons and aggregated_results.framework_comparisons:
        print("Framework Comparisons:")
        print("-" * 80)
        for comparison in aggregated_results.framework_comparisons[:3]:
            print(f"{comparison.framework_a} vs {comparison.framework_b}")
            print(
                f"    Overlap: {comparison.overlap_percentage:.1f}% " f"({comparison.common_controls} common controls)"
            )
            print(f"    Correlation: {comparison.compliance_correlation:.2f}")
            print(f"    Unique to {comparison.framework_a}: {comparison.framework_a_unique}")
            print(f"    Unique to {comparison.framework_b}: {comparison.framework_b_unique}")
            print()

    # Performance metrics
    if args.show_performance and aggregated_results.performance_metrics:
        print("Performance Metrics:")
        print("-" * 40)
        for metric, value in aggregated_results.performance_metrics.items():
            if isinstance(value, float):
                print(f"{metric:25} {value:8.2f}")
            else:
                print(f"{metric:25} {value:8}")

    # Export results if requested
    if args.export:
        export_format = args.export_format
        output_data = await aggregation_service.export_aggregated_results(aggregated_results, export_format)

        if args.output:
            with open(args.output, "w") as f:
                f.write(output_data)
            print(f"\nResults exported to {args.output} ({export_format} format)")
        else:
            print(f"\nExported Results ({export_format} format):")
            print("=" * 80)
            print(output_data)


async def generate_dashboard_data(args):
    """Generate dashboard data for web interface"""
    aggregation_service = ResultAggregationService()

    # Load scan results
    if args.scan_files:
        scan_results = await load_scan_results(args.scan_files)
    else:
        print("No scan files provided. Use --scan-files to specify input files.")
        return

    if not scan_results:
        print("No valid scan results loaded.")
        return

    print(f"Generating dashboard data from {len(scan_results)} scan results...")

    # Generate dashboard data
    dashboard_data = await aggregation_service.generate_compliance_dashboard_data(scan_results)

    # Output dashboard data
    if args.output:
        with open(args.output, "w") as f:
            json.dump(dashboard_data, f, indent=2)
        print(f"Dashboard data exported to {args.output}")
    else:
        print(json.dumps(dashboard_data, indent=2))


async def trend_analysis(args):
    """Perform trend analysis on historical scan results"""
    aggregation_service = ResultAggregationService()

    # Load scan results
    if args.scan_files:
        scan_results = await load_scan_results(args.scan_files)
    else:
        print("No scan files provided. Use --scan-files to specify input files.")
        return

    if not scan_results:
        print("No valid scan results loaded.")
        return

    # Sort by time
    scan_results.sort(key=lambda sr: sr.started_at)

    print(f"Performing trend analysis on {len(scan_results)} scan results")
    print(f"Time range: {scan_results[0].started_at} to {scan_results[-1].started_at}")

    # Perform time series aggregation
    aggregated_results = await aggregation_service.aggregate_scan_results(
        scan_results, AggregationLevel.TIME_SERIES, args.time_period
    )

    # Display trend analysis
    print("\n" + "=" * 80)
    print("COMPLIANCE TREND ANALYSIS")
    print("=" * 80)

    for trend in aggregated_results.trend_analysis:
        print(f"\nMetric: {trend.metric_name}")
        print(f"Current Value: {trend.current_value:.1f}%")
        if trend.previous_value is not None:
            print(f"Previous Value: {trend.previous_value:.1f}%")
            if trend.change_percentage is not None:
                direction_symbol = (
                    "↗"
                    if trend.trend_direction.value == "improving"
                    else "↘" if trend.trend_direction.value == "declining" else "→"
                )
                print(f"Change: {direction_symbol} {trend.change_percentage:+.1f}% ({trend.trend_direction.value})")
        print(f"Data Points: {len(trend.data_points)}")

        if args.show_data_points:
            print("Historical Data:")
            for timestamp, value in trend.data_points[-10:]:  # Last 10 points
                print(f"  {timestamp.strftime('%Y-%m-%d %H:%M')} {value:6.1f}%")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Compliance result analysis and aggregation tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze scan results at organization level
  python -m backend.app.cli.result_analysis analyze --scan-files scan1.json scan2.json

  # Perform framework-level analysis with export
  python -m backend.app.cli.result_analysis analyze \\
    --scan-files *.json --level framework_level \\
    --export --export-format json --output results.json

  # Generate dashboard data
  python -m backend.app.cli.result_analysis dashboard \\
    --scan-files recent_scans/*.json --output dashboard.json

  # Trend analysis
  python -m backend.app.cli.result_analysis trends \\
    --scan-files historical/*.json --time-period "30 days"
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze compliance scan results")
    analyze_parser.add_argument(
        "--scan-files",
        nargs="+",
        required=True,
        help="JSON files containing scan results",
    )
    analyze_parser.add_argument(
        "--level",
        choices=["rule_level", "framework_level", "host_level", "organization_level"],
        default="organization_level",
        help="Aggregation level (default: organization_level)",
    )
    analyze_parser.add_argument("--time-period", default="current", help="Time period description for analysis")
    analyze_parser.add_argument("--show-hosts", action="store_true", help="Show per-host breakdown")
    analyze_parser.add_argument("--show-strategic", action="store_true", help="Show strategic recommendations")
    analyze_parser.add_argument("--show-comparisons", action="store_true", help="Show framework comparisons")
    analyze_parser.add_argument("--show-performance", action="store_true", help="Show performance metrics")
    analyze_parser.add_argument(
        "--max-gaps",
        type=int,
        default=5,
        help="Maximum number of compliance gaps to show",
    )
    analyze_parser.add_argument("--export", action="store_true", help="Export results")
    analyze_parser.add_argument(
        "--export-format",
        choices=["json", "csv"],
        default="json",
        help="Export format (default: json)",
    )
    analyze_parser.add_argument("--output", help="Output file for exported results")

    # Dashboard command
    dashboard_parser = subparsers.add_parser("dashboard", help="Generate dashboard data")
    dashboard_parser.add_argument(
        "--scan-files",
        nargs="+",
        required=True,
        help="JSON files containing scan results",
    )
    dashboard_parser.add_argument("--output", help="Output file for dashboard data (JSON format)")

    # Trends command
    trends_parser = subparsers.add_parser("trends", help="Perform trend analysis")
    trends_parser.add_argument(
        "--scan-files",
        nargs="+",
        required=True,
        help="JSON files containing historical scan results",
    )
    trends_parser.add_argument(
        "--time-period",
        default="historical",
        help="Time period description for trend analysis",
    )
    trends_parser.add_argument("--show-data-points", action="store_true", help="Show historical data points")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    try:
        if args.command == "analyze":
            asyncio.run(analyze_results(args))
        elif args.command == "dashboard":
            asyncio.run(generate_dashboard_data(args))
        elif args.command == "trends":
            asyncio.run(trend_analysis(args))

        return 0

    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
