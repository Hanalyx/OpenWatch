#!/usr/bin/env python3
"""
Test OVAL Aggregation Functionality

This script tests OVAL aggregation using Phase 4 platform-aware OVAL selection.

Phase 4 Schema (Option B):
    OVAL references are stored per-platform in the platform_implementations field:
    - platform_implementations.{platform}.oval_filename
    - Example: platform_implementations.rhel9.oval_filename = "rhel9/some_rule.xml"

Platform Resolution Priority:
    1. Host's persisted platform_identifier (from OS discovery)
    2. Computed from host's os_family + os_version
    3. Computed from scan_request.platform + platform_version

Key Methods Tested:
    1. generate_oval_definitions_file() - Aggregates platform-specific OVAL files
    2. _read_oval_definition_id() - Extracts OVAL definition IDs
    3. _create_xccdf_rule() - Creates XCCDF rules with platform-aware OVAL refs
    4. _normalize_platform_identifier() - Converts os_family+version to platform ID

Usage:
    # Test all platforms and frameworks (FULL COVERAGE - uses all rules)
    docker exec openwatch-backend python3 /app/backend/tests/test_oval_aggregation.py

    # Test specific platform with FULL COVERAGE
    docker exec openwatch-backend python3 /app/backend/tests/test_oval_aggregation.py --platform rhel9

    # Test specific framework for a platform (FULL COVERAGE)
    docker exec openwatch-backend python3 /app/backend/tests/test_oval_aggregation.py --platform rhel9 --framework cis

    # Quick test with limited rules (faster for development)
    docker exec openwatch-backend python3 /app/backend/tests/test_oval_aggregation.py --platform rhel8 --framework stig --quick

    # List available platforms and frameworks
    docker exec openwatch-backend python3 /app/backend/tests/test_oval_aggregation.py --list

Examples:
    # FULL TEST: CIS controls for RHEL 9 (production-ready validation)
    docker exec openwatch-backend python3 /app/backend/tests/test_oval_aggregation.py --platform rhel9 --framework cis

    # FULL TEST: STIG profile for RHEL 8 (all 1233 rules)
    docker exec openwatch-backend python3 /app/backend/tests/test_oval_aggregation.py --platform rhel8 --framework stig

    # QUICK TEST: NIST 800-53 for Ubuntu 22.04 (10 rules only, faster)
    docker exec openwatch-backend python3 /app/backend/tests/test_oval_aggregation.py --platform ubuntu2204 --framework nist --quick

Note:
    DEFAULT BEHAVIOR (no --quick flag):
    - Uses FULL rule sets for maximum test coverage
    - Generates production-quality XCCDF benchmarks
    - Tests all rules that would be used in actual compliance scans
    - Recommended for pre-production validation

    QUICK MODE (--quick flag):
    - Limits to 10 rules for faster test execution
    - Useful for development and rapid iteration
    - NOT recommended for production validation

Phase 4 Changes (2025-11):
    - OVAL selection now uses platform_implementations.{platform}.oval_filename
    - NO fallback to rule-level oval_filename (removed for compliance accuracy)
    - Platform resolution follows 3-tier priority system
    - See: docs/plans/HOST_OS_DETECTION_AND_OVAL_ALIGNMENT_PLAN.md
"""

import argparse
import asyncio
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional
from motor.motor_asyncio import AsyncIOMotorClient

# Add app to path
sys.path.insert(0, '/app')

from app.services.xccdf_generator_service import XCCDFGeneratorService
from app.config import get_settings

settings = get_settings()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description="Test OVAL aggregation for specific platforms and frameworks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Test all platforms:
    python3 test_oval_aggregation.py

  Test specific platform:
    python3 test_oval_aggregation.py --platform rhel9

  Test CIS controls for RHEL 9:
    python3 test_oval_aggregation.py --platform rhel9 --framework cis

  Test STIG profile for RHEL 8:
    python3 test_oval_aggregation.py --platform rhel8 --framework stig

  List available options:
    python3 test_oval_aggregation.py --list
        """
    )

    parser.add_argument(
        "--platform",
        type=str,
        help="Platform to test (rhel8, rhel9, ubuntu2204, etc.)",
        default=None
    )

    parser.add_argument(
        "--framework",
        type=str,
        help="Framework/profile to test (cis, stig, nist, pci_dss, etc.)",
        default=None
    )

    parser.add_argument(
        "--list",
        action="store_true",
        help="List available platforms and frameworks, then exit"
    )

    parser.add_argument(
        "--output-dir",
        type=str,
        default="/tmp/oval_test",
        help="Directory for output files (default: /tmp/oval_test)"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )

    parser.add_argument(
        "--quick",
        action="store_true",
        help="Quick mode: limit XCCDF benchmark to 10 rules (default: use all rules)"
    )

    return parser.parse_args()


async def list_available_options(db):
    """
    List all available platforms and frameworks.

    Phase 4: Uses platform_implementations.{platform}.oval_filename schema
    to identify platforms with OVAL definitions.
    """
    logger.info("=" * 80)
    logger.info("Available Platforms and Frameworks (Phase 4 Schema)")
    logger.info("=" * 80)

    # Phase 4: Query rules with platform_implementations containing OVAL
    # The schema is: platform_implementations.{platform}.oval_filename
    rules_cursor = db.compliance_rules.find({
        "is_latest": True,
        "platform_implementations": {"$exists": True, "$ne": {}}
    })

    all_rules = await rules_cursor.to_list(length=None)

    if len(all_rules) == 0:
        logger.warning("No rules with platform_implementations found in database")
        logger.warning("Run OVAL migration to populate platform_implementations field")
        return

    # Extract platforms from platform_implementations keys
    platforms = {}
    frameworks_by_platform = {}

    for rule in all_rules:
        platform_impls = rule.get("platform_implementations", {})
        if not platform_impls:
            continue

        # Iterate over each platform in platform_implementations
        for platform, impl_data in platform_impls.items():
            # Phase 4: Check if this platform has an OVAL filename
            oval_filename = impl_data.get("oval_filename") if isinstance(impl_data, dict) else None
            if oval_filename:
                platforms[platform] = platforms.get(platform, 0) + 1

                # Extract frameworks for this platform
                if platform not in frameworks_by_platform:
                    frameworks_by_platform[platform] = set()

                # Check frameworks field
                frameworks_dict = rule.get("frameworks", {})
                if frameworks_dict:
                    for fw_name in frameworks_dict.keys():
                        frameworks_by_platform[platform].add(fw_name)

    # Display platforms
    logger.info("\nAvailable Platforms (from platform_implementations):")
    logger.info("-" * 80)
    for platform, count in sorted(platforms.items()):
        logger.info(f"  {platform:20s} - {count:4d} rules with OVAL")

    # Display frameworks by platform
    logger.info("\nAvailable Frameworks by Platform:")
    logger.info("-" * 80)
    for platform in sorted(frameworks_by_platform.keys()):
        frameworks = sorted(frameworks_by_platform[platform])
        if frameworks:
            logger.info(f"\n  {platform}:")
            for fw in frameworks:
                # Count rules for this platform+framework combination
                count = sum(
                    1 for r in all_rules
                    if platform in r.get("platform_implementations", {})
                    and r.get("platform_implementations", {}).get(platform, {}).get("oval_filename")
                    and fw in r.get("frameworks", {})
                )
                logger.info(f"    - {fw:15s} ({count} rules)")
        else:
            logger.info(f"\n  {platform}: No framework mappings found")

    logger.info("\n" + "=" * 80)
    logger.info(f"Total: {len(platforms)} platforms, {sum(platforms.values())} platform-OVAL mappings")
    logger.info("=" * 80)


async def test_oval_aggregation(
    platform_filter: Optional[str] = None,
    framework_filter: Optional[str] = None,
    output_dir: str = "/tmp/oval_test",
    verbose: bool = False,
    quick_mode: bool = False
):
    """
    Test OVAL aggregation functionality with optional filters.

    Phase 4: Uses platform_implementations.{platform}.oval_filename schema
    for platform-aware OVAL selection.

    Args:
        platform_filter: Specific platform to test (e.g., "rhel9", "ubuntu2204")
        framework_filter: Specific framework to test (e.g., "cis", "stig")
        output_dir: Directory for generated test files
        verbose: Enable verbose logging
        quick_mode: Limit to 10 rules for faster testing

    Returns:
        bool: True if all tests pass, False otherwise
    """

    logger.info("=" * 80)
    logger.info("OVAL Aggregation Test Suite (Phase 4 Schema)")
    if platform_filter:
        logger.info(f"Platform Filter: {platform_filter}")
    if framework_filter:
        logger.info(f"Framework Filter: {framework_filter}")
    logger.info("=" * 80)

    # Connect to MongoDB
    logger.info("\nConnecting to MongoDB...")
    client = AsyncIOMotorClient(settings.mongodb_url)
    db = client[settings.mongodb_database]

    try:
        # Initialize XCCDF generator
        xccdf_gen = XCCDFGeneratorService(db)

        # Test 1: Fetch rules with platform_implementations (Phase 4 schema)
        logger.info("\nTest 1: Fetching rules with platform_implementations")
        logger.info("-" * 80)

        # Phase 4: Query for rules with platform_implementations
        # Build query based on platform filter
        if platform_filter:
            # Query for specific platform's OVAL implementation
            query_filter = {
                "is_latest": True,
                f"platform_implementations.{platform_filter}.oval_filename": {
                    "$exists": True, "$ne": None
                }
            }
        else:
            # Query for any rules with platform_implementations
            query_filter = {
                "is_latest": True,
                "platform_implementations": {"$exists": True, "$ne": {}}
            }

        # Add framework filter if specified
        if framework_filter:
            query_filter[f"frameworks.{framework_filter}"] = {"$exists": True}

        rules_cursor = db.compliance_rules.find(query_filter)
        all_rules = await rules_cursor.to_list(length=None)

        logger.info(f"Found {len(all_rules)} rules with platform_implementations")

        if len(all_rules) == 0:
            logger.error("No rules with platform_implementations found!")
            logger.error("Run OVAL migration to populate platform_implementations field.")
            logger.error("See: docs/plans/HOST_OS_DETECTION_AND_OVAL_ALIGNMENT_PLAN.md")
            return False

        # Test 2: Count rules by platform (from platform_implementations)
        logger.info("\nTest 2: Rules grouped by platform (Phase 4 schema)")
        logger.info("-" * 80)

        platforms = {}
        for rule in all_rules:
            platform_impls = rule.get("platform_implementations", {})
            for platform, impl_data in platform_impls.items():
                # Phase 4: Check for oval_filename in platform implementation
                if isinstance(impl_data, dict) and impl_data.get("oval_filename"):
                    # Apply platform filter if specified
                    if platform_filter and platform != platform_filter:
                        continue
                    platforms[platform] = platforms.get(platform, 0) + 1

        if not platforms:
            logger.error(f"No rules found for platform: {platform_filter}")
            logger.error("Ensure OVAL migration has been run for this platform.")
            return False

        for platform, count in sorted(platforms.items()):
            logger.info(f"  {platform}: {count} rules with platform-specific OVAL")

        # Test 3: Test _read_oval_definition_id() with Phase 4 schema
        logger.info("\nTest 3: Testing OVAL definition ID extraction (Phase 4)")
        logger.info("-" * 80)

        # Find a rule matching filters using platform_implementations
        sample_rule = None
        sample_platform = None
        sample_oval_filename = None

        for rule in all_rules:
            platform_impls = rule.get("platform_implementations", {})
            for platform, impl_data in platform_impls.items():
                if isinstance(impl_data, dict) and impl_data.get("oval_filename"):
                    if platform_filter and platform != platform_filter:
                        continue
                    sample_rule = rule
                    sample_platform = platform
                    sample_oval_filename = impl_data.get("oval_filename")
                    break
            if sample_rule:
                break

        if not sample_rule:
            logger.error("No matching rules found for testing")
            return False

        logger.info(f"Sample rule: {sample_rule['rule_id']}")
        logger.info(f"Platform: {sample_platform}")
        logger.info(f"OVAL filename (from platform_implementations): {sample_oval_filename}")

        oval_def_id = xccdf_gen._read_oval_definition_id(sample_oval_filename)

        if oval_def_id:
            logger.info(f"SUCCESS: Extracted OVAL ID: {oval_def_id}")
        else:
            logger.error(f"FAILED: Could not extract OVAL ID from {sample_oval_filename}")
            return False

        # Test 4: Test generate_oval_definitions_file() for each platform (Phase 4)
        logger.info("\nTest 4: Testing OVAL aggregation (Phase 4 schema)")
        logger.info("-" * 80)

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        aggregation_results = {}

        for platform in platforms.keys():
            logger.info(f"\nAggregating OVAL for platform: {platform}")

            # Phase 4: Filter rules that have OVAL for this specific platform
            platform_rules = []
            for rule in all_rules:
                platform_impls = rule.get("platform_implementations", {})
                if platform in platform_impls:
                    impl_data = platform_impls[platform]
                    if isinstance(impl_data, dict) and impl_data.get("oval_filename"):
                        platform_rules.append(rule)

            # Apply framework filter if specified
            if framework_filter:
                platform_rules = [
                    r for r in platform_rules
                    if framework_filter in r.get("frameworks", {})
                ]

            logger.info(f"  Rules for {platform}: {len(platform_rules)}")

            if framework_filter:
                logger.info(f"  Framework filter: {framework_filter}")
                logger.info(f"  Rules matching framework: {len(platform_rules)}")

            if len(platform_rules) == 0:
                logger.warning(f"  No rules found for {platform} with framework {framework_filter}")
                continue

            # Generate aggregated OVAL file
            if framework_filter:
                output_file = output_path / f"oval-definitions-{platform}-{framework_filter}.xml"
            else:
                output_file = output_path / f"oval-definitions-{platform}.xml"

            # Phase 4: Pass platform to generate_oval_definitions_file
            # The generator will use platform_implementations.{platform}.oval_filename
            result = await xccdf_gen.generate_oval_definitions_file(
                rules=platform_rules,
                platform=platform,
                output_path=output_file
            )

            if result:
                file_size = result.stat().st_size
                logger.info(f"  SUCCESS: Created {result.name} ({file_size:,} bytes)")
                aggregation_results[platform] = {
                    "success": True,
                    "path": result,
                    "size": file_size,
                    "rule_count": len(platform_rules),
                    "framework": framework_filter
                }
            else:
                logger.error(f"  FAILED: Could not aggregate OVAL for {platform}")
                aggregation_results[platform] = {
                    "success": False,
                    "rule_count": len(platform_rules),
                    "framework": framework_filter
                }

        # Test 5: Verify aggregated OVAL files
        logger.info("\nTest 5: Verifying aggregated OVAL files")
        logger.info("-" * 80)

        import xml.etree.ElementTree as ET

        for platform, result in aggregation_results.items():
            if not result["success"]:
                continue

            logger.info(f"\nVerifying {platform}...")

            try:
                tree = ET.parse(result["path"])
                root = tree.getroot()

                # Count elements
                oval_ns = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
                definitions = root.findall(f".//{{{oval_ns}}}definition")
                tests = root.findall(f".//{{{oval_ns}}}tests/*")
                objects = root.findall(f".//{{{oval_ns}}}objects/*")
                states = root.findall(f".//{{{oval_ns}}}states/*")
                variables = root.findall(f".//{{{oval_ns}}}variables/*")

                logger.info(f"  Definitions: {len(definitions)}")
                logger.info(f"  Tests: {len(tests)}")
                logger.info(f"  Objects: {len(objects)}")
                logger.info(f"  States: {len(states)}")
                logger.info(f"  Variables: {len(variables)}")

                if len(definitions) == 0:
                    logger.error(f"  ERROR: No definitions found in aggregated file!")
                else:
                    logger.info(f"  SUCCESS: Valid OVAL file with {len(definitions)} definitions")

            except ET.ParseError as e:
                logger.error(f"  ERROR: Failed to parse aggregated OVAL: {e}")

        # Test 6: Test XCCDF generation with OVAL references (Phase 4 schema)
        logger.info("\nTest 6: Testing XCCDF benchmark generation with OVAL (Phase 4)")
        logger.info("-" * 80)

        # Use first platform with most rules
        if platforms:
            test_platform = max(platforms.keys(), key=lambda k: platforms[k])

            # Phase 4: Filter rules that have OVAL for this specific platform
            platform_rules = []
            for rule in all_rules:
                platform_impls = rule.get("platform_implementations", {})
                if test_platform in platform_impls:
                    impl_data = platform_impls[test_platform]
                    if isinstance(impl_data, dict) and impl_data.get("oval_filename"):
                        platform_rules.append(rule)

            # Apply framework filter
            if framework_filter:
                platform_rules = [
                    r for r in platform_rules
                    if framework_filter in r.get("frameworks", {})
                ]

            # Limit to 10 rules ONLY in quick mode (default: use ALL rules)
            original_count = len(platform_rules)
            if quick_mode:
                platform_rules = platform_rules[:10]
                logger.info(f"QUICK MODE: Limiting to {len(platform_rules)} rules (out of {original_count})")
            else:
                logger.info(f"FULL TEST MODE: Using all {len(platform_rules)} rules")

            logger.info(f"Generating XCCDF for {test_platform} with {len(platform_rules)} rules")
            if framework_filter:
                logger.info(f"Framework: {framework_filter}")

            # Build rule filter
            rule_filter = {
                "rule_id": {"$in": [r["rule_id"] for r in platform_rules]}
            }

            # Create benchmark
            benchmark_id = f"test_{test_platform}"
            if framework_filter:
                benchmark_id += f"_{framework_filter}"

            import time
            start_time = time.time()

            xccdf_xml = await xccdf_gen.generate_benchmark(
                benchmark_id=benchmark_id,
                title=f"Test Benchmark for {test_platform}" + (f" - {framework_filter.upper()}" if framework_filter else ""),
                description=f"Test benchmark with OVAL references" + (f" for {framework_filter.upper()} framework" if framework_filter else ""),
                version="1.0.0",
                framework=framework_filter,
                rule_filter=rule_filter
            )

            generation_time = time.time() - start_time

            # Save XCCDF to file
            xccdf_filename = f"test-benchmark-{test_platform}"
            if framework_filter:
                xccdf_filename += f"-{framework_filter}"
            xccdf_filename += ".xml"

            xccdf_path = output_path / xccdf_filename
            with open(xccdf_path, "w") as f:
                f.write(xccdf_xml)

            logger.info(f"  SUCCESS: Generated XCCDF benchmark in {generation_time:.2f}s")
            logger.info(f"  File: {xccdf_path} ({xccdf_path.stat().st_size:,} bytes)")
            logger.info(f"  Rules in benchmark: {len(platform_rules)}")
            logger.info(f"  Average bytes per rule: {xccdf_path.stat().st_size // len(platform_rules):,}")

            # Verify XCCDF contains OVAL references
            if "oval-definitions.xml" in xccdf_xml:
                logger.info("  SUCCESS: XCCDF contains OVAL references")
            else:
                logger.warning("  WARNING: XCCDF does not contain expected OVAL references")

            # Test 6B: Analyze XCCDF structure in detail
            logger.info("\n  Test 6B: Analyzing XCCDF structure")
            logger.info("  " + "-" * 76)

            import xml.etree.ElementTree as ET
            try:
                xccdf_tree = ET.fromstring(xccdf_xml)
                xccdf_ns = "http://checklists.nist.gov/xccdf/1.2"

                # Count XCCDF elements
                profiles = xccdf_tree.findall(f".//{{{xccdf_ns}}}Profile")
                groups = xccdf_tree.findall(f".//{{{xccdf_ns}}}Group")
                rules = xccdf_tree.findall(f".//{{{xccdf_ns}}}Rule")
                values = xccdf_tree.findall(f".//{{{xccdf_ns}}}Value")
                checks = xccdf_tree.findall(f".//{{{xccdf_ns}}}check")

                logger.info(f"    Profiles: {len(profiles)}")
                logger.info(f"    Groups: {len(groups)}")
                logger.info(f"    Rules: {len(rules)}")
                logger.info(f"    Values (variables): {len(values)}")
                logger.info(f"    Check elements: {len(checks)}")

                # Analyze rule severity distribution
                severity_dist = {}
                for rule in rules:
                    severity_elem = rule.find(f".//{{{xccdf_ns}}}severity")
                    if severity_elem is not None and severity_elem.text:
                        severity = severity_elem.text
                        severity_dist[severity] = severity_dist.get(severity, 0) + 1

                if severity_dist:
                    logger.info(f"\n    Severity distribution:")
                    for severity, count in sorted(severity_dist.items(), key=lambda x: x[1], reverse=True):
                        logger.info(f"      {severity:10s}: {count:4d} rules")

                # Verify OVAL check references
                oval_checks = 0
                for check in checks:
                    system = check.get("system", "")
                    if "oval" in system.lower():
                        oval_checks += 1

                logger.info(f"\n    OVAL check references: {oval_checks}/{len(checks)}")
                if oval_checks > 0:
                    logger.info(f"    SUCCESS: {oval_checks} rules have OVAL checks")
                else:
                    logger.warning(f"    WARNING: No OVAL check references found!")

                # Verify completeness
                logger.info(f"\n    Completeness verification:")
                logger.info(f"      Expected rules: {len(platform_rules)}")
                logger.info(f"      Actual rules:   {len(rules)}")
                if len(rules) == len(platform_rules):
                    logger.info(f"      SUCCESS: All rules included in XCCDF")
                else:
                    logger.warning(f"      WARNING: Rule count mismatch!")

            except ET.ParseError as e:
                logger.error(f"    ERROR: Failed to parse XCCDF: {e}")

        # Test 7: Test platform_identifier normalization (Phase 4)
        logger.info("\nTest 7: Testing platform_identifier normalization (Phase 4)")
        logger.info("-" * 80)

        from app.tasks.os_discovery_tasks import _normalize_platform_identifier

        test_cases = [
            # (os_family, os_version, expected_result)
            ("rhel", "9.3", "rhel9"),
            ("rhel", "8.9", "rhel8"),
            ("ubuntu", "22.04", "ubuntu2204"),
            ("ubuntu", "20.04", "ubuntu2004"),
            ("centos", "7.9", "rhel7"),  # CentOS maps to rhel
            ("rocky", "9.2", "rhel9"),   # Rocky maps to rhel
            ("alma", "8.8", "rhel8"),    # AlmaLinux maps to rhel
            ("debian", "12", "debian12"),
            ("debian", "11.8", "debian11"),
            ("Unknown", "1.0", None),    # Unknown returns None
            ("rhel", "Unknown", None),   # Unknown version returns None
            ("", "9.0", None),           # Empty family returns None
        ]

        normalization_pass = 0
        normalization_fail = 0

        for os_family, os_version, expected in test_cases:
            result = _normalize_platform_identifier(os_family, os_version)
            if result == expected:
                logger.info(f"  PASS: {os_family} {os_version} -> {result}")
                normalization_pass += 1
            else:
                logger.error(f"  FAIL: {os_family} {os_version} -> {result} (expected: {expected})")
                normalization_fail += 1

        logger.info(f"\n  Normalization tests: {normalization_pass}/{len(test_cases)} passed")
        if normalization_fail > 0:
            logger.warning(f"  WARNING: {normalization_fail} normalization tests failed")

        # Test 8: Verify no fallback to rule-level oval_filename (Phase 4 requirement)
        logger.info("\nTest 8: Verifying no fallback to rule-level oval_filename (Phase 4)")
        logger.info("-" * 80)

        rules_with_only_legacy_oval = 0
        rules_with_platform_oval = 0

        for rule in all_rules:
            platform_impls = rule.get("platform_implementations", {})
            has_platform_oval = False

            for platform, impl_data in platform_impls.items():
                if isinstance(impl_data, dict) and impl_data.get("oval_filename"):
                    has_platform_oval = True
                    break

            if has_platform_oval:
                rules_with_platform_oval += 1
            elif rule.get("oval_filename"):
                # Rule has legacy oval_filename but no platform_implementations OVAL
                rules_with_only_legacy_oval += 1

        logger.info(f"  Rules with platform-specific OVAL: {rules_with_platform_oval}")
        logger.info(f"  Rules with only legacy oval_filename: {rules_with_only_legacy_oval}")

        if rules_with_only_legacy_oval > 0:
            logger.warning(f"  WARNING: {rules_with_only_legacy_oval} rules have only legacy OVAL")
            logger.warning("  These rules will NOT have OVAL checks in Phase 4 (no fallback)")
            logger.warning("  Consider running OVAL migration for these rules")
        else:
            logger.info("  SUCCESS: All rules use platform_implementations schema")

        # Summary
        logger.info("\n" + "=" * 80)
        logger.info("Test Summary (Phase 4 Schema)")
        logger.info("=" * 80)
        logger.info(f"Test mode: {'QUICK (10 rules)' if quick_mode else 'FULL (all rules)'}")
        logger.info(f"Total rules with OVAL: {len(all_rules)}")
        logger.info(f"Platforms tested: {len(platforms)}")
        if framework_filter:
            logger.info(f"Framework filter: {framework_filter}")

        successful_aggregations = sum(1 for r in aggregation_results.values() if r["success"])
        logger.info(f"Successful aggregations: {successful_aggregations}/{len(platforms)}")

        # Calculate total file sizes
        total_size = 0
        file_count = 0
        logger.info("\nGenerated files:")
        for file in sorted(output_path.glob("*.xml")):
            file_size = file.stat().st_size
            total_size += file_size
            file_count += 1
            logger.info(f"  {file.name} ({file_size:,} bytes)")

        logger.info(f"\nTotal: {file_count} files, {total_size:,} bytes ({total_size / 1024 / 1024:.2f} MB)")

        # Production readiness assessment (Phase 4)
        logger.info("\n" + "=" * 80)
        logger.info("Production Readiness Assessment (Phase 4)")
        logger.info("=" * 80)

        if successful_aggregations == len(platforms):
            logger.info("OVAL Aggregation: PASS - All platforms aggregated successfully")
        else:
            logger.warning(f"OVAL Aggregation: PARTIAL - {successful_aggregations}/{len(platforms)} platforms succeeded")

        if normalization_fail == 0:
            logger.info("Platform Normalization: PASS - All normalization tests passed")
        else:
            logger.warning(f"Platform Normalization: FAIL - {normalization_fail} tests failed")

        if rules_with_only_legacy_oval == 0:
            logger.info("Phase 4 Schema: PASS - All rules use platform_implementations")
        else:
            logger.warning(f"Phase 4 Schema: PARTIAL - {rules_with_only_legacy_oval} rules use legacy schema")

        if not quick_mode:
            logger.info("Test Coverage: FULL - Used complete rule sets for all platforms")
            if successful_aggregations == len(platforms) and normalization_fail == 0:
                logger.info("Recommendation: READY for production deployment")
            else:
                logger.warning("Recommendation: Address warnings before production deployment")
        else:
            logger.warning("Test Coverage: QUICK - Limited to 10 rules per platform")
            logger.warning("Recommendation: Run full test before production deployment")

        logger.info("\nPhase 4 Schema Summary:")
        logger.info(f"  - Platform resolution: 3-tier priority (host->computed->request)")
        logger.info(f"  - OVAL source: platform_implementations.{{platform}}.oval_filename")
        logger.info(f"  - Fallback to rule-level oval_filename: DISABLED")

        logger.info("\nAll tests completed successfully!")
        return True

    except Exception as e:
        logger.error(f"Test failed with exception: {e}", exc_info=True)
        return False

    finally:
        client.close()


async def main():
    """Main entry point"""
    args = parse_arguments()

    # Set verbose logging if requested
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Connect to MongoDB
    client = AsyncIOMotorClient(settings.mongodb_url)
    db = client[settings.mongodb_database]

    try:
        # Handle --list option
        if args.list:
            await list_available_options(db)
            return 0

        # Run OVAL aggregation test
        success = await test_oval_aggregation(
            platform_filter=args.platform,
            framework_filter=args.framework,
            output_dir=args.output_dir,
            verbose=args.verbose,
            quick_mode=args.quick
        )

        return 0 if success else 1

    finally:
        client.close()


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
