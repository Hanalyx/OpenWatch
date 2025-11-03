#!/usr/bin/env python3
"""
Scan Orchestrator Service

Central coordinator for multi-scanner compliance scanning.
Routes rules to appropriate scanners and aggregates results.
"""

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from ..models.scan_models import (
    RuleResult,
    ScanConfiguration,
    ScanResult,
    ScanResultSummary,
    ScanStatus,
)
from .scanners import ScannerFactory

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """
    Orchestrates compliance scanning across multiple scanner types

    Responsibilities:
    1. Query rules from MongoDB based on scan configuration
    2. Group rules by scanner_type
    3. Execute scanners in parallel
    4. Aggregate results from all scanners
    5. Store results in MongoDB
    """

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.compliance_rules
        self.scanner_factory = ScannerFactory()

    async def execute_scan(
        self,
        config: ScanConfiguration,
        started_by: str,
        scan_name: Optional[str] = None,
    ) -> ScanResult:
        """
        Execute compliance scan

        Args:
            config: Scan configuration (target, framework, variables, etc.)
            started_by: Username/ID of user who initiated scan
            scan_name: Optional human-readable scan name

        Returns:
            ScanResult with complete scan execution details
        """
        # Generate scan ID
        scan_id = str(uuid.uuid4())

        logger.info(f"Starting scan {scan_id}: framework={config.framework}, target={config.target.identifier}")

        # Create initial scan result record
        scan_result = ScanResult(
            scan_id=scan_id,
            scan_name=scan_name,
            config=config,
            status=ScanStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            started_by=started_by,
        )

        # Save to MongoDB
        await scan_result.insert()

        try:
            # 1. Query rules from MongoDB
            rules = await self._get_rules(config)

            if not rules:
                scan_result.status = ScanStatus.FAILED
                scan_result.errors.append("No rules found matching scan configuration")
                scan_result.completed_at = datetime.now(timezone.utc)
                await scan_result.save()
                return scan_result

            logger.info(f"Scan {scan_id}: Found {len(rules)} rules")

            # 2. Group rules by scanner_type
            rules_by_scanner = self._group_by_scanner(rules)

            logger.info(f"Scan {scan_id}: Grouped into {len(rules_by_scanner)} scanner types")

            # 3. Execute scanners in parallel
            scanner_tasks = []
            for scanner_type, scanner_rules in rules_by_scanner.items():
                task = self._execute_scanner(scanner_type=scanner_type, rules=scanner_rules, config=config)
                scanner_tasks.append(task)

            # Wait for all scanners to complete
            scanner_results = await asyncio.gather(*scanner_tasks, return_exceptions=True)

            # 4. Aggregate results
            all_rule_results = []
            scanner_versions = {}
            errors = []
            warnings = []

            for idx, result in enumerate(scanner_results):
                if isinstance(result, Exception):
                    scanner_type = list(rules_by_scanner.keys())[idx]
                    error_msg = f"Scanner {scanner_type} failed: {str(result)}"
                    logger.error(error_msg)
                    errors.append(error_msg)
                else:
                    rule_results, summary, version = result
                    all_rule_results.extend(rule_results)
                    scanner_type = rule_results[0].scanner_type if rule_results else f"scanner_{idx}"
                    scanner_versions[scanner_type] = version

            # 5. Calculate overall summary
            overall_summary = self._calculate_overall_summary(all_rule_results)

            # 6. Update scan result
            scan_result.status = ScanStatus.COMPLETED
            scan_result.completed_at = datetime.now(timezone.utc)
            scan_result.duration_seconds = (scan_result.completed_at - scan_result.started_at).total_seconds()
            scan_result.summary = overall_summary
            scan_result.results_by_rule = all_rule_results
            scan_result.scanner_versions = scanner_versions
            scan_result.errors = errors
            scan_result.warnings = warnings

            await scan_result.save()

            logger.info(
                f"Scan {scan_id} completed: "
                f"{overall_summary.passed}/{overall_summary.total_rules} passed "
                f"({overall_summary.compliance_percentage:.1f}%)"
            )

            return scan_result

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")

            # Update scan result with error
            scan_result.status = ScanStatus.FAILED
            scan_result.completed_at = datetime.now(timezone.utc)
            scan_result.errors.append(str(e))
            await scan_result.save()

            raise

    async def _get_rules(self, config: ScanConfiguration) -> List[Dict[str, Any]]:
        """
        Query rules from MongoDB based on scan configuration

        Filters:
        - is_latest: true (only get current version)
        - framework/framework_version if specified
        - Additional rule_filter from config
        """
        query = {"is_latest": True}

        # Filter by framework
        if config.framework and config.framework_version:
            query[f"frameworks.{config.framework}.{config.framework_version}"] = {"$exists": True}

        # Apply additional filters
        if config.rule_filter:
            query.update(config.rule_filter)

        # Query MongoDB
        rules = await self.collection.find(query).to_list(length=None)

        return rules

    def _group_by_scanner(self, rules: List[Dict[str, Any]]) -> Dict[str, List[Dict]]:
        """
        Group rules by scanner_type

        Returns: Dict mapping scanner_type to list of rules
        """
        groups = {}

        for rule in rules:
            scanner_type = rule.get("scanner_type", "oscap")  # Default to oscap

            if scanner_type not in groups:
                groups[scanner_type] = []

            groups[scanner_type].append(rule)

        return groups

    async def _execute_scanner(
        self, scanner_type: str, rules: List[Dict[str, Any]], config: ScanConfiguration
    ) -> tuple[List[RuleResult], ScanResultSummary, str]:
        """
        Execute a single scanner

        Returns: (rule_results, summary, scanner_version)
        """
        logger.info(f"Executing {scanner_type} scanner with {len(rules)} rules")

        # Get scanner instance
        scanner = self.scanner_factory.get_scanner(scanner_type)

        # Execute scan
        rule_results, summary = await scanner.scan(
            rules=rules,
            target=config.target,
            variables=config.variable_overrides,
            scan_options=config.scan_options,
        )

        return rule_results, summary, scanner.version

    def _calculate_overall_summary(self, all_results: List[RuleResult]) -> ScanResultSummary:
        """Calculate overall summary from all scanner results"""
        summary = ScanResultSummary(total_rules=len(all_results))

        # Count by status
        for result in all_results:
            if result.status == "pass":
                summary.passed += 1
            elif result.status == "fail":
                summary.failed += 1
            elif result.status == "error":
                summary.error += 1
            elif result.status == "notapplicable":
                summary.not_applicable += 1
            elif result.status == "notchecked":
                summary.not_checked += 1
            elif result.status == "notselected":
                summary.not_selected += 1
            elif result.status == "informational":
                summary.informational += 1
            elif result.status == "fixed":
                summary.fixed += 1

        # Calculate compliance percentage
        evaluated = summary.passed + summary.failed
        if evaluated > 0:
            summary.compliance_percentage = (summary.passed / evaluated) * 100

        # Breakdown by severity
        summary.by_severity = self._group_by_severity(all_results)

        # Breakdown by scanner
        summary.by_scanner = self._group_by_scanner_summary(all_results)

        return summary

    def _group_by_severity(self, results: List[RuleResult]) -> Dict[str, Dict[str, int]]:
        """Group results by severity"""
        by_severity = {}

        for result in results:
            severity = result.severity
            if severity not in by_severity:
                by_severity[severity] = {
                    "total": 0,
                    "passed": 0,
                    "failed": 0,
                    "error": 0,
                }

            by_severity[severity]["total"] += 1

            if result.status == "pass":
                by_severity[severity]["passed"] += 1
            elif result.status == "fail":
                by_severity[severity]["failed"] += 1
            elif result.status == "error":
                by_severity[severity]["error"] += 1

        return by_severity

    def _group_by_scanner_summary(self, results: List[RuleResult]) -> Dict[str, Dict[str, int]]:
        """Group results by scanner type"""
        by_scanner = {}

        for result in results:
            scanner = result.scanner_type
            if scanner not in by_scanner:
                by_scanner[scanner] = {"total": 0, "passed": 0, "failed": 0}

            by_scanner[scanner]["total"] += 1

            if result.status == "pass":
                by_scanner[scanner]["passed"] += 1
            elif result.status == "fail":
                by_scanner[scanner]["failed"] += 1

        return by_scanner

    async def get_scan_result(self, scan_id: str) -> Optional[ScanResult]:
        """Get scan result by ID"""
        return await ScanResult.find_one(ScanResult.scan_id == scan_id)

    async def list_scans(
        self,
        skip: int = 0,
        limit: int = 50,
        status: Optional[ScanStatus] = None,
        started_by: Optional[str] = None,
    ) -> List[ScanResult]:
        """List scans with optional filters"""
        query = {}

        if status:
            query["status"] = status

        if started_by:
            query["started_by"] = started_by

        return await ScanResult.find(query).skip(skip).limit(limit).sort("-started_at").to_list()
