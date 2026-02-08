"""
Scan Orchestrator

Central coordinator for multi-scanner compliance scanning.
Routes rules to appropriate scanners and aggregates results.

This module is part of the engine layer, providing core scanning orchestration
that can be used by API endpoints, CLI tools, and background tasks.

Responsibilities:
    1. Query rules from MongoDB based on scan configuration
    2. Group rules by scanner_type
    3. Execute scanners in parallel
    4. Aggregate results from all scanners
    5. Store results in MongoDB

Example:
    from app.services.engine import ScanOrchestrator

    orchestrator = ScanOrchestrator(db=mongodb)
    result = await orchestrator.execute_scan(
        config=scan_config,
        started_by="admin",
        scan_name="Weekly STIG Compliance"
    )
"""

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.scan_models import RuleResult, ScanConfiguration, ScanResult, ScanResultSummary, ScanStatus
from app.repositories import ComplianceRuleRepository, ScanResultRepository

# Scanner factory from the parent engine module
# Provides registry-based scanner instantiation for multi-scanner orchestration
from ..scanners import ScannerFactory

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """
    Orchestrates compliance scanning across multiple scanner types.

    The orchestrator is the central coordinator for multi-scanner compliance
    scanning. It handles the complete scan lifecycle:

    1. Query rules from MongoDB based on scan configuration
    2. Group rules by scanner_type (oscap, kubernetes, custom, etc.)
    3. Execute scanners in parallel for efficiency
    4. Aggregate results from all scanners
    5. Calculate overall compliance summary
    6. Store results in MongoDB

    Attributes:
        db: AsyncIOMotorDatabase for MongoDB operations.
        collection: MongoDB collection for compliance rules.
        scanner_factory: Factory for creating scanner instances.

    Example:
        >>> orchestrator = ScanOrchestrator(db=mongodb)
        >>> result = await orchestrator.execute_scan(
        ...     config=scan_config,
        ...     started_by="admin",
        ...     scan_name="Weekly STIG Compliance"
        ... )
        >>> print(f"Compliance: {result.summary.compliance_percentage}%")
    """

    def __init__(self, db: AsyncIOMotorDatabase):
        """
        Initialize the scan orchestrator.

        Args:
            db: AsyncIOMotorDatabase instance for MongoDB operations.
        """
        self.db = db
        self.scanner_factory = ScannerFactory()

        # Repository Pattern: Centralized MongoDB access
        self._scan_result_repo = ScanResultRepository()
        self._compliance_repo = ComplianceRuleRepository()

    async def execute_scan(
        self,
        config: ScanConfiguration,
        started_by: str,
        scan_name: Optional[str] = None,
    ) -> ScanResult:
        """
        Execute compliance scan.

        This is the main entry point for scan execution. It coordinates
        the complete scan lifecycle from rule selection to result storage.

        Args:
            config: Scan configuration (target, framework, variables, etc.)
            started_by: Username/ID of user who initiated scan
            scan_name: Optional human-readable scan name

        Returns:
            ScanResult with complete scan execution details including:
            - scan_id: Unique identifier for this scan
            - status: Final scan status (COMPLETED, FAILED)
            - summary: Compliance statistics
            - results_by_rule: Individual rule results
            - scanner_versions: Versions of scanners used
            - errors: Any errors encountered
            - warnings: Any warnings generated

        Raises:
            Exception: If scan execution fails critically.
        """
        # Generate scan ID
        scan_id = str(uuid.uuid4())

        logger.info(
            "Starting scan %s: framework=%s, target=%s",
            scan_id,
            config.framework,
            config.target.identifier,
        )

        # Create initial scan result record
        scan_result = ScanResult(
            scan_id=scan_id,
            scan_name=scan_name,
            config=config,
            status=ScanStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            started_by=started_by,
        )

        # Repository Pattern: Use create() for new documents
        await self._scan_result_repo.create(scan_result)

        try:
            # 1. Query rules from MongoDB
            rules = await self._get_rules(config)

            if not rules:
                scan_result.status = ScanStatus.FAILED
                scan_result.errors.append("No rules found matching scan configuration")
                scan_result.completed_at = datetime.now(timezone.utc)
                # Repository Pattern: Use update_one() for updates
                await self._scan_result_repo.update_one(
                    {"scan_id": scan_result.scan_id},
                    {
                        "$set": {
                            "status": scan_result.status.value,
                            "errors": scan_result.errors,
                            "completed_at": scan_result.completed_at,
                        }
                    },
                )
                return scan_result

            logger.info("Scan %s: Found %d rules", scan_id, len(rules))

            # 2. Group rules by scanner_type
            rules_by_scanner = self._group_by_scanner(rules)

            logger.info(
                "Scan %s: Grouped into %d scanner types",
                scan_id,
                len(rules_by_scanner),
            )

            # 3. Execute scanners in parallel
            scanner_tasks = []
            for scanner_type, scanner_rules in rules_by_scanner.items():
                task = self._execute_scanner(scanner_type=scanner_type, rules=scanner_rules, config=config)
                scanner_tasks.append(task)

            # Wait for all scanners to complete
            scanner_results = await asyncio.gather(*scanner_tasks, return_exceptions=True)

            # 4. Aggregate results
            all_rule_results: List[RuleResult] = []
            scanner_versions: Dict[str, str] = {}
            errors: List[str] = []
            warnings: List[str] = []

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

            # Repository Pattern: Use update_one() for updates
            await self._scan_result_repo.update_one(
                {"scan_id": scan_result.scan_id},
                {
                    "$set": {
                        "status": scan_result.status.value,
                        "completed_at": scan_result.completed_at,
                        "duration_seconds": scan_result.duration_seconds,
                        "summary": scan_result.summary.model_dump(),
                        "results_by_rule": [r.model_dump() for r in scan_result.results_by_rule],
                        "scanner_versions": scan_result.scanner_versions,
                        "errors": scan_result.errors,
                        "warnings": scan_result.warnings,
                    }
                },
            )

            logger.info(
                "Scan %s completed: %d/%d passed (%.1f%%)",
                scan_id,
                overall_summary.passed,
                overall_summary.total_rules,
                overall_summary.compliance_percentage,
            )

            return scan_result

        except Exception as e:
            logger.error("Scan %s failed: %s", scan_id, e)

            # Update scan result with error
            scan_result.status = ScanStatus.FAILED
            scan_result.completed_at = datetime.now(timezone.utc)
            scan_result.errors.append(str(e))
            # Repository Pattern: Use update_one() for updates
            await self._scan_result_repo.update_one(
                {"scan_id": scan_result.scan_id},
                {
                    "$set": {
                        "status": scan_result.status.value,
                        "completed_at": scan_result.completed_at,
                        "errors": scan_result.errors,
                    }
                },
            )

            raise

    async def _get_rules(self, config: ScanConfiguration) -> List[Dict[str, Any]]:
        """
        Query rules from MongoDB based on scan configuration.

        Filters applied:
        - is_latest: true (only get current version)
        - framework/framework_version if specified
        - Additional rule_filter from config

        Args:
            config: Scan configuration with framework and filter settings.

        Returns:
            List of rule documents from MongoDB.
        """
        query: Dict[str, Any] = {"is_latest": True}

        # Filter by framework
        if config.framework and config.framework_version:
            query[f"frameworks.{config.framework}.{config.framework_version}"] = {"$exists": True}

        # Apply additional filters
        if config.rule_filter:
            query.update(config.rule_filter)

        # Repository Pattern: Use find_many() for queries
        rules = await self._compliance_repo.find_many(query, limit=10000)

        # Convert Beanie documents to dicts for scanner consumption
        return [rule.model_dump() if hasattr(rule, "model_dump") else rule for rule in rules]

    def _group_by_scanner(self, rules: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group rules by scanner_type.

        Args:
            rules: List of rule documents from MongoDB.

        Returns:
            Dict mapping scanner_type to list of rules for that scanner.
        """
        groups: Dict[str, List[Dict[str, Any]]] = {}

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
        Execute a single scanner.

        Args:
            scanner_type: Type of scanner to execute (e.g., "oscap", "kubernetes").
            rules: List of rules for this scanner.
            config: Scan configuration.

        Returns:
            Tuple of (rule_results, summary, scanner_version).
        """
        logger.info("Executing %s scanner with %d rules", scanner_type, len(rules))

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
        """
        Calculate overall summary from all scanner results.

        Args:
            all_results: Combined list of rule results from all scanners.

        Returns:
            ScanResultSummary with aggregated statistics.
        """
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
        """
        Group results by severity.

        Args:
            results: List of rule results.

        Returns:
            Dict mapping severity to status counts.
        """
        by_severity: Dict[str, Dict[str, int]] = {}

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
        """
        Group results by scanner type.

        Args:
            results: List of rule results.

        Returns:
            Dict mapping scanner_type to status counts.
        """
        by_scanner: Dict[str, Dict[str, int]] = {}

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
        """
        Get scan result by ID.

        Args:
            scan_id: Unique scan identifier.

        Returns:
            ScanResult if found, None otherwise.
        """
        # Repository Pattern: Use find_by_scan_id() for lookup
        return await self._scan_result_repo.find_by_scan_id(scan_id)

    async def list_scans(
        self,
        skip: int = 0,
        limit: int = 50,
        status: Optional[ScanStatus] = None,
        started_by: Optional[str] = None,
    ) -> List[ScanResult]:
        """
        List scans with optional filters.

        Args:
            skip: Number of records to skip (for pagination).
            limit: Maximum number of records to return.
            status: Filter by scan status.
            started_by: Filter by user who started the scan.

        Returns:
            List of ScanResult documents.
        """
        query: Dict[str, Any] = {}

        if status:
            query["status"] = status.value

        if started_by:
            query["started_by"] = started_by

        # Repository Pattern: Use find_many() with pagination and sort
        return await self._scan_result_repo.find_many(query, skip=skip, limit=limit, sort=[("started_at", -1)])
