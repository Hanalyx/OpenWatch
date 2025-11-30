"""
Remediation orchestrator service for ORSA architecture.

Coordinates remediation execution across multiple executors, manages remediation
lifecycle, tracks results, and integrates with MongoDB for rule retrieval and
result storage.
"""

import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from ..models.remediation_models import (
    BulkRemediationJob,
    RemediationExecutionResult,
    RemediationResult,
    RemediationStatus,
    RemediationSummary,
    RemediationTarget,
)
from .remediators import RemediationExecutorFactory

logger = logging.getLogger(__name__)


class RemediationOrchestrator:
    """
    Central coordinator for remediation execution.

    Responsibilities:
    - Query rules from MongoDB
    - Route to appropriate executor based on remediation type
    - Execute remediations with proper error handling
    - Track remediation status and results
    - Support bulk remediation from scan results
    - Manage rollback operations
    """

    def __init__(self, db: AsyncIOMotorDatabase):
        """
        Initialize remediation orchestrator.

        Args:
            db: MongoDB database instance
        """
        self.db = db
        self.collection = db.compliance_rules

    async def execute_remediation(
        self,
        rule_id: str,
        target: RemediationTarget,
        variable_overrides: Optional[Dict[str, str]] = None,
        dry_run: bool = False,
        executed_by: str = None,
        scan_id: Optional[str] = None,
    ) -> RemediationResult:
        """
        Execute remediation for a single rule.

        Args:
            rule_id: Rule ID to remediate
            target: Target system
            variable_overrides: Variable values to override
            dry_run: Preview mode (no actual changes)
            executed_by: Username executing remediation
            scan_id: Related scan ID (if applicable)

        Returns:
            RemediationResult document

        Raises:
            ValueError: Rule not found or missing remediation
            ExecutorNotAvailableError: Executor tool not available
            ExecutorValidationError: Remediation content invalid
            ExecutorExecutionError: Execution failed
        """
        remediation_id = str(uuid.uuid4())

        logger.info(
            f"Starting remediation {remediation_id} for rule {rule_id} " f"(dry_run={dry_run})"
        )

        # Query rule from MongoDB
        rule = await self._get_rule(rule_id)

        # Extract remediation content
        remediation_data = rule.get("remediation")
        if not remediation_data:
            raise ValueError(f"Rule {rule_id} has no remediation content")

        executor_type = remediation_data.get("type", "bash")
        content = remediation_data.get("content", "")

        if not content:
            raise ValueError(f"Rule {rule_id} has empty remediation content")

        # Prepare variables
        variables = self._prepare_variables(rule, variable_overrides)

        # Create RemediationResult document
        remediation_result = RemediationResult(
            remediation_id=remediation_id,
            rule_id=rule_id,
            rule_title=rule.get("title", "Unknown"),
            executor_type=executor_type,
            target=target,
            status=RemediationStatus.PENDING,
            dry_run=dry_run,
            content_executed=content,
            variables_applied=variables,
            executed_by=executed_by or "unknown",
            scan_id=scan_id,
        )

        # Save initial state
        await remediation_result.insert()
        remediation_result.add_audit_entry("Created", {"dry_run": dry_run})

        try:
            # Get executor
            executor = RemediationExecutorFactory.get_executor(executor_type)

            # Update status to RUNNING
            remediation_result.status = RemediationStatus.RUNNING
            remediation_result.started_at = datetime.utcnow()
            await remediation_result.save()
            remediation_result.add_audit_entry("Started", {"executor": executor_type})

            # Execute remediation
            execution_result = await executor.execute(
                content=content, target=target, variables=variables, dry_run=dry_run
            )

            # Update result
            remediation_result.execution_result = execution_result
            remediation_result.status = (
                RemediationStatus.COMPLETED
                if execution_result.success
                else RemediationStatus.FAILED
            )
            remediation_result.completed_at = datetime.utcnow()

            # Generate rollback content if changes were made
            if execution_result.success and execution_result.changes_made and not dry_run:
                rollback_content = self._generate_rollback_content(rule, execution_result)
                if rollback_content:
                    remediation_result.rollback_available = True
                    remediation_result.rollback_content = rollback_content

            await remediation_result.save()
            remediation_result.add_audit_entry(
                "Completed" if execution_result.success else "Failed",
                {
                    "exit_code": execution_result.exit_code,
                    "duration": execution_result.duration_seconds,
                },
            )

            logger.info(
                f"Remediation {remediation_id} completed: " f"success={execution_result.success}"
            )

            return remediation_result

        except Exception as e:
            # Update status to FAILED
            remediation_result.status = RemediationStatus.FAILED
            remediation_result.completed_at = datetime.utcnow()
            remediation_result.execution_result = RemediationExecutionResult(
                success=False, error_message=str(e)
            )
            await remediation_result.save()
            remediation_result.add_audit_entry("Failed", {"error": str(e)})

            logger.error(f"Remediation {remediation_id} failed: {e}")
            raise

    async def execute_bulk_remediation(
        self,
        target: RemediationTarget,
        scan_id: Optional[str] = None,
        rule_ids: Optional[List[str]] = None,
        rule_filter: Optional[Dict[str, Any]] = None,
        variable_overrides: Optional[Dict[str, str]] = None,
        dry_run: bool = False,
        executed_by: str = None,
    ) -> BulkRemediationJob:
        """
        Execute remediation for multiple rules.

        Args:
            target: Target system
            scan_id: Source scan ID (to remediate failed rules)
            rule_ids: Specific rule IDs to remediate
            rule_filter: Filter criteria (e.g., {'severity': ['high']})
            variable_overrides: Variable overrides
            dry_run: Preview mode
            executed_by: Username

        Returns:
            BulkRemediationJob with results

        Raises:
            ValueError: No rules matched criteria
        """
        job_id = str(uuid.uuid4())

        logger.info(
            f"Starting bulk remediation job {job_id} " f"(scan_id={scan_id}, dry_run={dry_run})"
        )

        # Get rules to remediate
        rules = await self._get_rules_for_bulk_remediation(
            scan_id=scan_id, rule_ids=rule_ids, rule_filter=rule_filter
        )

        if not rules:
            raise ValueError("No rules matched remediation criteria")

        # Create job document
        job = BulkRemediationJob(
            job_id=job_id,
            scan_id=scan_id,
            rule_filter=rule_filter,
            target=target,
            dry_run=dry_run,
            status=RemediationStatus.RUNNING,
            started_at=datetime.utcnow(),
            total_remediations=len(rules),
            executed_by=executed_by or "unknown",
        )
        await job.insert()

        # Execute remediations
        for rule in rules:
            try:
                result = await self.execute_remediation(
                    rule_id=rule["rule_id"],
                    target=target,
                    variable_overrides=variable_overrides,
                    dry_run=dry_run,
                    executed_by=executed_by,
                    scan_id=scan_id,
                )

                job.remediation_ids.append(result.remediation_id)

                if result.status == RemediationStatus.COMPLETED:
                    job.completed_remediations += 1
                else:
                    job.failed_remediations += 1

                await job.save()

            except Exception as e:
                logger.error(f"Failed to remediate rule {rule['rule_id']}: {e}")
                job.failed_remediations += 1
                await job.save()

        # Mark job complete
        job.status = RemediationStatus.COMPLETED
        job.completed_at = datetime.utcnow()
        await job.save()

        logger.info(
            f"Bulk remediation job {job_id} completed: "
            f"{job.completed_remediations}/{job.total_remediations} succeeded"
        )

        return job

    async def rollback_remediation(
        self, remediation_id: str, executed_by: str = None
    ) -> RemediationResult:
        """
        Rollback a remediation.

        Args:
            remediation_id: Remediation to rollback
            executed_by: Username executing rollback

        Returns:
            Updated RemediationResult

        Raises:
            ValueError: Remediation not found or rollback not available
            ExecutorExecutionError: Rollback execution failed
        """
        logger.info(f"Rolling back remediation {remediation_id}")

        # Get original remediation
        original = await RemediationResult.find_one(
            RemediationResult.remediation_id == remediation_id
        )

        if not original:
            raise ValueError(f"Remediation {remediation_id} not found")

        if not original.rollback_available:
            raise ValueError(f"Remediation {remediation_id} does not support rollback")

        if original.rollback_executed:
            raise ValueError(f"Remediation {remediation_id} already rolled back")

        # Get executor
        executor = RemediationExecutorFactory.get_executor(original.executor_type)

        # Execute rollback
        rollback_result = await executor.rollback(
            remediation_id=remediation_id,
            rollback_content=original.rollback_content,
            target=original.target,
        )

        # Update original remediation
        original.rollback_executed = True
        original.rollback_result = rollback_result
        original.status = RemediationStatus.ROLLED_BACK
        await original.save()
        original.add_audit_entry(
            "Rolled back",
            {"executed_by": executed_by, "success": rollback_result.success},
        )

        logger.info(
            f"Rollback for remediation {remediation_id} completed: "
            f"success={rollback_result.success}"
        )

        return original

    async def get_remediation_result(self, remediation_id: str) -> Optional[RemediationResult]:
        """Get remediation result by ID."""
        return await RemediationResult.find_one(RemediationResult.remediation_id == remediation_id)

    async def list_remediations(
        self,
        skip: int = 0,
        limit: int = 50,
        status: Optional[RemediationStatus] = None,
        executed_by: Optional[str] = None,
        scan_id: Optional[str] = None,
    ) -> List[RemediationResult]:
        """
        List remediations with filters.

        Args:
            skip: Pagination offset
            limit: Max results
            status: Filter by status
            executed_by: Filter by user
            scan_id: Filter by scan

        Returns:
            List of RemediationResult documents
        """
        query = {}
        if status:
            query["status"] = status.value
        if executed_by:
            query["executed_by"] = executed_by
        if scan_id:
            query["scan_id"] = scan_id

        results = await RemediationResult.find(query).skip(skip).limit(limit).to_list()
        return results

    async def get_remediation_statistics(
        self, days: int = 30, executed_by: Optional[str] = None
    ) -> RemediationSummary:
        """
        Get remediation statistics.

        Args:
            days: Days to include in stats
            executed_by: Filter by user

        Returns:
            RemediationSummary with aggregated stats
        """
        # Build aggregation pipeline
        match_stage = {}
        if executed_by:
            match_stage["executed_by"] = executed_by

        # Query remediations
        results = await RemediationResult.find(match_stage).to_list()

        # Calculate summary
        summary = RemediationSummary()
        summary.total = len(results)

        for result in results:
            if result.status == RemediationStatus.PENDING:
                summary.pending += 1
            elif result.status == RemediationStatus.RUNNING:
                summary.running += 1
            elif result.status == RemediationStatus.COMPLETED:
                summary.completed += 1
            elif result.status == RemediationStatus.FAILED:
                summary.failed += 1
            elif result.status == RemediationStatus.ROLLED_BACK:
                summary.rolled_back += 1

            # By executor
            executor = result.executor_type
            summary.by_executor[executor] = summary.by_executor.get(executor, 0) + 1

        # Calculate success rate
        if summary.total > 0:
            summary.success_rate = (summary.completed / summary.total) * 100

        return summary

    # Private helper methods

    async def _get_rule(self, rule_id: str) -> Dict[str, Any]:
        """Get rule from MongoDB."""
        rule = await self.collection.find_one({"rule_id": rule_id})
        if not rule:
            raise ValueError(f"Rule {rule_id} not found")
        return rule

    async def _get_rules_for_bulk_remediation(
        self,
        scan_id: Optional[str] = None,
        rule_ids: Optional[List[str]] = None,
        rule_filter: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get rules for bulk remediation.

        Priority:
        1. scan_id: Get failed rules from scan
        2. rule_ids: Get specific rules
        3. rule_filter: Query with filter
        """
        if scan_id:
            # Get failed rules from scan
            from ..models.scan_models import ScanResult

            scan = await ScanResult.find_one(ScanResult.scan_id == scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")

            failed_rule_ids = [r.rule_id for r in scan.results_by_rule if r.status == "fail"]

            if not failed_rule_ids:
                return []

            return await self.collection.find({"rule_id": {"$in": failed_rule_ids}}).to_list(
                length=None
            )

        elif rule_ids:
            # Get specific rules
            return await self.collection.find({"rule_id": {"$in": rule_ids}}).to_list(length=None)

        elif rule_filter:
            # Query with filter
            return await self.collection.find(rule_filter).to_list(length=None)

        return []

    def _prepare_variables(
        self, rule: Dict[str, Any], overrides: Optional[Dict[str, str]] = None
    ) -> Dict[str, str]:
        """
        Prepare variables for remediation execution.

        Combines rule default variables with user overrides.

        Args:
            rule: Rule document
            overrides: User-provided variable overrides

        Returns:
            Merged variable dictionary
        """
        variables = {}

        # Start with rule defaults
        if "xccdf_variables" in rule:
            for var_id, var_def in rule["xccdf_variables"].items():
                default_value = var_def.get("default")
                if default_value is not None:
                    variables[var_id] = str(default_value)

        # Apply overrides
        if overrides:
            variables.update(overrides)

        return variables

    def _generate_rollback_content(
        self, rule: Dict[str, Any], execution_result: RemediationExecutionResult
    ) -> Optional[str]:
        """
        Generate rollback content.

        Default implementation returns None (no automatic rollback).
        Future: Implement intelligent rollback generation.

        Args:
            rule: Rule document
            execution_result: Execution result

        Returns:
            Rollback content, or None
        """
        # Future: Implement rollback generation
        # - Parse execution_result.changes_made
        # - Generate inverse operations
        # - Create rollback script/playbook

        return None
