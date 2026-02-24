"""
Remediation Service for Phase 4

Orchestrates remediation execution with license validation, rollback support,
and audit logging. Provides step-level result tracking and real Kensa dry-run
plan previews.

Part of Phase 4: Remediation + Subscription (Kensa Integration Plan)
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.engine import Row
from sqlalchemy.orm import Session

from app.schemas.remediation_schemas import (
    RemediationJobCreate,
    RemediationJobResponse,
    RemediationPlanResponse,
    RemediationPlanRuleDetail,
    RemediationResultResponse,
    RemediationStatus,
    RemediationStepResponse,
    RemediationSummary,
    RollbackResponse,
)
from app.services.licensing.service import LicenseRequiredError, LicenseService
from app.utils.mutation_builders import InsertBuilder, UpdateBuilder
from app.utils.query_builder import QueryBuilder

logger = logging.getLogger(__name__)


class RemediationService:
    """
    Service for managing remediation jobs with license enforcement.

    Provides:
    - Job creation with OpenWatch+ license validation
    - Async execution via Celery tasks
    - Rollback support with state snapshots
    - Step-level result tracking
    - Real Kensa dry-run plan previews
    - Audit logging for compliance
    """

    def __init__(self, db: Session):
        self.db = db
        self.license_service = LicenseService()

    def create_job(
        self,
        request: RemediationJobCreate,
        user_id: int,
    ) -> RemediationJobResponse:
        """
        Create a new remediation job.

        Requires OpenWatch+ license for remediation feature.

        Args:
            request: Remediation job configuration
            user_id: User creating the job

        Returns:
            Created job response

        Raises:
            LicenseRequiredError: If remediation feature not licensed
            ValueError: If host not found or rules invalid
        """
        # Check license
        if not self.license_service.has_feature("remediation"):
            raise LicenseRequiredError(
                "remediation",
                "Remediation requires an OpenWatch+ subscription",
            )

        # Validate host exists
        host = self._get_host(request.host_id)
        if not host:
            raise ValueError(f"Host {request.host_id} not found")

        # Validate rules exist
        valid_rules = self._validate_rules(request.rule_ids)
        if not valid_rules:
            raise ValueError("No valid rules found for remediation")

        # Create job
        job_id = uuid4()
        builder = (
            InsertBuilder("remediation_jobs")
            .columns(
                "id",
                "host_id",
                "scan_id",
                "rule_ids",
                "dry_run",
                "framework",
                "status",
                "total_rules",
                "requested_by",
            )
            .values(
                job_id,
                request.host_id,
                request.scan_id,
                json.dumps(valid_rules),  # JSONB requires json.dumps()
                request.dry_run,
                request.framework,
                "pending",
                len(valid_rules),
                user_id,
            )
            .returning("*")
        )

        query, params = builder.build()
        result = self.db.execute(text(query), params)
        row = result.fetchone()
        self.db.commit()

        # Log audit event
        self._log_audit(
            job_id,
            "created",
            user_id,
            {
                "host_id": str(request.host_id),
                "rule_count": len(valid_rules),
                "dry_run": request.dry_run,
            },
        )

        logger.info(
            f"Created remediation job {job_id} for host {request.host_id} "
            f"with {len(valid_rules)} rules (dry_run={request.dry_run})"
        )

        return self._row_to_job_response(row)

    def get_job(self, job_id: UUID) -> Optional[RemediationJobResponse]:
        """Get remediation job by ID."""
        builder = QueryBuilder("remediation_jobs").where("id = :id", job_id, "id")
        query, params = builder.build()
        result = self.db.execute(text(query), params)
        row = result.fetchone()

        if not row:
            return None

        return self._row_to_job_response(row)

    def get_job_results(self, job_id: UUID) -> List[RemediationResultResponse]:
        """Get all results for a remediation job."""
        builder = (
            QueryBuilder("remediation_results")
            .where("job_id = :job_id", job_id, "job_id")
            .order_by("created_at", "ASC")
        )
        query, params = builder.build()
        result = self.db.execute(text(query), params)
        rows = result.fetchall()

        return [self._row_to_result_response(row) for row in rows]

    def list_jobs(
        self,
        host_id: Optional[UUID] = None,
        status: Optional[str] = None,
        page: int = 1,
        per_page: int = 20,
    ) -> Tuple[List[RemediationJobResponse], int]:
        """
        List remediation jobs with filtering.

        Args:
            host_id: Filter by host
            status: Filter by status
            page: Page number
            per_page: Items per page

        Returns:
            Tuple of (jobs, total_count)
        """
        builder = QueryBuilder("remediation_jobs")

        if host_id:
            builder = builder.where("host_id = :host_id", host_id, "host_id")
        if status:
            builder = builder.where("status = :status", status, "status")

        builder = builder.order_by("created_at", "DESC").paginate(page, per_page)

        query, params = builder.build()
        result = self.db.execute(text(query), params)
        rows = result.fetchall()

        # Get total count
        count_query, count_params = builder.count_query()
        count_result = self.db.execute(text(count_query), count_params)
        total = count_result.scalar() or 0

        jobs = [self._row_to_job_response(row) for row in rows]
        return jobs, total

    def get_summary(self, host_id: Optional[UUID] = None) -> RemediationSummary:
        """Get remediation summary statistics."""
        where_clause = ""
        params: Dict[str, Any] = {}

        if host_id:
            where_clause = "WHERE host_id = :host_id"
            params["host_id"] = host_id

        query = f"""
            SELECT
                COUNT(*) as total_jobs,
                COUNT(*) FILTER (WHERE status = 'pending') as pending_jobs,
                COUNT(*) FILTER (WHERE status = 'running') as running_jobs,
                COUNT(*) FILTER (WHERE status = 'completed') as completed_jobs,
                COUNT(*) FILTER (WHERE status = 'failed') as failed_jobs,
                COUNT(*) FILTER (WHERE status = 'rolled_back') as rolled_back_jobs,
                COALESCE(SUM(completed_rules), 0) as total_rules_remediated,
                COALESCE(SUM(failed_rules), 0) as total_rules_failed,
                COUNT(*) FILTER (WHERE rollback_available = true) as rollback_available_count
            FROM remediation_jobs
            {where_clause}
        """

        result = self.db.execute(text(query), params)
        row = result.fetchone()

        total_rules = (row.total_rules_remediated or 0) + (row.total_rules_failed or 0)
        success_rate = 0.0
        if total_rules > 0:
            success_rate = (row.total_rules_remediated / total_rules) * 100

        return RemediationSummary(
            total_jobs=row.total_jobs or 0,
            pending_jobs=row.pending_jobs or 0,
            running_jobs=row.running_jobs or 0,
            completed_jobs=row.completed_jobs or 0,
            failed_jobs=row.failed_jobs or 0,
            rolled_back_jobs=row.rolled_back_jobs or 0,
            total_rules_remediated=row.total_rules_remediated or 0,
            total_rules_failed=row.total_rules_failed or 0,
            success_rate=round(success_rate, 2),
            rollback_available_count=row.rollback_available_count or 0,
        )

    def get_remediation_plan(
        self,
        host_id: UUID,
        rule_ids: List[str],
    ) -> RemediationPlanResponse:
        """
        Get a remediation plan via Kensa dry-run.

        Connects to the host via SSH, runs each requested rule in dry-run mode,
        and returns step-level preview data with risk classification.

        Args:
            host_id: Target host
            rule_ids: Rules to include in plan

        Returns:
            Remediation plan with real step-level preview and risk summary
        """
        try:
            from runner._config import load_config, resolve_variables
            from runner._loading import load_rules
            from runner._orchestration import remediate_rule
            from runner.detect import detect_capabilities
            from runner.paths import get_rules_path
            from runner.risk import classify_step_risk

            from app.plugins.kensa import KensaSessionFactory

            rules_path = get_rules_path()
            factory = KensaSessionFactory(self.db)

            async def _run_dry_run():
                async with factory.create_session(str(host_id)) as ssh:
                    caps = detect_capabilities(ssh)
                    rules = load_rules(rules_path)
                    config = load_config(rules_path)
                    rules = [resolve_variables(r, config, strict=False) for r in rules]
                    rule_map = {r["id"]: r for r in rules}

                    plan_rules = []
                    all_warnings = []
                    requires_reboot = False
                    risk_counts: Dict[str, int] = {"high": 0, "medium": 0, "low": 0, "na": 0}

                    for rule_id in rule_ids:
                        rule = rule_map.get(rule_id)
                        if not rule:
                            all_warnings.append(f"Rule {rule_id} not found in Kensa rules")
                            continue

                        result = remediate_rule(ssh, rule, caps, dry_run=True)

                        # Classify risk for each step
                        steps = []
                        max_risk = "na"
                        risk_order = {"high": 3, "medium": 2, "low": 1, "na": 0}
                        for step in result.step_results:
                            risk = classify_step_risk(step.mechanism, rule.get("remediation", {}))
                            steps.append(
                                {
                                    "step_index": step.step_index,
                                    "mechanism": step.mechanism,
                                    "detail": step.detail,
                                    "risk_level": risk,
                                    "verified": step.verified,
                                }
                            )
                            if risk_order.get(risk, 0) > risk_order.get(max_risk, 0):
                                max_risk = risk

                        risk_counts[max_risk] = risk_counts.get(max_risk, 0) + 1

                        rule_warnings = []
                        if any(s["mechanism"] in ("grub_parameter_set", "kernel_module_disable") for s in steps):
                            requires_reboot = True
                            rule_warnings.append(f"Rule {rule_id} may require a system reboot")

                        plan_rules.append(
                            RemediationPlanRuleDetail(
                                rule_id=rule_id,
                                title=rule.get("title", ""),
                                severity=rule.get("severity", "medium"),
                                risk_level=max_risk,
                                steps=steps,
                                estimated_duration_seconds=max(5, len(steps) * 3),
                                requires_reboot=any(
                                    s["mechanism"] in ("grub_parameter_set", "kernel_module_disable") for s in steps
                                ),
                                warnings=rule_warnings,
                            )
                        )
                        all_warnings.extend(rule_warnings)

                    total_duration = sum(r.estimated_duration_seconds for r in plan_rules) + 10

                    return RemediationPlanResponse(
                        host_id=host_id,
                        rule_count=len(plan_rules),
                        rules=plan_rules,
                        estimated_duration_seconds=total_duration,
                        warnings=all_warnings,
                        requires_reboot=requires_reboot,
                        dependencies=[],
                        risk_summary=risk_counts,
                    )

            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, _run_dry_run())
                return future.result(timeout=120)

        except ImportError:
            logger.warning("Kensa runner not available, falling back to static plan")
            return self._static_remediation_plan(host_id, rule_ids)

    def _static_remediation_plan(
        self,
        host_id: UUID,
        rule_ids: List[str],
    ) -> RemediationPlanResponse:
        """Fallback static plan when Kensa runner is not available."""
        rules_query = """
            SELECT rule_id, title, severity, category
            FROM kensa_rules
            WHERE rule_id = ANY(:rule_ids)
        """
        result = self.db.execute(text(rules_query), {"rule_ids": rule_ids})
        rules = result.fetchall()

        rule_details = []
        requires_reboot = False
        warnings = []

        for rule in rules:
            rule_warnings = []
            reboot = False
            # Check category for rules that likely need reboot
            if rule.category in ("boot-settings", "kernel-modules"):
                requires_reboot = True
                reboot = True
                rule_warnings.append(f"Rule {rule.rule_id} may require a system reboot")

            rule_details.append(
                RemediationPlanRuleDetail(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    severity=rule.severity,
                    risk_level="medium",
                    steps=[
                        {
                            "mechanism": "unknown",
                            "detail": "Static preview (Kensa unavailable)",
                        }
                    ],
                    estimated_duration_seconds=5,
                    requires_reboot=reboot,
                    warnings=rule_warnings,
                )
            )
            warnings.extend(rule_warnings)

        estimated_duration = len(rules) * 5 + 10

        return RemediationPlanResponse(
            host_id=host_id,
            rule_count=len(rules),
            rules=rule_details,
            estimated_duration_seconds=estimated_duration,
            warnings=warnings,
            requires_reboot=requires_reboot,
            dependencies=[],
            risk_summary={"medium": len(rules)},
        )

    def start_job(self, job_id: UUID) -> bool:
        """
        Mark job as started.

        Called by Celery task when execution begins.
        """
        builder = (
            UpdateBuilder("remediation_jobs")
            .set("status", "running")
            .set_raw("started_at", "CURRENT_TIMESTAMP")
            .where("id = :id", job_id, "id")
            .where("status = :expected_status", "pending", "expected_status")
        )

        query, params = builder.build()
        result = self.db.execute(text(query), params)
        self.db.commit()

        return result.rowcount > 0

    def update_job_progress(
        self,
        job_id: UUID,
        completed: int,
        failed: int,
        skipped: int = 0,
    ) -> None:
        """Update job progress counters."""
        query = """
            UPDATE remediation_jobs
            SET
                completed_rules = :completed,
                failed_rules = :failed,
                skipped_rules = :skipped,
                progress = CASE
                    WHEN total_rules > 0 THEN
                        (((:completed + :failed + :skipped)::float / total_rules) * 100)::int
                    ELSE 0
                END
            WHERE id = :job_id
        """
        self.db.execute(
            text(query),
            {
                "job_id": job_id,
                "completed": completed,
                "failed": failed,
                "skipped": skipped,
            },
        )
        self.db.commit()

    def complete_job(
        self,
        job_id: UUID,
        status: str = "completed",
        error_message: Optional[str] = None,
        rollback_available: bool = False,
    ) -> None:
        """
        Mark job as completed (or failed).

        Called by Celery task when execution finishes.
        """
        builder = (
            UpdateBuilder("remediation_jobs")
            .set("status", status)
            .set("rollback_available", rollback_available)
            .set_if("error_message", error_message)
            .set_raw("completed_at", "CURRENT_TIMESTAMP")
            .where("id = :id", job_id, "id")
        )

        query, params = builder.build()
        self.db.execute(text(query), params)
        self.db.commit()

        logger.info(f"Remediation job {job_id} completed with status: {status}")

    def add_result(
        self,
        job_id: UUID,
        rule_id: str,
        status: str,
        exit_code: Optional[int] = None,
        stdout: Optional[str] = None,
        stderr: Optional[str] = None,
        duration_ms: Optional[int] = None,
        error_message: Optional[str] = None,
        pre_state: Optional[Dict] = None,
        remediated: Optional[bool] = None,
        remediation_detail: Optional[str] = None,
        rolled_back: Optional[bool] = None,
        step_count: Optional[int] = None,
        risk_level: Optional[str] = None,
        evidence: Optional[str] = None,
        framework_refs: Optional[str] = None,
    ) -> UUID:
        """Add a remediation result for a rule."""
        result_id = uuid4()
        rollback_available = pre_state is not None

        builder = (
            InsertBuilder("remediation_results")
            .columns(
                "id",
                "job_id",
                "rule_id",
                "status",
                "exit_code",
                "stdout",
                "stderr",
                "duration_ms",
                "error_message",
                "pre_state",
                "rollback_available",
                "remediated",
                "remediation_detail",
                "rolled_back",
                "step_count",
                "risk_level",
                "evidence",
                "framework_refs",
                "started_at",
                "completed_at",
            )
            .values(
                result_id,
                job_id,
                rule_id,
                status,
                exit_code,
                stdout,
                stderr,
                duration_ms,
                error_message,
                json.dumps(pre_state) if pre_state is not None else None,
                rollback_available,
                remediated,
                remediation_detail,
                rolled_back,
                step_count,
                risk_level,
                evidence,
                framework_refs,
                datetime.utcnow(),
                datetime.utcnow() if status in ("completed", "failed") else None,
            )
        )

        query, params = builder.build()
        self.db.execute(text(query), params)
        self.db.commit()

        return result_id

    def add_step_result(
        self,
        result_id: UUID,
        step_index: int,
        mechanism: str,
        success: bool,
        detail: Optional[str] = None,
        pre_state_data: Optional[Dict] = None,
        pre_state_capturable: Optional[bool] = None,
        verified: Optional[bool] = None,
        verify_detail: Optional[str] = None,
        risk_level: Optional[str] = None,
    ) -> UUID:
        """
        Add a step-level result for a rule remediation.

        Args:
            result_id: Parent remediation_results ID
            step_index: Order within rule (0-indexed)
            mechanism: Kensa mechanism type (config_set, service_enabled, etc.)
            success: Whether this step succeeded
            detail: Step-level detail message
            pre_state_data: PreState.data dict for rollback
            pre_state_capturable: Whether pre-state is capturable (False for command_exec)
            verified: Post-step verification result
            verify_detail: Verification detail message
            risk_level: Risk classification (high/medium/low/na)

        Returns:
            UUID of the created step record
        """
        step_id = uuid4()
        builder = (
            InsertBuilder("remediation_steps")
            .columns(
                "id",
                "result_id",
                "step_index",
                "mechanism",
                "success",
                "detail",
                "pre_state_data",
                "pre_state_capturable",
                "verified",
                "verify_detail",
                "risk_level",
            )
            .values(
                step_id,
                result_id,
                step_index,
                mechanism,
                success,
                detail,
                json.dumps(pre_state_data) if pre_state_data is not None else None,
                pre_state_capturable,
                verified,
                verify_detail,
                risk_level,
            )
        )

        query, params = builder.build()
        self.db.execute(text(query), params)
        self.db.commit()

        return step_id

    def get_step_results(self, result_id: UUID) -> List[RemediationStepResponse]:
        """Get step-level results for a specific rule remediation."""
        builder = (
            QueryBuilder("remediation_steps")
            .where("result_id = :result_id", result_id, "result_id")
            .order_by("step_index", "ASC")
        )
        query, params = builder.build()
        result = self.db.execute(text(query), params)
        rows = result.fetchall()

        return [self._row_to_step_response(row) for row in rows]

    def rollback_job(
        self,
        job_id: UUID,
        user_id: int,
        rule_ids: Optional[List[str]] = None,
    ) -> RollbackResponse:
        """
        Rollback a remediation job.

        Requires OpenWatch+ license.

        Args:
            job_id: Job to rollback
            user_id: User requesting rollback
            rule_ids: Specific rules to rollback (all if None)

        Returns:
            Rollback operation response
        """
        # Check license
        if not self.license_service.has_feature("rollback"):
            raise LicenseRequiredError("rollback", "Rollback requires an OpenWatch+ subscription")

        # Get original job
        job = self.get_job(job_id)
        if not job:
            raise ValueError(f"Job {job_id} not found")

        if not job.rollback_available:
            raise ValueError(f"Job {job_id} does not have rollback available")

        if job.status == RemediationStatus.ROLLED_BACK:
            raise ValueError(f"Job {job_id} has already been rolled back")

        # Create rollback job
        rollback_job_id = uuid4()
        target_rules = rule_ids or job.rule_ids

        builder = (
            InsertBuilder("remediation_jobs")
            .columns(
                "id",
                "host_id",
                "scan_id",
                "rule_ids",
                "dry_run",
                "status",
                "total_rules",
                "rollback_job_id",
                "requested_by",
            )
            .values(
                rollback_job_id,
                job.host_id,
                job.scan_id,
                json.dumps(target_rules),  # JSONB requires json.dumps()
                False,
                "pending",
                len(target_rules),
                job_id,  # Link to original job
                user_id,
            )
        )

        query, params = builder.build()
        self.db.execute(text(query), params)
        self.db.commit()

        # Log audit
        self._log_audit(
            rollback_job_id,
            "rollback_created",
            user_id,
            {
                "original_job_id": str(job_id),
                "rule_count": len(target_rules),
            },
        )

        logger.info(f"Created rollback job {rollback_job_id} for job {job_id}")

        return RollbackResponse(
            rollback_job_id=rollback_job_id,
            original_job_id=job_id,
            status=RemediationStatus.PENDING,
            rules_rolled_back=0,
            rules_failed=0,
            message=f"Rollback job created for {len(target_rules)} rules",
        )

    def cancel_job(self, job_id: UUID, user_id: int) -> bool:
        """Cancel a pending or running job."""
        # Note: Using raw SQL here because UpdateBuilder.where() doesn't support
        # bare conditions like "status IN ('pending', 'running')" without params
        query = """
            UPDATE remediation_jobs
            SET status = 'cancelled', completed_at = CURRENT_TIMESTAMP
            WHERE id = :id AND status IN ('pending', 'running')
        """
        result = self.db.execute(text(query), {"id": job_id})
        self.db.commit()

        if result.rowcount > 0:
            self._log_audit(job_id, "cancelled", user_id, {})
            logger.info(f"Cancelled remediation job {job_id}")
            return True

        return False

    def _get_host(self, host_id: UUID) -> Optional[Row]:
        """Get host by ID."""
        query = "SELECT id, hostname, status FROM hosts WHERE id = :id"
        result = self.db.execute(text(query), {"id": host_id})
        return result.fetchone()

    def _validate_rules(self, rule_ids: List[str]) -> List[str]:
        """Validate rules exist and return valid ones."""
        query = """
            SELECT rule_id FROM kensa_rules
            WHERE rule_id = ANY(:rule_ids)
        """
        result = self.db.execute(text(query), {"rule_ids": rule_ids})
        rows = result.fetchall()
        return [row.rule_id for row in rows]

    def _log_audit(
        self,
        job_id: UUID,
        action: str,
        user_id: int,
        details: Dict[str, Any],
    ) -> None:
        """Log remediation audit event."""
        query = """
            INSERT INTO audit_logs (
                action, user_id, resource_type, resource_id,
                details, ip_address, timestamp
            ) VALUES (
                :action, :user_id, 'remediation_job', :job_id,
                :details, '0.0.0.0', CURRENT_TIMESTAMP
            )
        """
        self.db.execute(
            text(query),
            {
                "job_id": str(job_id),
                "user_id": user_id,
                "action": action,
                "details": json.dumps(details),
            },
        )

    def _row_to_job_response(self, row: Row) -> RemediationJobResponse:
        """Convert database row to job response."""
        duration = None
        if row.started_at and row.completed_at:
            duration = (row.completed_at - row.started_at).total_seconds()

        return RemediationJobResponse(
            id=row.id,
            host_id=row.host_id,
            scan_id=row.scan_id,
            rule_ids=row.rule_ids or [],
            dry_run=row.dry_run,
            status=RemediationStatus(row.status),
            progress=row.progress or 0,
            total_rules=row.total_rules or 0,
            completed_rules=row.completed_rules or 0,
            failed_rules=row.failed_rules or 0,
            skipped_rules=row.skipped_rules or 0,
            error_message=row.error_message,
            rollback_available=row.rollback_available or False,
            rollback_job_id=row.rollback_job_id,
            requested_by=row.requested_by,
            created_at=row.created_at,
            started_at=row.started_at,
            completed_at=row.completed_at,
            duration_seconds=duration,
        )

    def _row_to_result_response(self, row: Row) -> RemediationResultResponse:
        """Convert database row to result response."""
        return RemediationResultResponse(
            id=row.id,
            job_id=row.job_id,
            rule_id=row.rule_id,
            status=RemediationStatus(row.status),
            exit_code=row.exit_code,
            stdout=row.stdout,
            stderr=row.stderr,
            duration_ms=row.duration_ms,
            error_message=row.error_message,
            rollback_available=row.rollback_available or False,
            rollback_executed=row.rollback_executed or False,
            created_at=row.created_at,
            started_at=row.started_at,
            completed_at=row.completed_at,
            remediated=getattr(row, "remediated", None),
            remediation_detail=getattr(row, "remediation_detail", None),
            rolled_back=getattr(row, "rolled_back", None),
            step_count=getattr(row, "step_count", None),
            risk_level=getattr(row, "risk_level", None),
            evidence=getattr(row, "evidence", None),
            framework_refs=getattr(row, "framework_refs", None),
        )

    def _row_to_step_response(self, row: Row) -> RemediationStepResponse:
        """Convert database row to step response."""
        return RemediationStepResponse(
            id=row.id,
            result_id=row.result_id,
            step_index=row.step_index,
            mechanism=row.mechanism,
            success=row.success,
            detail=row.detail,
            pre_state_data=row.pre_state_data,
            pre_state_capturable=row.pre_state_capturable,
            verified=row.verified,
            verify_detail=row.verify_detail,
            risk_level=row.risk_level,
            created_at=row.created_at,
        )
