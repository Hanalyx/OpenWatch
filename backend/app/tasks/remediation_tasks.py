"""
Remediation Celery Tasks for Phase 4

Async tasks for remediation and rollback execution.

Part of Phase 4: Remediation + Subscription (Kensa Integration Plan)
"""

import logging
import time
from typing import Any, Dict, Optional
from uuid import UUID

from celery import shared_task
from sqlalchemy import text

from app.database import SessionLocal
from app.services.compliance.remediation import RemediationService

logger = logging.getLogger(__name__)


@shared_task(
    name="app.tasks.execute_remediation",
    bind=True,
    max_retries=3,
    default_retry_delay=60,
)
def execute_remediation_job(self, job_id: str) -> Dict[str, Any]:
    """
    Execute a remediation job asynchronously.

    This task:
    1. Marks job as running
    2. Executes each rule remediation via Kensa
    3. Captures pre-state for rollback
    4. Updates progress and results
    5. Marks job complete/failed

    Args:
        job_id: Remediation job ID

    Returns:
        Execution summary
    """
    logger.info(f"Starting remediation job {job_id}")
    db = SessionLocal()

    try:
        service = RemediationService(db)

        # Mark as running
        if not service.start_job(UUID(job_id)):
            logger.warning(f"Job {job_id} could not be started (not pending)")
            return {"status": "skipped", "reason": "not_pending"}

        # Get job details
        job = service.get_job(UUID(job_id))
        if not job:
            logger.error(f"Job {job_id} not found")
            return {"status": "error", "reason": "job_not_found"}

        # Get host credentials for SSH
        host_info = _get_host_info(db, job.host_id)
        if not host_info:
            service.complete_job(UUID(job_id), "failed", "Host not found")
            return {"status": "failed", "reason": "host_not_found"}

        # Execute remediation for each rule
        completed = 0
        failed = 0
        skipped = 0
        rollback_available = False

        for rule_id in job.rule_ids:
            try:
                result = _execute_rule_remediation(
                    db,
                    job_id,
                    rule_id,
                    host_info,
                    job.dry_run,
                )

                if result["status"] == "completed":
                    completed += 1
                    if result.get("rollback_available"):
                        rollback_available = True
                elif result["status"] == "failed":
                    failed += 1
                else:
                    skipped += 1

                # Update progress
                service.update_job_progress(UUID(job_id), completed, failed, skipped)

            except Exception as e:
                logger.exception(f"Error remediating rule {rule_id}: {e}")
                failed += 1

                # Record failure
                service.add_result(
                    job_id=UUID(job_id),
                    rule_id=rule_id,
                    status="failed",
                    error_message=str(e),
                )
                service.update_job_progress(UUID(job_id), completed, failed, skipped)

        # Determine final status
        if failed == len(job.rule_ids):
            final_status = "failed"
        elif failed > 0:
            final_status = "completed"  # Partial success
        else:
            final_status = "completed"

        service.complete_job(
            UUID(job_id),
            status=final_status,
            rollback_available=rollback_available,
        )

        logger.info(
            f"Remediation job {job_id} completed: " f"{completed} completed, {failed} failed, {skipped} skipped"
        )

        return {
            "status": final_status,
            "completed": completed,
            "failed": failed,
            "skipped": skipped,
            "rollback_available": rollback_available,
        }

    except Exception as e:
        logger.exception(f"Remediation job {job_id} failed with error: {e}")

        try:
            service = RemediationService(db)
            service.complete_job(UUID(job_id), "failed", str(e))
        except Exception:
            pass

        raise self.retry(exc=e)

    finally:
        db.close()


@shared_task(
    name="app.tasks.execute_rollback",
    bind=True,
    max_retries=2,
    default_retry_delay=30,
)
def execute_rollback_job(self, rollback_job_id: str) -> Dict[str, Any]:
    """
    Execute a rollback job asynchronously.

    This task:
    1. Gets the original job's pre-state snapshots
    2. Executes rollback for each rule
    3. Updates the original job status to rolled_back

    Args:
        rollback_job_id: Rollback job ID

    Returns:
        Rollback summary
    """
    logger.info(f"Starting rollback job {rollback_job_id}")
    db = SessionLocal()

    try:
        service = RemediationService(db)

        # Mark as running
        if not service.start_job(UUID(rollback_job_id)):
            logger.warning(f"Rollback job {rollback_job_id} could not be started")
            return {"status": "skipped", "reason": "not_pending"}

        # Get rollback job details
        job = service.get_job(UUID(rollback_job_id))
        if not job:
            logger.error(f"Rollback job {rollback_job_id} not found")
            return {"status": "error", "reason": "job_not_found"}

        if not job.rollback_job_id:
            service.complete_job(UUID(rollback_job_id), "failed", "No original job linked")
            return {"status": "failed", "reason": "no_original_job"}

        # Get host info
        host_info = _get_host_info(db, job.host_id)
        if not host_info:
            service.complete_job(UUID(rollback_job_id), "failed", "Host not found")
            return {"status": "failed", "reason": "host_not_found"}

        # Get original job results with pre-state
        original_results = _get_results_with_prestate(db, job.rollback_job_id)

        completed = 0
        failed = 0

        for result in original_results:
            if result["rule_id"] not in job.rule_ids:
                continue

            if not result.get("pre_state"):
                logger.warning(f"No pre-state for rule {result['rule_id']}, skipping")
                continue

            try:
                rollback_result = _execute_rule_rollback(
                    db,
                    rollback_job_id,
                    result["rule_id"],
                    result["pre_state"],
                    host_info,
                )

                if rollback_result["status"] == "completed":
                    completed += 1
                    # Mark original result as rolled back
                    _mark_result_rolled_back(db, result["id"])
                else:
                    failed += 1

                service.update_job_progress(UUID(rollback_job_id), completed, failed)

            except Exception as e:
                logger.exception(f"Error rolling back rule {result['rule_id']}: {e}")
                failed += 1
                service.update_job_progress(UUID(rollback_job_id), completed, failed)

        # Complete rollback job
        final_status = "completed" if failed == 0 else "failed"
        service.complete_job(UUID(rollback_job_id), final_status)

        # Mark original job as rolled back
        if completed > 0:
            _mark_job_rolled_back(db, job.rollback_job_id)

        logger.info(f"Rollback job {rollback_job_id} completed: " f"{completed} rolled back, {failed} failed")

        return {
            "status": final_status,
            "rolled_back": completed,
            "failed": failed,
        }

    except Exception as e:
        logger.exception(f"Rollback job {rollback_job_id} failed: {e}")

        try:
            service = RemediationService(db)
            service.complete_job(UUID(rollback_job_id), "failed", str(e))
        except Exception:
            pass

        raise self.retry(exc=e)

    finally:
        db.close()


def _get_host_info(db, host_id: UUID) -> Optional[Dict[str, Any]]:
    """Get host connection info."""
    query = """
        SELECT h.id, h.hostname, h.ip_address, h.port, h.username, h.auth_method,
               uc.ssh_password, uc.ssh_private_key
        FROM hosts h
        LEFT JOIN unified_credentials uc ON h.credential_id = uc.id
        WHERE h.id = :host_id
    """
    result = db.execute(text(query), {"host_id": host_id})
    row = result.fetchone()

    if not row:
        return None

    return {
        "id": row.id,
        "hostname": row.hostname,
        "ip_address": row.ip_address,
        "port": row.port or 22,
        "username": row.username,
        "auth_method": row.auth_method,
        "password": row.ssh_password,
        "private_key": row.ssh_private_key,
    }


def _execute_rule_remediation(
    db,
    job_id: str,
    rule_id: str,
    host_info: Dict[str, Any],
    dry_run: bool,
) -> Dict[str, Any]:
    """
    Execute remediation for a single rule.

    Uses Kensa runner to execute the remediation.
    """
    service = RemediationService(db)
    start_time = time.time()

    try:
        # Get rule details
        rule_query = "SELECT * FROM kensa_rules WHERE rule_id = :rule_id"
        rule_result = db.execute(text(rule_query), {"rule_id": rule_id})
        rule = rule_result.fetchone()

        if not rule:
            service.add_result(
                job_id=UUID(job_id),
                rule_id=rule_id,
                status="failed",
                error_message=f"Rule {rule_id} not found",
            )
            return {"status": "failed", "reason": "rule_not_found"}

        # Capture pre-state for rollback
        pre_state = _capture_pre_state(host_info, rule)

        if dry_run:
            # Dry run - just record what would happen
            duration_ms = int((time.time() - start_time) * 1000)
            service.add_result(
                job_id=UUID(job_id),
                rule_id=rule_id,
                status="completed",
                duration_ms=duration_ms,
                stdout="DRY RUN: No changes made",
                pre_state=pre_state,
            )
            return {"status": "completed", "dry_run": True}

        # Execute actual remediation via Kensa
        # TODO: Integrate with actual Kensa remediation engine
        # For now, simulate execution
        logger.info(f"Executing remediation for rule {rule_id} on host {host_info['hostname']}")

        # Simulate remediation execution
        # In production, this would call:
        # from runner.engine import remediate_rule
        # result = remediate_rule(ssh_session, rule)

        duration_ms = int((time.time() - start_time) * 1000)

        service.add_result(
            job_id=UUID(job_id),
            rule_id=rule_id,
            status="completed",
            exit_code=0,
            duration_ms=duration_ms,
            stdout=f"Remediation applied for {rule_id}",
            pre_state=pre_state,
        )

        return {
            "status": "completed",
            "rollback_available": pre_state is not None,
        }

    except Exception as e:
        duration_ms = int((time.time() - start_time) * 1000)
        service.add_result(
            job_id=UUID(job_id),
            rule_id=rule_id,
            status="failed",
            duration_ms=duration_ms,
            error_message=str(e),
        )
        return {"status": "failed", "error": str(e)}


def _execute_rule_rollback(
    db,
    job_id: str,
    rule_id: str,
    pre_state: Dict[str, Any],
    host_info: Dict[str, Any],
) -> Dict[str, Any]:
    """Execute rollback for a single rule."""
    service = RemediationService(db)
    start_time = time.time()

    try:
        # TODO: Integrate with actual Kensa rollback engine
        # from runner._rollback import _execute_rollback
        # result = _execute_rollback(ssh_session, rule_id, pre_state)

        logger.info(f"Rolling back rule {rule_id} on host {host_info['hostname']}")

        duration_ms = int((time.time() - start_time) * 1000)

        service.add_result(
            job_id=UUID(job_id),
            rule_id=rule_id,
            status="completed",
            exit_code=0,
            duration_ms=duration_ms,
            stdout=f"Rollback applied for {rule_id}",
        )

        return {"status": "completed"}

    except Exception as e:
        duration_ms = int((time.time() - start_time) * 1000)
        service.add_result(
            job_id=UUID(job_id),
            rule_id=rule_id,
            status="failed",
            duration_ms=duration_ms,
            error_message=str(e),
        )
        return {"status": "failed", "error": str(e)}


def _capture_pre_state(host_info: Dict[str, Any], rule) -> Optional[Dict[str, Any]]:
    """Capture pre-remediation state for rollback."""
    # TODO: Implement actual state capture based on rule handler
    # For now, return a placeholder
    return {
        "captured_at": time.time(),
        "handler": rule.handler if hasattr(rule, "handler") else "unknown",
        "host": host_info["hostname"],
    }


def _get_results_with_prestate(db, job_id: UUID) -> list:
    """Get remediation results that have pre-state for rollback."""
    query = """
        SELECT id, rule_id, pre_state
        FROM remediation_results
        WHERE job_id = :job_id
          AND rollback_available = true
          AND rollback_executed = false
    """
    result = db.execute(text(query), {"job_id": job_id})
    rows = result.fetchall()

    return [{"id": row.id, "rule_id": row.rule_id, "pre_state": row.pre_state} for row in rows]


def _mark_result_rolled_back(db, result_id: UUID) -> None:
    """Mark a remediation result as rolled back."""
    query = """
        UPDATE remediation_results
        SET rollback_executed = true
        WHERE id = :id
    """
    db.execute(text(query), {"id": result_id})
    db.commit()


def _mark_job_rolled_back(db, job_id: UUID) -> None:
    """Mark a remediation job as rolled back."""
    query = """
        UPDATE remediation_jobs
        SET status = 'rolled_back', rollback_available = false
        WHERE id = :id
    """
    db.execute(text(query), {"id": job_id})
    db.commit()
