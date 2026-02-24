"""
Remediation Celery Tasks for Phase 4

Async tasks for remediation and rollback execution using the Kensa
compliance engine. Replaces stub implementations with real Kensa API calls.

Part of Phase 4: Remediation + Subscription (Kensa Integration Plan)
"""

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional
from uuid import UUID

from celery import shared_task
from sqlalchemy import text

from app.database import SessionLocal
from app.services.compliance.remediation import RemediationService

logger = logging.getLogger(__name__)


def _get_rules_path() -> str:
    """Get the Kensa rules directory path."""
    try:
        from runner.paths import get_rules_path

        return str(get_rules_path())
    except ImportError:
        import os

        return os.environ.get("KENSA_RULES_PATH", "/opt/kensa/rules")


def _load_and_resolve_rules(rules_path: str) -> List[Dict]:
    """Load Kensa rules and resolve template variables."""
    from runner._config import load_config, resolve_variables
    from runner._loading import load_rules

    rules = load_rules(rules_path)
    config = load_config(rules_path)
    return [resolve_variables(r, config, strict=False) for r in rules]


@shared_task(
    name="app.tasks.execute_remediation",
    bind=True,
    max_retries=3,
    default_retry_delay=60,
)
def execute_remediation_job(self, job_id: str) -> Dict[str, Any]:
    """
    Execute a remediation job asynchronously.

    Establishes a single SSH session to the host, loads and resolves all rules
    once, then iterates through requested rules calling Kensa's remediate_rule.

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

        # Execute via Kensa with shared SSH session
        try:
            result = asyncio.run(_run_remediation(db, job, service))
        except ImportError as e:
            logger.error(f"Kensa runner not available: {e}")
            service.complete_job(UUID(job_id), "failed", "Kensa runner not available")
            return {"status": "failed", "reason": "kensa_unavailable"}

        # Determine final status
        if result["failed"] == len(job.rule_ids):
            final_status = "failed"
        else:
            final_status = "completed"

        service.complete_job(
            UUID(job_id),
            status=final_status,
            rollback_available=result["rollback_available"],
        )

        logger.info(
            f"Remediation job {job_id} completed: "
            f"{result['completed']} completed, {result['failed']} failed, "
            f"{result['skipped']} skipped"
        )

        return {
            "status": final_status,
            "completed": result["completed"],
            "failed": result["failed"],
            "skipped": result["skipped"],
            "rollback_available": result["rollback_available"],
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


async def _run_remediation(db, job, service) -> Dict[str, Any]:
    """
    Core remediation logic with shared SSH session.

    Runs inside asyncio.run() from the Celery task. Creates a single SSH
    session via KensaSessionFactory and processes all rules sequentially.
    """
    from runner.detect import detect_capabilities

    from app.plugins.kensa import KensaSessionFactory

    rules_path = _get_rules_path()
    rules = _load_and_resolve_rules(rules_path)
    rule_map = {r["id"]: r for r in rules}

    factory = KensaSessionFactory(db)
    job_id = str(job.id)

    completed = 0
    failed = 0
    skipped = 0
    rollback_available = False

    async with factory.create_session(str(job.host_id)) as ssh:
        caps = detect_capabilities(ssh)

        for rule_id in job.rule_ids:
            try:
                result = _execute_rule_remediation(
                    db,
                    job_id,
                    rule_id,
                    ssh,
                    caps,
                    rule_map,
                    job.dry_run,
                    service,
                )

                if result["status"] == "completed":
                    completed += 1
                    if result.get("rollback_available"):
                        rollback_available = True
                elif result["status"] == "failed":
                    failed += 1
                elif result["status"] == "manual":
                    # Manual steps count as "completed" for progress
                    # but the individual result keeps "manual" status
                    completed += 1
                else:
                    skipped += 1

                service.update_job_progress(UUID(job_id), completed, failed, skipped)

            except Exception as e:
                logger.exception(f"Error remediating rule {rule_id}: {e}")
                failed += 1

                service.add_result(
                    job_id=UUID(job_id),
                    rule_id=rule_id,
                    status="failed",
                    error_message=str(e),
                )
                service.update_job_progress(UUID(job_id), completed, failed, skipped)

    return {
        "completed": completed,
        "failed": failed,
        "skipped": skipped,
        "rollback_available": rollback_available,
    }


def _execute_rule_remediation(
    db,
    job_id: str,
    rule_id: str,
    ssh,
    caps: Dict[str, bool],
    rule_map: Dict[str, Dict],
    dry_run: bool,
    service: RemediationService,
) -> Dict[str, Any]:
    """
    Execute remediation for a single rule using Kensa.

    Calls remediate_rule() with the shared SSH session, then stores the
    rule-level result and individual step results.

    Args:
        db: Database session
        job_id: Remediation job ID (str)
        rule_id: Kensa rule ID
        ssh: Connected Kensa SSHSession
        caps: Host capabilities from detect_capabilities()
        rule_map: Pre-loaded and resolved rules keyed by ID
        dry_run: Whether to simulate remediation
        service: RemediationService instance

    Returns:
        Status dict with rollback_available flag
    """
    from runner._orchestration import remediate_rule
    from runner.risk import classify_step_risk

    from app.plugins.kensa.evidence import serialize_evidence, serialize_framework_refs

    start_time = time.time()

    rule = rule_map.get(rule_id)
    if not rule:
        service.add_result(
            job_id=UUID(job_id),
            rule_id=rule_id,
            status="failed",
            error_message=f"Rule {rule_id} not found in Kensa rules",
        )
        return {"status": "failed", "reason": "rule_not_found"}

    try:
        result = remediate_rule(
            ssh,
            rule,
            caps,
            dry_run=dry_run,
            rollback_on_failure=True,
            snapshot=True,
        )

        duration_ms = int((time.time() - start_time) * 1000)

        # Classify risk and determine max risk across steps
        risk_order = {"high": 3, "medium": 2, "low": 1, "na": 0}
        max_risk = "na"
        step_count = len(result.step_results) if result.step_results else 0

        # Build pre-state aggregate for rollback
        pre_state_steps = []
        has_rollback = False
        for step in result.step_results or []:
            risk = classify_step_risk(step.mechanism, rule.get("remediation", {}))
            if risk_order.get(risk, 0) > risk_order.get(max_risk, 0):
                max_risk = risk
            if step.pre_state and step.pre_state.capturable:
                has_rollback = True
                pre_state_steps.append(
                    {
                        "step_index": step.step_index,
                        "mechanism": step.mechanism,
                        "data": step.pre_state.data if step.pre_state else None,
                        "capturable": step.pre_state.capturable if step.pre_state else False,
                    }
                )

        pre_state = {"steps": pre_state_steps} if pre_state_steps else None

        # Determine rule-level status from step outcomes
        # - "completed": all steps succeeded (or rule was remediated)
        # - "manual":    at least one step requires manual intervention
        # - "failed":    at least one non-manual step failed
        any_manual = any(not s.success and s.mechanism == "manual" for s in (result.step_results or []))
        any_failed = any(not s.success and s.mechanism != "manual" for s in (result.step_results or []))

        if any_failed:
            rule_status = "failed"
        elif any_manual:
            rule_status = "manual"
        elif result.remediated or dry_run:
            rule_status = "completed"
        else:
            rule_status = "failed"

        # Serialize Kensa evidence and framework refs
        evidence_json = serialize_evidence(result)
        framework_refs_json = serialize_framework_refs(result)

        # Store rule-level result
        result_id = service.add_result(
            job_id=UUID(job_id),
            rule_id=rule_id,
            status=rule_status,
            exit_code=0 if rule_status == "completed" else 1,
            duration_ms=duration_ms,
            stdout=result.remediation_detail,
            pre_state=pre_state,
            remediated=result.remediated,
            remediation_detail=result.remediation_detail,
            rolled_back=result.rolled_back,
            step_count=step_count,
            risk_level=max_risk,
            evidence=evidence_json,
            framework_refs=framework_refs_json,
        )

        # Store step-level results
        for step in result.step_results or []:
            risk = classify_step_risk(step.mechanism, rule.get("remediation", {}))
            pre_state_data = None
            pre_state_capturable = None
            if step.pre_state:
                pre_state_data = step.pre_state.data if hasattr(step.pre_state, "data") else None
                pre_state_capturable = step.pre_state.capturable if hasattr(step.pre_state, "capturable") else None

            service.add_step_result(
                result_id=result_id,
                step_index=step.step_index,
                mechanism=step.mechanism,
                success=step.success,
                detail=step.detail,
                pre_state_data=pre_state_data,
                pre_state_capturable=pre_state_capturable,
                verified=step.verified,
                verify_detail=step.verify_detail if hasattr(step, "verify_detail") else None,
                risk_level=risk,
            )

        return {
            "status": rule_status,
            "rollback_available": has_rollback and not dry_run,
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


@shared_task(
    name="app.tasks.execute_rollback",
    bind=True,
    max_retries=2,
    default_retry_delay=30,
)
def execute_rollback_job(self, rollback_job_id: str) -> Dict[str, Any]:
    """
    Execute a rollback job asynchronously.

    Establishes a single SSH session, reconstructs RemediationStepRecord
    objects from stored pre-state data, and calls Kensa's rollback_from_stored.

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

        # Get original job results with pre-state
        original_results = _get_results_with_prestate(db, job.rollback_job_id)

        try:
            result = asyncio.run(_run_rollback(db, job, service, original_results, rollback_job_id))
        except ImportError as e:
            logger.error(f"Kensa runner not available for rollback: {e}")
            service.complete_job(UUID(rollback_job_id), "failed", "Kensa runner not available")
            return {"status": "failed", "reason": "kensa_unavailable"}

        # Complete rollback job
        final_status = "completed" if result["failed"] == 0 else "failed"
        service.complete_job(UUID(rollback_job_id), final_status)

        # Mark original job as rolled back
        if result["completed"] > 0:
            _mark_job_rolled_back(db, job.rollback_job_id)

        logger.info(
            f"Rollback job {rollback_job_id} completed: "
            f"{result['completed']} rolled back, {result['failed']} failed"
        )

        return {
            "status": final_status,
            "rolled_back": result["completed"],
            "failed": result["failed"],
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


async def _run_rollback(db, job, service, original_results, rollback_job_id) -> Dict[str, Any]:
    """Core rollback logic with shared SSH session."""
    from app.plugins.kensa import KensaSessionFactory

    factory = KensaSessionFactory(db)

    completed = 0
    failed = 0

    async with factory.create_session(str(job.host_id)) as ssh:
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
                    ssh,
                    service,
                )

                if rollback_result["status"] == "completed":
                    completed += 1
                    _mark_result_rolled_back(db, result["id"])
                else:
                    failed += 1

                service.update_job_progress(UUID(rollback_job_id), completed, failed)

            except Exception as e:
                logger.exception(f"Error rolling back rule {result['rule_id']}: {e}")
                failed += 1
                service.update_job_progress(UUID(rollback_job_id), completed, failed)

    return {"completed": completed, "failed": failed}


def _execute_rule_rollback(
    db,
    job_id: str,
    rule_id: str,
    pre_state: Dict[str, Any],
    ssh,
    service: RemediationService,
) -> Dict[str, Any]:
    """
    Execute rollback for a single rule using Kensa.

    Reconstructs RemediationStepRecord objects from stored pre-state data
    and calls rollback_from_stored().

    Args:
        db: Database session
        job_id: Rollback job ID
        rule_id: Rule to rollback
        pre_state: Stored pre-state dict with 'steps' key
        ssh: Connected Kensa SSHSession
        service: RemediationService instance

    Returns:
        Status dict
    """
    from runner._orchestration import rollback_from_stored
    from runner.storage import RemediationStepRecord

    start_time = time.time()

    try:
        # Reconstruct step records from stored pre-state
        step_records = []
        for step_data in pre_state.get("steps", []):
            step_records.append(
                RemediationStepRecord(
                    id=None,
                    remediation_id=None,
                    step_index=step_data["step_index"],
                    mechanism=step_data["mechanism"],
                    success=True,
                    detail="",
                    pre_state_data=step_data.get("data"),
                    pre_state_capturable=step_data.get("capturable", False),
                )
            )

        if not step_records:
            logger.warning(f"No rollback steps for rule {rule_id}")
            service.add_result(
                job_id=UUID(job_id),
                rule_id=rule_id,
                status="failed",
                error_message="No rollback step records available",
            )
            return {"status": "failed", "reason": "no_step_records"}

        # Execute rollback via Kensa
        logger.info(f"Rolling back rule {rule_id} ({len(step_records)} steps)")
        rollback_results = rollback_from_stored(ssh, step_records)

        duration_ms = int((time.time() - start_time) * 1000)

        # Check overall success
        all_success = all(r.success for r in rollback_results)

        # Build detail message
        details = []
        for r in rollback_results:
            status_str = "OK" if r.success else "FAILED"
            details.append(f"Step {r.step_index}: {status_str} - {r.detail}")
        detail_text = "; ".join(details)

        service.add_result(
            job_id=UUID(job_id),
            rule_id=rule_id,
            status="completed" if all_success else "failed",
            exit_code=0 if all_success else 1,
            duration_ms=duration_ms,
            stdout=detail_text,
        )

        return {"status": "completed" if all_success else "failed"}

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
