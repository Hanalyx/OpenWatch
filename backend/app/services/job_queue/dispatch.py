"""Drop-in replacement for Celery .delay() calls.

Provides enqueue_task() which inserts a job into the PostgreSQL
job_queue table. Call sites migrate from:

    some_task.delay(scan_id=scan_id, host_id=host_id)

to:

    enqueue_task("app.tasks.some_task", scan_id=scan_id, host_id=host_id)
"""

import logging
from typing import Any, Dict, Optional

from app.database import SessionLocal

from .service import JobQueueService

logger = logging.getLogger(__name__)

# Map task names to their configured queue (mirrors celery_app.py task_routes).
_TASK_QUEUES: Dict[str, str] = {
    "app.tasks.scan_host": "scans",
    "app.tasks.process_scan_result": "results",
    "app.tasks.cleanup_old_files": "maintenance",
    "app.tasks.check_host_connectivity": "host_monitoring",
    "app.tasks.dispatch_host_checks": "host_monitoring",
    "app.tasks.queue_host_checks": "monitoring",
    "app.tasks.detect_stale_scans": "maintenance",
    "app.tasks.execute_scan": "scans",
    "app.tasks.enrich_scan_results": "default",
    "app.tasks.execute_remediation": "default",
    "app.tasks.execute_remediation_legacy": "default",
    "app.tasks.execute_rollback": "default",
    "app.tasks.import_scap_content": "default",
    "app.tasks.deliver_webhook": "default",
    "app.tasks.execute_host_discovery": "default",
    "app.tasks.dispatch_alert_notifications": "default",
    "app.tasks.dispatch_compliance_scans": "compliance_scanning",
    "app.tasks.run_scheduled_kensa_scan": "compliance_scanning",
    "app.tasks.initialize_compliance_schedules": "compliance_scanning",
    "app.tasks.expire_compliance_maintenance": "compliance_scanning",
    "app.tasks.execute_kensa_scan": "scans",
    "app.tasks.ping_all_managed_hosts": "default",
    "app.tasks.trigger_os_discovery": "default",
    "app.tasks.batch_os_discovery": "default",
    "app.tasks.discover_all_hosts_os": "default",
    "app.tasks.scheduled_group_scan": "scans",
    "app.tasks.execute_compliance_scan_async": "scans",
    "app.tasks.send_compliance_notification": "default",
    "app.tasks.compliance_alert_check": "default",
    "app.tasks.send_compliance_alerts": "default",
    "app.tasks.compliance_monitoring_task": "default",
    "app.tasks.backfill_transactions": "default",
    "app.tasks.backfill_host_rule_state": "default",
    "create_daily_posture_snapshots": "default",
    "cleanup_old_posture_snapshots": "maintenance",
    "expire_compliance_exceptions": "default",
    "generate_audit_export": "default",
    "cleanup_expired_audit_exports": "maintenance",
    "backfill_posture_snapshots": "default",
    "backfill_snapshot_rule_states": "default",
    "app.tasks.check_kensa_updates": "default",
    "app.tasks.cleanup_old_update_records": "maintenance",
    "app.tasks.perform_auto_update": "default",
}


def enqueue_task(
    task_name: str,
    queue: Optional[str] = None,
    delay_seconds: int = 0,
    max_retries: int = 3,
    timeout_seconds: int = 3600,
    **kwargs: Any,
) -> str:
    """Enqueue a task into the PostgreSQL job queue.

    Drop-in replacement for ``celery_task.delay(**kwargs)``.

    Args:
        task_name: Dotted task name (must match registry key).
        queue: Override the default queue for this task.
        delay_seconds: Delay before the job becomes eligible.
        max_retries: Maximum retry attempts on failure.
        timeout_seconds: Per-execution timeout enforced by the worker.
        **kwargs: Arguments forwarded to the task handler.

    Returns:
        String UUID of the created job.
    """
    resolved_queue = queue or _TASK_QUEUES.get(task_name, "default")

    db = SessionLocal()
    try:
        service = JobQueueService(db)
        job_id = service.enqueue(
            task_name=task_name,
            args=kwargs,
            queue=resolved_queue,
            delay_seconds=delay_seconds,
            max_retries=max_retries,
            timeout_seconds=timeout_seconds,
        )
        logger.debug("Enqueued %s (job=%s, queue=%s)", task_name, job_id, resolved_queue)
        return job_id
    finally:
        db.close()
