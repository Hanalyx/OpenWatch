"""Task name to callable registry for the job queue worker.

Maps Celery task names to their underlying functions so the same
implementations can be dispatched by either Celery or the PostgreSQL
job queue during the migration period.

All tasks are registered here, including bind=True tasks which get
a wrapper that strips the self argument and converts self.retry()
calls to exceptions (caught by the worker's retry logic).
"""

import functools
import logging
from typing import Callable, Dict

logger = logging.getLogger(__name__)


def _wrap_bound_task(func: Callable) -> Callable:
    """Wrap a Celery bind=True task to work without Celery.

    Strips the 'self' argument and converts self.retry() calls
    to exceptions (caught by the worker's retry logic).

    Args:
        func: The original Celery task function that expects self as first arg.

    Returns:
        Wrapper function that can be called with **kwargs only.
    """

    @functools.wraps(func)
    def wrapper(**kwargs):
        class _MockTask:
            """Minimal mock of a Celery task instance."""

            class RetryError(Exception):
                pass

            def retry(self, exc=None, countdown=None, max_retries=None):
                raise exc or self.RetryError("Retry requested")

            @property
            def request(self):
                class _Req:
                    id = "job-queue"
                    retries = 0

                return _Req()

        return func(_MockTask(), **kwargs)

    return wrapper


def build_registry() -> Dict[str, Callable]:
    """Build the task registry by importing all task functions.

    Each entry maps a Celery task name to the underlying function.
    During the migration period, both Celery and job_queue use the
    same function implementations.

    Returns:
        Dict mapping task name strings to callable handlers.
    """
    registry: Dict[str, Callable] = {}

    # ------------------------------------------------------------------
    # 1. Liveness tasks (no bind)
    # ------------------------------------------------------------------
    try:
        from app.tasks.liveness_tasks import ping_all_managed_hosts

        registry["app.tasks.ping_all_managed_hosts"] = ping_all_managed_hosts
    except ImportError:
        logger.warning("Could not import liveness_tasks")

    # ------------------------------------------------------------------
    # 2. Stale scan detection (no bind)
    # ------------------------------------------------------------------
    try:
        from app.tasks.stale_scan_detection import detect_stale_scans

        registry["app.tasks.detect_stale_scans"] = detect_stale_scans
    except ImportError:
        logger.warning("Could not import stale_scan_detection")

    # ------------------------------------------------------------------
    # 3. Monitoring tasks (both bind=True)
    # ------------------------------------------------------------------
    try:
        from app.tasks.monitoring_tasks import check_host_connectivity

        registry["app.tasks.check_host_connectivity"] = _wrap_bound_task(check_host_connectivity)
    except ImportError:
        logger.warning("Could not import monitoring_tasks.check_host_connectivity")

    try:
        from app.tasks.monitoring_tasks import queue_host_checks

        registry["app.tasks.queue_host_checks"] = _wrap_bound_task(queue_host_checks)
    except ImportError:
        logger.warning("Could not import monitoring_tasks.queue_host_checks")

    # ------------------------------------------------------------------
    # 4. Adaptive monitoring dispatcher (bind=True)
    # ------------------------------------------------------------------
    try:
        from app.tasks.adaptive_monitoring_dispatcher import dispatch_host_checks

        registry["app.tasks.dispatch_host_checks"] = _wrap_bound_task(dispatch_host_checks)
    except ImportError:
        logger.warning("Could not import adaptive_monitoring_dispatcher")

    # ------------------------------------------------------------------
    # 5. Compliance tasks (mixed bind/no-bind)
    # ------------------------------------------------------------------
    try:
        from app.tasks.compliance_tasks import scheduled_group_scan

        registry["app.tasks.scheduled_group_scan"] = _wrap_bound_task(scheduled_group_scan)
    except ImportError:
        logger.warning("Could not import compliance_tasks.scheduled_group_scan")

    try:
        from app.tasks.compliance_tasks import execute_compliance_scan_async

        registry["app.tasks.execute_compliance_scan_async"] = _wrap_bound_task(execute_compliance_scan_async)
    except ImportError:
        logger.warning("Could not import compliance_tasks.execute_compliance_scan_async")

    try:
        from app.tasks.compliance_tasks import send_compliance_notification

        registry["app.tasks.send_compliance_notification"] = send_compliance_notification
    except ImportError:
        logger.warning("Could not import compliance_tasks.send_compliance_notification")

    try:
        from app.tasks.compliance_tasks import compliance_alert_check

        registry["app.tasks.compliance_alert_check"] = compliance_alert_check
    except ImportError:
        logger.warning("Could not import compliance_tasks.compliance_alert_check")

    try:
        from app.tasks.compliance_tasks import send_compliance_alerts

        registry["app.tasks.send_compliance_alerts"] = send_compliance_alerts
    except ImportError:
        logger.warning("Could not import compliance_tasks.send_compliance_alerts")

    try:
        from app.tasks.compliance_tasks import compliance_monitoring_task

        registry["app.tasks.compliance_monitoring_task"] = compliance_monitoring_task
    except ImportError:
        logger.warning("Could not import compliance_tasks.compliance_monitoring_task")

    # ------------------------------------------------------------------
    # 6. Compliance scheduler tasks (all bind=True)
    # ------------------------------------------------------------------
    try:
        from app.tasks.compliance_scheduler_tasks import dispatch_compliance_scans

        registry["app.tasks.dispatch_compliance_scans"] = _wrap_bound_task(dispatch_compliance_scans)
    except ImportError:
        logger.warning("Could not import compliance_scheduler_tasks.dispatch_compliance_scans")

    try:
        from app.tasks.compliance_scheduler_tasks import run_scheduled_kensa_scan

        registry["app.tasks.run_scheduled_kensa_scan"] = _wrap_bound_task(run_scheduled_kensa_scan)
    except ImportError:
        logger.warning("Could not import compliance_scheduler_tasks.run_scheduled_kensa_scan")

    try:
        from app.tasks.compliance_scheduler_tasks import initialize_compliance_schedules

        registry["app.tasks.initialize_compliance_schedules"] = _wrap_bound_task(initialize_compliance_schedules)
    except ImportError:
        logger.warning("Could not import compliance_scheduler_tasks.initialize_compliance_schedules")

    try:
        from app.tasks.compliance_scheduler_tasks import expire_compliance_maintenance

        registry["app.tasks.expire_compliance_maintenance"] = _wrap_bound_task(expire_compliance_maintenance)
    except ImportError:
        logger.warning("Could not import compliance_scheduler_tasks.expire_compliance_maintenance")

    # ------------------------------------------------------------------
    # 7. Scan tasks (bind=True for execute_scan_celery)
    # ------------------------------------------------------------------
    try:
        from app.tasks.scan_tasks import execute_scan_celery

        registry["app.tasks.execute_scan"] = _wrap_bound_task(execute_scan_celery)
    except ImportError:
        logger.warning("Could not import scan_tasks.execute_scan_celery")

    # ------------------------------------------------------------------
    # 8. Kensa scan tasks (bind=True)
    # ------------------------------------------------------------------
    try:
        from app.tasks.kensa_scan_tasks import execute_kensa_scan_task

        registry["app.tasks.execute_kensa_scan"] = _wrap_bound_task(execute_kensa_scan_task)
    except ImportError:
        logger.warning("Could not import kensa_scan_tasks")

    # ------------------------------------------------------------------
    # 9. Posture tasks (no bind, shared_task)
    # ------------------------------------------------------------------
    try:
        from app.tasks.posture_tasks import create_daily_posture_snapshots

        registry["create_daily_posture_snapshots"] = create_daily_posture_snapshots
    except ImportError:
        logger.warning("Could not import posture_tasks.create_daily_posture_snapshots")

    try:
        from app.tasks.posture_tasks import cleanup_old_posture_snapshots

        registry["cleanup_old_posture_snapshots"] = cleanup_old_posture_snapshots
    except ImportError:
        logger.warning("Could not import posture_tasks.cleanup_old_posture_snapshots")

    # ------------------------------------------------------------------
    # 10. Background tasks (mixed bind/no-bind)
    # ------------------------------------------------------------------
    try:
        from app.tasks.background_tasks import enrich_scan_results_celery

        registry["app.tasks.enrich_scan_results"] = enrich_scan_results_celery
    except ImportError:
        logger.warning("Could not import background_tasks.enrich_scan_results_celery")

    try:
        from app.tasks.background_tasks import execute_remediation_celery

        registry["app.tasks.execute_remediation_legacy"] = execute_remediation_celery
    except ImportError:
        logger.warning("Could not import background_tasks.execute_remediation_celery")

    try:
        from app.tasks.background_tasks import import_scap_content_celery

        registry["app.tasks.import_scap_content"] = _wrap_bound_task(import_scap_content_celery)
    except ImportError:
        logger.warning("Could not import background_tasks.import_scap_content_celery")

    try:
        from app.tasks.background_tasks import deliver_webhook_celery

        registry["app.tasks.deliver_webhook"] = deliver_webhook_celery
    except ImportError:
        logger.warning("Could not import background_tasks.deliver_webhook_celery")

    try:
        from app.tasks.background_tasks import execute_host_discovery_celery

        registry["app.tasks.execute_host_discovery"] = execute_host_discovery_celery
    except ImportError:
        logger.warning("Could not import background_tasks.execute_host_discovery_celery")

    # ------------------------------------------------------------------
    # 11. Remediation tasks (bind=True, shared_task)
    # ------------------------------------------------------------------
    try:
        from app.tasks.remediation_tasks import execute_remediation_job

        registry["app.tasks.execute_remediation"] = _wrap_bound_task(execute_remediation_job)
    except ImportError:
        logger.warning("Could not import remediation_tasks.execute_remediation_job")

    try:
        from app.tasks.remediation_tasks import execute_rollback_job

        registry["app.tasks.execute_rollback"] = _wrap_bound_task(execute_rollback_job)
    except ImportError:
        logger.warning("Could not import remediation_tasks.execute_rollback_job")

    # ------------------------------------------------------------------
    # 12. Notification tasks (no bind)
    # ------------------------------------------------------------------
    try:
        from app.tasks.notification_tasks import dispatch_alert_notifications

        registry["app.tasks.dispatch_alert_notifications"] = dispatch_alert_notifications
    except ImportError:
        logger.warning("Could not import notification_tasks")

    # ------------------------------------------------------------------
    # 13. OS discovery tasks (all bind=True)
    # ------------------------------------------------------------------
    try:
        from app.tasks.os_discovery_tasks import trigger_os_discovery

        registry["app.tasks.trigger_os_discovery"] = _wrap_bound_task(trigger_os_discovery)
    except ImportError:
        logger.warning("Could not import os_discovery_tasks.trigger_os_discovery")

    try:
        from app.tasks.os_discovery_tasks import batch_os_discovery

        registry["app.tasks.batch_os_discovery"] = _wrap_bound_task(batch_os_discovery)
    except ImportError:
        logger.warning("Could not import os_discovery_tasks.batch_os_discovery")

    try:
        from app.tasks.os_discovery_tasks import discover_all_hosts_os

        registry["app.tasks.discover_all_hosts_os"] = _wrap_bound_task(discover_all_hosts_os)
    except ImportError:
        logger.warning("Could not import os_discovery_tasks.discover_all_hosts_os")

    # ------------------------------------------------------------------
    # 14. Exception tasks (no bind, shared_task)
    # ------------------------------------------------------------------
    try:
        from app.tasks.exception_tasks import expire_compliance_exceptions

        registry["expire_compliance_exceptions"] = expire_compliance_exceptions
    except ImportError:
        logger.warning("Could not import exception_tasks")

    # ------------------------------------------------------------------
    # 15. Audit export tasks (mixed bind/no-bind)
    # ------------------------------------------------------------------
    try:
        from app.tasks.audit_export_tasks import generate_audit_export_task

        registry["generate_audit_export"] = _wrap_bound_task(generate_audit_export_task)
    except ImportError:
        logger.warning("Could not import audit_export_tasks.generate_audit_export_task")

    try:
        from app.tasks.audit_export_tasks import cleanup_expired_audit_exports

        registry["cleanup_expired_audit_exports"] = cleanup_expired_audit_exports
    except ImportError:
        logger.warning("Could not import audit_export_tasks.cleanup_expired_audit_exports")

    # ------------------------------------------------------------------
    # 16. Plugin update tasks (no bind, shared_task)
    # ------------------------------------------------------------------
    try:
        from app.tasks.plugin_update_tasks import check_kensa_updates

        registry["app.tasks.check_kensa_updates"] = check_kensa_updates
    except ImportError:
        logger.warning("Could not import plugin_update_tasks.check_kensa_updates")

    try:
        from app.tasks.plugin_update_tasks import cleanup_old_update_records

        registry["app.tasks.cleanup_old_update_records"] = cleanup_old_update_records
    except ImportError:
        logger.warning("Could not import plugin_update_tasks.cleanup_old_update_records")

    try:
        from app.tasks.plugin_update_tasks import perform_auto_update

        registry["app.tasks.perform_auto_update"] = perform_auto_update
    except ImportError:
        logger.warning("Could not import plugin_update_tasks.perform_auto_update")

    # ------------------------------------------------------------------
    # 17. Backfill tasks (mixed bind/no-bind)
    # ------------------------------------------------------------------
    try:
        from app.tasks.backfill_posture_snapshots import backfill_posture_snapshots

        registry["backfill_posture_snapshots"] = backfill_posture_snapshots
    except ImportError:
        logger.warning("Could not import backfill_posture_snapshots")

    try:
        from app.tasks.backfill_snapshot_rule_states import backfill_snapshot_rule_states

        registry["backfill_snapshot_rule_states"] = backfill_snapshot_rule_states
    except ImportError:
        logger.warning("Could not import backfill_snapshot_rule_states")

    try:
        from app.tasks.transaction_backfill_tasks import backfill_transactions_from_scans

        registry["app.tasks.backfill_transactions"] = _wrap_bound_task(backfill_transactions_from_scans)
    except ImportError:
        logger.warning("Could not import transaction_backfill_tasks")

    try:
        from app.tasks.state_backfill_tasks import backfill_host_rule_state

        registry["app.tasks.backfill_host_rule_state"] = _wrap_bound_task(backfill_host_rule_state)
    except ImportError:
        logger.warning("Could not import state_backfill_tasks")

    # ------------------------------------------------------------------
    # 18. Retention policy enforcement (no bind)
    # ------------------------------------------------------------------
    try:
        from app.tasks.retention_tasks import cleanup_old_transactions

        registry["app.tasks.enforce_retention"] = cleanup_old_transactions
    except ImportError:
        logger.warning("Could not import retention_tasks.cleanup_old_transactions")

    logger.info("Task registry built: %d tasks registered", len(registry))
    return registry
