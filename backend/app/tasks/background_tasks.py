"""
General-purpose Celery tasks migrated from FastAPI BackgroundTasks.

Consolidates all background work under Celery for consistent timeouts,
retries, crash recovery, and observability.

All tasks are sync (def, not async def) because Celery does not
natively support async tasks. Async service calls are executed via
_run_async().
"""

import asyncio
import logging
from typing import Any, Dict, List
from uuid import UUID

from app.celery_app import celery_app

logger = logging.getLogger(__name__)


def _run_async(coro):
    """Run an async coroutine synchronously for Celery task compatibility."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# Task 1: Scan result enrichment (consolidated from two near-identical fns)
# ---------------------------------------------------------------------------


@celery_app.task(
    name="app.tasks.enrich_scan_results",
    time_limit=600,
    soft_time_limit=540,
)
def enrich_scan_results_celery(
    scan_id: str,
    result_file: str,
    scan_metadata: Dict[str, Any],
    generate_report: bool,
) -> None:
    """
    Enrich scan results with intelligence data and generate reports.

    Consolidates the two identical enrichment functions previously in
    scans/helpers.py and mongodb_scan_api.py.
    """
    try:
        logger.info("Starting background enrichment for scan %s", scan_id)

        from app.routes.scans.helpers import get_compliance_reporter, get_enrichment_service

        enrichment_svc = _run_async(get_enrichment_service())
        enriched_results = _run_async(
            enrichment_svc.enrich_scan_results(
                result_file_path=result_file,
                scan_metadata=scan_metadata,
            )
        )

        if generate_report:
            reporter = _run_async(get_compliance_reporter())
            framework = scan_metadata.get("framework")
            target_frameworks: List[str] = [str(framework)] if framework else []

            _run_async(
                reporter.generate_compliance_report(
                    enriched_results=enriched_results,
                    target_frameworks=target_frameworks,
                    report_format="json",
                )
            )
            logger.info("Generated compliance report for scan %s", scan_id)

        logger.info("Background enrichment completed for scan %s", scan_id)

    except Exception as e:
        logger.error("Background enrichment failed for scan %s: %s", scan_id, e)


# ---------------------------------------------------------------------------
# Task 2: Remediation execution
# ---------------------------------------------------------------------------


@celery_app.task(
    name="app.tasks.execute_remediation",
    time_limit=3600,
    soft_time_limit=3300,
)
def execute_remediation_celery(
    job_id: str,
    provider: str,
    scan_id: str,
    host_id: str,
    failed_rules: List[str],
    options: Dict[str, Any],
) -> None:
    """Execute remediation job via the configured provider."""
    try:
        logger.info("Starting remediation job %s with provider %s", job_id, provider)

        from app.routes.remediation_provider import (
            _execute_aegis_remediation,
            _execute_ansible_remediation,
            _execute_manual_remediation,
        )

        uid_job = UUID(job_id)
        uid_scan = UUID(scan_id)
        uid_host = UUID(host_id)

        if provider == "aegis":
            _run_async(_execute_aegis_remediation(uid_job, uid_scan, uid_host, failed_rules, options))
        elif provider == "ansible":
            _run_async(_execute_ansible_remediation(uid_job, uid_scan, uid_host, failed_rules, options))
        elif provider == "manual":
            _run_async(_execute_manual_remediation(uid_job, uid_scan, uid_host, failed_rules, options))
        else:
            logger.error("Unknown remediation provider: %s", provider)

    except Exception as e:
        logger.error("Error executing remediation job %s: %s", job_id, e)


# ---------------------------------------------------------------------------
# Task 3: SCAP content import
# ---------------------------------------------------------------------------


@celery_app.task(
    bind=True,
    name="app.tasks.import_scap_content",
    time_limit=3600,
    soft_time_limit=3300,
)
def import_scap_content_celery(
    self,
    import_id: str,
    file_path: str,
    deduplication_strategy: str,
    batch_size: int,
) -> Dict[str, Any]:
    """
    Import SCAP content into MongoDB.

    Progress is tracked via Celery's update_state() so callers can poll
    via AsyncResult(task_id).
    """
    try:
        self.update_state(state="PROGRESS", meta={"current_phase": "starting", "import_id": import_id})

        from app.services.content import ImportProgress, process_scap_content

        def progress_callback(progress: ImportProgress) -> None:
            self.update_state(
                state="PROGRESS",
                meta={
                    "import_id": import_id,
                    "current_phase": progress.stage.value if progress.stage else "processing",
                    "processed_rules": progress.processed_count,
                    "total_rules": progress.total_count,
                    "progress_percentage": progress.percent_complete,
                },
            )

        result = process_scap_content(
            source_path=file_path,
            progress_callback=progress_callback,
            batch_size=batch_size,
            deduplication=deduplication_strategy,
        )

        return {
            "status": "completed",
            "import_id": import_id,
            "statistics": {
                "imported": result.imported_count,
                "updated": result.updated_count,
                "skipped": result.skipped_count,
                "errors": result.failed_count,
            },
        }

    except Exception as e:
        logger.error("SCAP import failed for %s: %s", import_id, e)
        return {
            "status": "failed",
            "import_id": import_id,
            "error": str(e),
        }


# ---------------------------------------------------------------------------
# Task 4: Webhook delivery
# ---------------------------------------------------------------------------


@celery_app.task(
    name="app.tasks.deliver_webhook",
    time_limit=120,
    soft_time_limit=90,
    max_retries=3,
    default_retry_delay=30,
)
def deliver_webhook_celery(
    url: str,
    secret_hash: str,
    event_data: Dict[str, Any],
    webhook_id: str,
    max_retries: int = 3,
) -> bool:
    """Deliver webhook to endpoint with signature verification."""
    from app.tasks.webhook_tasks import deliver_webhook

    return _run_async(deliver_webhook(url, secret_hash, event_data, webhook_id, max_retries))


# ---------------------------------------------------------------------------
# Task 5: Host discovery
# ---------------------------------------------------------------------------


@celery_app.task(
    name="app.tasks.execute_host_discovery",
    time_limit=300,
    soft_time_limit=240,
)
def execute_host_discovery_celery(host_id: str) -> None:
    """Discover basic system information for a host."""
    try:
        from app.database import SessionLocal
        from app.models.sql_models import Host
        from app.routes.hosts.discovery import HostBasicDiscoveryService

        host_uuid = UUID(host_id)
        db = SessionLocal()
        try:
            host = db.query(Host).filter(Host.id == host_uuid).first()

            if host:
                discovery_service = HostBasicDiscoveryService()
                discovery_service.discover_basic_system_info(host)

                db.add(host)
                db.commit()
                logger.info("Background discovery completed for host %s", host_id)
            else:
                logger.warning("Host %s not found for discovery", host_id)
        finally:
            db.close()

    except Exception as e:
        logger.error("Background discovery failed for host %s: %s", host_id, e)
