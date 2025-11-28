"""
Adaptive Monitoring Dispatcher for Celery Beat

This module implements the dispatcher pattern for the adaptive host monitoring scheduler.
The dispatcher is called periodically by Celery Beat and queues individual host check tasks.

Architecture:
1. Celery Beat calls dispatch_host_checks() every 30 seconds
2. Dispatcher queries hosts WHERE next_check_time <= NOW()
3. Individual check tasks dispatched with state-based priority
4. Each task updates host state and calculates next_check_time

This design ensures:
- No mass network flooding (hosts checked as they become due)
- Scalable to 1000+ hosts (distributed across time)
- Adaptive intervals (critical hosts checked more frequently)
- Resource-aware (respects max_concurrent_checks limit)
"""

import logging
from datetime import datetime
from typing import Any, Dict

from backend.app.celery_app import celery_app
from backend.app.database import get_db
from backend.app.services.adaptive_scheduler_service import adaptive_scheduler_service

logger = logging.getLogger(__name__)

# Note: check_host_connectivity is imported at runtime to avoid circular imports
# It's accessed via celery_app.tasks['backend.app.tasks.check_host_connectivity']


@celery_app.task(bind=True, name="backend.app.tasks.dispatch_host_checks")
def dispatch_host_checks(self: Any) -> Dict[str, Any]:
    """
    Dispatcher task that runs every 30 seconds via Celery Beat.

    Queries hosts that are due for checking and dispatches individual
    check tasks with appropriate priorities.

    Returns:
        dict: Dispatch results including number of hosts dispatched
    """
    try:
        logger.debug("Running adaptive monitoring dispatcher...")

        # Get database session
        db = next(get_db())

        try:
            # Check if scheduler is enabled
            config = adaptive_scheduler_service.get_config(db)

            if not config["enabled"]:
                logger.debug("Adaptive scheduler is disabled, skipping dispatch")
                return {"status": "disabled", "hosts_dispatched": 0}

            # Get hosts due for checking (respects max_concurrent_checks)
            hosts_due = adaptive_scheduler_service.get_hosts_due_for_check(db)

            if not hosts_due:
                logger.debug("No hosts due for checking")
                return {"status": "ok", "hosts_dispatched": 0, "next_check": "none due"}

            # Dispatch individual check tasks with priorities
            dispatched_count = 0
            for host in hosts_due:
                try:
                    # Get priority based on host state
                    priority = adaptive_scheduler_service.get_priority_for_state(db, host["status"])

                    # Dispatch individual host check task with priority
                    # Use send_task to avoid circular import
                    celery_app.send_task(
                        "backend.app.tasks.check_host_connectivity",
                        args=[host["id"], priority],
                        priority=priority,  # Celery queue priority
                        queue="host_monitoring",  # Dedicated queue for monitoring tasks
                    )

                    dispatched_count += 1
                    logger.debug(
                        f"Dispatched check for {host['hostname']} " f"(status: {host['status']}, priority: {priority})"
                    )

                except Exception as dispatch_error:
                    logger.error(f"Failed to dispatch check for host {host['id']}: {dispatch_error}")

            logger.info(f"Dispatched {dispatched_count} host checks")

            return {
                "status": "ok",
                "hosts_dispatched": dispatched_count,
                "timestamp": datetime.utcnow().isoformat(),
            }

        finally:
            db.close()

    except Exception as e:
        logger.error(f"Error in adaptive monitoring dispatcher: {e}")
        return {"status": "error", "error": str(e), "hosts_dispatched": 0}


# Note: check_host_connectivity task is imported from monitoring_tasks.py (line 29)
# and is used by the dispatcher on line 83. The task performs comprehensive
# connectivity checks (ping → port → SSH) and updates the monitoring state machine.


# Celery Beat Schedule Configuration
# This should be added to celeryconfig.py or celery_app.py
CELERY_BEAT_SCHEDULE = {
    "dispatch-host-checks-every-30-seconds": {
        "task": "backend.app.tasks.dispatch_host_checks",
        "schedule": 30.0,  # Run every 30 seconds
        "options": {
            "queue": "host_monitoring",
            "priority": 10,  # Highest priority for dispatcher
        },
    },
}
