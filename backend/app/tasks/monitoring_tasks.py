"""
Background tasks for host monitoring.

Active Celery tasks:
    - check_host_connectivity: Comprehensive ping/port/SSH check for a single host
    - queue_host_checks: Dispatcher that queues hosts due for monitoring
"""

import logging
from datetime import datetime

from sqlalchemy import text

from app.celery_app import celery_app
from app.config import get_settings
from app.database import get_db_session
from app.encryption import EncryptionConfig, create_encryption_service
from app.services.monitoring import HostMonitoringStateMachine, get_host_monitor

logger = logging.getLogger(__name__)


@celery_app.task(
    bind=True,
    name="app.tasks.check_host_connectivity",
    time_limit=300,
    soft_time_limit=240,
)
def check_host_connectivity(self, host_id: str, priority: int = 5) -> dict:
    """
    Perform comprehensive connectivity check for a host (ping → port → SSH).

    This is the core Celery task for the Adaptive Host Monitoring approach.
    It performs 3-step verification and implements adaptive check intervals.

    Args:
        host_id: UUID of the host to check
        priority: Celery queue priority (1-10, higher = more urgent)

    Returns:
        dict with check results including new state and next check interval

    Check Steps:
        1. Ping check (ICMP or socket fallback)
        2. Port connectivity check (TCP port 22)
        3. SSH authentication check (full credential validation)

    State Transitions:
        HEALTHY → (1 failure) → DEGRADED (5 min checks)
        DEGRADED → (2 failures) → CRITICAL (2 min checks)
        CRITICAL → (3 failures) → DOWN (30 min checks)
        Any state → (3 successes) → HEALTHY (30 min checks)
    """
    try:
        with get_db_session() as db:
            # Get host details for comprehensive check
            host_result = db.execute(
                text(
                    """
                SELECT id, hostname, ip_address, port, username, auth_method,
                       encrypted_credentials, status
                FROM hosts
                WHERE id = :host_id AND is_active = true
            """
                ),
                {"host_id": host_id},
            ).fetchone()

            if not host_result:
                logger.warning(f"Host {host_id} not found or inactive for connectivity check")
                return {
                    "host_id": host_id,
                    "success": False,
                    "error": "Host not found or inactive",
                    "new_state": "UNKNOWN",
                }

            # Import HostMonitor for comprehensive check

            # Prepare host data for comprehensive check
            host_data = {
                "id": str(host_result.id),
                "hostname": host_result.hostname,
                "ip_address": host_result.ip_address,
                "port": host_result.port or 22,
                "username": host_result.username,
                "auth_method": host_result.auth_method,
                "encrypted_credentials": host_result.encrypted_credentials,
            }

            # Create encryption service
            settings = get_settings()
            encryption_service = create_encryption_service(master_key=settings.master_key, config=EncryptionConfig())

            # Perform comprehensive check (ping → port → SSH)
            monitor = get_host_monitor(db, encryption_service)

            # Run comprehensive check synchronously (we're already in async Celery task)
            import asyncio

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                check_result = loop.run_until_complete(monitor.comprehensive_host_check(host_data, db))
            finally:
                loop.close()

            # Extract check results
            ping_success = check_result.get("ping_success", False)
            port_open = check_result.get("port_open", False)
            ssh_accessible = check_result.get("ssh_accessible", False)
            response_time_ms = check_result.get("response_time_ms")
            error_message = check_result.get("error_message")
            status = check_result.get("status", "offline")

            # Overall success if SSH is accessible
            check_success = ssh_accessible

            # Map comprehensive check status to error type
            if not ping_success:
                error_type = "NETWORK_UNREACHABLE"
            elif not port_open:
                error_type = "PORT_CLOSED"
            elif not ssh_accessible:
                error_type = "SSH_AUTH_FAILED"
            else:
                error_type = None

            logger.info(
                f"Comprehensive check for {host_result.hostname}: "
                f"ping={ping_success}, port={port_open}, ssh={ssh_accessible}, "
                f"status={status}, response_time={response_time_ms}ms"
            )

            # Update monitoring state using state machine
            state_machine = HostMonitoringStateMachine(db)
            new_state, check_interval = state_machine.transition_state(
                host_id=host_id,
                ping_success=ping_success,
                ssh_success=ssh_accessible,
                privilege_success=ssh_accessible,  # If SSH works, we assume privilege works
                response_time_ms=response_time_ms,
                error_message=error_message,
                error_type=error_type,
            )

            # Return results
            return {
                "host_id": host_id,
                "hostname": host_result.hostname,
                "ip_address": host_result.ip_address,
                "success": check_success,
                "previous_state": host_result.status,
                "new_state": new_state.value,
                "check_interval_minutes": check_interval,
                "response_time_ms": response_time_ms,
                "diagnostics": {
                    "ping_success": ping_success,
                    "port_open": port_open,
                    "ssh_accessible": ssh_accessible,
                    "status": status,
                },
                "error_message": error_message,
                "error_type": error_type,
                "priority": priority,
                "checked_at": datetime.utcnow().isoformat(),
            }

    except Exception as exc:
        logger.error(f"Critical error in check_host_connectivity for {host_id}: {exc}")
        # Retry with exponential backoff (max 3 retries)
        raise self.retry(exc=exc, countdown=min(2**self.request.retries * 60, 300), max_retries=3)


@celery_app.task(
    bind=True,
    name="app.tasks.queue_host_checks",
    time_limit=120,
    soft_time_limit=90,
)
def queue_host_checks(self, limit: int = 100) -> dict:
    """
    Queue connectivity checks for hosts that are due for monitoring.

    This task acts as the queue producer - it queries the database for hosts
    that need checking and dispatches individual check_host_connectivity tasks.

    Args:
        limit: Maximum number of hosts to queue in this batch

    Returns:
        dict with statistics about queued checks
    """
    try:
        with get_db_session() as db:
            # Get hosts to check using state machine logic
            state_machine = HostMonitoringStateMachine(db)
            hosts_to_check = state_machine.get_hosts_to_check(limit=limit)

            if not hosts_to_check:
                logger.debug("No hosts due for monitoring checks")
                return {"queued_count": 0, "message": "No hosts due for monitoring"}

            # Dispatch individual check tasks with priority-based queueing
            queued_count = 0
            state_distribution = {}

            for host in hosts_to_check:
                try:
                    # Track state distribution for monitoring
                    state = host.get("state", "UNKNOWN")
                    state_distribution[state] = state_distribution.get(state, 0) + 1

                    # Dispatch task with priority (Celery priority: 0-9, higher = more urgent)
                    check_host_connectivity.apply_async(
                        args=[host["id"], host["priority"]],
                        priority=host["priority"],
                        queue="monitoring",
                    )

                    queued_count += 1

                except Exception as e:
                    logger.error(f"Failed to queue check for host {host.get('hostname', host['id'])}: {e}")
                    continue

            logger.info(f"Queued {queued_count} host connectivity checks. " f"State distribution: {state_distribution}")

            return {
                "queued_count": queued_count,
                "total_due": len(hosts_to_check),
                "state_distribution": state_distribution,
                "queued_at": datetime.utcnow().isoformat(),
            }

    except Exception as exc:
        logger.error(f"Failed to queue host checks: {exc}")
        raise self.retry(exc=exc, countdown=60, max_retries=3)
