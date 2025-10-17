"""
Background tasks for host monitoring and credential maintenance
"""
import logging
from typing import Optional, Tuple
from datetime import datetime
from celery import Celery
from sqlalchemy import text

from backend.app.celery_app import celery_app
from backend.app.database import get_db, get_db_session
from backend.app.services.host_monitor import host_monitor
from backend.app.services.auth_service import get_auth_service
from backend.app.services.host_monitoring_state import HostMonitoringStateMachine, MonitoringState
from backend.app.services.unified_ssh_service import UnifiedSSHService

logger = logging.getLogger(__name__)

def periodic_host_monitoring():
    """
    Periodic task to monitor all hosts
    This can be called by Celery or a scheduler like cron
    """
    try:
        logger.info("Starting periodic host monitoring...")
        
        # Get database session
        db = next(get_db())
        
        # Monitor all hosts
        import asyncio
        results = asyncio.run(host_monitor.monitor_all_hosts(db))
        
        # Log results
        online_count = sum(1 for r in results if r['status'] == 'online')
        total_count = len(results)
        
        logger.info(f"Host monitoring completed: {online_count}/{total_count} hosts online")
        
        # Log any status changes
        for result in results:
            if result.get('error_message'):
                logger.warning(f"Host {result['hostname']} ({result['ip_address']}): {result['error_message']}")
        
        db.close()
        return f"Monitored {total_count} hosts, {online_count} online"
        
    except Exception as e:
        logger.error(f"Error in periodic host monitoring: {e}")
        return f"Error: {str(e)}"

def periodic_credential_purge():
    """
    Daily task to purge inactive credentials older than 90 days.
    Maintains compliance audit trail while preventing unbounded database growth.
    """
    try:
        logger.info("Starting periodic credential purge (90-day retention)...")

        # Get database session
        db = next(get_db())

        try:
            # Purge old inactive credentials
            auth_service = get_auth_service(db)
            purged_count = auth_service.purge_old_inactive_credentials(retention_days=90)

            if purged_count > 0:
                logger.info(f"Credential purge completed: {purged_count} inactive credentials removed")
            else:
                logger.debug("Credential purge completed: No credentials to purge")

            return f"Purged {purged_count} old inactive credentials"

        finally:
            db.close()

    except Exception as e:
        logger.error(f"Error in periodic credential purge: {e}")
        return f"Error: {str(e)}"

@celery_app.task(bind=True, name='backend.app.tasks.check_host_connectivity')
def check_host_connectivity(self, host_id: str, priority: int = 5) -> dict:
    """
    Check SSH connectivity for a host and update monitoring state.

    This is the core Celery task for the Hybrid Monitoring approach.
    It implements adaptive check intervals based on host health state.

    Args:
        host_id: UUID of the host to check
        priority: Celery queue priority (1-10, higher = more urgent)

    Returns:
        dict with check results including new state and next check interval

    State Transitions:
        HEALTHY → (1 failure) → DEGRADED (5 min checks)
        DEGRADED → (2 failures) → CRITICAL (2 min checks)
        CRITICAL → (3 failures) → DOWN (30 min checks)
        Any state → (3 successes) → HEALTHY (30 min checks)
    """
    try:
        with get_db_session() as db:
            # Get host details
            host_result = db.execute(text("""
                SELECT id, hostname, ip_address, monitoring_state, username, auth_method,
                       encrypted_credentials
                FROM hosts
                WHERE id = :host_id AND is_active = true
            """), {"host_id": host_id}).fetchone()

            if not host_result:
                logger.warning(f"Host {host_id} not found or inactive for connectivity check")
                return {
                    "host_id": host_id,
                    "success": False,
                    "error": "Host not found or inactive",
                    "new_state": "UNKNOWN"
                }

            # Check SSH connectivity
            check_success = False
            response_time_ms = None
            error_message = None
            error_type = None

            try:
                start_time = datetime.utcnow()

                # Use UnifiedSSHService to check connectivity
                ssh_service = UnifiedSSHService(db)

                # Test SSH connection with simple command
                ssh_result = ssh_service.execute_command(
                    host_id=host_id,
                    command="echo 'connectivity_check'",
                    timeout=10
                )

                # Calculate response time
                response_time_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)

                if ssh_result.get('success'):
                    check_success = True
                    logger.debug(f"Host {host_result.hostname} connectivity check: SUCCESS ({response_time_ms}ms)")
                else:
                    error_message = ssh_result.get('error', 'SSH connection failed')
                    error_type = ssh_result.get('error_type', 'CONNECTION_FAILED')
                    logger.warning(f"Host {host_result.hostname} connectivity check: FAILED - {error_message}")

            except TimeoutError:
                error_message = "SSH connection timeout"
                error_type = "TIMEOUT"
                logger.warning(f"Host {host_result.hostname} connectivity check: TIMEOUT")
            except ConnectionError as e:
                error_message = f"SSH connection error: {str(e)}"
                error_type = "CONNECTION_REFUSED"
                logger.warning(f"Host {host_result.hostname} connectivity check: {error_message}")
            except Exception as e:
                error_message = f"SSH check failed: {str(e)}"
                error_type = "UNKNOWN_ERROR"
                logger.error(f"Host {host_result.hostname} connectivity check error: {e}")

            # Update monitoring state using state machine
            state_machine = HostMonitoringStateMachine(db)
            new_state, check_interval = state_machine.transition_state(
                host_id=host_id,
                check_success=check_success,
                response_time_ms=response_time_ms,
                error_message=error_message,
                error_type=error_type
            )

            # Return results
            return {
                "host_id": host_id,
                "hostname": host_result.hostname,
                "ip_address": host_result.ip_address,
                "success": check_success,
                "previous_state": host_result.monitoring_state,
                "new_state": new_state.value,
                "check_interval_minutes": check_interval,
                "response_time_ms": response_time_ms,
                "error_message": error_message,
                "error_type": error_type,
                "priority": priority,
                "checked_at": datetime.utcnow().isoformat()
            }

    except Exception as exc:
        logger.error(f"Critical error in check_host_connectivity for {host_id}: {exc}")
        # Retry with exponential backoff (max 3 retries)
        raise self.retry(exc=exc, countdown=min(2 ** self.request.retries * 60, 300), max_retries=3)


@celery_app.task(bind=True, name='backend.app.tasks.queue_host_checks')
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
                return {
                    "queued_count": 0,
                    "message": "No hosts due for monitoring"
                }

            # Dispatch individual check tasks with priority-based queueing
            queued_count = 0
            state_distribution = {}

            for host in hosts_to_check:
                try:
                    # Track state distribution for monitoring
                    state = host.get('state', 'UNKNOWN')
                    state_distribution[state] = state_distribution.get(state, 0) + 1

                    # Dispatch task with priority (Celery priority: 0-9, higher = more urgent)
                    check_host_connectivity.apply_async(
                        args=[host['id'], host['priority']],
                        priority=host['priority'],
                        queue='monitoring'
                    )

                    queued_count += 1

                except Exception as e:
                    logger.error(f"Failed to queue check for host {host.get('hostname', host['id'])}: {e}")
                    continue

            logger.info(
                f"Queued {queued_count} host connectivity checks. "
                f"State distribution: {state_distribution}"
            )

            return {
                "queued_count": queued_count,
                "total_due": len(hosts_to_check),
                "state_distribution": state_distribution,
                "queued_at": datetime.utcnow().isoformat()
            }

    except Exception as exc:
        logger.error(f"Failed to queue host checks: {exc}")
        raise self.retry(exc=exc, countdown=60, max_retries=3)


# Example function to set up periodic monitoring with APScheduler
def setup_host_monitoring_scheduler():
    """
    Set up periodic host monitoring using APScheduler
    This only creates the scheduler instance - jobs are configured by restore_scheduler_state()
    """
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        import atexit

        scheduler = BackgroundScheduler()

        # Don't auto-start or add jobs here - let restore_scheduler_state() handle it
        # This allows database configuration to control the scheduler behavior
        logger.info("Host monitoring scheduler instance created (not started)")

        # Shut down the scheduler when exiting the app
        atexit.register(lambda: scheduler.shutdown())

        return scheduler

    except ImportError:
        logger.warning("APScheduler not available, periodic monitoring disabled")
        return None
    except Exception as e:
        logger.error(f"Failed to setup monitoring scheduler: {e}")
        return None