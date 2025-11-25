"""
Host Monitoring API Routes
"""

import logging
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..config import get_settings
from ..database import get_db
from ..encryption import EncryptionConfig, create_encryption_service
from ..services.host_monitor import get_host_monitor

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/monitoring", tags=["Monitoring"])


class HostCheckRequest(BaseModel):
    host_id: str


@router.post("/hosts/check")
async def check_host_status(
    request: HostCheckRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Check status of a specific host
    """
    try:
        from sqlalchemy import text

        # Get host details
        result = db.execute(
            text(
                """
            SELECT id, hostname, ip_address, port, username, auth_method
            FROM hosts WHERE id = :id
        """
            ),
            {"id": request.host_id},
        )

        host_row = result.fetchone()
        if not host_row:
            raise HTTPException(status_code=404, detail="Host not found")

        host_data = {
            "id": str(host_row.id),
            "hostname": host_row.hostname,
            "ip_address": str(host_row.ip_address),
            "port": host_row.port or 22,
            "username": host_row.username,
            "auth_method": host_row.auth_method,
            # NOTE: encrypted_credentials removed - using centralized auth service
        }

        # Create encryption service
        settings = get_settings()
        encryption_service = create_encryption_service(
            master_key=settings.master_key, config=EncryptionConfig()
        )

        # Create host monitor with dependencies
        monitor = get_host_monitor(db, encryption_service)

        # Perform comprehensive check with DB connection for credential access
        check_result = await monitor.comprehensive_host_check(host_data, db)

        # Update database with new status and response time
        await monitor.update_host_status(
            db,
            request.host_id,
            check_result["status"],
            response_time_ms=check_result.get("response_time_ms"),
        )

        return {
            "host_id": request.host_id,
            "status": check_result["status"],
            "ping_success": check_result["ping_success"],
            "port_open": check_result["port_open"],
            "ssh_accessible": check_result["ssh_accessible"],
            "response_time_ms": check_result["response_time_ms"],
            "error_message": check_result["error_message"],
            "timestamp": check_result["timestamp"],
            # SSH credential information
            "ssh_credentials_used": check_result.get("ssh_credentials_source"),
            "ssh_username": check_result.get("ssh_username"),
            "ready_for_scans": check_result["ssh_accessible"],
            "credential_details": check_result.get("credential_details"),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error checking host status: {e}")
        raise HTTPException(status_code=500, detail="Failed to check host status")


@router.post("/hosts/check-all")
async def check_all_hosts_status(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Check status of all hosts (runs in background)
    """
    try:
        # Create wrapper function for background monitoring
        async def monitor_with_encryption():
            # Create encryption service
            settings = get_settings()
            encryption_service = create_encryption_service(
                master_key=settings.master_key, config=EncryptionConfig()
            )
            # Create host monitor with dependencies
            monitor = get_host_monitor(db, encryption_service)
            await monitor.monitor_all_hosts(db)

        # Run monitoring in background
        background_tasks.add_task(monitor_with_encryption)

        return {"message": "Host monitoring started in background", "status": "running"}

    except Exception as e:
        logger.error(f"Error starting host monitoring: {e}")
        raise HTTPException(status_code=500, detail="Failed to start host monitoring")


@router.get("/hosts/status")
async def get_hosts_status_summary(
    db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)
):
    """
    Get summary of all host statuses with monitoring statistics
    """
    try:
        from datetime import datetime

        from sqlalchemy import text

        # Get status breakdown
        result = db.execute(
            text(
                """
            SELECT
                status,
                COUNT(*) as count
            FROM hosts
            WHERE is_active = true
            GROUP BY status
        """
            )
        )

        status_counts = {}
        total = 0
        for row in result:
            status_counts[row.status] = row.count
            total += row.count

        # Calculate average response time from active hosts
        avg_response_result = db.execute(
            text(
                """
            SELECT AVG(response_time_ms) as avg_response
            FROM hosts
            WHERE is_active = true
              AND response_time_ms IS NOT NULL
              AND status != 'down'
        """
            )
        )
        avg_response_row = avg_response_result.fetchone()
        avg_response_time = (
            round(avg_response_row.avg_response)
            if avg_response_row and avg_response_row.avg_response
            else 0
        )

        # Count monitoring checks performed today
        today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        checks_today_result = db.execute(
            text(
                """
            SELECT COUNT(*) as check_count
            FROM host_monitoring_history
            WHERE check_time >= :today_start
        """
            ),
            {"today_start": today_start},
        )
        checks_today_row = checks_today_result.fetchone()
        checks_today = checks_today_row.check_count if checks_today_row else 0

        return {
            "total_hosts": total,
            "status_breakdown": status_counts,
            "online_percentage": round(
                (status_counts.get("online", 0) / total * 100) if total > 0 else 0, 1
            ),
            "avg_response_time_ms": avg_response_time,
            "checks_today": checks_today,
        }

    except Exception as e:
        logger.error(f"Error getting host status summary: {e}")
        raise HTTPException(status_code=500, detail="Failed to get host status summary")


@router.post("/hosts/{host_id}/ping")
async def ping_host(
    host_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Simple ping test for a specific host
    """
    try:
        from sqlalchemy import text

        # Get host IP
        result = db.execute(
            text(
                """
            SELECT ip_address FROM hosts WHERE id = :id
        """
            ),
            {"id": host_id},
        )

        host_row = result.fetchone()
        if not host_row:
            raise HTTPException(status_code=404, detail="Host not found")

        ip_address = str(host_row.ip_address)

        # Create host monitor (ping doesn't need encryption service)
        monitor = get_host_monitor()

        # Perform ping
        ping_success = await monitor.ping_host(ip_address)

        return {
            "host_id": host_id,
            "ip_address": ip_address,
            "ping_success": ping_success,
            "timestamp": datetime.utcnow().isoformat(),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error pinging host: {e}")
        raise HTTPException(status_code=500, detail="Failed to ping host")


@router.post("/hosts/{host_id}/check-connectivity")
async def jit_connectivity_check(
    host_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Just-In-Time (JIT) connectivity check for a specific host.

    This endpoint performs an IMMEDIATE comprehensive connectivity check for manual troubleshooting.
    It's called when:
    - User clicks "Check Status" button (immediate diagnostics)
    - Before starting a compliance scan (ensure host is reachable)
    - Manual refresh from UI

    The check runs SYNCHRONOUSLY and provides detailed diagnostics:
    1. Ping check (ICMP or socket fallback)
    2. Port connectivity check (TCP port 22)
    3. SSH authentication check (full credential validation)

    Returns granular status: online, reachable, ping_only, offline, error
    """
    try:
        from sqlalchemy import text

        # Get host details for comprehensive check
        result = db.execute(
            text(
                """
            SELECT id, hostname, ip_address, port, username, auth_method,
                   encrypted_credentials, status
            FROM hosts
            WHERE id = :host_id AND is_active = true
        """
            ),
            {"host_id": host_id},
        )

        host = result.fetchone()
        if not host:
            raise HTTPException(status_code=404, detail="Host not found or inactive")

        # Prepare host data for comprehensive check
        host_data = {
            "id": str(host.id),
            "hostname": host.hostname,
            "ip_address": host.ip_address,
            "port": host.port or 22,
            "username": host.username,
            "auth_method": host.auth_method,
            "encrypted_credentials": host.encrypted_credentials,
        }

        # Create encryption service
        settings = get_settings()
        encryption_service = create_encryption_service(
            master_key=settings.master_key, config=EncryptionConfig()
        )

        # Perform comprehensive check (ping → port → SSH)
        monitor = get_host_monitor(db, encryption_service)
        check_result = await monitor.comprehensive_host_check(host_data, db)

        logger.info(
            f"JIT comprehensive check for {host.hostname}: "
            f"status={check_result['status']}, "
            f"ping={check_result['ping_success']}, "
            f"port={check_result['port_open']}, "
            f"ssh={check_result['ssh_accessible']}, "
            f"response_time={check_result['response_time_ms']}ms"
        )

        return {
            "host_id": host_id,
            "hostname": check_result["hostname"],
            "ip_address": check_result["ip_address"],
            "current_status": check_result["status"],
            "previous_status": host.status,
            "last_check": check_result["timestamp"],
            "response_time_ms": check_result["response_time_ms"],
            "diagnostics": {
                "ping_success": check_result["ping_success"],
                "port_open": check_result["port_open"],
                "ssh_accessible": check_result["ssh_accessible"],
                "ssh_credentials_source": check_result.get("ssh_credentials_source"),
                "credential_details": check_result.get("credential_details"),
            },
            "error_message": check_result.get("error_message"),
            "message": "Comprehensive connectivity check completed",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error performing JIT connectivity check for {host_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to check connectivity: {str(e)}")


@router.get("/hosts/{host_id}/state")
async def get_host_monitoring_state(
    host_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Get detailed monitoring state for a host.

    Returns the host's current monitoring state machine status, including:
    - Current state (HEALTHY/DEGRADED/CRITICAL/DOWN/MAINTENANCE)
    - Consecutive failures/successes
    - Next scheduled check time
    - Check priority
    - Response time history
    """
    try:
        from sqlalchemy import text

        # Get host monitoring state
        result = db.execute(
            text(
                """
            SELECT h.id, h.hostname, h.ip_address,
                   h.ping_consecutive_failures, h.ping_consecutive_successes,
                   h.ssh_consecutive_failures, h.ssh_consecutive_successes,
                   h.next_check_time, h.last_state_change, h.check_priority,
                   h.response_time_ms, h.last_check, h.status
            FROM hosts h
            WHERE h.id = :host_id AND h.is_active = true
        """
            ),
            {"host_id": host_id},
        )

        host = result.fetchone()
        if not host:
            raise HTTPException(status_code=404, detail="Host not found or inactive")

        # Get recent history (last 10 checks)
        history_result = db.execute(
            text(
                """
            SELECT check_time, monitoring_state, previous_state, response_time_ms,
                   success, error_message, error_type
            FROM host_monitoring_history
            WHERE host_id = :host_id
            ORDER BY check_time DESC
            LIMIT 10
        """
            ),
            {"host_id": host_id},
        )

        history = []
        for row in history_result:
            history.append(
                {
                    "check_time": row.check_time.isoformat(),
                    "state": row.monitoring_state,
                    "previous_state": row.previous_state,
                    "response_time_ms": row.response_time_ms,
                    "success": row.success,
                    "error_message": row.error_message,
                    "error_type": row.error_type,
                }
            )

        # Derive monitoring state from status and failure counters
        # This provides backward compatibility with the monitoring state machine
        if host.status == "online":
            derived_state = "HEALTHY"
        elif host.ssh_consecutive_failures >= 3:
            derived_state = "CRITICAL"
        elif host.ssh_consecutive_failures >= 1 or host.ping_consecutive_failures >= 2:
            derived_state = "DEGRADED"
        elif host.status == "offline":
            derived_state = "DOWN"
        else:
            derived_state = "UNKNOWN"

        return {
            "host_id": str(host.id),
            "hostname": host.hostname,
            "ip_address": host.ip_address,
            "current_state": derived_state,
            "current_status": host.status,
            "ping_consecutive_failures": host.ping_consecutive_failures,
            "ping_consecutive_successes": host.ping_consecutive_successes,
            "ssh_consecutive_failures": host.ssh_consecutive_failures,
            "ssh_consecutive_successes": host.ssh_consecutive_successes,
            "next_check_time": (host.next_check_time.isoformat() if host.next_check_time else None),
            "last_state_change": (
                host.last_state_change.isoformat() if host.last_state_change else None
            ),
            "check_priority": host.check_priority,
            "response_time_ms": host.response_time_ms,
            "last_check": host.last_check.isoformat() if host.last_check else None,
            "check_interval_info": _get_interval_info(derived_state),
            "recent_history": history,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting monitoring state for {host_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get monitoring state")


def _get_interval_info(state: str) -> dict:
    """Helper function to get check interval info for a state"""
    intervals = {
        "HEALTHY": {"minutes": 30, "description": "Stable - 30 min checks"},
        "DEGRADED": {"minutes": 5, "description": "Showing issues - 5 min checks"},
        "CRITICAL": {"minutes": 2, "description": "Repeated failures - 2 min checks"},
        "DOWN": {"minutes": 30, "description": "Confirmed down - 30 min checks"},
        "MAINTENANCE": {"minutes": 0, "description": "No checks during maintenance"},
    }
    return intervals.get(state, {"minutes": 30, "description": "Unknown state"})
