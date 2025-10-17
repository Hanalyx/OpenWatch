"""
Host Monitoring API Routes
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
import logging
from datetime import datetime

from ..database import get_db
from ..auth import get_current_user
from ..services.host_monitor import host_monitor
from ..services.host_monitoring_state import HostMonitoringStateMachine
from ..tasks.monitoring_tasks import check_host_connectivity

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/monitoring", tags=["Monitoring"])


from pydantic import BaseModel

class HostCheckRequest(BaseModel):
    host_id: str

@router.post("/hosts/check")
async def check_host_status(
    request: HostCheckRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Check status of a specific host
    """
    try:
        from sqlalchemy import text
        
        # Get host details
        result = db.execute(text("""
            SELECT id, hostname, ip_address, port, username, auth_method
            FROM hosts WHERE id = :id
        """), {"id": request.host_id})
        
        host_row = result.fetchone()
        if not host_row:
            raise HTTPException(status_code=404, detail="Host not found")
        
        host_data = {
            'id': str(host_row.id),
            'hostname': host_row.hostname,
            'ip_address': str(host_row.ip_address),
            'port': host_row.port or 22,
            'username': host_row.username,
            'auth_method': host_row.auth_method,
            # NOTE: encrypted_credentials removed - using centralized auth service
        }
        
        # Set database session for SSH service configuration access
        host_monitor.set_database_session(db)
        
        # Perform comprehensive check with DB connection for credential access
        check_result = await host_monitor.comprehensive_host_check(host_data, db)
        
        # Update database with new status
        await host_monitor.update_host_status(
            db, request.host_id, check_result['status']
        )
        
        return {
            "host_id": request.host_id,
            "status": check_result['status'],
            "ping_success": check_result['ping_success'],
            "port_open": check_result['port_open'],
            "ssh_accessible": check_result['ssh_accessible'],
            "response_time_ms": check_result['response_time_ms'],
            "error_message": check_result['error_message'],
            "timestamp": check_result['timestamp'],
            # SSH credential information
            "ssh_credentials_used": check_result.get('ssh_credentials_source'),
            "ssh_username": check_result.get('ssh_username'),
            "ready_for_scans": check_result['ssh_accessible'],
            "credential_details": check_result.get('credential_details')
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
    current_user: dict = Depends(get_current_user)
):
    """
    Check status of all hosts (runs in background)
    """
    try:
        # Create wrapper function to set database session before monitoring
        async def monitor_with_session():
            host_monitor.set_database_session(db)
            await host_monitor.monitor_all_hosts(db)
        
        # Run monitoring in background
        background_tasks.add_task(monitor_with_session)
        
        return {
            "message": "Host monitoring started in background",
            "status": "running"
        }
        
    except Exception as e:
        logger.error(f"Error starting host monitoring: {e}")
        raise HTTPException(status_code=500, detail="Failed to start host monitoring")


@router.get("/hosts/status")
async def get_hosts_status_summary(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Get summary of all host statuses
    """
    try:
        from sqlalchemy import text
        
        result = db.execute(text("""
            SELECT 
                status,
                COUNT(*) as count
            FROM hosts 
            WHERE is_active = true
            GROUP BY status
        """))
        
        status_counts = {}
        total = 0
        for row in result:
            status_counts[row.status] = row.count
            total += row.count
        
        return {
            "total_hosts": total,
            "status_breakdown": status_counts,
            "online_percentage": round((status_counts.get('online', 0) / total * 100) if total > 0 else 0, 1)
        }
        
    except Exception as e:
        logger.error(f"Error getting host status summary: {e}")
        raise HTTPException(status_code=500, detail="Failed to get host status summary")


@router.post("/hosts/{host_id}/ping")
async def ping_host(
    host_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Simple ping test for a specific host
    """
    try:
        from sqlalchemy import text
        
        # Get host IP
        result = db.execute(text("""
            SELECT ip_address FROM hosts WHERE id = :id
        """), {"id": host_id})
        
        host_row = result.fetchone()
        if not host_row:
            raise HTTPException(status_code=404, detail="Host not found")
        
        ip_address = str(host_row.ip_address)
        
        # Perform ping
        ping_success = await host_monitor.ping_host(ip_address)
        
        return {
            "host_id": host_id,
            "ip_address": ip_address,
            "ping_success": ping_success,
            "timestamp": host_monitor.__class__.__module__
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error pinging host: {e}")
        raise HTTPException(status_code=500, detail="Failed to ping host")


@router.post("/hosts/{host_id}/check-connectivity")
async def jit_connectivity_check(
    host_id: str,
    priority: int = 9,  # JIT checks are high priority
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Just-In-Time (JIT) connectivity check for a specific host.

    This endpoint triggers an immediate connectivity check using the Hybrid Monitoring approach.
    It's called when:
    - User navigates to host details page (fresh status)
    - Before starting a compliance scan (ensure host is reachable)
    - Manual refresh from UI

    The check runs asynchronously via Celery with high priority (9).
    Returns the current state and queues a background check.
    """
    try:
        from sqlalchemy import text

        # Get current host state
        result = db.execute(text("""
            SELECT id, hostname, ip_address, monitoring_state, response_time_ms,
                   last_check, status
            FROM hosts
            WHERE id = :host_id AND is_active = true
        """), {"host_id": host_id})

        host = result.fetchone()
        if not host:
            raise HTTPException(status_code=404, detail="Host not found or inactive")

        # Queue immediate connectivity check with high priority
        task = check_host_connectivity.apply_async(
            args=[host_id, priority],
            priority=priority,
            queue='monitoring'
        )

        logger.info(
            f"JIT connectivity check queued for host {host.hostname} "
            f"(task_id: {task.id}, priority: {priority})"
        )

        return {
            "host_id": host_id,
            "hostname": host.hostname,
            "ip_address": host.ip_address,
            "current_state": host.monitoring_state,
            "current_status": host.status,
            "last_check": host.last_check.isoformat() if host.last_check else None,
            "response_time_ms": host.response_time_ms,
            "check_queued": True,
            "task_id": task.id,
            "priority": priority,
            "message": "Fresh connectivity check queued with high priority"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error queueing JIT connectivity check for {host_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to queue connectivity check")


@router.get("/hosts/{host_id}/state")
async def get_host_monitoring_state(
    host_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
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
        result = db.execute(text("""
            SELECT h.id, h.hostname, h.ip_address, h.monitoring_state,
                   h.consecutive_failures, h.consecutive_successes,
                   h.next_check_time, h.last_state_change, h.check_priority,
                   h.response_time_ms, h.last_check, h.status
            FROM hosts h
            WHERE h.id = :host_id AND h.is_active = true
        """), {"host_id": host_id})

        host = result.fetchone()
        if not host:
            raise HTTPException(status_code=404, detail="Host not found or inactive")

        # Get recent history (last 10 checks)
        history_result = db.execute(text("""
            SELECT check_time, monitoring_state, previous_state, response_time_ms,
                   success, error_message, error_type
            FROM host_monitoring_history
            WHERE host_id = :host_id
            ORDER BY check_time DESC
            LIMIT 10
        """), {"host_id": host_id})

        history = []
        for row in history_result:
            history.append({
                "check_time": row.check_time.isoformat(),
                "state": row.monitoring_state,
                "previous_state": row.previous_state,
                "response_time_ms": row.response_time_ms,
                "success": row.success,
                "error_message": row.error_message,
                "error_type": row.error_type
            })

        return {
            "host_id": str(host.id),
            "hostname": host.hostname,
            "ip_address": host.ip_address,
            "current_state": host.monitoring_state,
            "current_status": host.status,
            "consecutive_failures": host.consecutive_failures,
            "consecutive_successes": host.consecutive_successes,
            "next_check_time": host.next_check_time.isoformat() if host.next_check_time else None,
            "last_state_change": host.last_state_change.isoformat() if host.last_state_change else None,
            "check_priority": host.check_priority,
            "response_time_ms": host.response_time_ms,
            "last_check": host.last_check.isoformat() if host.last_check else None,
            "check_interval_info": _get_interval_info(host.monitoring_state),
            "recent_history": history
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
        "MAINTENANCE": {"minutes": 0, "description": "No checks during maintenance"}
    }
    return intervals.get(state, {"minutes": 30, "description": "Unknown state"})