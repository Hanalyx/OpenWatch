"""
Host Monitoring API Routes
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
import logging

from ..database import get_db
from ..auth import get_current_user
from ..services.host_monitor import host_monitor

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/monitoring", tags=["Monitoring"])


from pydantic import BaseModel


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

        # Perform comprehensive check with DB connection for credential access
        check_result = await host_monitor.comprehensive_host_check(host_data, db)

        # Update database with new status
        await host_monitor.update_host_status(db, request.host_id, check_result["status"])

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
        # Run monitoring in background
        background_tasks.add_task(host_monitor.monitor_all_hosts, db)

        return {"message": "Host monitoring started in background", "status": "running"}

    except Exception as e:
        logger.error(f"Error starting host monitoring: {e}")
        raise HTTPException(status_code=500, detail="Failed to start host monitoring")


@router.get("/hosts/status")
async def get_hosts_status_summary(
    db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)
):
    """
    Get summary of all host statuses
    """
    try:
        from sqlalchemy import text

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

        return {
            "total_hosts": total,
            "status_breakdown": status_counts,
            "online_percentage": round(
                (status_counts.get("online", 0) / total * 100) if total > 0 else 0, 1
            ),
        }

    except Exception as e:
        logger.error(f"Error getting host status summary: {e}")
        raise HTTPException(status_code=500, detail="Failed to get host status summary")


@router.post("/hosts/{host_id}/ping")
async def ping_host(
    host_id: str, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)
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

        # Perform ping
        ping_success = await host_monitor.ping_host(ip_address)

        return {
            "host_id": host_id,
            "ip_address": ip_address,
            "ping_success": ping_success,
            "timestamp": host_monitor.__class__.__module__,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error pinging host: {e}")
        raise HTTPException(status_code=500, detail="Failed to ping host")
