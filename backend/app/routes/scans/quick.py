"""
Quick Scan Endpoints - One-click scanning for hosts and host groups.

This module provides simplified scan initiation endpoints that auto-detect
platform information and queue scans immediately without requiring a wizard.

Endpoints:
    POST /quick              - Quick scan for host(s) or host group
    GET  /quick/{scan_id}    - Get quick scan status

Security Notes:
    - All endpoints require JWT authentication
    - Platform is auto-detected from host_system_info or hosts.platform_identifier
    - Framework defaults to CIS (most common)
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.tasks.aegis_scan_tasks import create_aegis_scan_record, execute_aegis_scan_task

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/quick", tags=["Quick Scan"])


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================


class QuickScanRequest(BaseModel):
    """Request model for quick scan."""

    host_id: Optional[str] = Field(
        None,
        description="Single host UUID to scan",
    )
    host_ids: Optional[List[str]] = Field(
        None,
        description="Multiple host UUIDs to scan",
    )
    host_group_id: Optional[int] = Field(
        None,
        description="Host group ID to scan all members",
    )
    framework: Optional[str] = Field(
        None,
        description="Framework to use (cis, stig). Defaults to CIS.",
    )

    @field_validator("framework")
    @classmethod
    def validate_framework(cls, v: Optional[str]) -> Optional[str]:
        """Validate framework is supported by Aegis."""
        if v is None:
            return None
        allowed = {"cis", "stig", "cis-rhel9-v2.0.0", "stig-rhel9-v2r7"}
        if v.lower() not in allowed:
            raise ValueError(f"Framework '{v}' not supported. Aegis supports: cis, stig")
        return v.lower()


class QuickScanHostResult(BaseModel):
    """Result for a single host in quick scan."""

    host_id: str
    hostname: str
    scan_id: str
    status: str


class QuickScanResponse(BaseModel):
    """Response model for quick scan."""

    message: str
    scan_count: int
    scans: List[QuickScanHostResult]
    queued_at: str


class QuickScanStatusResponse(BaseModel):
    """Status response for a quick scan."""

    scan_id: str
    host_id: str
    hostname: str
    status: str
    progress: int
    compliance_score: Optional[float] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error_message: Optional[str] = None


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def _get_hosts_from_group(db: Session, group_id: int) -> List[Dict[str, Any]]:
    """Get all hosts in a host group."""
    query = text(
        """
        SELECT h.id, h.hostname, h.display_name
        FROM hosts h
        INNER JOIN host_group_memberships hgm ON hgm.host_id = h.id
        WHERE hgm.group_id = :group_id
          AND h.is_active = true
        ORDER BY h.hostname
    """
    )
    result = db.execute(query, {"group_id": group_id}).fetchall()
    return [
        {
            "id": str(row.id),
            "hostname": row.hostname,
            "display_name": row.display_name,
        }
        for row in result
    ]


def _get_host_info(db: Session, host_id: str) -> Optional[Dict[str, Any]]:
    """Get host information by ID."""
    query = text(
        """
        SELECT id, hostname, display_name, is_active
        FROM hosts
        WHERE id = :id
    """
    )
    result = db.execute(query, {"id": host_id}).fetchone()
    if not result:
        return None
    return {
        "id": str(result.id),
        "hostname": result.hostname,
        "display_name": result.display_name,
        "is_active": result.is_active,
    }


def _verify_group_exists(db: Session, group_id: int) -> bool:
    """Verify host group exists."""
    query = text("SELECT id FROM host_groups WHERE id = :id")
    result = db.execute(query, {"id": group_id}).fetchone()
    return result is not None


# =============================================================================
# ENDPOINTS
# =============================================================================


@router.post("", response_model=QuickScanResponse)
async def quick_scan(
    request: QuickScanRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> QuickScanResponse:
    """
    Trigger a quick Aegis compliance scan.

    This endpoint provides one-click scanning functionality:
    - Auto-detects platform from host_system_info
    - Defaults to CIS framework (or uses specified framework)
    - Queues scan via Celery and returns immediately

    Specify ONE of:
    - host_id: Scan a single host
    - host_ids: Scan multiple hosts
    - host_group_id: Scan all hosts in a group

    Args:
        request: Quick scan configuration.
        db: SQLAlchemy database session.
        current_user: Authenticated user from JWT token.

    Returns:
        QuickScanResponse with queued scan information.

    Raises:
        HTTPException 400: Invalid request (no targets or multiple target types).
        HTTPException 404: Host or group not found.
    """
    user_id = current_user.get("id")

    # Validate exactly one target type is specified
    targets_specified = sum(
        [
            request.host_id is not None,
            request.host_ids is not None and len(request.host_ids) > 0,
            request.host_group_id is not None,
        ]
    )

    if targets_specified == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Must specify host_id, host_ids, or host_group_id",
        )

    if targets_specified > 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Specify only one of host_id, host_ids, or host_group_id",
        )

    # Collect target hosts
    hosts_to_scan: List[Dict[str, Any]] = []

    if request.host_id:
        # Single host
        host_info = _get_host_info(db, request.host_id)
        if not host_info:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Host not found: {request.host_id}",
            )
        if not host_info["is_active"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Host is inactive: {request.host_id}",
            )
        hosts_to_scan.append(host_info)

    elif request.host_ids:
        # Multiple hosts
        for hid in request.host_ids:
            host_info = _get_host_info(db, hid)
            if not host_info:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Host not found: {hid}",
                )
            if not host_info["is_active"]:
                logger.warning(f"Skipping inactive host: {hid}")
                continue
            hosts_to_scan.append(host_info)

        if not hosts_to_scan:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="All specified hosts are inactive",
            )

    elif request.host_group_id:
        # Host group
        if not _verify_group_exists(db, request.host_group_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Host group not found: {request.host_group_id}",
            )

        hosts_to_scan = _get_hosts_from_group(db, request.host_group_id)
        if not hosts_to_scan:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Host group has no active members",
            )

    # Queue scans for each host
    scans: List[QuickScanHostResult] = []
    framework = request.framework or "cis"

    for host in hosts_to_scan:
        try:
            # Create scan record
            scan_id = create_aegis_scan_record(
                db=db,
                host_id=host["id"],
                user_id=user_id,
                framework=framework,
            )

            # Queue Celery task
            execute_aegis_scan_task.delay(
                scan_id=scan_id,
                host_id=host["id"],
                framework=framework,
            )

            scans.append(
                QuickScanHostResult(
                    host_id=host["id"],
                    hostname=host["display_name"] or host["hostname"],
                    scan_id=scan_id,
                    status="queued",
                )
            )

            logger.info(
                "Quick scan queued: scan=%s host=%s framework=%s user=%s",
                scan_id,
                host["id"],
                framework,
                user_id,
            )

        except Exception as e:
            logger.error(f"Failed to queue scan for host {host['id']}: {e}")
            # Continue with other hosts
            scans.append(
                QuickScanHostResult(
                    host_id=host["id"],
                    hostname=host["display_name"] or host["hostname"],
                    scan_id="",
                    status=f"failed: {str(e)[:100]}",
                )
            )

    successful_scans = [s for s in scans if s.status == "queued"]
    message = f"Queued {len(successful_scans)} scan(s) for {len(hosts_to_scan)} host(s)"

    if len(successful_scans) < len(hosts_to_scan):
        message += f" ({len(hosts_to_scan) - len(successful_scans)} failed to queue)"

    return QuickScanResponse(
        message=message,
        scan_count=len(successful_scans),
        scans=scans,
        queued_at=datetime.now(timezone.utc).isoformat(),
    )


@router.get("/{scan_id}", response_model=QuickScanStatusResponse)
async def get_quick_scan_status(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> QuickScanStatusResponse:
    """
    Get the status of a quick scan.

    Args:
        scan_id: UUID of the scan.
        db: SQLAlchemy database session.
        current_user: Authenticated user from JWT token.

    Returns:
        QuickScanStatusResponse with current scan status.

    Raises:
        HTTPException 404: Scan not found.
    """
    query = text(
        """
        SELECT
            s.id,
            s.host_id,
            h.hostname,
            h.display_name,
            s.status,
            s.progress,
            s.started_at,
            s.completed_at,
            s.error_message,
            sr.score
        FROM scans s
        INNER JOIN hosts h ON h.id = s.host_id
        LEFT JOIN scan_results sr ON sr.scan_id = s.id
        WHERE s.id = :scan_id
    """
    )
    result = db.execute(query, {"scan_id": scan_id}).fetchone()

    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan not found: {scan_id}",
        )

    # Parse compliance score
    compliance_score = None
    if result.score:
        try:
            # Score stored as string like "85.50" or "85.50%"
            score_str = str(result.score).replace("%", "")
            compliance_score = float(score_str)
        except (ValueError, TypeError):
            pass

    return QuickScanStatusResponse(
        scan_id=str(result.id),
        host_id=str(result.host_id),
        hostname=result.display_name or result.hostname,
        status=result.status,
        progress=result.progress or 0,
        compliance_score=compliance_score,
        started_at=result.started_at.isoformat() if result.started_at else None,
        completed_at=result.completed_at.isoformat() if result.completed_at else None,
        error_message=result.error_message,
    )
