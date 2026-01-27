"""
Host Groups Scanning Router

Handles group-based compliance scanning operations including:
- Starting group scans for all hosts in a group
- Tracking scan session progress
- Cancelling running scan sessions
- Listing scan session history

These endpoints align with frontend scanService.ts methods:
- startGroupScan()      -> POST /{group_id}/scan
- getGroupScanSessions() -> GET /{group_id}/scan-sessions
- getGroupScanProgress() -> GET /{group_id}/scan-sessions/{session_id}/progress
- cancelGroupScan()      -> POST /{group_id}/scan-sessions/{session_id}/cancel

Security:
    - All endpoints require authentication via get_current_user
    - Per-host authorization validation via BulkScanOrchestrator
    - Comprehensive audit logging of authorization decisions
    - SQL injection prevented via parameterized queries
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth import get_current_user, require_permissions
from app.database import get_db
from app.services.bulk_scan_orchestrator import BulkScanOrchestrator

from .models import (
    CancelScanResponse,
    ComplianceMetricsResponse,
    GroupComplianceReportResponse,
    GroupScanHistoryResponse,
    GroupScanRequest,
    GroupScanScheduleRequest,
    GroupScanSessionResponse,
    IndividualScanProgress,
    ScanProgressResponse,
    ScanSessionStatus,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# =============================================================================
# GROUP SCAN OPERATIONS - Aligned with frontend scanService.ts
# =============================================================================


@router.post("/{group_id}/scan", response_model=GroupScanSessionResponse)
async def start_group_scan(
    group_id: int,
    request: GroupScanRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> GroupScanSessionResponse:
    """
    Start a compliance scan for all hosts in a group.

    This endpoint aligns with frontend ScanService.startGroupScan().
    Creates a scan session and queues individual scans for each host in the group.

    Authorization:
        - User must have 'scans:create' permission
        - Per-host authorization is validated via BulkScanOrchestrator

    Args:
        group_id: The ID of the host group to scan.
        request: GroupScanRequest with scan configuration.
        db: Database session dependency.
        current_user: Authenticated user dictionary.

    Returns:
        GroupScanSessionResponse with session details.

    Raises:
        HTTPException: 400 if no hosts in group, 403 if unauthorized,
                       404 if group not found, 500 if scan creation fails.
    """
    require_permissions(current_user, "scans:create")

    try:
        # Verify group exists and get its details
        group_result = db.execute(
            text("""
                SELECT id, name, compliance_framework, default_profile_id
                FROM host_groups
                WHERE id = :group_id
            """),
            {"group_id": group_id},
        )
        group = group_result.fetchone()

        if not group:
            raise HTTPException(status_code=404, detail="Host group not found")

        # Get all active hosts in the group
        hosts_result = db.execute(
            text("""
                SELECT h.id, h.hostname, h.display_name, h.ip_address
                FROM hosts h
                JOIN host_group_memberships hgm ON h.id = hgm.host_id
                WHERE hgm.group_id = :group_id AND h.active = true
            """),
            {"group_id": group_id},
        )
        hosts = hosts_result.fetchall()

        if not hosts:
            raise HTTPException(status_code=400, detail="No active hosts found in group")

        # Generate scan session name (session_id comes from orchestrator)
        session_name = (
            request.scan_name or f"Group Scan - {group.name} - {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}"
        )

        # Use the profile from request, or fall back to group default
        profile_id = request.profile_id or group.default_profile_id
        if not profile_id:
            raise HTTPException(
                status_code=400,
                detail="No profile specified and group has no default profile configured",
            )

        # Use BulkScanOrchestrator for authorization and scan creation
        orchestrator = BulkScanOrchestrator(db)
        host_ids = [str(host.id) for host in hosts]

        try:
            # Create bulk scan session with authorization validation
            scan_session = await orchestrator.create_bulk_scan_session(
                host_ids=host_ids,
                template_id=request.template_id or "auto",
                name_prefix=session_name,
                priority=request.priority.value if request.priority else "normal",
                user_id=str(current_user["id"]),
                stagger_delay=30,  # 30 second delay between scans
            )

            # Store group-specific session metadata
            db.execute(
                text("""
                    INSERT INTO group_scan_sessions (
                        session_id, group_id, total_hosts, status, scan_config,
                        estimated_completion, created_at, created_by
                    ) VALUES (
                        :session_id, :group_id, :total_hosts, :status, :config,
                        :estimated_completion, :created_at, :created_by
                    )
                """),
                {
                    "session_id": scan_session.id,
                    "group_id": group_id,
                    "total_hosts": len(hosts),
                    "status": "pending",
                    "config": json.dumps(
                        {
                            "profile_id": profile_id,
                            "priority": request.priority.value if request.priority else "normal",
                            "template_id": request.template_id,
                            "framework": request.framework or group.compliance_framework,
                        }
                    ),
                    "estimated_completion": datetime.utcnow() + timedelta(minutes=len(hosts) * 15),
                    "created_at": datetime.utcnow(),
                    "created_by": str(current_user["id"]),
                },
            )
            db.commit()

            # Start the scan session
            await orchestrator.start_bulk_scan_session(scan_session.id)

            return GroupScanSessionResponse(
                session_id=scan_session.id,
                session_name=scan_session.name,
                total_hosts=len(hosts),
                status=ScanSessionStatus.PENDING,
                created_at=scan_session.created_at,
                estimated_completion=scan_session.estimated_completion,
                group_id=group_id,
                group_name=group.name,
                authorized_hosts=scan_session.authorized_hosts,
                unauthorized_hosts=scan_session.unauthorized_hosts,
            )

        except PermissionError as pe:
            logger.warning(f"Authorization failed for group scan: {pe}")
            raise HTTPException(
                status_code=403,
                detail=str(pe),
            )
        except ValueError as ve:
            logger.warning(f"Validation failed for group scan: {ve}")
            raise HTTPException(
                status_code=400,
                detail=str(ve),
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting group scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to start group scan")


@router.get("/{group_id}/scan-sessions", response_model=List[GroupScanSessionResponse])
async def get_group_scan_sessions(
    group_id: int,
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[GroupScanSessionResponse]:
    """
    List all scan sessions for a host group.

    This endpoint aligns with frontend ScanService.getGroupScanSessions().

    Args:
        group_id: The ID of the host group.
        limit: Maximum number of sessions to return (default 50, max 200).
        offset: Number of sessions to skip for pagination.
        db: Database session dependency.
        current_user: Authenticated user dictionary.

    Returns:
        List of GroupScanSessionResponse objects.

    Raises:
        HTTPException: 404 if group not found, 500 if query fails.
    """
    try:
        # Verify group exists
        group_check = db.execute(
            text("SELECT id, name FROM host_groups WHERE id = :group_id"),
            {"group_id": group_id},
        ).fetchone()

        if not group_check:
            raise HTTPException(status_code=404, detail="Host group not found")

        # Query scan sessions for this group
        result = db.execute(
            text("""
                SELECT
                    gss.session_id,
                    gss.total_hosts,
                    gss.status,
                    gss.scan_config,
                    gss.created_at,
                    gss.estimated_completion,
                    ss.name as session_name,
                    ss.completed_hosts,
                    ss.failed_hosts
                FROM group_scan_sessions gss
                LEFT JOIN scan_sessions ss ON gss.session_id = ss.id
                WHERE gss.group_id = :group_id
                ORDER BY gss.created_at DESC
                LIMIT :limit OFFSET :offset
            """),
            {"group_id": group_id, "limit": limit, "offset": offset},
        )

        sessions = []
        for row in result:
            sessions.append(
                GroupScanSessionResponse(
                    session_id=row.session_id,
                    session_name=row.session_name or f"Scan Session {row.session_id[:8]}",
                    total_hosts=row.total_hosts,
                    status=(ScanSessionStatus(row.status) if row.status else ScanSessionStatus.PENDING),
                    created_at=row.created_at,
                    estimated_completion=row.estimated_completion,
                    group_id=group_id,
                    group_name=group_check.name,
                )
            )

        return sessions

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting group scan sessions: {e}")
        raise HTTPException(status_code=500, detail="Failed to get scan sessions")


@router.get(
    "/{group_id}/scan-sessions/{session_id}/progress",
    response_model=ScanProgressResponse,
)
async def get_group_scan_progress(
    group_id: int,
    session_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> ScanProgressResponse:
    """
    Get real-time progress of a group scan session.

    This endpoint aligns with frontend ScanService.getGroupScanProgress().

    Args:
        group_id: The ID of the host group.
        session_id: The UUID of the scan session.
        db: Database session dependency.
        current_user: Authenticated user dictionary.

    Returns:
        ScanProgressResponse with detailed progress information.

    Raises:
        HTTPException: 404 if session not found, 500 if query fails.
    """
    try:
        # Use BulkScanOrchestrator to get progress
        orchestrator = BulkScanOrchestrator(db)
        progress = await orchestrator.get_bulk_scan_progress(session_id)

        # Map to response model
        individual_scans = [
            IndividualScanProgress(
                scan_id=scan["scan_id"],
                scan_name=scan.get("scan_name", ""),
                hostname=scan.get("hostname", ""),
                display_name=scan.get("display_name", scan.get("hostname", "")),
                status=(ScanSessionStatus(scan["status"]) if scan.get("status") else ScanSessionStatus.PENDING),
                progress=scan.get("progress", 0),
                started_at=scan.get("started_at"),
                completed_at=scan.get("completed_at"),
                compliance_score=scan.get("compliance_score"),
                failed_rules=scan.get("failed_rules"),
                total_rules=scan.get("total_rules"),
            )
            for scan in progress.get("individual_scans", [])
        ]

        return ScanProgressResponse(
            session_id=progress["session_id"],
            session_name=progress.get("session_name", f"Session {session_id[:8]}"),
            status=(ScanSessionStatus(progress["status"]) if progress.get("status") else ScanSessionStatus.PENDING),
            progress_percent=progress.get("progress_percent", 0),
            total_hosts=progress.get("total_hosts", 0),
            completed_hosts=progress.get("completed_hosts", 0),
            failed_hosts=progress.get("failed_hosts", 0),
            running_hosts=progress.get("running_hosts", 0),
            started_at=progress.get("started_at"),
            estimated_completion=progress.get("estimated_completion"),
            individual_scans=individual_scans,
        )

    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        logger.error(f"Error getting scan progress: {e}")
        raise HTTPException(status_code=500, detail="Failed to get scan progress")


@router.post(
    "/{group_id}/scan-sessions/{session_id}/cancel",
    response_model=CancelScanResponse,
)
async def cancel_group_scan(
    group_id: int,
    session_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> CancelScanResponse:
    """
    Cancel a running group scan session.

    This endpoint aligns with frontend ScanService.cancelGroupScan().

    Args:
        group_id: The ID of the host group.
        session_id: The UUID of the scan session to cancel.
        db: Database session dependency.
        current_user: Authenticated user dictionary.

    Returns:
        CancelScanResponse with cancellation status.

    Raises:
        HTTPException: 400 if session not running, 404 if session not found,
                       500 if cancellation fails.
    """
    require_permissions(current_user, "scans:cancel")

    try:
        # Verify session exists and belongs to this group
        session_check = db.execute(
            text("""
                SELECT session_id, status, total_hosts
                FROM group_scan_sessions
                WHERE session_id = :session_id AND group_id = :group_id
            """),
            {"session_id": session_id, "group_id": group_id},
        ).fetchone()

        if not session_check:
            raise HTTPException(
                status_code=404,
                detail="Scan session not found for this group",
            )

        if session_check.status in ("completed", "cancelled", "failed"):
            raise HTTPException(
                status_code=400,
                detail=f"Cannot cancel session with status '{session_check.status}'",
            )

        # Cancel all running/pending scans in the session
        cancel_result = db.execute(
            text("""
                UPDATE scans
                SET status = 'cancelled',
                    completed_at = :completed_at,
                    error_message = 'Cancelled by user'
                WHERE id IN (
                    SELECT s.id FROM scans s
                    WHERE s.scan_options::jsonb->>'session_id' = :session_id
                    AND s.status IN ('pending', 'running')
                )
                RETURNING id
            """),
            {"session_id": session_id, "completed_at": datetime.utcnow()},
        )
        cancelled_scan_ids = [row.id for row in cancel_result]

        # Update session status
        db.execute(
            text("""
                UPDATE group_scan_sessions
                SET status = 'cancelled'
                WHERE session_id = :session_id
            """),
            {"session_id": session_id},
        )

        # Also update scan_sessions table if it exists
        db.execute(
            text("""
                UPDATE scan_sessions
                SET status = 'cancelled', completed_at = :completed_at
                WHERE id = :session_id
            """),
            {"session_id": session_id, "completed_at": datetime.utcnow()},
        )

        db.commit()

        logger.info(
            f"User {current_user['id']} cancelled scan session {session_id} "
            f"({len(cancelled_scan_ids)} scans cancelled)"
        )

        return CancelScanResponse(
            session_id=session_id,
            status="cancelled",
            message="Successfully cancelled scan session",
            cancelled_scans=len(cancelled_scan_ids),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error cancelling group scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to cancel scan session")


# =============================================================================
# COMPLIANCE REPORTING ENDPOINTS (from group_compliance.py)
# =============================================================================


@router.get("/{group_id}/compliance/report", response_model=GroupComplianceReportResponse)
async def get_group_compliance_report(
    group_id: int,
    framework: str = Query(None, description="Filter by compliance framework"),
    date_from: datetime = Query(None),
    date_to: datetime = Query(None),
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> GroupComplianceReportResponse:
    """
    Generate comprehensive compliance report for a host group.

    Includes trend analysis, risk assessment, and compliance gaps.

    Args:
        group_id: The ID of the host group.
        framework: Optional filter by compliance framework.
        date_from: Optional start date for report period.
        date_to: Optional end date for report period.
        db: Database session dependency.
        current_user: Authenticated user dictionary.

    Returns:
        GroupComplianceReportResponse with detailed compliance data.

    Raises:
        HTTPException: 404 if group not found or no data, 500 if report fails.
    """
    require_permissions(current_user, "reports:view")

    try:
        # Get group information
        group = db.execute(
            text("SELECT id, name FROM host_groups WHERE id = :group_id"),
            {"group_id": group_id},
        ).fetchone()

        if not group:
            raise HTTPException(status_code=404, detail="Host group not found")

        # Build date filters for parameterized query
        params: Dict[str, Any] = {"group_id": group_id}
        date_conditions = []

        if date_from:
            date_conditions.append("s.completed_at >= :date_from")
            params["date_from"] = date_from
        if date_to:
            date_conditions.append("s.completed_at <= :date_to")
            params["date_to"] = date_to
        if framework:
            # Framework filtering would need a different approach since scap_content is removed
            # For now, we skip this filter
            pass

        date_filter = (" AND " + " AND ".join(date_conditions)) if date_conditions else ""

        # Get latest scan results for each host in the group
        compliance_query = f"""
            WITH latest_scans AS (
                SELECT DISTINCT ON (h.id)
                    h.id as host_id,
                    h.hostname,
                    h.ip_address,
                    h.os_family,
                    s.id as scan_id,
                    s.completed_at,
                    sr.total_rules,
                    sr.passed_rules,
                    sr.failed_rules,
                    sr.score,
                    sr.severity_high,
                    sr.severity_medium,
                    sr.severity_low
                FROM hosts h
                JOIN host_group_memberships hgm ON h.id = hgm.host_id
                JOIN scans s ON h.id = s.host_id
                JOIN scan_results sr ON s.id = sr.scan_id
                WHERE hgm.group_id = :group_id
                    AND s.status = 'completed'
                    AND h.active = true
                    {date_filter}
                ORDER BY h.id, s.completed_at DESC
            )
            SELECT * FROM latest_scans
        """

        compliance_data = db.execute(text(compliance_query), params).fetchall()

        if not compliance_data:
            raise HTTPException(status_code=404, detail="No compliance data found for group")

        # Calculate group metrics
        total_hosts = len(compliance_data)
        total_rules = sum(row.total_rules or 0 for row in compliance_data)
        total_passed = sum(row.passed_rules or 0 for row in compliance_data)
        total_failed = sum(row.failed_rules or 0 for row in compliance_data)

        overall_score = (total_passed / total_rules * 100) if total_rules > 0 else 0

        high_risk_hosts = len([r for r in compliance_data if (r.severity_high or 0) > 0])
        medium_risk_hosts = len([r for r in compliance_data if (r.severity_medium or 0) > 0])

        # Get compliance trend
        trend_data = db.execute(
            text("""
                SELECT
                    DATE(s.completed_at) as scan_date,
                    AVG(CAST(sr.score AS FLOAT)) as avg_score,
                    COUNT(*) as scan_count
                FROM scans s
                JOIN scan_results sr ON s.id = sr.scan_id
                JOIN hosts h ON s.host_id = h.id
                JOIN host_group_memberships hgm ON h.id = hgm.host_id
                WHERE hgm.group_id = :group_id
                    AND s.completed_at >= :trend_start
                    AND s.status = 'completed'
                GROUP BY DATE(s.completed_at)
                ORDER BY scan_date
            """),
            {"group_id": group_id, "trend_start": datetime.utcnow() - timedelta(days=30)},
        ).fetchall()

        # Get top failed rules
        failed_rules = db.execute(
            text("""
                SELECT
                    srd.rule_id,
                    srd.rule_title,
                    srd.severity,
                    COUNT(*) as failure_count,
                    ROUND(COUNT(*) * 100.0 / :total_hosts, 2) as failure_percentage
                FROM scan_rule_details srd
                JOIN scans s ON srd.scan_id = s.id
                JOIN hosts h ON s.host_id = h.id
                JOIN host_group_memberships hgm ON h.id = hgm.host_id
                WHERE hgm.group_id = :group_id
                    AND srd.result = 'fail'
                    AND s.status = 'completed'
                GROUP BY srd.rule_id, srd.rule_title, srd.severity
                ORDER BY failure_count DESC
                LIMIT 10
            """),
            {"group_id": group_id, "total_hosts": total_hosts},
        ).fetchall()

        return GroupComplianceReportResponse(
            group_id=group_id,
            group_name=group.name,
            report_generated_at=datetime.utcnow(),
            compliance_framework=framework,
            total_hosts=total_hosts,
            overall_compliance_score=round(overall_score, 2),
            total_rules_evaluated=total_rules,
            total_passed_rules=total_passed,
            total_failed_rules=total_failed,
            high_risk_hosts=high_risk_hosts,
            medium_risk_hosts=medium_risk_hosts,
            framework_distribution={},  # Simplified since scap_content removed
            compliance_trend=[
                {
                    "date": row.scan_date.isoformat(),
                    "score": round(row.avg_score or 0, 2),
                    "scan_count": row.scan_count,
                }
                for row in trend_data
            ],
            top_failed_rules=[
                {
                    "rule_id": row.rule_id,
                    "rule_title": row.rule_title,
                    "severity": row.severity,
                    "failure_count": row.failure_count,
                    "failure_percentage": float(row.failure_percentage or 0),
                }
                for row in failed_rules
            ],
            host_compliance_summary=[
                {
                    "host_id": str(row.host_id),
                    "hostname": row.hostname,
                    "ip_address": row.ip_address,
                    "os_family": row.os_family,
                    "compliance_score": float(row.score or 0),
                    "total_rules": row.total_rules or 0,
                    "passed_rules": row.passed_rules or 0,
                    "failed_rules": row.failed_rules or 0,
                    "high_severity_issues": row.severity_high or 0,
                    "last_scan_date": row.completed_at.isoformat() if row.completed_at else None,
                }
                for row in compliance_data
            ],
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating compliance report: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate compliance report")


@router.get("/{group_id}/compliance/metrics", response_model=ComplianceMetricsResponse)
async def get_group_compliance_metrics(
    group_id: int,
    timeframe: str = Query("30d", pattern="^(7d|30d|90d|1y)$"),
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> ComplianceMetricsResponse:
    """
    Get detailed compliance metrics and KPIs for a host group.

    Args:
        group_id: The ID of the host group.
        timeframe: Time period for metrics (7d, 30d, 90d, 1y).
        db: Database session dependency.
        current_user: Authenticated user dictionary.

    Returns:
        ComplianceMetricsResponse with detailed metrics.

    Raises:
        HTTPException: 500 if metrics generation fails.
    """
    require_permissions(current_user, "reports:view")

    try:
        timeframe_days = {"7d": 7, "30d": 30, "90d": 90, "1y": 365}
        start_date = datetime.utcnow() - timedelta(days=timeframe_days[timeframe])

        metrics = db.execute(
            text("""
                SELECT
                    COUNT(DISTINCT h.id) as total_hosts,
                    COUNT(DISTINCT s.id) as total_scans,
                    AVG(CAST(sr.score AS FLOAT)) as avg_compliance_score,
                    SUM(sr.failed_rules) as total_violations,
                    SUM(sr.severity_high) as critical_issues,
                    SUM(sr.severity_medium) as high_issues,
                    SUM(sr.severity_low) as medium_issues
                FROM hosts h
                JOIN host_group_memberships hgm ON h.id = hgm.host_id
                LEFT JOIN scans s ON h.id = s.host_id AND s.completed_at >= :start_date
                LEFT JOIN scan_results sr ON s.id = sr.scan_id
                WHERE hgm.group_id = :group_id AND h.active = true
            """),
            {"group_id": group_id, "start_date": start_date},
        ).fetchone()

        if metrics is None:
            raise HTTPException(status_code=500, detail="Failed to retrieve compliance metrics")

        # Compliance trend over time
        trend_metrics = db.execute(
            text("""
                SELECT
                    DATE_TRUNC('week', s.completed_at) as week_start,
                    AVG(CAST(sr.score AS FLOAT)) as avg_score,
                    COUNT(*) as scan_count,
                    SUM(sr.failed_rules) as total_failures
                FROM scans s
                JOIN scan_results sr ON s.id = sr.scan_id
                JOIN hosts h ON s.host_id = h.id
                JOIN host_group_memberships hgm ON h.id = hgm.host_id
                WHERE hgm.group_id = :group_id
                    AND s.completed_at >= :start_date
                    AND s.status = 'completed'
                GROUP BY DATE_TRUNC('week', s.completed_at)
                ORDER BY week_start
            """),
            {"group_id": group_id, "start_date": start_date},
        ).fetchall()

        return ComplianceMetricsResponse(
            group_id=group_id,
            timeframe=timeframe,
            metrics_generated_at=datetime.utcnow(),
            total_hosts=metrics.total_hosts or 0,
            total_scans=metrics.total_scans or 0,
            average_compliance_score=round(metrics.avg_compliance_score or 0, 2),
            total_violations=metrics.total_violations or 0,
            critical_issues=metrics.critical_issues or 0,
            high_issues=metrics.high_issues or 0,
            medium_issues=metrics.medium_issues or 0,
            frameworks_evaluated=0,  # Simplified since scap_content removed
            compliance_trend=[
                {
                    "period": row.week_start.isoformat() if row.week_start else None,
                    "average_score": round(row.avg_score or 0, 2),
                    "scan_count": row.scan_count,
                    "total_failures": row.total_failures or 0,
                }
                for row in trend_metrics
            ],
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting compliance metrics: {e}")
        raise HTTPException(status_code=500, detail="Failed to get compliance metrics")


@router.get("/{group_id}/scan-history", response_model=List[GroupScanHistoryResponse])
async def get_group_scan_history(
    group_id: int,
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[GroupScanHistoryResponse]:
    """
    Get scan history for a host group.

    Args:
        group_id: The ID of the host group.
        limit: Maximum number of entries to return.
        offset: Number of entries to skip for pagination.
        db: Database session dependency.
        current_user: Authenticated user dictionary.

    Returns:
        List of GroupScanHistoryResponse objects.

    Raises:
        HTTPException: 500 if query fails.
    """
    require_permissions(current_user, "reports:view")

    try:
        history = db.execute(
            text("""
                SELECT
                    gss.session_id,
                    gss.status,
                    gss.total_hosts,
                    gss.created_at,
                    gss.scan_config,
                    ss.completed_at,
                    COALESCE(ss.completed_hosts, 0) as hosts_scanned,
                    COALESCE(ss.completed_hosts, 0) as successful_hosts,
                    COALESCE(ss.failed_hosts, 0) as failed_hosts,
                    COALESCE(
                        CASE WHEN ss.total_hosts > 0
                        THEN (ss.completed_hosts::float / ss.total_hosts) * 100
                        ELSE 0 END,
                        0
                    ) as avg_progress
                FROM group_scan_sessions gss
                LEFT JOIN scan_sessions ss ON gss.session_id = ss.id
                WHERE gss.group_id = :group_id
                ORDER BY gss.created_at DESC
                LIMIT :limit OFFSET :offset
            """),
            {"group_id": group_id, "limit": limit, "offset": offset},
        ).fetchall()

        return [
            GroupScanHistoryResponse(
                session_id=row.session_id,
                status=row.status,
                total_hosts=row.total_hosts,
                hosts_scanned=row.hosts_scanned or 0,
                successful_hosts=row.successful_hosts or 0,
                failed_hosts=row.failed_hosts or 0,
                average_progress=round(row.avg_progress or 0, 2),
                started_at=row.created_at,
                completed_at=row.completed_at,
                scan_config=json.loads(row.scan_config) if row.scan_config else {},
            )
            for row in history
        ]

    except Exception as e:
        logger.error(f"Error getting scan history: {e}")
        raise HTTPException(status_code=500, detail="Failed to get scan history")


@router.post("/{group_id}/compliance/schedule")
async def schedule_group_compliance_scan(
    group_id: int,
    schedule_request: GroupScanScheduleRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Schedule recurring compliance scans for a host group.

    Args:
        group_id: The ID of the host group.
        schedule_request: Schedule configuration with cron expression.
        db: Database session dependency.
        current_user: Authenticated user dictionary.

    Returns:
        Success message dictionary.

    Raises:
        HTTPException: 404 if group not found, 500 if scheduling fails.
    """
    require_permissions(current_user, "scans:create")

    try:
        # Verify group exists
        group = db.execute(
            text("SELECT id FROM host_groups WHERE id = :group_id"),
            {"group_id": group_id},
        ).fetchone()

        if not group:
            raise HTTPException(status_code=404, detail="Host group not found")

        # Update group with scheduling configuration
        db.execute(
            text("""
                UPDATE host_groups SET
                    auto_scan_enabled = :enabled,
                    scan_schedule = :schedule,
                    default_profile_id = :profile_id,
                    compliance_framework = :framework
                WHERE id = :group_id
            """),
            {
                "group_id": group_id,
                "enabled": schedule_request.enabled,
                "schedule": schedule_request.cron_expression,
                "profile_id": schedule_request.profile_id,
                "framework": schedule_request.compliance_framework,
            },
        )

        db.commit()

        if schedule_request.enabled:
            # Note: Celery beat schedule configuration would go here
            # For now, we just store the schedule in the database
            logger.info(f"Scheduled group scan for group {group_id} with cron: {schedule_request.cron_expression}")
            return {"message": "Group compliance scan scheduled successfully"}
        else:
            return {"message": "Group compliance scan scheduling disabled"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error scheduling group scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to schedule group scan")


# =============================================================================
# HELPER FUNCTIONS - For backward compatibility with Celery tasks
# =============================================================================


def execute_group_compliance_scan(
    group_id: int,
    host_ids: List[str],
    scap_content_id: str,
    profile_id: str,
    db: Session,
    user_id: str = "system",
) -> Dict[str, Any]:
    """
    Execute a compliance scan for hosts in a group.

    This function provides backward compatibility for compliance_tasks.py.
    It creates individual scans for each host using the scan task infrastructure.

    Note: The scap_content_id parameter is kept for backward compatibility but
    is no longer used. The profile_id is used to determine the scan configuration.

    Args:
        group_id: The ID of the host group.
        host_ids: List of host UUIDs to scan.
        scap_content_id: Legacy parameter (deprecated, kept for compatibility).
        profile_id: The compliance profile ID to use.
        db: Database session.
        user_id: User ID initiating the scan (default: "system" for scheduled).

    Returns:
        Dictionary with scan results:
        - status: "completed", "partial", or "failed"
        - scan_ids: List of created scan IDs
        - error: Error message if failed

    Security:
        This function is called from Celery tasks which run with system privileges.
        The original authorization was validated when the scheduled scan was created.
    """
    from app.tasks.scan_tasks import execute_scan

    try:
        scan_ids = []
        failed_hosts = []

        for host_id in host_ids:
            try:
                # Get host details
                host_result = db.execute(
                    text("""
                        SELECT id, hostname, ip_address, platform, platform_version
                        FROM hosts WHERE id = :host_id
                    """),
                    {"host_id": host_id},
                ).fetchone()

                if not host_result:
                    failed_hosts.append({"host_id": host_id, "error": "Host not found"})
                    continue

                # Create scan record
                scan_id = str(uuid4())
                scan_name = f"Scheduled-{host_result.hostname}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

                db.execute(
                    text("""
                        INSERT INTO scans (
                            id, host_id, scan_name, profile_id, status,
                            created_at, created_by, scan_type
                        ) VALUES (
                            :scan_id, :host_id, :scan_name, :profile_id, 'pending',
                            :created_at, :created_by, 'compliance'
                        )
                    """),
                    {
                        "scan_id": scan_id,
                        "host_id": host_id,
                        "scan_name": scan_name,
                        "profile_id": profile_id,
                        "created_at": datetime.utcnow(),
                        "created_by": user_id,
                    },
                )
                db.commit()

                # Queue the scan task
                execute_scan.delay(
                    scan_id=scan_id,
                    host_id=host_id,
                    profile_id=profile_id,
                    platform=host_result.platform,
                    platform_version=host_result.platform_version,
                )

                scan_ids.append(scan_id)

            except Exception as host_error:
                logger.error(f"Failed to create scan for host {host_id}: {host_error}")
                failed_hosts.append({"host_id": host_id, "error": str(host_error)})

        # Determine overall status
        if len(failed_hosts) == len(host_ids):
            return {"status": "failed", "error": "All host scans failed", "scan_ids": []}
        elif failed_hosts:
            return {
                "status": "partial",
                "scan_ids": scan_ids,
                "failed_hosts": failed_hosts,
            }
        else:
            return {"status": "completed", "scan_ids": scan_ids}

    except Exception as e:
        logger.error(f"execute_group_compliance_scan failed: {e}")
        return {"status": "failed", "error": str(e), "scan_ids": []}
