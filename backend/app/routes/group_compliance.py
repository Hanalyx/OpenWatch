"""
Group Compliance Scanning Routes
Enhanced endpoints for comprehensive group-based compliance scanning and reporting
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy import and_, or_, text
from sqlalchemy.orm import Session

from backend.app.auth import get_current_user, require_permissions
from backend.app.celery_app import celery_app
from backend.app.database import Host, HostGroup, Scan, ScanResult, ScapContent, get_db
from backend.app.schemas.group_compliance import (
    ComplianceMetricsResponse,
    GroupComplianceReportResponse,
    GroupComplianceScanRequest,
    GroupComplianceScanResponse,
    GroupScanHistoryResponse,
    GroupScanScheduleRequest,
)

# GroupScanService removed - using unified API instead
from backend.app.services.scap_scanner import SCAPScanner

router = APIRouter(prefix="/group-compliance", tags=["group-compliance"])


@router.post("/{group_id}/scan", response_model=GroupComplianceScanResponse)
async def start_group_compliance_scan(
    group_id: int,
    scan_request: GroupComplianceScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Start a comprehensive compliance scan for all hosts in a group
    Supports multiple compliance frameworks and custom configurations
    """
    # Verify user permissions
    require_permissions(current_user, "scans:create")

    # Get the host group
    group = db.query(HostGroup).filter(HostGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Host group not found")

    # Get hosts in the group
    hosts = db.execute(
        text(
            """
        SELECT h.id, h.hostname, h.ip_address, h.os_family, h.architecture
        FROM hosts h
        JOIN host_group_memberships hgm ON h.id = hgm.host_id
        WHERE hgm.group_id = :group_id AND h.active = true
    """
        ),
        {"group_id": group_id},
    ).fetchall()

    if not hosts:
        raise HTTPException(status_code=400, detail="No active hosts found in group")

    # Validate SCAP content
    content_id = scan_request.scap_content_id or group.scap_content_id
    if not content_id:
        raise HTTPException(status_code=400, detail="No SCAP content specified")

    scap_content = db.query(ScapContent).filter(ScapContent.id == content_id).first()
    if not scap_content:
        raise HTTPException(status_code=404, detail="SCAP content not found")

    # Create group scan session
    session_id = str(uuid4())
    session_config = {
        "scap_content_id": content_id,
        "profile_id": scan_request.profile_id or group.default_profile_id,
        "compliance_framework": scan_request.compliance_framework or group.compliance_framework,
        "scan_options": scan_request.scan_options or {},
        "email_notifications": scan_request.email_notifications,
        "generate_reports": scan_request.generate_reports,
        "remediation_mode": scan_request.remediation_mode,
        "started_by": current_user["user_id"],
        "started_at": datetime.utcnow().isoformat(),
    }

    # Insert group scan session
    db.execute(
        text(
            """
        INSERT INTO group_scan_sessions (
            session_id, group_id, total_hosts, status, scan_config,
            estimated_completion, created_at, created_by
        ) VALUES (
            :session_id, :group_id, :total_hosts, 'pending', :config,
            :estimated_completion, :created_at, :created_by
        )
    """
        ),
        {
            "session_id": session_id,
            "group_id": group_id,
            "total_hosts": len(hosts),
            "config": json.dumps(session_config),
            "estimated_completion": datetime.utcnow() + timedelta(minutes=len(hosts) * 15),
            "created_at": datetime.utcnow(),
            "created_by": current_user["user_id"],
        },
    )

    # Initialize host progress tracking
    for host in hosts:
        db.execute(
            text(
                """
            INSERT INTO group_scan_host_progress (
                session_id, host_id, status, progress
            ) VALUES (:session_id, :host_id, 'pending', 0)
        """
            ),
            {"session_id": session_id, "host_id": host.id},
        )

    db.commit()

    # Execute scan directly for now (can be moved to background task later)
    host_ids = [host.id for host in hosts]
    scan_result = execute_group_compliance_scan(
        group_id=group_id,
        host_ids=host_ids,
        scap_content_id=content_id,
        profile_id=session_config["profile_id"],
        db=db,
        user_id=current_user["user_id"],
        session_id=session_id,
    )

    return GroupComplianceScanResponse(
        session_id=session_id,
        group_id=group_id,
        group_name=group.name,
        total_hosts=len(hosts),
        status="pending",
        estimated_completion=datetime.utcnow() + timedelta(minutes=len(hosts) * 15),
        compliance_framework=session_config["compliance_framework"],
        profile_id=session_config["profile_id"],
    )


@router.get("/{group_id}/report", response_model=GroupComplianceReportResponse)
async def get_group_compliance_report(
    group_id: int,
    framework: Optional[str] = Query(None, description="Filter by compliance framework"),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Generate comprehensive compliance report for a host group
    Includes trend analysis, risk assessment, and compliance gaps
    """
    require_permissions(current_user, "reports:view")

    # Get group information
    group = db.query(HostGroup).filter(HostGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Host group not found")

    # Build date filters
    date_filter = ""
    params = {"group_id": group_id}

    if date_from:
        date_filter += " AND s.completed_at >= :date_from"
        params["date_from"] = date_from
    if date_to:
        date_filter += " AND s.completed_at <= :date_to"
        params["date_to"] = date_to
    if framework:
        date_filter += " AND sc.compliance_framework = :framework"
        params["framework"] = framework

    # Get latest scan results for each host in the group
    compliance_data = db.execute(
        text(
            f"""
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
                sr.severity_low,
                sc.compliance_framework,
                sc.profile_id
            FROM hosts h
            JOIN host_group_memberships hgm ON h.id = hgm.host_id
            JOIN scans s ON h.id = s.host_id
            JOIN scan_results sr ON s.id = sr.scan_id
            JOIN scap_content sc ON s.content_id = sc.id
            WHERE hgm.group_id = :group_id 
                AND s.status = 'completed'
                AND h.active = true
                {date_filter}
            ORDER BY h.id, s.completed_at DESC
        )
        SELECT * FROM latest_scans
    """
        ),
        params,
    ).fetchall()

    if not compliance_data:
        raise HTTPException(status_code=404, detail="No compliance data found for group")

    # Calculate group metrics
    total_hosts = len(compliance_data)
    total_rules = sum(row.total_rules for row in compliance_data)
    total_passed = sum(row.passed_rules for row in compliance_data)
    total_failed = sum(row.failed_rules for row in compliance_data)

    # Compliance score calculation
    overall_score = (total_passed / total_rules * 100) if total_rules > 0 else 0

    # Risk analysis
    high_risk_hosts = len([r for r in compliance_data if r.severity_high > 0])
    medium_risk_hosts = len([r for r in compliance_data if r.severity_medium > 0])

    # Compliance distribution by framework
    framework_distribution = {}
    for row in compliance_data:
        framework = row.compliance_framework or "Unknown"
        if framework not in framework_distribution:
            framework_distribution[framework] = {
                "hosts": 0,
                "total_rules": 0,
                "passed_rules": 0,
                "avg_score": 0,
            }
        framework_distribution[framework]["hosts"] += 1
        framework_distribution[framework]["total_rules"] += row.total_rules
        framework_distribution[framework]["passed_rules"] += row.passed_rules

    # Calculate average scores for each framework
    for framework_data in framework_distribution.values():
        if framework_data["total_rules"] > 0:
            framework_data["avg_score"] = framework_data["passed_rules"] / framework_data["total_rules"] * 100

    # Get compliance trend (last 30 days)
    trend_data = db.execute(
        text(
            """
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
    """
        ),
        {"group_id": group_id, "trend_start": datetime.utcnow() - timedelta(days=30)},
    ).fetchall()

    # Top failed rules analysis
    failed_rules = db.execute(
        text(
            """
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
    """
        ),
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
        framework_distribution=framework_distribution,
        compliance_trend=[
            {
                "date": row.scan_date.isoformat(),
                "score": round(row.avg_score, 2),
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
                "failure_percentage": row.failure_percentage,
            }
            for row in failed_rules
        ],
        host_compliance_summary=[
            {
                "host_id": row.host_id,
                "hostname": row.hostname,
                "ip_address": row.ip_address,
                "os_family": row.os_family,
                "compliance_score": float(row.score),
                "total_rules": row.total_rules,
                "passed_rules": row.passed_rules,
                "failed_rules": row.failed_rules,
                "high_severity_issues": row.severity_high,
                "last_scan_date": row.completed_at.isoformat(),
            }
            for row in compliance_data
        ],
    )


@router.get("/{group_id}/metrics", response_model=ComplianceMetricsResponse)
async def get_group_compliance_metrics(
    group_id: int,
    timeframe: str = Query("30d", regex="^(7d|30d|90d|1y)$"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Get detailed compliance metrics and KPIs for a host group
    """
    require_permissions(current_user, "reports:view")

    # Calculate timeframe
    timeframe_days = {"7d": 7, "30d": 30, "90d": 90, "1y": 365}
    start_date = datetime.utcnow() - timedelta(days=timeframe_days[timeframe])

    # Get compliance metrics
    metrics = db.execute(
        text(
            """
        SELECT 
            COUNT(DISTINCT h.id) as total_hosts,
            COUNT(DISTINCT s.id) as total_scans,
            AVG(CAST(sr.score AS FLOAT)) as avg_compliance_score,
            SUM(sr.failed_rules) as total_violations,
            SUM(sr.severity_high) as critical_issues,
            SUM(sr.severity_medium) as high_issues,
            SUM(sr.severity_low) as medium_issues,
            COUNT(DISTINCT sc.compliance_framework) as frameworks_count
        FROM hosts h
        JOIN host_group_memberships hgm ON h.id = hgm.host_id
        LEFT JOIN scans s ON h.id = s.host_id AND s.completed_at >= :start_date
        LEFT JOIN scan_results sr ON s.id = sr.scan_id
        LEFT JOIN scap_content sc ON s.content_id = sc.id
        WHERE hgm.group_id = :group_id AND h.active = true
    """
        ),
        {"group_id": group_id, "start_date": start_date},
    ).fetchone()

    # Compliance trend over time
    trend_metrics = db.execute(
        text(
            """
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
    """
        ),
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
        frameworks_evaluated=metrics.frameworks_count or 0,
        compliance_trend=[
            {
                "period": row.week_start.isoformat(),
                "average_score": round(row.avg_score, 2),
                "scan_count": row.scan_count,
                "total_failures": row.total_failures,
            }
            for row in trend_metrics
        ],
    )


@router.post("/{group_id}/schedule", response_model=Dict[str, str])
async def schedule_group_compliance_scan(
    group_id: int,
    schedule_request: GroupScanScheduleRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Schedule recurring compliance scans for a host group
    """
    require_permissions(current_user, "scans:create")

    # Verify group exists
    group = db.query(HostGroup).filter(HostGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Host group not found")

    # Update group with scheduling configuration
    db.execute(
        text(
            """
        UPDATE host_groups SET
            auto_scan_enabled = :enabled,
            scan_schedule = :schedule,
            scap_content_id = :content_id,
            default_profile_id = :profile_id,
            compliance_framework = :framework
        WHERE id = :group_id
    """
        ),
        {
            "group_id": group_id,
            "enabled": schedule_request.enabled,
            "schedule": schedule_request.cron_expression,
            "content_id": schedule_request.scap_content_id,
            "profile_id": schedule_request.profile_id,
            "framework": schedule_request.compliance_framework,
        },
    )

    db.commit()

    # Schedule the recurring task using Celery
    if schedule_request.enabled:
        celery_app.conf.beat_schedule[f"group-scan-{group_id}"] = {
            "task": "backend.app.tasks.scheduled_group_scan",
            "schedule": schedule_request.cron_expression,
            "args": (group_id, schedule_request.dict()),
        }
        return {"message": "Group compliance scan scheduled successfully"}
    else:
        # Remove existing schedule
        if f"group-scan-{group_id}" in celery_app.conf.beat_schedule:
            del celery_app.conf.beat_schedule[f"group-scan-{group_id}"]
        return {"message": "Group compliance scan scheduling disabled"}


@router.get("/{group_id}/scan-history", response_model=List[GroupScanHistoryResponse])
async def get_group_scan_history(
    group_id: int,
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Get scan history for a host group
    """
    require_permissions(current_user, "reports:view")

    history = db.execute(
        text(
            """
        SELECT 
            gss.session_id,
            gss.status,
            gss.total_hosts,
            gss.created_at,
            gss.completed_at,
            gss.scan_config,
            COUNT(gshp.host_id) as hosts_scanned,
            SUM(CASE WHEN gshp.status = 'completed' THEN 1 ELSE 0 END) as successful_hosts,
            SUM(CASE WHEN gshp.status = 'failed' THEN 1 ELSE 0 END) as failed_hosts,
            AVG(gshp.progress) as avg_progress
        FROM group_scan_sessions gss
        LEFT JOIN group_scan_host_progress gshp ON gss.session_id = gshp.session_id
        WHERE gss.group_id = :group_id
        GROUP BY gss.session_id, gss.status, gss.total_hosts, gss.created_at, gss.completed_at, gss.scan_config
        ORDER BY gss.created_at DESC
        LIMIT :limit OFFSET :offset
    """
        ),
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


def execute_group_compliance_scan(
    group_id: int,
    host_ids: List[str],
    scap_content_id: int,
    profile_id: str,
    db: Session,
    user_id: str,
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Execute compliance scan for hosts using unified approach
    Returns scan execution results
    """
    try:
        # Initialize SCAP scanner directly
        scanner = SCAPScanner()

        # Get SCAP content details
        scap_content = db.query(ScapContent).filter(ScapContent.id == scap_content_id).first()

        if not scap_content:
            return {"status": "failed", "error": "SCAP content not found"}

        # Execute scan for each host
        scan_results = []
        for host_id in host_ids:
            try:
                # Get host details
                host = db.query(Host).filter(Host.id == host_id).first()
                if not host:
                    continue

                # Create scan record
                scan = Scan(
                    host_id=host_id,
                    content_id=scap_content_id,
                    profile_id=profile_id,
                    status="running",
                    started_by=user_id,
                    started_at=datetime.utcnow(),
                )
                db.add(scan)
                db.flush()  # Get scan ID

                # Execute SCAP scan
                scan_result = scanner.scan_host(host=host, scap_content=scap_content, profile_id=profile_id)

                # Update scan status
                scan.status = "completed"
                scan.completed_at = datetime.utcnow()

                # Store scan results
                if scan_result:
                    result = ScanResult(
                        scan_id=scan.id,
                        total_rules=scan_result.get("total_rules", 0),
                        passed_rules=scan_result.get("passed_rules", 0),
                        failed_rules=scan_result.get("failed_rules", 0),
                        score=scan_result.get("score", 0),
                        severity_high=scan_result.get("severity_high", 0),
                        severity_medium=scan_result.get("severity_medium", 0),
                        severity_low=scan_result.get("severity_low", 0),
                    )
                    db.add(result)

                scan_results.append({"host_id": host_id, "scan_id": scan.id, "status": "completed"})

            except Exception as host_error:
                # Mark host scan as failed
                if "scan" in locals():
                    scan.status = "failed"
                    scan.error_message = str(host_error)
                    scan.completed_at = datetime.utcnow()

                scan_results.append({"host_id": host_id, "status": "failed", "error": str(host_error)})

        db.commit()

        return {
            "status": "completed",
            "scan_results": scan_results,
            "total_hosts": len(host_ids),
            "successful_scans": len([r for r in scan_results if r["status"] == "completed"]),
        }

    except Exception as e:
        db.rollback()
        return {"status": "failed", "error": str(e)}


async def send_compliance_scan_notification(session_id: str, group_id: int, config: Dict[str, Any], db: Session):
    """
    Send email notification about completed compliance scan
    """
    # This would integrate with an email service
    # For now, log the notification
    print(f"Compliance scan notification: Session {session_id} for group {group_id} completed")
