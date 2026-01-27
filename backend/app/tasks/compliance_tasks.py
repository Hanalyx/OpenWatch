"""
Compliance Scanning Celery Tasks
Background tasks for scheduled and batch compliance scanning
"""

import json
from datetime import datetime, timedelta
from typing import Any, Dict, List

from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.celery_app import celery_app
from backend.app.database import HostGroup, get_db_session

# Import from new modular host_groups package (Phase 1 API Standardization)
from backend.app.routes.host_groups import execute_group_compliance_scan

# GroupScanService removed - using group_compliance API instead


@celery_app.task(bind=True, name="backend.app.tasks.scheduled_group_scan")
def scheduled_group_scan(self, group_id: int, config: Dict[str, Any]):
    """
    Scheduled compliance scan for a host group
    Executed via Celery Beat scheduler
    """
    session_id = f"scheduled-{group_id}-{int(datetime.utcnow().timestamp())}"

    try:
        # Get database session
        with get_db_session() as db:
            # Verify group still exists and has auto-scan enabled
            group = db.query(HostGroup).filter(HostGroup.id == group_id, HostGroup.auto_scan_enabled.is_(True)).first()

            if not group:
                self.retry(countdown=300, max_retries=3)  # Retry after 5 minutes
                return

            # Get hosts in the group
            hosts = db.execute(
                text("""
                SELECT h.id, h.hostname, h.ip_address, h.os_family, h.architecture
                FROM hosts h
                JOIN host_group_memberships hgm ON h.id = hgm.host_id
                WHERE hgm.group_id = :group_id AND h.active = true
            """),
                {"group_id": group_id},
            ).fetchall()

            if not hosts:
                print(f"No active hosts found in group {group_id} for scheduled scan")
                return

            # Create session configuration
            session_config = {
                "scap_content_id": group.scap_content_id,
                "profile_id": group.default_profile_id,
                "compliance_framework": group.compliance_framework,
                "scan_options": config.get("scan_options", {}),
                "email_notifications": config.get("email_notifications", True),
                "generate_reports": True,
                "remediation_mode": config.get("remediation_mode", "report_only"),
                "scheduled": True,
                "started_by": "system",
                "started_at": datetime.utcnow().isoformat(),
            }

            # Create group scan session
            db.execute(
                text("""
                INSERT INTO group_scan_sessions (
                    session_id, group_id, total_hosts, status, scan_config,
                    estimated_completion, created_at, created_by
                ) VALUES (
                    :session_id, :group_id, :total_hosts, 'pending', :config,
                    :estimated_completion, :created_at, 'system'
                )
            """),
                {
                    "session_id": session_id,
                    "group_id": group_id,
                    "total_hosts": len(hosts),
                    "config": json.dumps(session_config),
                    "estimated_completion": datetime.utcnow() + timedelta(minutes=len(hosts) * 15),
                    "created_at": datetime.utcnow(),
                },
            )

            # Initialize host progress tracking
            for host in hosts:
                db.execute(
                    text("""
                    INSERT INTO group_scan_host_progress (
                        session_id, host_id, status, progress
                    ) VALUES (:session_id, :host_id, 'pending', 0)
                """),
                    {"session_id": session_id, "host_id": host.id},
                )

            db.commit()

            # Execute the scan asynchronously
            execute_compliance_scan_async.delay(session_id, group_id, [dict(host) for host in hosts], session_config)

            print(f"Scheduled compliance scan started for group {group_id}, session: {session_id}")

    except Exception as exc:
        print(f"Scheduled scan failed for group {group_id}: {str(exc)}")
        # Retry with exponential backoff
        raise self.retry(exc=exc, countdown=60, max_retries=3)


@celery_app.task(bind=True, name="backend.app.tasks.execute_compliance_scan_async")
def execute_compliance_scan_async(self, session_id: str, group_id: int, hosts: List[Dict], config: Dict[str, Any]):
    """
    Execute compliance scan asynchronously
    """
    try:
        with get_db_session() as db:
            # Update session status
            db.execute(
                text("""
                UPDATE group_scan_sessions
                SET status = 'in_progress', started_at = :started_at
                WHERE session_id = :session_id
            """),
                {"session_id": session_id, "started_at": datetime.utcnow()},
            )
            db.commit()

            # Execute the scan for each host using unified API
            successful_scans = 0
            failed_scans = 0

            for host in hosts:
                try:
                    # Update host status
                    db.execute(
                        text("""
                        UPDATE group_scan_host_progress
                        SET status = 'in_progress', progress = 10
                        WHERE session_id = :session_id AND host_id = :host_id
                    """),
                        {"session_id": session_id, "host_id": host["id"]},
                    )
                    db.commit()

                    # Use the unified group-compliance scan execution
                    scan_result = execute_group_compliance_scan(
                        group_id=group_id,
                        host_ids=[host["id"]],
                        scap_content_id=config["scap_content_id"],
                        profile_id=config["profile_id"],
                        db=db,
                        user_id="system",
                    )

                    # Update progress based on scan result
                    if scan_result.get("status") == "completed":
                        db.execute(
                            text("""
                            UPDATE group_scan_host_progress
                            SET status = 'completed', progress = 100, scan_id = :scan_id
                            WHERE session_id = :session_id AND host_id = :host_id
                        """),
                            {
                                "session_id": session_id,
                                "host_id": host["id"],
                                "scan_id": scan_result.get("scan_id"),
                            },
                        )
                        successful_scans += 1
                    else:
                        raise Exception(scan_result.get("error", "Scan failed"))

                    db.commit()

                except Exception as host_error:
                    # Update host as failed
                    db.execute(
                        text("""
                        UPDATE group_scan_host_progress
                        SET status = 'failed', error_message = :error
                        WHERE session_id = :session_id AND host_id = :host_id
                    """),
                        {
                            "session_id": session_id,
                            "host_id": host["id"],
                            "error": str(host_error),
                        },
                    )
                    db.commit()

                    failed_scans += 1
                    print(f"Host scan failed for {host['hostname']}: {str(host_error)}")

            # Update session completion
            final_status = "completed" if failed_scans == 0 else "partial"
            db.execute(
                text("""
                UPDATE group_scan_sessions
                SET status = :status, completed_at = :completed_at,
                    successful_hosts = :successful, failed_hosts = :failed
                WHERE session_id = :session_id
            """),
                {
                    "session_id": session_id,
                    "status": final_status,
                    "completed_at": datetime.utcnow(),
                    "successful": successful_scans,
                    "failed": failed_scans,
                },
            )
            db.commit()

            # Send notifications if configured
            if config.get("email_notifications"):
                send_compliance_notification.delay(
                    session_id,
                    group_id,
                    {
                        "successful_scans": successful_scans,
                        "failed_scans": failed_scans,
                        "total_hosts": len(hosts),
                    },
                )

            print(
                f"Compliance scan completed for group {group_id}: {successful_scans} successful, {failed_scans} failed"
            )

    except Exception as exc:
        # Mark session as failed
        with get_db_session() as db:
            db.execute(
                text("""
                UPDATE group_scan_sessions
                SET status = 'failed', completed_at = :completed_at, error_message = :error
                WHERE session_id = :session_id
            """),
                {
                    "session_id": session_id,
                    "completed_at": datetime.utcnow(),
                    "error": str(exc),
                },
            )
            db.commit()

        raise self.retry(exc=exc, countdown=300, max_retries=2)


@celery_app.task(name="backend.app.tasks.send_compliance_notification")
def send_compliance_notification(session_id: str, group_id: int, summary: Dict[str, Any]):
    """
    Send compliance scan completion notification
    """
    try:
        with get_db_session() as db:
            # Get group and session details
            session_info = db.execute(
                text("""
                SELECT gss.*, hg.name as group_name
                FROM group_scan_sessions gss
                JOIN host_groups hg ON gss.group_id = hg.id
                WHERE gss.session_id = :session_id
            """),
                {"session_id": session_id},
            ).fetchone()

            if not session_info:
                return

            # Prepare notification payload
            notification_data = {
                "event_type": "compliance_scan_completed",
                "session_id": session_id,
                "group_id": group_id,
                "group_name": session_info.group_name,
                "timestamp": datetime.utcnow().isoformat(),
                "summary": summary,
                "compliance_framework": json.loads(session_info.scan_config or "{}").get("compliance_framework"),
                "total_hosts": session_info.total_hosts,
                "status": session_info.status,
            }

            # Here you would integrate with your notification system
            # For example: send email, Slack notification, webhook, etc.
            print(f"Compliance scan notification: {json.dumps(notification_data, indent=2)}")

            # Log notification in audit trail
            db.execute(
                text("""
                INSERT INTO audit_logs (
                    action, resource_type, resource_id, details, timestamp
                ) VALUES (
                    'COMPLIANCE_NOTIFICATION_SENT', 'group_scan', :session_id, :details, :timestamp
                )
            """),
                {
                    "session_id": session_id,
                    "details": json.dumps(notification_data),
                    "timestamp": datetime.utcnow(),
                },
            )
            db.commit()

    except Exception as e:
        print(f"Failed to send compliance notification for session {session_id}: {str(e)}")


@celery_app.task(name="backend.app.tasks.compliance_report_generation")
def compliance_report_generation(group_id: int, report_config: Dict[str, Any]):
    """
    Generate comprehensive compliance reports
    """
    try:
        with get_db_session() as db:
            # Generate compliance report data
            report_data = generate_compliance_report_data(db, group_id, report_config)

            # Save report to file system or cloud storage
            report_path = save_compliance_report(report_data, report_config.get("format", "json"))

            # Update group with latest report
            db.execute(
                text("""
                UPDATE host_groups
                SET last_compliance_report = :report_path,
                    last_report_generated = :timestamp
                WHERE id = :group_id
            """),
                {
                    "group_id": group_id,
                    "report_path": report_path,
                    "timestamp": datetime.utcnow(),
                },
            )
            db.commit()

            print(f"Compliance report generated for group {group_id}: {report_path}")

    except Exception as e:
        print(f"Failed to generate compliance report for group {group_id}: {str(e)}")


def generate_compliance_report_data(db: Session, group_id: int, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate compliance report data from database
    """
    # This would contain the logic to generate comprehensive compliance reports
    # Similar to the report endpoint but for background processing


def save_compliance_report(report_data: Dict[str, Any], format: str = "json") -> str:
    """
    Save compliance report to storage
    """
    # This would handle saving reports to file system, S3, etc.
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"compliance_report_{timestamp}.{format}"

    # Mock implementation - in reality, save to appropriate storage
    print(f"Saving compliance report: {filename}")
    return f"/reports/compliance/{filename}"


@celery_app.task(name="backend.app.tasks.compliance_alert_check")
def compliance_alert_check(group_id: int):
    """
    Check compliance metrics against alert rules
    """
    try:
        with get_db_session() as db:
            # Get latest compliance metrics for group
            metrics = db.execute(
                text("""
                SELECT
                    AVG(CAST(sr.score AS FLOAT)) as avg_score,
                    SUM(sr.severity_high) as critical_issues,
                    COUNT(DISTINCT h.id) as total_hosts
                FROM hosts h
                JOIN host_group_memberships hgm ON h.id = hgm.host_id
                JOIN scans s ON h.id = s.host_id
                JOIN scan_results sr ON s.id = sr.scan_id
                WHERE hgm.group_id = :group_id
                    AND s.completed_at >= :recent_threshold
                    AND s.status = 'completed'
            """),
                {
                    "group_id": group_id,
                    "recent_threshold": datetime.utcnow() - timedelta(days=7),
                },
            ).fetchone()

            if metrics and metrics.avg_score:
                # Check alert rules
                alerts_triggered = []

                # Score below threshold alert
                if metrics.avg_score < 80:
                    alerts_triggered.append(
                        {
                            "type": "low_compliance_score",
                            "value": metrics.avg_score,
                            "threshold": 80,
                            "message": f"Compliance score ({metrics.avg_score:.1f}%) below threshold",
                        }
                    )

                # Critical issues alert
                if metrics.critical_issues > 0:
                    alerts_triggered.append(
                        {
                            "type": "critical_issues_detected",
                            "value": metrics.critical_issues,
                            "message": f"{metrics.critical_issues} critical compliance issues detected",
                        }
                    )

                # Send alerts if any triggered
                if alerts_triggered:
                    send_compliance_alerts.delay(group_id, alerts_triggered)

    except Exception as e:
        print(f"Failed to check compliance alerts for group {group_id}: {str(e)}")


@celery_app.task(name="backend.app.tasks.send_compliance_alerts")
def send_compliance_alerts(group_id: int, alerts: List[Dict[str, Any]]):
    """
    Send compliance alert notifications
    """
    try:
        # This would integrate with alerting systems (email, Slack, PagerDuty, etc.)
        print(f"Compliance alerts for group {group_id}: {json.dumps(alerts, indent=2)}")

        with get_db_session() as db:
            # Log alerts in audit trail
            for alert in alerts:
                db.execute(
                    text("""
                    INSERT INTO audit_logs (
                        action, resource_type, resource_id, details, timestamp
                    ) VALUES (
                        'COMPLIANCE_ALERT_SENT', 'host_group', :group_id, :details, :timestamp
                    )
                """),
                    {
                        "group_id": str(group_id),
                        "details": json.dumps(alert),
                        "timestamp": datetime.utcnow(),
                    },
                )
            db.commit()

    except Exception as e:
        print(f"Failed to send compliance alerts for group {group_id}: {str(e)}")


# Periodic tasks registration
@celery_app.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    """
    Setup periodic compliance tasks
    """
    # Check for compliance alerts every hour
    sender.add_periodic_task(
        3600.0,  # Every hour
        compliance_monitoring_task.s(),
        name="compliance_monitoring",
    )


@celery_app.task(name="backend.app.tasks.compliance_monitoring_task")
def compliance_monitoring_task():
    """
    Periodic task to monitor compliance across all groups
    """
    try:
        with get_db_session() as db:
            # Get all groups with auto-scan enabled
            groups = db.execute(text("""
                SELECT id FROM host_groups
                WHERE auto_scan_enabled = true AND active = true
            """)).fetchall()

            # Check alerts for each group
            for group in groups:
                compliance_alert_check.delay(group.id)

    except Exception as e:
        print(f"Failed to run compliance monitoring task: {str(e)}")
