"""
Celery tasks for SCAP scanning operations
"""

import asyncio
import json
import logging
import re
from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from ..database import SessionLocal

# SemanticEngine provides intelligent scan analysis and compliance intelligence
# Engine module exceptions and integration services
# ScanExecutionError provides standardized error handling for scan failures
from ..services.engine import ScanExecutionError, get_semantic_engine

# UnifiedSCAPScanner provides execute_local_scan, execute_remote_scan,
# and test_ssh_connection methods with legacy compatibility
from ..services.engine.scanners import UnifiedSCAPScanner
from ..services.error_classification import ErrorClassificationService
from .webhook_tasks import send_scan_completed_webhook, send_scan_failed_webhook

logger = logging.getLogger(__name__)

# Initialize services
# UnifiedSCAPScanner handles SSH-based SCAP scanning operations
scap_scanner = UnifiedSCAPScanner()
error_service = ErrorClassificationService()


def execute_scan_task(
    scan_id: str,
    host_data: Dict[str, Any],
    content_path: str,
    profile_id: str,
    scan_options: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Execute SCAP scan task
    This is designed to work with or without Celery
    """
    db = SessionLocal()

    try:
        logger.info(f"Starting scan task: {scan_id}")

        # Update scan status to running
        db.execute(
            text("""
            UPDATE scans SET status = 'running', progress = 5
            WHERE id = :scan_id
        """),
            {"scan_id": scan_id},
        )
        db.commit()

        # Check if this is part of a group scan and update group scan progress
        group_scan_session_id = scan_options.get("session_id") if scan_options else None
        if group_scan_session_id and scan_options.get("group_scan"):
            try:
                from ..services.group_scan_service import GroupScanProgressTracker

                progress_tracker = GroupScanProgressTracker(db)
                progress_tracker.update_host_status(
                    group_scan_session_id,
                    host_data.get("id", "unknown"),
                    "scanning",
                    scan_id,
                )
                logger.debug(f"Updated group scan progress for session {group_scan_session_id}")
            except Exception as e:
                logger.error(f"Failed to update group scan progress: {e}")
                # Don't fail the entire scan for group progress tracking errors

        # Decrypt credentials (handle both formats for compatibility)
        credentials = {}
        if host_data["hostname"] == "localhost":
            # No credentials needed for localhost
            credentials = {"type": "local"}
        else:
            # Use centralized authentication service for all credential resolution
            try:
                from ..config import get_settings
                from ..encryption import EncryptionConfig, create_encryption_service
                from ..services.auth import get_auth_service

                # Create encryption service for credential decryption
                settings = get_settings()
                encryption_config = EncryptionConfig()
                encryption_service = create_encryption_service(master_key=settings.master_key, config=encryption_config)

                auth_service = get_auth_service(db, encryption_service)

                # Determine if we should use default credentials or host-specific
                use_default = host_data.get("auth_method") in [
                    "default",
                    "system_default",
                ]
                target_id = None if use_default else host_data.get("id")

                logger.info(
                    f"Resolving credentials for scan {scan_id}: use_default={use_default}, target_id={target_id}"
                )

                # Resolve credentials using centralized service
                credential_data = auth_service.resolve_credential(target_id=target_id, use_default=use_default)

                if not credential_data:
                    logger.error(f"No credentials available for scan {scan_id}")
                    _update_scan_error(db, scan_id, "No credentials available for host")
                    return

                # Convert to format expected by scan tasks
                credentials = {
                    "username": credential_data.username,
                    "auth_method": credential_data.auth_method.value,
                    "password": credential_data.password,
                    "private_key": credential_data.private_key,  # Consistent field naming
                    "private_key_passphrase": credential_data.private_key_passphrase,
                }

                # Update host_data to use resolved credentials
                host_data["username"] = credential_data.username
                host_data["auth_method"] = credential_data.auth_method.value

                logger.info(f"Resolved {credential_data.source} credentials for scan {scan_id}")

                # JIT Platform Detection - ensure we have platform info for correct content selection
                # This follows the SSH Connection Best Practices from CLAUDE.md
                host_id = host_data.get("id")
                if host_id and scan_options.get("enable_jit_detection", True):
                    try:
                        from ..services.platform_content_service import get_platform_content_service

                        platform_service = get_platform_content_service(db)
                        platform_info = asyncio.run(
                            platform_service.get_host_platform_with_jit_detection(
                                host_id=host_id,
                                credential_data=credential_data,
                            )
                        )

                        if platform_info and platform_info.platform_identifier:
                            logger.info(
                                f"Platform for scan {scan_id}: {platform_info.platform_identifier} "
                                f"(source: {platform_info.source})"
                            )
                            # Store platform info for content selection
                            host_data["platform_identifier"] = platform_info.platform_identifier
                            host_data["os_family"] = platform_info.platform
                            host_data["os_version"] = platform_info.platform_version

                            # Check if we need to select different content for this platform
                            if scan_options.get("auto_select_content", False):
                                content_result = asyncio.run(
                                    platform_service.get_content_for_platform(
                                        platform_info.platform_identifier,
                                        scan_options.get("compliance_framework"),
                                    )
                                )
                                if content_result:
                                    logger.info(
                                        f"Auto-selected content for {platform_info.platform_identifier}: "
                                        f"{content_result.name} ({content_result.match_type} match)"
                                    )
                                    # Update content_path if different content was found
                                    if content_result.file_path != content_path:
                                        logger.info(
                                            f"Switching content from {content_path} to "
                                            f"{content_result.file_path} for platform match"
                                        )
                                        content_path = content_result.file_path
                        else:
                            logger.warning(f"Could not determine platform for host in scan {scan_id}")
                    except Exception as jit_error:
                        logger.warning(
                            f"JIT platform detection failed for scan {scan_id}: {jit_error}. "
                            "Continuing with provided content."
                        )
                        # Don't fail the scan, just continue with the original content

            except Exception as e:
                logger.error(f"Failed to resolve credentials for scan {scan_id}: {e}")
                _update_scan_error(db, scan_id, f"Credential resolution failed: {str(e)}", e)
                return

        # Update progress
        db.execute(
            text("""
            UPDATE scans SET progress = 10 WHERE id = :scan_id
        """),
            {"scan_id": scan_id},
        )
        db.commit()

        # Extract the appropriate credential based on auth method
        if host_data["auth_method"] == "password":
            credential_value = credentials.get("password", "")
        elif host_data["auth_method"] in ["ssh_key", "ssh-key"]:
            credential_value = credentials.get("private_key", "")
        else:
            credential_value = credentials.get("credential", "")

        # Test SSH connection first
        if host_data["hostname"] != "localhost":
            logger.info(f"Testing SSH connection for scan {scan_id}")

            # Extract the appropriate credential based on auth method
            if host_data["auth_method"] == "password":
                credential_value = credentials.get("password", "")
            elif host_data["auth_method"] == "ssh_key":
                credential_value = credentials.get("private_key", "")
            else:
                credential_value = credentials.get("credential", "")

            ssh_test = scap_scanner.test_ssh_connection(
                hostname=host_data["hostname"],
                port=host_data["port"],
                username=host_data["username"],
                auth_method=host_data["auth_method"],
                credential=credential_value,
            )

            if not ssh_test["success"]:
                logger.error(f"SSH connection failed for scan {scan_id}: {ssh_test['message']}")
                # Create a synthetic exception for SSH failure
                ssh_error = Exception(f"SSH connection failed: {ssh_test['message']}")
                _update_scan_error(
                    db,
                    scan_id,
                    f"SSH connection failed: {ssh_test['message']}",
                    ssh_error,
                )
                return

            if not ssh_test.get("oscap_available", False):
                logger.warning(f"OpenSCAP not available on remote host for scan {scan_id}")
                # Create a synthetic exception for missing dependency
                dep_error = Exception("OpenSCAP not available on remote host")
                _update_scan_error(db, scan_id, "OpenSCAP not available on remote host", dep_error)
                return

        # Update progress
        db.execute(
            text("""
            UPDATE scans SET progress = 20 WHERE id = :scan_id
        """),
            {"scan_id": scan_id},
        )
        db.commit()

        # Execute scan
        logger.info(f"Executing SCAP scan: {scan_id}")

        try:
            # Update progress to indicate scan execution has started
            db.execute(
                text("""
                UPDATE scans SET progress = 30 WHERE id = :scan_id
            """),
                {"scan_id": scan_id},
            )
            db.commit()

            # Extract rule_id from scan_options for rule-specific rescans
            rule_id = scan_options.get("rule_id") if scan_options else None

            if host_data["hostname"] == "localhost":
                # Local scan
                scan_results = scap_scanner.execute_local_scan(
                    content_path=content_path,
                    profile_id=profile_id,
                    scan_id=scan_id,
                    rule_id=rule_id,
                )
            else:
                # Remote scan
                scan_results = scap_scanner.execute_remote_scan(
                    hostname=host_data["hostname"],
                    port=host_data["port"],
                    username=host_data["username"],
                    auth_method=host_data["auth_method"],
                    credential=credential_value,
                    content_path=content_path,
                    profile_id=profile_id,
                    scan_id=scan_id,
                    rule_id=rule_id,
                )

            # Update progress after scan execution
            db.execute(
                text("""
                UPDATE scans SET progress = 90 WHERE id = :scan_id
            """),
                {"scan_id": scan_id},
            )
            db.commit()

            # Check for scan errors
            if "error" in scan_results:
                logger.error(f"Scan execution failed for {scan_id}: {scan_results['error']}")
                scan_error = Exception(scan_results["error"])
                _update_scan_error(db, scan_id, scan_results["error"], scan_error)
                return
        except Exception as e:
            logger.error(f"Scan execution failed for {scan_id}: {str(e)}", exc_info=True)
            _update_scan_error(db, scan_id, f"Scan execution error: {str(e)}", e)
            return

        # Update scan record with results
        db.execute(
            text("""
            UPDATE scans
            SET status = 'completed', progress = 100, completed_at = :completed_at,
                result_file = :result_file, report_file = :report_file
            WHERE id = :scan_id
        """),
            {
                "scan_id": scan_id,
                "completed_at": datetime.utcnow(),
                "result_file": scan_results.get("xml_result"),
                "report_file": scan_results.get("html_report"),
            },
        )
        db.commit()

        # Save scan results summary
        _save_scan_results(db, scan_id, scan_results)

        # Update group scan progress if this is part of a group scan
        if group_scan_session_id and scan_options.get("group_scan"):
            try:
                from ..services.group_scan_service import GroupScanProgressTracker

                progress_tracker = GroupScanProgressTracker(db)

                # Get scan result ID for linking
                scan_result_id = None
                result_query = db.execute(
                    text("SELECT id FROM scan_results WHERE scan_id = :scan_id"),
                    {"scan_id": scan_id},
                ).fetchone()
                if result_query:
                    scan_result_id = str(result_query.id)

                progress_tracker.update_host_status(
                    group_scan_session_id,
                    host_data.get("id", "unknown"),
                    "completed",
                    scan_id,
                    scan_result_id,
                )
                logger.debug(f"Updated group scan progress to completed for session {group_scan_session_id}")
            except Exception as e:
                logger.error(f"Failed to update group scan completion progress: {e}")

        # Process scan with semantic intelligence
        try:
            asyncio.run(_process_semantic_intelligence(db, scan_id, scan_results, host_data))
        except Exception as e:
            logger.error(f"Semantic intelligence processing failed for {scan_id}: {e}")
            # Continue with normal flow - don't break existing functionality

        # Send webhook notification for successful completion
        try:
            # Prepare scan data for webhook
            webhook_data = {
                "hostname": host_data["hostname"],
                "profile_id": profile_id,
                "status": "completed",
                "total_rules": scan_results.get("rules_total", 0),
                "passed_rules": scan_results.get("rules_passed", 0),
                "failed_rules": scan_results.get("rules_failed", 0),
                "score": scan_results.get("score", 0),
                "completed_at": datetime.utcnow().isoformat(),
            }

            # Run webhook delivery in a new event loop (for Celery worker context)
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(send_scan_completed_webhook(scan_id, webhook_data))
                loop.close()
                logger.debug(f"Webhook notification sent for completed scan: {scan_id}")
            except Exception as loop_error:
                logger.warning(f"Failed to send webhook notification for scan {scan_id}: {loop_error}")

        except Exception as webhook_error:
            logger.error(f"Failed to send completion webhook for scan {scan_id}: {webhook_error}")

        logger.info(f"Scan completed successfully: {scan_id}")

    except ScanExecutionError as e:
        logger.error(f"Scan execution error for {scan_id}: {e}")
        _update_scan_error(db, scan_id, str(e), e)
    except Exception as e:
        logger.error(f"Unexpected error in scan task {scan_id}: {e}")
        _update_scan_error(db, scan_id, f"Unexpected error: {str(e)}", e)
    finally:
        db.close()


def _update_scan_error(
    db: Session, scan_id: str, error_message: str, original_exception: Optional[Exception] = None
) -> None:
    """Update scan with error status and set progress to 100% to indicate completion"""
    try:
        # Classify error if original exception provided
        classified_error = None
        if original_exception:
            try:
                import asyncio

                classified_error = asyncio.run(error_service.classify_error(original_exception, {"scan_id": scan_id}))
                # Use classified error message if available
                if classified_error:
                    error_message = f"{classified_error.message} (Code: {classified_error.error_code})"
                    logger.info(
                        f"Error classified for scan {scan_id}: {classified_error.category.value} - {classified_error.error_code}"  # noqa: E501
                    )
            except Exception as e:
                logger.warning(f"Failed to classify error for scan {scan_id}: {e}")
                # Continue with original error message

        # Get scan data for webhook notification and check for group scan
        scan_result = db.execute(
            text("""
            SELECT s.id, h.hostname, s.profile_id, s.scan_options, s.host_id
            FROM scans s
            JOIN hosts h ON s.host_id = h.id
            WHERE s.id = :scan_id
        """),
            {"scan_id": scan_id},
        )

        scan_data = scan_result.fetchone()

        # Check if this is part of a group scan and update progress
        if scan_data and scan_data.scan_options:
            try:
                import json

                scan_options = json.loads(scan_data.scan_options)
                group_scan_session_id = scan_options.get("session_id")

                if group_scan_session_id and scan_options.get("group_scan"):
                    from ..services.group_scan_service import GroupScanProgressTracker

                    progress_tracker = GroupScanProgressTracker(db)
                    asyncio.run(
                        progress_tracker.update_host_status(
                            group_scan_session_id,
                            str(scan_data.host_id),
                            "failed",
                            scan_id,
                            error_message=error_message,
                        )
                    )
                    logger.debug(f"Updated group scan progress to failed for session {group_scan_session_id}")
            except Exception as e:
                logger.error(f"Failed to update group scan failure progress: {e}")

        db.execute(
            text("""
            UPDATE scans
            SET status = 'failed', progress = 100, completed_at = :completed_at, error_message = :error_message
            WHERE id = :scan_id
        """),
            {
                "scan_id": scan_id,
                "completed_at": datetime.utcnow(),
                "error_message": error_message,
            },
        )
        db.commit()

        # Send webhook notification for scan failure
        if scan_data:
            try:
                webhook_data = {
                    "hostname": scan_data.hostname,
                    "profile_id": scan_data.profile_id,
                    "status": "failed",
                    "completed_at": datetime.utcnow().isoformat(),
                }

                # Run webhook delivery in a new event loop (for Celery worker context)
                try:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    loop.run_until_complete(send_scan_failed_webhook(scan_id, webhook_data, error_message))
                    loop.close()
                    logger.debug(f"Webhook notification sent for failed scan: {scan_id}")
                except Exception as loop_error:
                    logger.warning(f"Failed to send webhook notification for scan {scan_id}: {loop_error}")

            except Exception as webhook_error:
                logger.error(f"Failed to send failure webhook for scan {scan_id}: {webhook_error}")

    except Exception as e:
        logger.error(f"Failed to update scan error status: {e}")


def _save_scan_results(db: Session, scan_id: str, scan_results: Dict[str, Any]) -> None:
    """Save scan results summary to database"""
    try:
        # Parse failed rules by severity
        # NIST SP 800-30 requires separate tracking of critical severity (CVSS >= 9.0)
        failed_rules = scan_results.get("failed_rules", [])
        severity_critical = len([r for r in failed_rules if r.get("severity") == "critical"])
        severity_high = len([r for r in failed_rules if r.get("severity") == "high"])
        severity_medium = len([r for r in failed_rules if r.get("severity") == "medium"])
        severity_low = len([r for r in failed_rules if r.get("severity") == "low"])

        # Parse passed rules by severity for accurate compliance visualization
        # NIST SP 800-137 Continuous Monitoring requires granular pass/fail tracking
        # to enable accurate compliance ring visualization (ComplianceRing component)
        passed_rules = scan_results.get("passed_rules", [])
        severity_critical_passed = len([r for r in passed_rules if r.get("severity") == "critical"])
        severity_high_passed = len([r for r in passed_rules if r.get("severity") == "high"])
        severity_medium_passed = len([r for r in passed_rules if r.get("severity") == "medium"])
        severity_low_passed = len([r for r in passed_rules if r.get("severity") == "low"])

        # Failed counts (align naming with database columns)
        severity_critical_failed = severity_critical
        severity_high_failed = severity_high
        severity_medium_failed = severity_medium
        severity_low_failed = severity_low

        # Insert scan results with granular per-severity pass/fail tracking
        db.execute(
            text("""
            INSERT INTO scan_results
            (scan_id, total_rules, passed_rules, failed_rules, error_rules,
             unknown_rules, not_applicable_rules, score,
             severity_critical, severity_high, severity_medium, severity_low,
             severity_critical_passed, severity_critical_failed,
             severity_high_passed, severity_high_failed,
             severity_medium_passed, severity_medium_failed,
             severity_low_passed, severity_low_failed,
             created_at)
            VALUES (:scan_id, :total_rules, :passed_rules, :failed_rules, :error_rules,
                    :unknown_rules, :not_applicable_rules, :score,
                    :severity_critical, :severity_high, :severity_medium, :severity_low,
                    :severity_critical_passed, :severity_critical_failed,
                    :severity_high_passed, :severity_high_failed,
                    :severity_medium_passed, :severity_medium_failed,
                    :severity_low_passed, :severity_low_failed,
                    :created_at)
        """),
            {
                "scan_id": scan_id,
                "total_rules": scan_results.get("rules_total", 0),
                "passed_rules": scan_results.get("rules_passed", 0),
                "failed_rules": scan_results.get("rules_failed", 0),
                "error_rules": scan_results.get("rules_error", 0),
                "unknown_rules": scan_results.get("rules_unknown", 0),
                "not_applicable_rules": scan_results.get("rules_notapplicable", 0),
                "score": f"{scan_results.get('score', 0):.1f}%",
                # Total failed rule counts by severity
                "severity_critical": severity_critical,
                "severity_high": severity_high,
                "severity_medium": severity_medium,
                "severity_low": severity_low,
                # Per-severity pass/fail breakdown for accurate compliance visualization
                "severity_critical_passed": severity_critical_passed,
                "severity_critical_failed": severity_critical_failed,
                "severity_high_passed": severity_high_passed,
                "severity_high_failed": severity_high_failed,
                "severity_medium_passed": severity_medium_passed,
                "severity_medium_failed": severity_medium_failed,
                "severity_low_passed": severity_low_passed,
                "severity_low_failed": severity_low_failed,
                "created_at": datetime.utcnow(),
            },
        )
        db.commit()

        logger.info(f"Scan results saved for {scan_id}")

    except Exception as e:
        logger.error(f"Failed to save scan results for {scan_id}: {e}")


# Celery task wrapper (if Celery is available)
try:
    from celery import current_app

    @current_app.task(bind=True)
    def execute_scan_celery_task(
        self: Any,
        scan_id: str,
        host_data: Dict[str, Any],
        content_path: str,
        profile_id: str,
        scan_options: Dict[str, Any],
    ) -> None:
        """Celery task wrapper for scan execution"""
        try:
            # Update task ID in database
            db = SessionLocal()
            db.execute(
                text("""
                UPDATE scans SET celery_task_id = :task_id WHERE id = :scan_id
            """),
                {"task_id": self.request.id, "scan_id": scan_id},
            )
            db.commit()
            db.close()

            # Execute scan
            execute_scan_task(scan_id, host_data, content_path, profile_id, scan_options)

        except Exception as e:
            logger.error(f"Celery task failed for scan {scan_id}: {e}")
            # Update scan with failure
            db = SessionLocal()
            _update_scan_error(db, scan_id, f"Task execution failed: {str(e)}")
            db.close()
            raise

except ImportError:
    logger.info("Celery not available, using background tasks only")


async def _process_semantic_intelligence(
    db: Session, scan_id: str, scan_results: Dict[str, Any], host_data: Dict[str, Any]
) -> None:
    """Process scan results with semantic intelligence"""

    try:
        logger.info(f"Starting semantic intelligence processing for scan: {scan_id}")

        # Get semantic engine from engine integration module
        # SemanticEngine provides intelligent compliance analysis
        semantic_engine = get_semantic_engine()

        # Build host information for semantic processing
        host_info = {
            "host_id": host_data.get("host_id"),
            "hostname": host_data.get("hostname"),
            "distribution_name": host_data.get("distribution_name"),
            "distribution_version": host_data.get("distribution_version"),
            "os_version": host_data.get("os_version", ""),
            "package_manager": host_data.get("package_manager"),
            "service_manager": host_data.get("service_manager"),
        }

        # Process scan with semantic intelligence
        intelligent_result = await semantic_engine.process_scan_with_intelligence(
            scan_results=scan_results, scan_id=scan_id, host_info=host_info
        )

        # Update scan record with semantic analysis information
        frameworks_analyzed = list(intelligent_result.framework_compliance_matrix.keys())
        semantic_rules_count = len(intelligent_result.semantic_rules)

        db.execute(
            text("""
            UPDATE scans SET
                semantic_analysis_completed = true,
                semantic_rules_count = :semantic_rules_count,
                frameworks_analyzed = :frameworks_analyzed,
                remediation_strategy = :remediation_strategy
            WHERE id = :scan_id
        """),
            {
                "scan_id": scan_id,
                "semantic_rules_count": semantic_rules_count,
                "frameworks_analyzed": frameworks_analyzed,
                "remediation_strategy": json.dumps(intelligent_result.remediation_strategy),
            },
        )
        db.commit()

        # Send enhanced webhook with semantic intelligence
        await _send_enhanced_semantic_webhook(scan_id, intelligent_result, host_data)

        logger.info(
            f"Semantic intelligence processing completed for scan {scan_id}: "
            f"{semantic_rules_count} semantic rules, "
            f"{len(frameworks_analyzed)} frameworks analyzed"
        )

    except Exception as e:
        logger.error(f"Error in semantic intelligence processing: {e}", exc_info=True)
        # Don't re-raise - we want to continue with normal scan processing


async def _send_enhanced_semantic_webhook(scan_id: str, intelligent_result: Any, host_data: Dict[str, Any]) -> None:
    """Send enhanced webhook with semantic intelligence data"""

    try:
        from .webhook_tasks import deliver_webhook

        # Get active webhook endpoints for semantic events
        db = SessionLocal()
        try:
            result = db.execute(text("""
                SELECT id, url, secret_hash FROM webhook_endpoints
                WHERE is_active = true
                AND (
                    event_types::jsonb ? 'semantic.analysis.completed'
                    OR event_types::jsonb ? 'scan.completed'
                )
            """))

            webhooks = result.fetchall()
        finally:
            db.close()

        if not webhooks:
            logger.debug("No active webhooks configured for semantic events")
            return

        # Create enhanced webhook payload with semantic intelligence
        webhook_data = {
            "event": "semantic.analysis.completed",
            "timestamp": datetime.utcnow().isoformat(),
            "data": {
                "scan_id": scan_id,
                "host_info": {
                    "host_id": host_data.get("host_id"),
                    "hostname": host_data.get("hostname"),
                    "distribution_family": host_data.get("distribution_family", "unknown"),
                    "distribution_name": host_data.get("distribution_name", "unknown"),
                    "distribution_version": host_data.get("distribution_version", "unknown"),
                    "package_manager": host_data.get("package_manager", "unknown"),
                    "service_manager": host_data.get("service_manager", "unknown"),
                },
                "semantic_analysis": {
                    "semantic_rules_count": len(intelligent_result.semantic_rules),
                    "frameworks_analyzed": list(intelligent_result.framework_compliance_matrix.keys()),
                    "framework_compliance_matrix": intelligent_result.framework_compliance_matrix,
                    "remediation_strategy": intelligent_result.remediation_strategy,
                    "semantic_rules": [
                        {
                            "name": rule.name,
                            "scap_rule_id": rule.scap_rule_id,
                            "title": rule.title,
                            "compliance_intent": rule.compliance_intent,
                            "business_impact": rule.business_impact,
                            "risk_level": rule.risk_level,
                            "frameworks": rule.frameworks,
                            "remediation_complexity": rule.remediation_complexity,
                            "estimated_fix_time": rule.estimated_fix_time,
                            "remediation_available": rule.remediation_available,
                        }
                        for rule in intelligent_result.semantic_rules[:10]  # Limit to avoid large payloads
                    ],
                },
                "original_scan_results": {
                    "total_rules": intelligent_result.original_results.get("rules_total", 0),
                    "passed_rules": intelligent_result.original_results.get("rules_passed", 0),
                    "failed_rules": intelligent_result.original_results.get("rules_failed", 0),
                    "score": intelligent_result.original_results.get("score", 0),
                },
            },
        }

        # Send to all configured endpoints
        for webhook in webhooks:
            try:
                await deliver_webhook(webhook.url, webhook.secret_hash, webhook_data, str(webhook.id))
            except Exception as e:
                logger.error(f"Failed to deliver semantic webhook to {webhook.url}: {e}")

    except Exception as e:
        logger.error(f"Error sending enhanced semantic webhook: {e}")


def _extract_host_distribution_info(host_data: Dict[str, Any]) -> Dict[str, str]:
    """Extract and normalize host distribution information"""

    # Try to extract distribution info from various sources
    os_version = host_data.get("os_version", "").lower()

    # Default values
    distribution_info = {
        "distribution_family": "unknown",
        "distribution_name": "unknown",
        "distribution_version": "unknown",
        "package_manager": "unknown",
        "service_manager": "systemd",  # Most modern systems use systemd
    }

    # Detect from OS version string
    if "rhel" in os_version or "red hat" in os_version:
        distribution_info["distribution_family"] = "redhat"
        distribution_info["distribution_name"] = "rhel"
        distribution_info["package_manager"] = "dnf"

        # Extract version
        version_match = re.search(r"(\d+)", os_version)
        if version_match:
            distribution_info["distribution_version"] = version_match.group(1)

    elif "ubuntu" in os_version:
        distribution_info["distribution_family"] = "debian"
        distribution_info["distribution_name"] = "ubuntu"
        distribution_info["package_manager"] = "apt"

        # Extract version
        version_match = re.search(r"(\d+\.\d+)", os_version)
        if version_match:
            distribution_info["distribution_version"] = version_match.group(1)

    elif "centos" in os_version:
        distribution_info["distribution_family"] = "redhat"
        distribution_info["distribution_name"] = "centos"
        distribution_info["package_manager"] = "yum"

    elif "oracle" in os_version:
        distribution_info["distribution_family"] = "redhat"
        distribution_info["distribution_name"] = "oracle"
        distribution_info["package_manager"] = "dnf"

    # Update host_data with distribution info (non-destructive)
    for key, value in distribution_info.items():
        if key not in host_data or not host_data[key]:
            host_data[key] = value

    return distribution_info
