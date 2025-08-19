"""
Celery tasks for SCAP scanning operations
"""
import os
import json
import logging
import asyncio
import re
from typing import Dict, Any
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.orm import Session

from ..database import SessionLocal
from ..services.scap_scanner import SCAPScanner, ScanExecutionError
from ..services.semantic_scap_engine import get_semantic_scap_engine
from ..services.crypto import decrypt_credentials
from .webhook_tasks import send_scan_completed_webhook, send_scan_failed_webhook

logger = logging.getLogger(__name__)

# Initialize scanner
scap_scanner = SCAPScanner()


def execute_scan_task(scan_id: str, host_data: Dict, content_path: str, 
                     profile_id: str, scan_options: Dict):
    """
    Execute SCAP scan task
    This is designed to work with or without Celery
    """
    db = SessionLocal()
    
    try:
        logger.info(f"Starting scan task: {scan_id}")
        
        # Update scan status to running
        db.execute(text("""
            UPDATE scans SET status = 'running', progress = 5 
            WHERE id = :scan_id
        """), {"scan_id": scan_id})
        db.commit()
        
        # Decrypt credentials (handle both formats for compatibility)
        credentials = {}
        if host_data["hostname"] == "localhost":
            # No credentials needed for localhost
            credentials = {"type": "local"}
        elif host_data.get("auth_method") in ["default", "system_default"]:
            # Use default system credentials
            try:
                logger.info(f"Using default system credentials for scan {scan_id}")
                
                # Get default system credentials
                result = db.execute(text("""
                    SELECT username, auth_method, encrypted_password, 
                           encrypted_private_key, private_key_passphrase
                    FROM system_credentials 
                    WHERE is_default = true AND is_active = true
                    LIMIT 1
                """))
                
                row = result.fetchone()
                if not row:
                    logger.error(f"No default system credentials found for scan {scan_id}")
                    _update_scan_error(db, scan_id, "No default system credentials configured")
                    return
                
                # Decrypt system credentials
                from ..services.encryption import decrypt_data
                credentials = {
                    "username": row.username,
                    "auth_method": row.auth_method
                }
                
                if row.encrypted_password:
                    credentials["password"] = decrypt_data(row.encrypted_password).decode()
                if row.encrypted_private_key:
                    credentials["private_key"] = decrypt_data(row.encrypted_private_key).decode()
                if row.private_key_passphrase:
                    credentials["private_key_passphrase"] = decrypt_data(row.private_key_passphrase).decode()
                
                # Update host_data to use system credentials
                host_data["username"] = row.username
                host_data["auth_method"] = row.auth_method
                
            except Exception as e:
                logger.error(f"Failed to get default system credentials for scan {scan_id}: {e}")
                _update_scan_error(db, scan_id, "Failed to retrieve default system credentials")
                return
        elif host_data.get("encrypted_credentials"):
            try:
                import base64
                if isinstance(host_data["encrypted_credentials"], str):
                    # Try Base64 decode first (legacy format)
                    try:
                        decoded = base64.b64decode(host_data["encrypted_credentials"]).decode()
                        credentials = json.loads(decoded)
                    except:
                        # If Base64 fails, try AES decryption
                        credentials = json.loads(decrypt_credentials(host_data["encrypted_credentials"]))
                else:
                    # Raw binary data, use AES decryption
                    credentials = json.loads(decrypt_credentials(host_data["encrypted_credentials"]))
                    
            except Exception as e:
                logger.error(f"Failed to decrypt credentials for scan {scan_id}: {e}")
                _update_scan_error(db, scan_id, "Failed to decrypt host credentials")
                return
        else:
            logger.error(f"No credentials available for scan {scan_id}")
            _update_scan_error(db, scan_id, "No credentials available for remote host")
            return
        
        # Update progress
        db.execute(text("""
            UPDATE scans SET progress = 10 WHERE id = :scan_id
        """), {"scan_id": scan_id})
        db.commit()
        
        # Extract the appropriate credential based on auth method
        if host_data["auth_method"] == "password":
            credential_value = credentials.get("password", "")
        elif host_data["auth_method"] in ["ssh_key", "ssh-key"]:
            credential_value = credentials.get("private_key", "")
        else:
            credential_value = credentials.get("credential", "")
        
        # Check if demo mode is enabled
        demo_mode = os.getenv("OPENWATCH_DEMO_MODE", "true").lower() == "true"
        
        if demo_mode:
            logger.info(f"Demo mode enabled - simulating scan execution for {scan_id}")
            
            # Simulate scan progression
            import time
            for progress in [20, 40, 60, 80, 95]:
                db.execute(text("""
                    UPDATE scans SET progress = :progress WHERE id = :scan_id
                """), {"scan_id": scan_id, "progress": progress})
                db.commit()
                time.sleep(0.5)  # Simulate work
            
            # Create mock results
            result_data = {
                "scan_id": scan_id,
                "hostname": host_data["hostname"],
                "profile_id": profile_id,
                "status": "completed",
                "total_rules": 150,
                "passed": 120,
                "failed": 25,
                "error": 5,
                "score": 80.0,
                "scan_time": "2025-08-06T03:45:00",
                "findings": [
                    {"rule_id": "demo_rule_1", "severity": "high", "status": "fail", "description": "Sample security finding"},
                    {"rule_id": "demo_rule_2", "severity": "medium", "status": "pass", "description": "Security control passed"}
                ]
            }
            
            # Update scan as completed
            db.execute(text("""
                UPDATE scans SET 
                    status = 'completed',
                    progress = 100,
                    completed_at = :completed_at
                WHERE id = :scan_id
            """), {
                "scan_id": scan_id,
                "completed_at": datetime.utcnow()
            })
            db.commit()
            
            # Send webhook notification for demo completion
            try:
                webhook_data = {
                    "hostname": host_data["hostname"],
                    "profile_id": profile_id,
                    "status": "completed",
                    "total_rules": 150,
                    "passed_rules": 120,
                    "failed_rules": 25,
                    "score": 80.0,
                    "completed_at": datetime.utcnow().isoformat()
                }
                
                asyncio.create_task(
                    send_scan_completed_webhook(scan_id, webhook_data)
                )
                logger.debug(f"Webhook notification queued for demo scan: {scan_id}")
            except Exception as webhook_error:
                logger.error(f"Failed to send demo completion webhook for scan {scan_id}: {webhook_error}")
            
            logger.info(f"Demo scan completed successfully: {scan_id}")
            return
        
        # Production mode - Test SSH connection first
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
                credential=credential_value
            )
            
            if not ssh_test["success"]:
                logger.error(f"SSH connection failed for scan {scan_id}: {ssh_test['message']}")
                _update_scan_error(db, scan_id, f"SSH connection failed: {ssh_test['message']}")
                return
            
            if not ssh_test.get("oscap_available", False):
                logger.warning(f"OpenSCAP not available on remote host for scan {scan_id}")
                _update_scan_error(db, scan_id, "OpenSCAP not available on remote host")
                return
        
        # Update progress
        db.execute(text("""
            UPDATE scans SET progress = 20 WHERE id = :scan_id
        """), {"scan_id": scan_id})
        db.commit()
        
        # Execute scan
        logger.info(f"Executing SCAP scan: {scan_id}")
        
        try:
            # Update progress to indicate scan execution has started
            db.execute(text("""
                UPDATE scans SET progress = 30 WHERE id = :scan_id
            """), {"scan_id": scan_id})
            db.commit()
            
            # Extract rule_id from scan_options for rule-specific rescans
            rule_id = scan_options.get("rule_id") if scan_options else None
            
            if host_data["hostname"] == "localhost":
                # Local scan
                scan_results = scap_scanner.execute_local_scan(
                    content_path=content_path,
                    profile_id=profile_id,
                    scan_id=scan_id,
                    rule_id=rule_id
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
                    rule_id=rule_id
                )
            
            # Update progress after scan execution
            db.execute(text("""
                UPDATE scans SET progress = 90 WHERE id = :scan_id
            """), {"scan_id": scan_id})
            db.commit()
            
            # Check for scan errors
            if "error" in scan_results:
                logger.error(f"Scan execution failed for {scan_id}: {scan_results['error']}")
                _update_scan_error(db, scan_id, scan_results["error"])
                return
        except Exception as e:
            logger.error(f"Scan execution failed for {scan_id}: {str(e)}", exc_info=True)
            _update_scan_error(db, scan_id, f"Scan execution error: {str(e)}")
            return
        
        # Update scan record with results
        db.execute(text("""
            UPDATE scans 
            SET status = 'completed', progress = 100, completed_at = :completed_at,
                result_file = :result_file, report_file = :report_file
            WHERE id = :scan_id
        """), {
            "scan_id": scan_id,
            "completed_at": datetime.utcnow(),
            "result_file": scan_results.get("xml_result"),
            "report_file": scan_results.get("html_report")
        })
        db.commit()
        
        # Save scan results summary
        _save_scan_results(db, scan_id, scan_results)
        
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
                "completed_at": datetime.utcnow().isoformat()
            }
            
            # Send webhook asynchronously
            asyncio.create_task(
                send_scan_completed_webhook(scan_id, webhook_data)
            )
            logger.debug(f"Webhook notification queued for completed scan: {scan_id}")
        except Exception as webhook_error:
            logger.error(f"Failed to send completion webhook for scan {scan_id}: {webhook_error}")
        
        logger.info(f"Scan completed successfully: {scan_id}")
        
    except ScanExecutionError as e:
        logger.error(f"Scan execution error for {scan_id}: {e}")
        _update_scan_error(db, scan_id, str(e))
    except Exception as e:
        logger.error(f"Unexpected error in scan task {scan_id}: {e}")
        _update_scan_error(db, scan_id, f"Unexpected error: {str(e)}")
    finally:
        db.close()


def _update_scan_error(db: Session, scan_id: str, error_message: str):
    """Update scan with error status and set progress to 100% to indicate completion"""
    try:
        # Get scan data for webhook notification
        scan_result = db.execute(text("""
            SELECT s.id, h.hostname, s.profile_id
            FROM scans s
            JOIN hosts h ON s.host_id = h.id
            WHERE s.id = :scan_id
        """), {"scan_id": scan_id})
        
        scan_data = scan_result.fetchone()
        
        db.execute(text("""
            UPDATE scans 
            SET status = 'failed', progress = 100, completed_at = :completed_at, error_message = :error_message
            WHERE id = :scan_id
        """), {
            "scan_id": scan_id,
            "completed_at": datetime.utcnow(),
            "error_message": error_message
        })
        db.commit()
        
        # Send webhook notification for scan failure
        if scan_data:
            try:
                webhook_data = {
                    "hostname": scan_data.hostname,
                    "profile_id": scan_data.profile_id,
                    "status": "failed",
                    "completed_at": datetime.utcnow().isoformat()
                }
                
                asyncio.create_task(
                    send_scan_failed_webhook(scan_id, webhook_data, error_message)
                )
                logger.debug(f"Webhook notification queued for failed scan: {scan_id}")
            except Exception as webhook_error:
                logger.error(f"Failed to send failure webhook for scan {scan_id}: {webhook_error}")
        
    except Exception as e:
        logger.error(f"Failed to update scan error status: {e}")


def _save_scan_results(db: Session, scan_id: str, scan_results: Dict):
    """Save scan results summary to database"""
    try:
        # Parse failed rules by severity
        failed_rules = scan_results.get("failed_rules", [])
        severity_high = len([r for r in failed_rules if r.get("severity") == "high"])
        severity_medium = len([r for r in failed_rules if r.get("severity") == "medium"])
        severity_low = len([r for r in failed_rules if r.get("severity") == "low"])
        
        # Insert scan results
        db.execute(text("""
            INSERT INTO scan_results 
            (scan_id, total_rules, passed_rules, failed_rules, error_rules,
             unknown_rules, not_applicable_rules, score, severity_high, 
             severity_medium, severity_low, created_at)
            VALUES (:scan_id, :total_rules, :passed_rules, :failed_rules, :error_rules,
                    :unknown_rules, :not_applicable_rules, :score, :severity_high,
                    :severity_medium, :severity_low, :created_at)
        """), {
            "scan_id": scan_id,
            "total_rules": scan_results.get("rules_total", 0),
            "passed_rules": scan_results.get("rules_passed", 0),
            "failed_rules": scan_results.get("rules_failed", 0),
            "error_rules": scan_results.get("rules_error", 0),
            "unknown_rules": scan_results.get("rules_unknown", 0),
            "not_applicable_rules": scan_results.get("rules_notapplicable", 0),
            "score": f"{scan_results.get('score', 0):.1f}%",
            "severity_high": severity_high,
            "severity_medium": severity_medium,
            "severity_low": severity_low,
            "created_at": datetime.utcnow()
        })
        db.commit()
        
        logger.info(f"Scan results saved for {scan_id}")
        
    except Exception as e:
        logger.error(f"Failed to save scan results for {scan_id}: {e}")


# Celery task wrapper (if Celery is available)
try:
    from celery import current_app
    
    @current_app.task(bind=True)
    def execute_scan_celery_task(self, scan_id: str, host_data: Dict, content_path: str, 
                                profile_id: str, scan_options: Dict):
        """Celery task wrapper for scan execution"""
        try:
            # Update task ID in database
            db = SessionLocal()
            db.execute(text("""
                UPDATE scans SET celery_task_id = :task_id WHERE id = :scan_id
            """), {"task_id": self.request.id, "scan_id": scan_id})
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
    db: Session,
    scan_id: str, 
    scan_results: Dict[str, Any],
    host_data: Dict[str, Any]
):
    """Process scan results with semantic intelligence"""
    
    try:
        logger.info(f"Starting semantic intelligence processing for scan: {scan_id}")
        
        # Get semantic SCAP engine
        semantic_engine = get_semantic_scap_engine()
        
        # Build host information for semantic processing
        host_info = {
            "host_id": host_data.get("host_id"),
            "hostname": host_data.get("hostname"),
            "distribution_name": host_data.get("distribution_name"),
            "distribution_version": host_data.get("distribution_version"),
            "os_version": host_data.get("os_version", ""),
            "package_manager": host_data.get("package_manager"),
            "service_manager": host_data.get("service_manager")
        }
        
        # Process scan with semantic intelligence
        intelligent_result = await semantic_engine.process_scan_with_intelligence(
            scan_results=scan_results,
            scan_id=scan_id,
            host_info=host_info
        )
        
        # Update scan record with semantic analysis information
        frameworks_analyzed = list(intelligent_result.framework_compliance_matrix.keys())
        semantic_rules_count = len(intelligent_result.semantic_rules)
        
        db.execute(text("""
            UPDATE scans SET
                semantic_analysis_completed = true,
                semantic_rules_count = :semantic_rules_count,
                frameworks_analyzed = :frameworks_analyzed,
                remediation_strategy = :remediation_strategy
            WHERE id = :scan_id
        """), {
            "scan_id": scan_id,
            "semantic_rules_count": semantic_rules_count,
            "frameworks_analyzed": frameworks_analyzed,
            "remediation_strategy": json.dumps(intelligent_result.remediation_strategy)
        })
        db.commit()
        
        # Send enhanced webhook with semantic intelligence
        await _send_enhanced_semantic_webhook(scan_id, intelligent_result, host_data)
        
        logger.info(f"Semantic intelligence processing completed for scan {scan_id}: "
                   f"{semantic_rules_count} semantic rules, "
                   f"{len(frameworks_analyzed)} frameworks analyzed")
        
    except Exception as e:
        logger.error(f"Error in semantic intelligence processing: {e}", exc_info=True)
        # Don't re-raise - we want to continue with normal scan processing


async def _send_enhanced_semantic_webhook(
    scan_id: str,
    intelligent_result: 'IntelligentScanResult', 
    host_data: Dict[str, Any]
):
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
                    "service_manager": host_data.get("service_manager", "unknown")
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
                            "remediation_available": rule.remediation_available
                        }
                        for rule in intelligent_result.semantic_rules[:10]  # Limit to avoid large payloads
                    ]
                },
                "original_scan_results": {
                    "total_rules": intelligent_result.original_results.get("rules_total", 0),
                    "passed_rules": intelligent_result.original_results.get("rules_passed", 0),
                    "failed_rules": intelligent_result.original_results.get("rules_failed", 0),
                    "score": intelligent_result.original_results.get("score", 0)
                }
            }
        }
        
        # Send to all configured endpoints
        for webhook in webhooks:
            try:
                await deliver_webhook(
                    webhook.url,
                    webhook.secret_hash,
                    webhook_data,
                    str(webhook.id)
                )
            except Exception as e:
                logger.error(f"Failed to deliver semantic webhook to {webhook.url}: {e}")
                
    except Exception as e:
        logger.error(f"Error sending enhanced semantic webhook: {e}")


def _extract_host_distribution_info(host_data: Dict[str, Any]) -> Dict[str, str]:
    """Extract and normalize host distribution information"""
    
    # Try to extract distribution info from various sources
    hostname = host_data.get("hostname", "")
    os_version = host_data.get("os_version", "").lower()
    
    # Default values
    distribution_info = {
        "distribution_family": "unknown",
        "distribution_name": "unknown", 
        "distribution_version": "unknown",
        "package_manager": "unknown",
        "service_manager": "systemd"  # Most modern systems use systemd
    }
    
    # Detect from OS version string
    if "rhel" in os_version or "red hat" in os_version:
        distribution_info["distribution_family"] = "redhat"
        distribution_info["distribution_name"] = "rhel"
        distribution_info["package_manager"] = "dnf"
        
        # Extract version
        version_match = re.search(r'(\d+)', os_version)
        if version_match:
            distribution_info["distribution_version"] = version_match.group(1)
    
    elif "ubuntu" in os_version:
        distribution_info["distribution_family"] = "debian"
        distribution_info["distribution_name"] = "ubuntu"
        distribution_info["package_manager"] = "apt"
        
        # Extract version
        version_match = re.search(r'(\d+\.\d+)', os_version)
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
    pass