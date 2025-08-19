"""
SCAP Scanning API Routes
Handles scan job creation, monitoring, and results
"""
import uuid
import json
from typing import List, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import text
from pydantic import BaseModel

from ..database import get_db
from ..services.scap_scanner import SCAPScanner
from ..auth import get_current_user
from ..tasks.scan_tasks import execute_scan_task
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["Scans"])

# Initialize SCAP scanner
scap_scanner = SCAPScanner()


class ScanRequest(BaseModel):
    name: str
    host_id: str  # Changed to str to handle UUID
    content_id: int
    profile_id: str
    scan_options: Optional[dict] = {}


class ScanUpdate(BaseModel):
    status: Optional[str] = None
    progress: Optional[int] = None
    error_message: Optional[str] = None


class RuleRescanRequest(BaseModel):
    rule_id: str
    name: Optional[str] = None


class VerificationScanRequest(BaseModel):
    host_id: str
    content_id: int
    profile_id: str
    original_scan_id: Optional[str] = None
    remediation_job_id: Optional[str] = None
    name: Optional[str] = None


@router.get("/")
async def list_scans(
    host_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """List scans with optional filtering"""
    try:
        # Quick fix: Check if there are any scans at all
        scan_count_result = db.execute(text("SELECT COUNT(*) as count FROM scans")).fetchone()
        if scan_count_result.count == 0:
            return {
                "scans": [],
                "total": 0,
                "limit": limit,
                "offset": offset
            }
        
        # Build query
        where_conditions = []
        params = {"limit": limit, "offset": offset}
        
        if host_id:
            where_conditions.append("s.host_id = %(host_id)s")
            params["host_id"] = host_id
        
        if status:
            where_conditions.append("s.status = %(status)s")
            params["status"] = status
        
        where_clause = "WHERE " + " AND ".join(where_conditions) if where_conditions else ""
        
        query = """
            SELECT s.id, s.name, s.host_id, s.content_id, s.profile_id, s.status,
                   s.progress, s.started_at, s.completed_at, s.started_by,
                   s.error_message, s.result_file, s.report_file,
                   h.display_name as host_name, h.hostname, h.ip_address, h.operating_system,
                   h.status as host_status, h.last_check,
                   c.name as content_name, c.filename as content_filename,
                   sr.total_rules, sr.passed_rules, sr.failed_rules, sr.error_rules,
                   sr.score, sr.severity_high, sr.severity_medium, sr.severity_low
            FROM scans s
            LEFT JOIN hosts h ON s.host_id = h.id
            LEFT JOIN scap_content c ON s.content_id = c.id
            LEFT JOIN scan_results sr ON sr.scan_id = s.id
            {}
            ORDER BY s.started_at DESC
            LIMIT :limit OFFSET :offset
        """.format(where_clause)
        
        result = db.execute(text(query), params)
        
        scans = []
        for row in result:
            scan_data = {
                "id": row.id,
                "name": row.name,
                "host_id": row.host_id,
                "host": {
                    "id": row.host_id,
                    "name": row.host_name,
                    "hostname": row.hostname,
                    "ip_address": row.ip_address,
                    "operating_system": row.operating_system,
                    "status": row.host_status,
                    "last_check": row.last_check.isoformat() if row.last_check else None
                },
                "content_id": row.content_id,
                "content_name": row.content_name,
                "content_filename": row.content_filename,
                "profile_id": row.profile_id,
                "status": row.status,
                "progress": row.progress,
                "started_at": row.started_at.isoformat() if row.started_at else None,
                "completed_at": row.completed_at.isoformat() if row.completed_at else None,
                "started_by": row.started_by,
                "error_message": row.error_message,
                "result_file": row.result_file,
                "report_file": row.report_file
            }
            
            # Add results if available
            if row.total_rules is not None:
                scan_data["scan_result"] = {
                    "id": f"result_{row.id}",
                    "scan_id": row.id,
                    "total_rules": row.total_rules,
                    "passed_rules": row.passed_rules,
                    "failed_rules": row.failed_rules,
                    "error_rules": row.error_rules,
                    "score": row.score,
                    "severity_high": row.severity_high,
                    "severity_medium": row.severity_medium,
                    "severity_low": row.severity_low,
                    "created_at": row.completed_at.isoformat() if row.completed_at else None
                }
            
            scans.append(scan_data)
        
        # Get total count
        count_query = """
            SELECT COUNT(*) as total
            FROM scans s
            LEFT JOIN hosts h ON s.host_id = h.id
            LEFT JOIN scap_content c ON s.content_id = c.id
            {}
        """.format(where_clause)
        total_result = db.execute(text(count_query), params).fetchone()
        
        return {
            "scans": scans,
            "total": total_result.total,
            "limit": limit,
            "offset": offset
        }
        
    except Exception as e:
        logger.error(f"Error listing scans: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve scans")


@router.post("/")
async def create_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Create and start a new SCAP scan"""
    try:
        # Validate host exists
        host_result = db.execute(text("""
            SELECT id, display_name, hostname, port, username, auth_method, encrypted_credentials
            FROM hosts WHERE id = :id AND is_active = true
        """), {"id": scan_request.host_id}).fetchone()
        
        if not host_result:
            raise HTTPException(status_code=404, detail="Host not found or inactive")
        
        # Validate SCAP content exists
        content_result = db.execute(text("""
            SELECT id, name, file_path, profiles FROM scap_content WHERE id = :id
        """), {"id": scan_request.content_id}).fetchone()
        
        if not content_result:
            raise HTTPException(status_code=404, detail="SCAP content not found")
        
        # Validate profile exists in content
        profiles = []
        if content_result.profiles:
            try:
                import json
                profiles = json.loads(content_result.profiles)
                profile_ids = [p.get("id") for p in profiles if p.get("id")]
                if scan_request.profile_id not in profile_ids:
                    raise HTTPException(status_code=400, detail="Profile not found in SCAP content")
            except:
                raise HTTPException(status_code=400, detail="Invalid SCAP content profiles")
        
        # Create scan record (let database auto-generate integer ID)
        import json
        result = db.execute(text("""
            INSERT INTO scans 
            (name, host_id, content_id, profile_id, status, progress, 
             scan_options, started_by, started_at)
            VALUES (:name, :host_id, :content_id, :profile_id, :status, 
                    :progress, :scan_options, :started_by, :started_at)
            RETURNING id
        """), {
            "name": scan_request.name,
            "host_id": scan_request.host_id,
            "content_id": scan_request.content_id,
            "profile_id": scan_request.profile_id,
            "status": "pending",
            "progress": 0,
            "scan_options": json.dumps(scan_request.scan_options),
            "started_by": current_user["id"],
            "started_at": datetime.utcnow()
        })
        
        # Get the generated scan ID
        scan_id = result.fetchone().id
        db.commit()
        
        # Start scan as background task
        background_tasks.add_task(
            execute_scan_task,
            scan_id=str(scan_id),
            host_data={
                "hostname": host_result.hostname,
                "port": host_result.port,
                "username": host_result.username,
                "auth_method": host_result.auth_method,
                "encrypted_credentials": host_result.encrypted_credentials
            },
            content_path=content_result.file_path,
            profile_id=scan_request.profile_id,
            scan_options=scan_request.scan_options
        )
        
        logger.info(f"Scan created and started: {scan_id}")
        
        return {
            "id": scan_id,
            "message": "Scan created and started successfully",
            "status": "pending"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating scan: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to create scan: {str(e)}")


@router.get("/{scan_id}")
async def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get scan details"""
    try:
        result = db.execute(text("""
            SELECT s.id, s.name, s.host_id, s.content_id, s.profile_id, s.status,
                   s.progress, s.result_file, s.report_file, s.error_message,
                   s.scan_options, s.started_at, s.completed_at, s.started_by,
                   s.celery_task_id,
                   h.display_name as host_name, h.hostname,
                   c.name as content_name, c.filename as content_filename
            FROM scans s
            JOIN hosts h ON s.host_id = h.id
            JOIN scap_content c ON s.content_id = c.id
            WHERE s.id = :id
        """), {"id": scan_id}).fetchone()
        
        if not result:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        scan_options = {}
        if result.scan_options:
            try:
                import json
                scan_options = json.loads(result.scan_options)
            except:
                pass
        
        scan_data = {
            "id": result.id,
            "name": result.name,
            "host_id": result.host_id,
            "host_name": result.host_name,
            "hostname": result.hostname,
            "content_id": result.content_id,
            "content_name": result.content_name,
            "content_filename": result.content_filename,
            "profile_id": result.profile_id,
            "status": result.status,
            "progress": result.progress,
            "result_file": result.result_file,
            "report_file": result.report_file,
            "error_message": result.error_message,
            "scan_options": scan_options,
            "started_at": result.started_at.isoformat() if result.started_at else None,
            "completed_at": result.completed_at.isoformat() if result.completed_at else None,
            "started_by": result.started_by,
            "celery_task_id": result.celery_task_id
        }
        
        # Add results summary if scan is completed
        if result.status == "completed":
            results = db.execute(text("""
                SELECT total_rules, passed_rules, failed_rules, error_rules,
                       unknown_rules, not_applicable_rules, score,
                       severity_high, severity_medium, severity_low
                FROM scan_results WHERE scan_id = :scan_id
            """), {"scan_id": scan_id}).fetchone()
            
            if results:
                scan_data["results"] = {
                    "total_rules": results.total_rules,
                    "passed_rules": results.passed_rules,
                    "failed_rules": results.failed_rules,
                    "error_rules": results.error_rules,
                    "unknown_rules": results.unknown_rules,
                    "not_applicable_rules": results.not_applicable_rules,
                    "score": results.score,
                    "severity_high": results.severity_high,
                    "severity_medium": results.severity_medium,
                    "severity_low": results.severity_low
                }
        
        return scan_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve scan")


@router.patch("/{scan_id}")
async def update_scan(
    scan_id: str,
    scan_update: ScanUpdate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Update scan status (internal use)"""
    try:
        # Check if scan exists
        existing = db.execute(text("""
            SELECT id FROM scans WHERE id = :id
        """), {"id": scan_id}).fetchone()
        
        if not existing:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Build update query
        updates = []
        params = {"id": scan_id}
        
        if scan_update.status is not None:
            updates.append("status = :status")
            params["status"] = scan_update.status
            
        if scan_update.progress is not None:
            updates.append("progress = :progress")
            params["progress"] = scan_update.progress
            
        if scan_update.error_message is not None:
            updates.append("error_message = :error_message")
            params["error_message"] = scan_update.error_message
        
        if scan_update.status == "completed":
            updates.append("completed_at = :completed_at")
            params["completed_at"] = datetime.utcnow()
        
        if updates:
            query = "UPDATE scans SET {} WHERE id = :id".format(', '.join(updates))
            db.execute(text(query), params)
            db.commit()
        
        return {"message": "Scan updated successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to update scan")


@router.delete("/{scan_id}")
async def delete_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Delete scan and its results"""
    try:
        # Check if scan exists and get status
        result = db.execute(text("""
            SELECT status, result_file, report_file FROM scans WHERE id = :id
        """), {"id": scan_id}).fetchone()
        
        if not result:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Don't allow deletion of running scans
        if result.status in ["pending", "running"]:
            raise HTTPException(
                status_code=409, 
                detail="Cannot delete running scan"
            )
        
        # Delete result files
        import os
        for file_path in [result.result_file, result.report_file]:
            if file_path and os.path.exists(file_path):
                try:
                    os.unlink(file_path)
                except Exception as e:
                    logger.warning(f"Failed to delete file {file_path}: {e}")
        
        # Delete scan results first (foreign key constraint)
        db.execute(text("""
            DELETE FROM scan_results WHERE scan_id = :scan_id
        """), {"scan_id": scan_id})
        
        # Delete scan record
        db.execute(text("""
            DELETE FROM scans WHERE id = :id
        """), {"id": scan_id})
        
        db.commit()
        
        logger.info(f"Scan deleted: {scan_id}")
        return {"message": "Scan deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete scan")


@router.post("/{scan_id}/stop")
async def stop_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Stop a running scan"""
    try:
        # Check if scan exists and is running
        result = db.execute(text("""
            SELECT status, celery_task_id FROM scans WHERE id = :id
        """), {"id": scan_id}).fetchone()
        
        if not result:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        if result.status not in ["pending", "running"]:
            raise HTTPException(
                status_code=400, 
                detail=f"Cannot stop scan with status: {result.status}"
            )
        
        # Try to revoke Celery task if available
        if result.celery_task_id:
            try:
                from celery import current_app
                current_app.control.revoke(result.celery_task_id, terminate=True)
            except Exception as e:
                logger.warning(f"Failed to revoke Celery task: {e}")
        
        # Update scan status
        db.execute(text("""
            UPDATE scans 
            SET status = 'stopped', completed_at = :completed_at,
                error_message = 'Scan stopped by user'
            WHERE id = :id
        """), {
            "id": scan_id,
            "completed_at": datetime.utcnow()
        })
        db.commit()
        
        logger.info(f"Scan stopped: {scan_id}")
        return {"message": "Scan stopped successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error stopping scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to stop scan")


@router.get("/{scan_id}/report/html")
async def get_scan_html_report(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Download scan HTML report"""
    try:
        # Get scan details
        result = db.execute(text("""
            SELECT report_file FROM scans WHERE id = :id
        """), {"id": scan_id}).fetchone()
        
        if not result or not result.report_file:
            raise HTTPException(status_code=404, detail="Report not found")
        
        # Check if file exists
        import os
        if not os.path.exists(result.report_file):
            raise HTTPException(status_code=404, detail="Report file not found")
        
        # Return file
        from fastapi.responses import FileResponse
        return FileResponse(
            result.report_file,
            media_type="text/html",
            filename=f"scan_{scan_id}_report.html"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting HTML report: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve report")


@router.get("/{scan_id}/report/json")
async def get_scan_json_report(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Export scan results as JSON"""
    try:
        # Get full scan details with results
        scan_data = await get_scan(scan_id, db, current_user)
        
        # Add enhanced rule results with remediation if available
        if scan_data.get("status") == "completed" and scan_data.get("result_file"):
            try:
                # Get the SCAP content file path for remediation extraction
                content_file = None
                content_result = db.execute(text("""
                    SELECT file_path FROM scap_content WHERE id = :content_id
                """), {"content_id": scan_data.get("content_id")}).fetchone()
                
                if content_result:
                    content_file = content_result.file_path
                
                # Temporarily disable enhanced parsing for performance (was taking 40+ seconds)
                # TODO: Implement caching or optimize the parsing logic
                enhanced_parsing_enabled = False
                
                if enhanced_parsing_enabled:
                    # Use enhanced SCAP scanner parsing
                    from ..services.scap_scanner import SCAPScanner
                    scanner = SCAPScanner()
                    enhanced_results = scanner._parse_scan_results(scan_data["result_file"], content_file)
                else:
                    enhanced_results = {}
                
                # Add enhanced rule details with remediation
                if "rule_details" in enhanced_results and enhanced_results["rule_details"]:
                    scan_data['rule_results'] = enhanced_results["rule_details"]
                    logger.info(f"Added {len(enhanced_results['rule_details'])} enhanced rules with remediation")
                else:
                    # Fallback to basic parsing for backward compatibility
                    import xml.etree.ElementTree as ET
                    import os
                    
                    if os.path.exists(scan_data["result_file"]):
                        tree = ET.parse(scan_data["result_file"])
                        root = tree.getroot()
                        
                        # Extract basic rule results
                        namespaces = {'xccdf': 'http://checklists.nist.gov/xccdf/1.2'}
                        rule_results = []
                        
                        for rule_result in root.findall('.//xccdf:rule-result', namespaces):
                            rule_id = rule_result.get('idref', '')
                            result_elem = rule_result.find('xccdf:result', namespaces)
                            
                            if result_elem is not None:
                                rule_results.append({
                                    'rule_id': rule_id,
                                    'result': result_elem.text,
                                    'severity': rule_result.get('severity', 'unknown'),
                                    'title': '',
                                    'description': '',
                                    'rationale': '',
                                    'remediation': {},
                                    'references': []
                                })
                        
                        scan_data['rule_results'] = rule_results
                        logger.info(f"Added {len(rule_results)} basic rules (fallback mode)")
                        
            except Exception as e:
                logger.error(f"Error extracting enhanced rule data: {e}")
                # Maintain backward compatibility - don't break if enhancement fails
                scan_data['rule_results'] = []
        
        return scan_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting JSON report: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate JSON report")


@router.get("/{scan_id}/report/csv") 
async def get_scan_csv_report(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Export scan results as CSV"""
    try:
        # Get scan data
        scan_data = await get_scan_json_report(scan_id, db, current_user)
        
        # Create CSV content
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write headers
        writer.writerow(['Scan Information'])
        writer.writerow(['ID', scan_data.get('id')])
        writer.writerow(['Name', scan_data.get('name')])
        writer.writerow(['Host', scan_data.get('host_name')])
        writer.writerow(['Status', scan_data.get('status')])
        writer.writerow(['Score', scan_data.get('results', {}).get('score', 'N/A')])
        writer.writerow([])
        
        # Write summary
        writer.writerow(['Summary Statistics'])
        writer.writerow(['Metric', 'Value'])
        if scan_data.get('results'):
            results = scan_data['results']
            writer.writerow(['Total Rules', results.get('total_rules')])
            writer.writerow(['Passed', results.get('passed_rules')])
            writer.writerow(['Failed', results.get('failed_rules')])
            writer.writerow(['Errors', results.get('error_rules')])
            writer.writerow(['High Severity', results.get('severity_high')])
            writer.writerow(['Medium Severity', results.get('severity_medium')])
            writer.writerow(['Low Severity', results.get('severity_low')])
        writer.writerow([])
        
        # Write rule results if available
        if 'rule_results' in scan_data:
            writer.writerow(['Rule Results'])
            writer.writerow(['Rule ID', 'Result', 'Severity'])
            for rule in scan_data['rule_results']:
                writer.writerow([
                    rule.get('rule_id'),
                    rule.get('result'),
                    rule.get('severity')
                ])
        
        # Return CSV
        from fastapi.responses import Response
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=scan_{scan_id}_report.csv"
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating CSV report: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate CSV report")


@router.get("/{scan_id}/failed-rules")
async def get_scan_failed_rules(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get failed rules from a completed scan for AEGIS integration"""
    try:
        # Verify scan exists and is completed
        scan_result = db.execute(text("""
            SELECT s.id, s.name, s.host_id, s.status, s.result_file, s.content_id, s.profile_id,
                   h.hostname, h.ip_address, h.display_name as host_name,
                   c.name as content_name, c.filename as content_filename,
                   sr.failed_rules, sr.total_rules, sr.score
            FROM scans s
            JOIN hosts h ON s.host_id = h.id
            JOIN scap_content c ON s.content_id = c.id
            LEFT JOIN scan_results sr ON sr.scan_id = s.id
            WHERE s.id = :scan_id
        """), {"scan_id": scan_id}).fetchone()
        
        if not scan_result:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        if scan_result.status != "completed":
            raise HTTPException(status_code=400, detail=f"Scan not completed (status: {scan_result.status})")
        
        if not scan_result.result_file or not scan_result.failed_rules or scan_result.failed_rules == 0:
            return {
                "scan_id": scan_id,
                "host_id": str(scan_result.host_id),
                "hostname": scan_result.hostname,
                "host_name": scan_result.host_name,
                "ip_address": scan_result.ip_address,
                "total_rules": scan_result.total_rules or 0,
                "failed_rules_count": 0,
                "compliance_score": scan_result.score,
                "failed_rules": []
            }
        
        # Parse the SCAP result file to extract failed rules
        import xml.etree.ElementTree as ET
        import os
        
        failed_rules = []
        if os.path.exists(scan_result.result_file):
            try:
                tree = ET.parse(scan_result.result_file)
                root = tree.getroot()
                
                # Extract failed rule results
                namespaces = {'xccdf': 'http://checklists.nist.gov/xccdf/1.2'}
                
                for rule_result in root.findall('.//xccdf:rule-result', namespaces):
                    result_elem = rule_result.find('xccdf:result', namespaces)
                    
                    if result_elem is not None and result_elem.text == 'fail':
                        rule_id = rule_result.get('idref', '')
                        severity = rule_result.get('severity', 'unknown')
                        
                        # Extract additional metadata if available
                        check_elem = rule_result.find('xccdf:check', namespaces)
                        check_content_ref = ""
                        if check_elem is not None:
                            content_ref = check_elem.find('xccdf:check-content-ref', namespaces)
                            if content_ref is not None:
                                check_content_ref = content_ref.get('href', '')
                        
                        failed_rule = {
                            'rule_id': rule_id,
                            'severity': severity,
                            'result': 'fail',
                            'check_content_ref': check_content_ref,
                            'remediation_available': True  # Assume remediation available for AEGIS
                        }
                        
                        failed_rules.append(failed_rule)
                        
            except Exception as e:
                logger.error(f"Error parsing scan results for failed rules: {e}")
                # Return basic info even if parsing fails
                pass
        
        response_data = {
            "scan_id": scan_id,
            "host_id": str(scan_result.host_id),
            "hostname": scan_result.hostname,
            "host_name": scan_result.host_name,
            "ip_address": scan_result.ip_address,
            "scan_name": scan_result.name,
            "content_name": scan_result.content_name,
            "profile_id": scan_result.profile_id,
            "total_rules": scan_result.total_rules or 0,
            "failed_rules_count": len(failed_rules),
            "compliance_score": scan_result.score,
            "failed_rules": failed_rules
        }
        
        logger.info(f"Retrieved {len(failed_rules)} failed rules for scan {scan_id}")
        return response_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting failed rules: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve failed rules")


@router.post("/verify")
async def create_verification_scan(
    verification_request: VerificationScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Create a verification scan after AEGIS remediation"""
    try:
        # Validate host exists and is active
        host_result = db.execute(text("""
            SELECT id, display_name, hostname, port, username, auth_method, encrypted_credentials
            FROM hosts WHERE id = :id AND is_active = true
        """), {"id": verification_request.host_id}).fetchone()
        
        if not host_result:
            raise HTTPException(status_code=404, detail="Host not found or inactive")
        
        # Validate SCAP content exists
        content_result = db.execute(text("""
            SELECT id, name, file_path, profiles FROM scap_content WHERE id = :id
        """), {"id": verification_request.content_id}).fetchone()
        
        if not content_result:
            raise HTTPException(status_code=404, detail="SCAP content not found")
        
        # Validate profile exists in content
        profiles = []
        if content_result.profiles:
            try:
                profiles = json.loads(content_result.profiles)
                profile_ids = [p.get("id") for p in profiles if p.get("id")]
                if verification_request.profile_id not in profile_ids:
                    raise HTTPException(status_code=400, detail="Profile not found in SCAP content")
            except:
                raise HTTPException(status_code=400, detail="Invalid SCAP content profiles")
        
        # Generate scan name
        scan_name = verification_request.name or f"Verification Scan - {host_result.hostname}"
        if verification_request.original_scan_id:
            scan_name += f" (Post-Remediation)"
        
        # Create verification scan record
        scan_options = {
            "verification_scan": True,
            "original_scan_id": verification_request.original_scan_id,
            "remediation_job_id": verification_request.remediation_job_id
        }
        
        result = db.execute(text("""
            INSERT INTO scans 
            (name, host_id, content_id, profile_id, status, progress, 
             scan_options, started_by, started_at, verification_scan)
            VALUES (:name, :host_id, :content_id, :profile_id, :status, 
                    :progress, :scan_options, :started_by, :started_at, :verification_scan)
            RETURNING id
        """), {
            "name": scan_name,
            "host_id": verification_request.host_id,
            "content_id": verification_request.content_id,
            "profile_id": verification_request.profile_id,
            "status": "pending",
            "progress": 0,
            "scan_options": json.dumps(scan_options),
            "started_by": current_user["id"],
            "started_at": datetime.utcnow(),
            "verification_scan": True
        })
        
        # Get the generated scan ID
        scan_id = result.fetchone().id
        db.commit()
        
        # Start verification scan as background task
        background_tasks.add_task(
            execute_scan_task,
            scan_id=str(scan_id),
            host_data={
                "hostname": host_result.hostname,
                "port": host_result.port,
                "username": host_result.username,
                "auth_method": host_result.auth_method,
                "encrypted_credentials": host_result.encrypted_credentials
            },
            content_path=content_result.file_path,
            profile_id=verification_request.profile_id,
            scan_options=scan_options
        )
        
        logger.info(f"Verification scan created and started: {scan_id}")
        
        response = {
            "id": scan_id,
            "message": "Verification scan created and started successfully",
            "status": "pending",
            "verification_scan": True,
            "host_id": verification_request.host_id,
            "host_name": host_result.display_name or host_result.hostname
        }
        
        # Add reference info if provided
        if verification_request.original_scan_id:
            response["original_scan_id"] = verification_request.original_scan_id
        if verification_request.remediation_job_id:
            response["remediation_job_id"] = verification_request.remediation_job_id
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating verification scan: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to create verification scan: {str(e)}")


@router.post("/{scan_id}/rescan/rule")
async def rescan_rule(
    scan_id: str,
    rescan_request: RuleRescanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Rescan a specific rule from a completed scan"""
    try:
        logger.info(f"Rule rescan requested for scan {scan_id}, rule {rescan_request.rule_id}")
        
        # Get the original scan details
        result = db.execute(text("""
            SELECT s.id, s.host_id, s.content_id, s.profile_id, s.name,
                   h.hostname, h.ip_address, h.port, h.username, h.auth_method, h.encrypted_credentials,
                   c.file_path, c.filename
            FROM scans s
            JOIN hosts h ON s.host_id = h.id
            JOIN scap_content c ON s.content_id = c.id
            WHERE s.id = :scan_id
        """), {"scan_id": scan_id})
        
        scan_data = result.fetchone()
        if not scan_data:
            raise HTTPException(status_code=404, detail="Original scan not found")
        
        # Validate that the host is still active
        if not scan_data.encrypted_credentials:
            raise HTTPException(status_code=400, detail="Host credentials not available")
        
        # Validate that the SCAP content file exists
        if not scan_data.file_path:
            raise HTTPException(status_code=400, detail="SCAP content file not found")
        
        # Create a new scan record for the rule rescan
        scan_name = rescan_request.name or f"Rule Rescan: {rescan_request.rule_id}"
        
        result = db.execute(text("""
            INSERT INTO scans (name, host_id, content_id, profile_id, status, progress, 
                             started_by, started_at, scan_options)
            VALUES (:name, :host_id, :content_id, :profile_id, :status, :progress,
                    :started_by, :started_at, :scan_options)
            RETURNING id
        """), {
            "name": scan_name,
            "host_id": scan_data.host_id,
            "content_id": scan_data.content_id,
            "profile_id": scan_data.profile_id,
            "status": "pending",
            "progress": 0,
            "started_by": current_user["id"],
            "started_at": datetime.utcnow(),
            "scan_options": json.dumps({"rule_id": rescan_request.rule_id, "rescan_type": "rule"})
        })
        
        new_scan_id = result.fetchone()[0]
        
        db.commit()
        
        # Prepare host data for scan execution
        host_data = {
            "id": scan_data.host_id,
            "hostname": scan_data.hostname,
            "ip_address": scan_data.ip_address,
            "port": scan_data.port,
            "username": scan_data.username,
            "auth_method": scan_data.auth_method,
            "encrypted_credentials": scan_data.encrypted_credentials  # This will be decrypted by the task
        }
        
        # Execute the rule-specific scan as background task
        scan_options = {"rule_id": rescan_request.rule_id, "rescan_type": "rule"}
        background_tasks.add_task(
            execute_scan_task,
            str(new_scan_id),
            host_data,
            scan_data.file_path,
            scan_data.profile_id,
            scan_options
        )
        
        logger.info(f"Rule rescan task scheduled: {new_scan_id}")
        
        return {
            "message": "Rule rescan initiated successfully",
            "scan_id": str(new_scan_id),
            "status": "pending",
            "rule_id": rescan_request.rule_id,
            "original_scan_id": scan_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error initiating rule rescan: {e}")
        raise HTTPException(status_code=500, detail="Failed to initiate rule rescan")


@router.post("/{scan_id}/remediate")
async def start_remediation(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Send failed rules to AEGIS for automated remediation"""
    try:
        # Get scan details and failed rules
        scan_result = db.execute(text("""
            SELECT s.id, s.name, s.host_id, h.hostname, h.ip_address, 
                   sr.failed_rules, sr.severity_high, sr.severity_medium, sr.severity_low
            FROM scans s
            JOIN hosts h ON s.host_id = h.id
            LEFT JOIN scan_results sr ON s.id = sr.scan_id
            WHERE s.id = :scan_id AND s.status = 'completed'
        """), {"scan_id": scan_id}).fetchone()
        
        if not scan_result:
            raise HTTPException(status_code=404, detail="Completed scan not found")
        
        if scan_result.failed_rules == 0:
            raise HTTPException(status_code=400, detail="No failed rules to remediate")
        
        # Get the actual failed rules
        failed_rules = db.execute(text("""
            SELECT rule_id, title, severity, description 
            FROM scan_rule_results 
            WHERE scan_id = :scan_id AND status = 'failed'
            ORDER BY CASE severity WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END
        """), {"scan_id": scan_id}).fetchall()
        
        # Mock AEGIS integration - in reality this would call AEGIS API
        import uuid
        remediation_job_id = str(uuid.uuid4())
        
        # Update scan with remediation request
        db.execute(text("""
            UPDATE scans 
            SET remediation_requested = true, 
                aegis_remediation_id = :job_id,
                remediation_status = 'pending'
            WHERE id = :scan_id
        """), {"scan_id": scan_id, "job_id": remediation_job_id})
        db.commit()
        
        logger.info(f"Remediation job created: {remediation_job_id} for scan {scan_id}")
        
        return {
            "job_id": remediation_job_id,
            "message": f"Remediation job created for {len(failed_rules)} failed rules",
            "scan_id": scan_id,
            "host": scan_result.hostname,
            "failed_rules_count": scan_result.failed_rules,
            "severity_breakdown": {
                "high": scan_result.severity_high,
                "medium": scan_result.severity_medium,
                "low": scan_result.severity_low
            },
            "status": "pending"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting remediation for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to start remediation job")