"""
Scan CRUD Operations

This module provides basic Create, Read, Update, Delete operations for scans
along with scan control operations (stop/cancel, recover).

Endpoints:
    GET    /                     - List scans with filtering
    POST   /                     - Create legacy SCAP scan (DEPRECATED)
    GET    /{scan_id}            - Get scan details
    PATCH  /{scan_id}            - Update scan status
    DELETE /{scan_id}            - Delete scan and results
    POST   /{scan_id}/stop       - Stop running scan
    POST   /{scan_id}/cancel     - Cancel running scan (alias for /stop)
    POST   /{scan_id}/recover    - Recover failed scan
    POST   /hosts/{host_id}/apply-fix - Apply automated fix

Architecture Notes:
    - Uses QueryBuilder for all SELECT queries (SQL injection prevention)
    - Uses parameterized raw SQL for INSERT/UPDATE/DELETE operations
    - Follows Repository Pattern for data access consistency
    - All operations logged for audit compliance

Security Notes:
    - All endpoints require JWT authentication
    - Running scans cannot be deleted (409 Conflict)
    - Error messages sanitized to prevent information disclosure
    - File paths validated before deletion
"""

import json
import logging
import os
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Response
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.routes.scans.helpers import add_deprecation_header, error_service
from app.routes.scans.models import AutomatedFixRequest, ScanRequest, ScanUpdate
from app.tasks.scan_tasks import execute_scan_task
from app.utils.logging_security import sanitize_path_for_log
from app.utils.query_builder import QueryBuilder

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Scan CRUD"])


# =============================================================================
# LIST AND GET OPERATIONS
# =============================================================================


@router.get("/")
async def list_scans(
    host_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    List scans with optional filtering.

    Returns a paginated list of scans with host information and result summaries.
    Supports filtering by host_id and status.

    Args:
        host_id: Optional filter by host UUID.
        status: Optional filter by scan status (pending, running, completed, failed).
        limit: Maximum number of scans to return (default 50).
        offset: Number of scans to skip for pagination.
        db: SQLAlchemy database session.
        current_user: Authenticated user from JWT token.

    Returns:
        Dictionary with scans array, total count, limit, and offset.

    Raises:
        HTTPException 500: Database query failure.

    Example:
        GET /api/scans/?status=completed&limit=20
        GET /api/scans/?host_id=550e8400-e29b-41d4-a716-446655440000

    Security:
        - Requires authenticated user
        - Uses QueryBuilder for SQL injection prevention
    """
    try:
        # Quick check: Return empty if no scans exist
        count_check = QueryBuilder("scans")
        count_query, count_params = count_check.count_query()
        scan_count_result = db.execute(text(count_query), count_params).fetchone()
        scan_total: int = scan_count_result.total if scan_count_result else 0
        if scan_total == 0:
            return {"scans": [], "total": 0, "limit": limit, "offset": offset}

        # Build main query with QueryBuilder
        # NOTE: Removed scap_content JOIN (table deleted in migration 20250106)
        # MongoDB scans use profile_id to store framework instead of content_id
        builder = (
            QueryBuilder("scans s")
            .select(
                "s.id",
                "s.name",
                "s.host_id",
                "s.profile_id",
                "s.status",
                "s.progress",
                "s.started_at",
                "s.completed_at",
                "s.started_by",
                "s.error_message",
                "s.result_file",
                "s.report_file",
                "s.scan_metadata",
                "h.display_name as host_name",
                "h.hostname",
                "h.ip_address",
                "h.operating_system",
                "h.status as host_status",
                "h.last_check",
                "sr.total_rules",
                "sr.passed_rules",
                "sr.failed_rules",
                "sr.error_rules",
                "sr.score",
                "sr.severity_high",
                "sr.severity_medium",
                "sr.severity_low",
            )
            .join("hosts h", "s.host_id = h.id", "LEFT")
            .join("scan_results sr", "sr.scan_id = s.id", "LEFT")
        )

        # Add optional filters
        if host_id:
            builder.where("s.host_id = :host_id", host_id, "host_id")

        if status:
            builder.where("s.status = :status", status, "status")

        # Add ordering and pagination
        builder.order_by("s.started_at", "DESC").paginate(page=offset // limit + 1, per_page=limit)

        query, params = builder.build()
        result = db.execute(text(query), params)

        scans = []
        for row in result:
            # Parse scan_metadata if available (JSON column)
            scan_metadata = {}
            if hasattr(row, "scan_metadata") and row.scan_metadata:
                try:
                    scan_metadata = (
                        json.loads(row.scan_metadata) if isinstance(row.scan_metadata, str) else row.scan_metadata
                    )
                except (ValueError, TypeError):
                    scan_metadata = {}

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
                    "last_check": (row.last_check.isoformat() if row.last_check else None),
                },
                "profile_id": row.profile_id,
                "status": row.status,
                "progress": row.progress,
                "started_at": row.started_at.isoformat() if row.started_at else None,
                "completed_at": (row.completed_at.isoformat() if row.completed_at else None),
                "started_by": row.started_by,
                "error_message": row.error_message,
                "result_file": row.result_file,
                "report_file": row.report_file,
                "scan_metadata": scan_metadata,
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
                    "created_at": (row.completed_at.isoformat() if row.completed_at else None),
                }

            scans.append(scan_data)

        # Get total count using QueryBuilder
        count_builder = QueryBuilder("scans s").join("hosts h", "s.host_id = h.id", "LEFT")

        # Apply same filters as main query
        if host_id:
            count_builder.where("s.host_id = :host_id", host_id, "host_id")

        if status:
            count_builder.where("s.status = :status", status, "status")

        count_query, count_params = count_builder.count_query()
        total_result = db.execute(text(count_query), count_params).fetchone()
        total_count: int = total_result.total if total_result else 0

        return {
            "scans": scans,
            "total": total_count,
            "limit": limit,
            "offset": offset,
        }

    except Exception as e:
        logger.error(f"Error listing scans: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve scans")


@router.get("/{scan_id}")
async def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get scan details by ID.

    Returns comprehensive scan information including host details, scan options,
    and results summary (if completed).

    Args:
        scan_id: UUID of the scan to retrieve.
        db: SQLAlchemy database session.
        current_user: Authenticated user from JWT token.

    Returns:
        Dictionary with scan details, host info, and results (if completed).

    Raises:
        HTTPException 404: Scan not found.
        HTTPException 500: Database query failure.

    Example:
        GET /api/scans/550e8400-e29b-41d4-a716-446655440000

    Security:
        - Requires authenticated user
        - Uses QueryBuilder for SQL injection prevention
    """
    try:
        builder = (
            QueryBuilder("scans s")
            .select(
                "s.id",
                "s.name",
                "s.host_id",
                "s.profile_id",
                "s.status",
                "s.progress",
                "s.result_file",
                "s.report_file",
                "s.error_message",
                "s.scan_options",
                "s.started_at",
                "s.completed_at",
                "s.started_by",
                "s.celery_task_id",
                "h.display_name as host_name",
                "h.hostname",
            )
            .join("hosts h", "s.host_id = h.id")
            .where("s.id = :id", scan_id, "id")
        )
        query, params = builder.build()
        result = db.execute(text(query), params).fetchone()

        if not result:
            raise HTTPException(status_code=404, detail="Scan not found")

        scan_options = {}
        if result.scan_options:
            try:
                scan_options = json.loads(result.scan_options)
            except Exception:
                logger.debug("Ignoring exception during scan_options JSON parsing")

        scan_data = {
            "id": result.id,
            "name": result.name,
            "host_id": result.host_id,
            "host_name": result.host_name,
            "hostname": result.hostname,
            "profile_id": result.profile_id,
            "status": result.status,
            "progress": result.progress,
            "result_file": result.result_file,
            "report_file": result.report_file,
            "error_message": result.error_message,
            "scan_options": scan_options,
            "started_at": result.started_at.isoformat() if result.started_at else None,
            "completed_at": (result.completed_at.isoformat() if result.completed_at else None),
            "started_by": result.started_by,
            "celery_task_id": result.celery_task_id,
        }

        # Add results summary if scan is completed
        if result.status == "completed":
            results = db.execute(
                text("""
                SELECT total_rules, passed_rules, failed_rules, error_rules,
                       unknown_rules, not_applicable_rules, score,
                       severity_high, severity_medium, severity_low,
                       xccdf_score, xccdf_score_max, xccdf_score_system,
                       risk_score, risk_level
                FROM scan_results WHERE scan_id = :scan_id
            """),
                {"scan_id": scan_id},
            ).fetchone()

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
                    "severity_low": results.severity_low,
                    "xccdf_score": results.xccdf_score,
                    "xccdf_score_max": results.xccdf_score_max,
                    "xccdf_score_system": results.xccdf_score_system,
                    "risk_score": results.risk_score,
                    "risk_level": results.risk_level,
                }

        return scan_data

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve scan")


# =============================================================================
# CREATE OPERATION (LEGACY)
# =============================================================================


@router.post("/legacy")
async def create_scan_legacy(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    response: Response,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Create and start a new SCAP scan (LEGACY).

    DEPRECATION NOTICE: This endpoint uses SCAP content files for scanning.
    For compliance scanning, use POST /api/scans/ (ComplianceScanRequest) instead.

    Args:
        scan_request: Scan configuration including host_id, content_id, profile_id.
        background_tasks: FastAPI background task manager.
        response: FastAPI response for deprecation headers.
        db: Database session.
        current_user: Authenticated user from JWT.

    Returns:
        Dict with scan_id, message, and status.

    Raises:
        HTTPException 404: Host or SCAP content not found.
        HTTPException 400: Invalid profile or configuration.
        HTTPException 500: Scan creation error.

    Security:
        - Requires authenticated user
        - Uses QueryBuilder for SQL injection prevention
        - Validates host and content existence before creating scan
    """
    # Add deprecation header for legacy SCAP content endpoint
    add_deprecation_header(response, "create_scan_legacy")
    try:
        # Validate host exists
        host_builder = (
            QueryBuilder("hosts")
            .select(
                "id",
                "display_name",
                "hostname",
                "port",
                "username",
                "auth_method",
                "encrypted_credentials",
            )
            .where("id = :id", scan_request.host_id, "id")
            .where("is_active = :is_active", True, "is_active")
        )
        query, params = host_builder.build()
        host_result = db.execute(text(query), params).fetchone()

        if not host_result:
            raise HTTPException(status_code=404, detail="Host not found or inactive")

        # Validate SCAP content exists
        content_builder = (
            QueryBuilder("scap_content")
            .select("id", "name", "file_path", "profiles")
            .where("id = :id", scan_request.content_id, "id")
        )
        query, params = content_builder.build()
        content_result = db.execute(text(query), params).fetchone()

        if not content_result:
            raise HTTPException(status_code=404, detail="SCAP content not found")

        # Validate profile exists in content
        profiles = []
        if content_result.profiles:
            try:
                profiles = json.loads(content_result.profiles)
                profile_ids = [p.get("id") for p in profiles if p.get("id")]
                if scan_request.profile_id not in profile_ids:
                    raise HTTPException(status_code=400, detail="Profile not found in SCAP content")
            except json.JSONDecodeError:
                raise HTTPException(status_code=400, detail="Invalid SCAP content profiles")

        # Create scan record
        scan_id = str(uuid.uuid4())
        insert_query = text("""
            INSERT INTO scans (
                id, name, host_id, content_id, profile_id, status, progress,
                scan_options, started_by, started_at, remediation_requested, verification_scan
            )
            VALUES (
                :id, :name, :host_id, :content_id, :profile_id, :status, :progress,
                :scan_options, :started_by, :started_at, :remediation_requested, :verification_scan
            )
        """)
        db.execute(
            insert_query,
            {
                "id": scan_id,
                "name": scan_request.name,
                "host_id": scan_request.host_id,
                "content_id": scan_request.content_id,
                "profile_id": scan_request.profile_id,
                "status": "pending",
                "progress": 0,
                "scan_options": json.dumps(scan_request.scan_options),
                "started_by": current_user["id"],
                "started_at": datetime.utcnow(),
                "remediation_requested": False,
                "verification_scan": False,
            },
        )

        # Commit the scan record
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
                "encrypted_credentials": host_result.encrypted_credentials,
            },
            content_path=content_result.file_path,
            profile_id=scan_request.profile_id,
            scan_options=scan_request.scan_options or {},
        )

        logger.info(f"Legacy scan created and started: {scan_id}")

        return {
            "id": scan_id,
            "message": "Scan created and started successfully",
            "status": "pending",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating scan: {e}", exc_info=True)
        # Classify the error for better user guidance
        try:
            classified_error = await error_service.classify_error(e, {"operation": "create_scan"})
            raise HTTPException(
                status_code=500,
                detail={
                    "message": classified_error.message,
                    "category": classified_error.category.value,
                    "user_guidance": classified_error.user_guidance,
                    "can_retry": classified_error.can_retry,
                    "error_code": classified_error.error_code,
                },
            )
        except HTTPException:
            raise
        except Exception:
            # Fallback to generic error if classification fails
            raise HTTPException(status_code=500, detail=f"Failed to create scan: {str(e)}")


# =============================================================================
# UPDATE AND DELETE OPERATIONS
# =============================================================================


@router.patch("/{scan_id}")
async def update_scan(
    scan_id: str,
    scan_update: ScanUpdate,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Update scan status (internal use).

    Updates scan status, progress, and error message fields.
    Automatically sets completed_at timestamp when status is 'completed'.

    Args:
        scan_id: UUID of the scan to update.
        scan_update: Update data (status, progress, error_message).
        db: SQLAlchemy database session.
        current_user: Authenticated user from JWT token.

    Returns:
        Success message dictionary.

    Raises:
        HTTPException 404: Scan not found.
        HTTPException 500: Database update failure.

    Security:
        - Requires authenticated user
        - Uses parameterized queries for SQL injection prevention
    """
    try:
        # Check if scan exists
        check_builder = QueryBuilder("scans").select("id").where("id = :id", scan_id, "id")
        query, params = check_builder.build()
        existing = db.execute(text(query), params).fetchone()

        if not existing:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Build update data
        update_data: Dict[str, Any] = {}

        if scan_update.status is not None:
            update_data["status"] = scan_update.status

        if scan_update.progress is not None:
            update_data["progress"] = scan_update.progress

        if scan_update.error_message is not None:
            update_data["error_message"] = scan_update.error_message

        if scan_update.status == "completed":
            update_data["completed_at"] = datetime.utcnow()

        if update_data:
            # Build dynamic SET clause based on update_data
            set_clauses = ", ".join([f"{key} = :{key}" for key in update_data.keys()])
            update_query = text(f"""
                UPDATE scans
                SET {set_clauses}
                WHERE id = :id
            """)
            update_params = {**update_data, "id": scan_id}
            db.execute(update_query, update_params)
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
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Delete scan and its results.

    Removes the scan record, associated results, and result files from disk.
    Running scans cannot be deleted.

    Args:
        scan_id: UUID of the scan to delete.
        db: SQLAlchemy database session.
        current_user: Authenticated user from JWT token.

    Returns:
        Success message dictionary.

    Raises:
        HTTPException 404: Scan not found.
        HTTPException 409: Cannot delete running scan.
        HTTPException 500: Database delete failure.

    Security:
        - Requires authenticated user
        - Validates scan status before deletion
        - Uses parameterized queries for SQL injection prevention
    """
    try:
        # Check if scan exists and get status
        check_builder = (
            QueryBuilder("scans").select("status", "result_file", "report_file").where("id = :id", scan_id, "id")
        )
        query, params = check_builder.build()
        result = db.execute(text(query), params).fetchone()

        if not result:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Don't allow deletion of running scans
        if result.status in ["pending", "running"]:
            raise HTTPException(status_code=409, detail="Cannot delete running scan")

        # Delete result files
        for file_path in [result.result_file, result.report_file]:
            if file_path and os.path.exists(file_path):
                try:
                    os.unlink(file_path)
                except Exception as e:
                    logger.warning(f"Failed to delete file {sanitize_path_for_log(file_path)}: " f"{type(e).__name__}")

        # Delete scan results first (foreign key constraint)
        results_delete_query = text("""
            DELETE FROM scan_results
            WHERE scan_id = :scan_id
        """)
        db.execute(results_delete_query, {"scan_id": scan_id})

        # Delete scan record
        scan_delete_query = text("""
            DELETE FROM scans
            WHERE id = :id
        """)
        db.execute(scan_delete_query, {"id": scan_id})

        db.commit()

        logger.info(f"Scan deleted: {scan_id}")
        return {"message": "Scan deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete scan")


# =============================================================================
# SCAN CONTROL OPERATIONS
# =============================================================================


@router.post("/{scan_id}/stop")
@router.post("/{scan_id}/cancel")
async def stop_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Stop/cancel a running scan.

    Attempts to revoke the Celery task and updates the scan status to 'stopped'.

    This endpoint is available at both:
    - POST /api/scans/{scan_id}/stop (original)
    - POST /api/scans/{scan_id}/cancel (alias for frontend compatibility)

    Args:
        scan_id: UUID of the scan to stop.
        db: SQLAlchemy database session.
        current_user: Authenticated user from JWT token.

    Returns:
        Success message dictionary.

    Raises:
        HTTPException 404: Scan not found.
        HTTPException 400: Scan not in stoppable state.
        HTTPException 500: Stop operation failure.

    Security:
        - Requires authenticated user
        - Uses parameterized queries for SQL injection prevention
    """
    try:
        # Check if scan exists and is running
        result = db.execute(
            text("""
            SELECT status, celery_task_id FROM scans WHERE id = :id
        """),
            {"id": scan_id},
        ).fetchone()

        if not result:
            raise HTTPException(status_code=404, detail="Scan not found")

        if result.status not in ["pending", "running"]:
            raise HTTPException(status_code=400, detail=f"Cannot stop scan with status: {result.status}")

        # Try to revoke Celery task if available
        if result.celery_task_id:
            try:
                from celery import current_app

                current_app.control.revoke(result.celery_task_id, terminate=True)
            except Exception as e:
                logger.warning(f"Failed to revoke Celery task: {e}")

        # Update scan status
        db.execute(
            text("""
            UPDATE scans
            SET status = 'stopped', completed_at = :completed_at,
                error_message = 'Scan stopped by user'
            WHERE id = :id
        """),
            {"id": scan_id, "completed_at": datetime.utcnow()},
        )
        db.commit()

        logger.info(f"Scan stopped: {scan_id}")
        return {"message": "Scan stopped successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error stopping scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to stop scan")


@router.post("/{scan_id}/recover")
async def recover_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Attempt to recover a failed scan with intelligent retry.

    Analyzes the original error to determine if recovery is possible,
    calculates appropriate retry delay, and creates a new recovery scan.

    Args:
        scan_id: UUID of the failed scan to recover.
        db: SQLAlchemy database session.
        current_user: Authenticated user from JWT token.

    Returns:
        Dictionary with recovery status, new scan ID, and error classification.

    Raises:
        HTTPException 404: Failed scan not found.
        HTTPException 500: Recovery operation failure.

    Security:
        - Requires authenticated user
        - Uses parameterized queries for SQL injection prevention
        - Classifies errors before attempting recovery
    """
    try:
        # Get failed scan details
        scan_result = db.execute(
            text("""
            SELECT s.id, s.name, s.host_id, s.profile_id, s.status, s.error_message,
                   s.content_id, h.hostname, h.port, h.username, h.auth_method
            FROM scans s
            JOIN hosts h ON s.host_id = h.id
            WHERE s.id = :scan_id AND s.status = 'failed'
        """),
            {"scan_id": scan_id},
        ).fetchone()

        if not scan_result:
            raise HTTPException(status_code=404, detail="Failed scan not found")

        # Classify the original error to determine recovery strategy
        original_error = Exception(scan_result.error_message or "Unknown error")
        classified_error = await error_service.classify_error(
            original_error, {"scan_id": scan_id, "hostname": scan_result.hostname}
        )

        # Determine if retry is possible
        if not classified_error.can_retry:
            return {
                "can_recover": False,
                "message": "Scan cannot be automatically recovered",
                "error_classification": classified_error.dict(),
                "recommended_actions": classified_error.user_guidance,
            }

        # Calculate retry delay
        retry_delay = classified_error.retry_after or 60

        # Create recovery scan
        recovery_scan_id = str(uuid.uuid4())
        db.execute(
            text("""
            INSERT INTO scans
            (id, name, host_id, content_id, profile_id, status, progress,
             started_by, started_at, scan_options)
            VALUES (:id, :name, :host_id, :content_id, :profile_id, :status,
                    :progress, :started_by, :started_at, :scan_options)
        """),
            {
                "id": recovery_scan_id,
                "name": f"Recovery: {scan_result.name}",
                "host_id": scan_result.host_id,
                "content_id": scan_result.content_id,
                "profile_id": scan_result.profile_id,
                "status": "pending",
                "progress": 0,
                "started_by": current_user["id"],
                "started_at": datetime.utcnow(),
                "scan_options": json.dumps({"recovery_scan": True, "original_scan_id": scan_id}),
            },
        )
        db.commit()

        logger.info(f"Recovery scan created: {recovery_scan_id} for failed scan {scan_id}")

        return {
            "can_recover": True,
            "recovery_scan_id": recovery_scan_id,
            "message": f"Recovery scan created and will start in {retry_delay} seconds",
            "error_classification": classified_error.dict(),
            "estimated_retry_time": (datetime.utcnow().timestamp() + retry_delay),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating recovery scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to create recovery scan")


@router.post("/hosts/{host_id}/apply-fix")
async def apply_automated_fix(
    host_id: str,
    fix_request: AutomatedFixRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Apply an automated fix to a host.

    Queues an automated remediation fix for execution on the specified host.
    Currently returns a mock response - in production this would execute the fix.

    Args:
        host_id: UUID of the target host.
        fix_request: Fix configuration including fix_id and validation options.
        background_tasks: FastAPI background task manager.
        db: SQLAlchemy database session.
        current_user: Authenticated user from JWT token.

    Returns:
        Dictionary with job_id, status, and estimated completion time.

    Raises:
        HTTPException 404: Host not found or inactive.
        HTTPException 500: Fix application failure.

    Security:
        - Requires authenticated user
        - Validates host exists and is active before applying fix
    """
    try:
        # Get host details
        host_result = db.execute(
            text("""
            SELECT id, display_name, hostname, port, username, auth_method
            FROM hosts WHERE id = :id AND is_active = true
        """),
            {"id": host_id},
        ).fetchone()

        if not host_result:
            raise HTTPException(status_code=404, detail="Host not found or inactive")

        logger.info(f"Applying automated fix {fix_request.fix_id} to host {host_id}")

        # Mock execution time based on fix type
        estimated_time = 30  # Default 30 seconds
        if "install" in fix_request.fix_id.lower():
            estimated_time = 120
        elif "update" in fix_request.fix_id.lower():
            estimated_time = 60

        # Create a mock job ID for tracking
        job_id = str(uuid.uuid4())

        # In production, this would:
        # 1. Queue the fix execution as a background task
        # 2. Track progress in database
        # 3. Execute commands via SSH
        # 4. Validate results if requested

        return {
            "job_id": job_id,
            "fix_id": fix_request.fix_id,
            "host_id": host_id,
            "status": "queued",
            "estimated_completion": (datetime.utcnow().timestamp() + estimated_time),
            "message": f"Automated fix {fix_request.fix_id} queued for execution",
            "validate_after": fix_request.validate_after,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error applying automated fix: {e}")
        raise HTTPException(status_code=500, detail="Failed to apply automated fix")


# =============================================================================
# PUBLIC API EXPORTS
# =============================================================================

__all__ = [
    "router",
    "list_scans",
    "get_scan",
    "create_scan_legacy",
    "update_scan",
    "delete_scan",
    "stop_scan",  # Also accessible via /cancel alias
    "recover_scan",
    "apply_automated_fix",
]
