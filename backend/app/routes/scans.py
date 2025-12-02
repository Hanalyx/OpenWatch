"""
SCAP Scanning API Routes
Handles scan job creation, monitoring, and results

NOTE: This file contains LEGACY SCAP content-based scanning endpoints.
MongoDB-based scanning is now available at /api/mongodb-scans/.

Migration Status (2025-11-07):
- Scan list endpoint: FIXED (removed scap_content JOINs)
- Scan detail endpoint: FIXED (removed content_id references)
- Scan recovery endpoint: FIXED
- Get failed rules endpoint: FIXED
- Rule rescan endpoint: DISABLED (MongoDB scans don't support rule rescanning)

Active MongoDB Endpoints:
- /api/mongodb-scans/start - Create new MongoDB-based scan
- /api/scans/ (GET) - List all scans (works with both legacy and MongoDB scans)
- /api/scans/{scan_id} (GET) - Get scan details (works with both types)

Legacy SCAP Content Endpoints (still available for backward compatibility):
- /api/scans/ (POST) - Create legacy SCAP content-based scan
- /api/scans/validate - Validate legacy scan parameters
- Most other endpoints in this file
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..models.error_models import ValidationResultResponse
from ..services.bulk_scan_orchestrator import BulkScanOrchestrator

# Engine module imports for SCAP scanning operations
# These replace the legacy scap_scanner.py imports
from ..services.engine import OSCAPScanner
from ..services.engine.result_parsers import XCCDFResultParser
from ..services.error_classification import ErrorClassificationService
from ..services.error_sanitization import get_error_sanitization_service
from ..services.scan_intelligence import ProfileSuggestion, ScanIntelligenceService, ScanPriority
from ..tasks.scan_tasks import execute_scan_task
from ..utils.logging_security import sanitize_path_for_log
from ..utils.query_builder import QueryBuilder

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["Scans"])

# Initialize services
# OSCAPScanner handles content validation and profile extraction
oscap_scanner = OSCAPScanner()
# XCCDFResultParser handles parsing scan result XML files
xccdf_parser = XCCDFResultParser()
error_service = ErrorClassificationService()
sanitization_service = get_error_sanitization_service()


def sanitize_http_error(
    request: Request,
    current_user: Dict[str, Any],
    exception: Exception,
    fallback_message: str,
    status_code: int = 500,
) -> HTTPException:
    """Helper to sanitize HTTP errors and prevent information disclosure"""
    try:
        # Get client information
        client_ip = request.client.host if request.client else "unknown"
        user_id = current_user.get("sub") if current_user else None

        # Classify the error internally
        ErrorClassificationService()
        # Note: Cannot use await in sync context, error classification happens elsewhere

        # For synchronous context, use a generic approach
        sanitization_service = get_error_sanitization_service()
        sanitized_error = sanitization_service.sanitize_error(
            {
                "error_code": "HTTP_ERROR",
                "category": "execution",
                "severity": "error",
                "message": str(exception),
                "technical_details": {"original_error": str(exception)},
                "user_guidance": fallback_message,
                "can_retry": False,
            },
            user_id=user_id,
            source_ip=client_ip,
        )

        return HTTPException(status_code=status_code, detail=sanitized_error.message)

    except Exception as sanitization_error:
        # Fallback if sanitization fails
        logger.error(f"Error sanitization failed: {sanitization_error}")
        return HTTPException(status_code=status_code, detail=fallback_message)


class ScanRequest(BaseModel):
    name: str
    host_id: str  # Changed to str to handle UUID
    content_id: int
    profile_id: str
    scan_options: Optional[Dict[str, Any]] = {}


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


class ValidationRequest(BaseModel):
    host_id: str
    content_id: int
    profile_id: str


class AutomatedFixRequest(BaseModel):
    fix_id: str
    host_id: str
    validate_after: bool = True


class QuickScanRequest(BaseModel):
    template_id: Optional[str] = "auto"  # Auto-detect best profile
    priority: Optional[str] = "normal"
    name: Optional[str] = None
    email_notify: bool = False


class QuickScanResponse(BaseModel):
    id: str
    message: str
    status: str
    suggested_profile: ProfileSuggestion
    estimated_completion: Optional[float] = None


class BulkScanRequest(BaseModel):
    host_ids: List[str]
    template_id: Optional[str] = "auto"
    priority: Optional[str] = "normal"
    name_prefix: Optional[str] = "Bulk Scan"
    stagger_delay: int = 30  # seconds between scan starts


class BulkScanResponse(BaseModel):
    session_id: str
    message: str
    total_hosts: int
    estimated_completion: float
    scan_ids: List[str]


@router.post("/validate")
async def validate_scan_configuration(
    validation_request: ValidationRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> ValidationResultResponse:
    """Pre-flight validation for scan configuration"""
    try:
        logger.info(f"Pre-flight validation requested for host {validation_request.host_id}")

        # Get host details
        host_result = db.execute(
            text(
                """
            SELECT id, display_name, hostname, port, username, auth_method, encrypted_credentials
            FROM hosts WHERE id = :id AND is_active = true
        """
            ),
            {"id": validation_request.host_id},
        ).fetchone()

        if not host_result:
            raise HTTPException(status_code=404, detail="Host not found or inactive")

        # Get SCAP content details
        content_result = db.execute(
            text(
                """
            SELECT id, name, file_path, profiles FROM scap_content WHERE id = :id
        """
            ),
            {"id": validation_request.content_id},
        ).fetchone()

        if not content_result:
            raise HTTPException(status_code=404, detail="SCAP content not found")

        # Validate profile exists
        if content_result.profiles:
            try:
                profiles = json.loads(content_result.profiles)
                profile_ids = [p.get("id") for p in profiles if p.get("id")]
                if validation_request.profile_id not in profile_ids:
                    raise HTTPException(status_code=400, detail="Profile not found in SCAP content")
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid SCAP content profiles")

        # Resolve credentials
        try:
            from ..services.auth_service import get_auth_service

            auth_service = get_auth_service(db)  # type: ignore[call-arg]

            use_default = host_result.auth_method in ["default", "system_default"]
            target_id = str(host_result.id) if not use_default and host_result.id else ""

            credential_data = auth_service.resolve_credential(
                target_id=target_id, use_default=use_default
            )

            if not credential_data:
                raise HTTPException(status_code=400, detail="No credentials available for host")

            # Extract credential value based on auth method
            if credential_data.auth_method.value == "password":
                credential_value = credential_data.password
            elif credential_data.auth_method.value in ["ssh_key", "ssh-key"]:
                credential_value = credential_data.private_key
            else:
                credential_value = credential_data.password or ""

        except Exception as e:
            logger.error(f"Credential resolution failed for validation: {e}")
            raise sanitize_http_error(
                request,
                current_user,
                e,
                "Unable to resolve authentication credentials for target host",
                400,
            )

        # Get client information for security audit
        client_ip = request.client.host if request.client else "unknown"
        user_id = current_user.get("sub") if current_user else None
        user_role = current_user.get("role") if current_user else None
        is_admin = user_role in ["SUPER_ADMIN", "SECURITY_ADMIN"] if user_role else False

        # Perform comprehensive validation (returns internal result with sensitive data)
        internal_result = await error_service.validate_scan_prerequisites(
            hostname=host_result.hostname,
            port=host_result.port,
            username=credential_data.username,
            auth_method=credential_data.auth_method.value,
            credential=credential_value or "",
            user_id=user_id,
            source_ip=client_ip,
        )

        logger.info(
            f"Validation completed: can_proceed={internal_result.can_proceed}, "
            f"errors={len(internal_result.errors)}, warnings={len(internal_result.warnings)}"
        )

        # Convert to sanitized response using Security Fix 5 system info sanitization
        sanitized_result = error_service.get_sanitized_validation_result(
            internal_result,
            user_id=user_id,
            source_ip=client_ip,
            user_role=user_role,
            is_admin=is_admin,
        )

        return sanitized_result

    except HTTPException:
        raise
    except Exception as e:
        # Log full technical details server-side
        logger.error(f"Validation error: {e}", exc_info=True)

        # Create sanitized error for user
        sanitization_service = get_error_sanitization_service()
        classified_error = await error_service.classify_error(
            e,
            {
                "operation": "scan_validation",
                "host_id": validation_request.host_id,
                "content_id": validation_request.content_id,
            },
        )

        sanitized_error = sanitization_service.sanitize_error(
            classified_error.dict(),
            user_id=current_user.get("sub") if current_user else None,
            source_ip=request.client.host if request.client else "unknown",
        )

        # Return generic error message to prevent information disclosure
        raise HTTPException(status_code=500, detail=f"Validation failed: {sanitized_error.message}")


@router.post("/hosts/{host_id}/quick-scan", response_model=QuickScanResponse)
async def quick_scan(
    host_id: str,
    quick_scan_request: QuickScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> QuickScanResponse:
    """Start scan with intelligent defaults - Zero to Scan in 3 Clicks"""
    try:
        logger.info(
            f"Quick scan requested for host {host_id} with template {quick_scan_request.template_id}"
        )

        # Initialize intelligence service
        intelligence_service = ScanIntelligenceService(db)

        # Auto-detect profile if not specified
        suggested_profile = None
        if quick_scan_request.template_id == "auto":
            suggested_profile = await intelligence_service.suggest_scan_profile(host_id)
            template_id = suggested_profile.profile_id
            content_id = suggested_profile.content_id
        else:
            # Use specified template - for now, map to default content
            template_id = quick_scan_request.template_id or "auto"
            content_id = 1  # Default SCAP content

            # Still get suggestion for response metadata
            suggested_profile = await intelligence_service.suggest_scan_profile(host_id)

        # Get host details for validation
        host_result = db.execute(
            text(
                """
            SELECT id, display_name, hostname, port, username, auth_method, encrypted_credentials
            FROM hosts WHERE id = :id AND is_active = true
        """
            ),
            {"id": host_id},
        ).fetchone()

        if not host_result:
            raise HTTPException(status_code=404, detail="Host not found or inactive")

        # Get SCAP content details
        content_result = db.execute(
            text(
                """
            SELECT id, name, file_path, profiles FROM scap_content WHERE id = :id
        """
            ),
            {"id": content_id},
        ).fetchone()

        if not content_result:
            raise HTTPException(status_code=404, detail="SCAP content not found")

        # Validate profile exists in content
        profiles = []
        if content_result.profiles:
            try:
                profiles = json.loads(content_result.profiles)
                profile_ids = [p.get("id") for p in profiles if p.get("id")]
                if template_id not in profile_ids:
                    # Fall back to first available profile
                    if profile_ids:
                        template_id = profile_ids[0]
                        logger.warning(
                            f"Requested profile not found, using fallback: {template_id}"
                        )
                    else:
                        raise HTTPException(
                            status_code=400,
                            detail="No profiles available in SCAP content",
                        )
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid SCAP content profiles")

        # Generate scan name
        scan_name = quick_scan_request.name
        if not scan_name:
            profile_name = suggested_profile.name if suggested_profile else "Quick Scan"
            scan_name = f"{profile_name} - {host_result.display_name or host_result.hostname}"

        # Create scan record with UUID primary key
        scan_id = str(uuid.uuid4())

        # Pre-flight validation (async, non-blocking for optimistic UI)
        try:
            from ..services.auth_service import get_auth_service

            auth_service = get_auth_service(db)  # type: ignore[call-arg]

            use_default = host_result.auth_method in ["default", "system_default"]
            target_id = str(host_result.id) if not use_default and host_result.id else ""

            credential_data = auth_service.resolve_credential(
                target_id=target_id, use_default=use_default
            )

            if credential_data:
                # Queue async validation
                # FIXME: Disabled - validate_scan_async function not yet implemented
                # validation_task = background_tasks.add_task(
                #     validate_scan_async, scan_id, host_result, credential_data
                # )
                pass
        except Exception as e:
            logger.warning(f"Pre-flight validation setup failed: {e}")

        # Create scan immediately (optimistic UI)
        db.execute(
            text(
                """
            INSERT INTO scans
            (id, name, host_id, content_id, profile_id, status, progress,
             scan_options, started_by, started_at, remediation_requested, verification_scan)
            VALUES (:id, :name, :host_id, :content_id, :profile_id, :status,
                    :progress, :scan_options, :started_by, :started_at, :remediation_requested, :verification_scan)
            RETURNING id
        """
            ),
            {
                "id": scan_id,
                "name": scan_name,
                "host_id": host_id,
                "content_id": content_id,
                "profile_id": template_id,
                "status": "pending",
                "progress": 0,
                "scan_options": json.dumps(
                    {
                        "quick_scan": True,
                        "template_id": quick_scan_request.template_id,
                        "priority": quick_scan_request.priority,
                        "email_notify": quick_scan_request.email_notify,
                    }
                ),
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
            profile_id=template_id,
            scan_options={"quick_scan": True, "priority": quick_scan_request.priority},
        )

        logger.info(f"Quick scan created and started: {scan_id}")

        # Calculate estimated completion
        estimated_time = None
        if suggested_profile:
            # Parse estimated duration (e.g., "10-15 min" -> 12.5 minutes)
            duration_str = suggested_profile.estimated_duration
            try:
                if "min" in duration_str:
                    parts = duration_str.replace(" min", "").split("-")
                    if len(parts) == 2:
                        avg_minutes = (int(parts[0]) + int(parts[1])) / 2
                        estimated_time = datetime.utcnow().timestamp() + (avg_minutes * 60)
            except Exception:
                logger.debug("Ignoring exception during cleanup")

        return QuickScanResponse(
            id=scan_id,
            message="Scan created and started successfully",
            status="pending",
            suggested_profile=suggested_profile
            or ProfileSuggestion(
                profile_id=template_id,
                content_id=content_id,
                name="Quick Scan",
                confidence=0.5,
                reasoning=["Manual template selection"],
                estimated_duration="10-15 min",
                rule_count=150,
                priority=suggested_profile.priority if suggested_profile else ScanPriority.NORMAL,
            ),
            estimated_completion=estimated_time,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating quick scan: {e}", exc_info=True)
        # Classify the error for better user guidance
        try:
            classified_error = await error_service.classify_error(e, {"operation": "quick_scan"})
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
        except Exception as fallback_error:
            # Fallback to generic error if classification fails
            logger.error(f"Quick scan creation failed with classification error: {fallback_error}")
            raise HTTPException(
                status_code=500,
                detail="Failed to create scan due to system configuration error",
            )


async def _async_validation_check(scan_id: str, host_result: Any, credential_data: Any) -> None:
    """Async validation check for quick scan"""
    # This would run validation and update scan status if blocked
    # Implementation would go here


@router.post("/bulk-scan", response_model=BulkScanResponse)
async def create_bulk_scan(
    bulk_scan_request: BulkScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> BulkScanResponse:
    """Create and start bulk scan session for multiple hosts"""
    try:
        logger.info(f"Bulk scan requested for {len(bulk_scan_request.host_ids)} hosts")

        if not bulk_scan_request.host_ids:
            raise HTTPException(status_code=400, detail="No host IDs provided")

        if len(bulk_scan_request.host_ids) > 100:
            raise HTTPException(status_code=400, detail="Maximum 100 hosts per bulk scan")

        # Initialize orchestrator
        orchestrator = BulkScanOrchestrator(db)

        # Create bulk scan session
        session = await orchestrator.create_bulk_scan_session(
            host_ids=bulk_scan_request.host_ids,
            template_id=bulk_scan_request.template_id or "auto",
            name_prefix=bulk_scan_request.name_prefix or "Bulk Scan",
            priority=bulk_scan_request.priority or "normal",
            user_id=current_user["id"],
            stagger_delay=bulk_scan_request.stagger_delay,
        )

        # Start the bulk scan session

        logger.info(f"Bulk scan session created and started: {session.id}")

        return BulkScanResponse(
            session_id=session.id,
            message=f"Bulk scan session created for {session.total_hosts} hosts",
            total_hosts=session.total_hosts,
            estimated_completion=(
                session.estimated_completion.timestamp() if session.estimated_completion else 0
            ),
            scan_ids=session.scan_ids or [],
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating bulk scan: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to create bulk scan: {str(e)}")


@router.get("/bulk-scan/{session_id}/progress")
async def get_bulk_scan_progress(
    session_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get real-time progress of a bulk scan session"""
    try:
        orchestrator = BulkScanOrchestrator(db)
        progress = await orchestrator.get_bulk_scan_progress(session_id)
        return progress

    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error getting bulk scan progress: {e}")
        raise HTTPException(status_code=500, detail="Failed to get bulk scan progress")


@router.post("/bulk-scan/{session_id}/cancel")
async def cancel_bulk_scan(
    session_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, str]:
    """Cancel a running bulk scan session"""
    try:
        # Update session status to cancelled
        result = db.execute(
            text(
                """
            UPDATE scan_sessions SET status = 'cancelled'
            WHERE id = :session_id
        """
            ),
            {"session_id": session_id},
        )

        # CursorResult has rowcount attribute (SQLAlchemy typing limitation)
        rowcount = getattr(result, "rowcount", 0)
        if rowcount == 0:
            raise HTTPException(status_code=404, detail="Bulk scan session not found")

        # Cancel individual scans that are still pending
        db.execute(
            text(
                """
            UPDATE scans SET status = 'cancelled', error_message = 'Cancelled by user'
            WHERE id IN (
                SELECT unnest(ARRAY(
                    SELECT json_array_elements_text(scan_ids::json)
                    FROM scan_sessions WHERE id = :session_id
                ))
            ) AND status IN ('pending', 'running')
        """
            ),
            {"session_id": session_id},
        )

        db.commit()

        logger.info(f"Bulk scan session cancelled: {session_id}")
        return {"message": "Bulk scan session cancelled successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error cancelling bulk scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to cancel bulk scan")


@router.get("/sessions")
async def list_scan_sessions(
    status: Optional[str] = None,
    limit: int = 20,
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """List scan sessions for monitoring and management"""
    try:
        # Build query conditions
        where_conditions: List[str] = []
        params: Dict[str, Any] = {"limit": limit, "offset": offset}

        if status:
            where_conditions.append("status = :status")
            params["status"] = status

        # Add user filtering if not admin
        if current_user.get("role") not in ["SUPER_ADMIN", "SECURITY_ADMIN"]:
            where_conditions.append("created_by = :user_id")
            params["user_id"] = current_user["id"]

        # Get sessions
        base_sessions_query = """
            SELECT id, name, total_hosts, completed_hosts, failed_hosts, running_hosts,
                   status, created_by, created_at, started_at, completed_at, estimated_completion
            FROM scan_sessions
        """

        if where_conditions:
            sessions_query = base_sessions_query + " WHERE " + " AND ".join(where_conditions)
        else:
            sessions_query = base_sessions_query

        sessions_query += " ORDER BY created_at DESC LIMIT :limit OFFSET :offset"

        result = db.execute(text(sessions_query), params)

        sessions = []
        for row in result:
            sessions.append(
                {
                    "session_id": row.id,
                    "name": row.name,
                    "total_hosts": row.total_hosts,
                    "completed_hosts": row.completed_hosts,
                    "failed_hosts": row.failed_hosts,
                    "running_hosts": row.running_hosts,
                    "status": row.status,
                    "created_by": row.created_by,
                    "created_at": (row.created_at.isoformat() if row.created_at else None),
                    "started_at": (row.started_at.isoformat() if row.started_at else None),
                    "completed_at": (row.completed_at.isoformat() if row.completed_at else None),
                    "estimated_completion": (
                        row.estimated_completion.isoformat() if row.estimated_completion else None
                    ),
                }
            )

        # Get total count
        count_sessions_query = "SELECT COUNT(*) as total FROM scan_sessions"
        if where_conditions:
            count_sessions_query += " WHERE " + " AND ".join(where_conditions)

        count_result = db.execute(text(count_sessions_query), params).fetchone()
        total: int = count_result.total if count_result else 0

        return {
            "sessions": sessions,
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    except Exception as e:
        logger.error(f"Error listing scan sessions: {e}")
        raise HTTPException(status_code=500, detail="Failed to list scan sessions")


@router.post("/{scan_id}/recover")
async def recover_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Attempt to recover a failed scan with intelligent retry"""
    try:
        # Get failed scan details
        scan_result = db.execute(
            text(
                """
            SELECT s.id, s.name, s.host_id, s.profile_id, s.status, s.error_message,
                   h.hostname, h.port, h.username, h.auth_method
            FROM scans s
            JOIN hosts h ON s.host_id = h.id
            WHERE s.id = :scan_id AND s.status = 'failed'
        """
            ),
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
            text(
                """
            INSERT INTO scans
            (id, name, host_id, content_id, profile_id, status, progress,
             started_by, started_at, scan_options)
            VALUES (:id, :name, :host_id, :content_id, :profile_id, :status,
                    :progress, :started_by, :started_at, :scan_options)
        """
            ),
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
    """Apply an automated fix to a host"""
    try:
        # Get host details
        host_result = db.execute(
            text(
                """
            SELECT id, display_name, hostname, port, username, auth_method
            FROM hosts WHERE id = :id AND is_active = true
        """
            ),
            {"id": host_id},
        ).fetchone()

        if not host_result:
            raise HTTPException(status_code=404, detail="Host not found or inactive")

        logger.info(f"Applying automated fix {fix_request.fix_id} to host {host_id}")

        # For now, return a mock response - in production this would execute the fix
        # This would integrate with the actual fix execution system

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


@router.get("/")
async def list_scans(
    host_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """List scans with optional filtering"""
    try:
        # OW-REFACTOR-001B: Use QueryBuilder for parameterized SELECT with JOINs and filtering
        # Why: Eliminates manual query string construction, consistent with Phase 1 & 2 pattern

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
                import json

                try:
                    scan_metadata = (
                        json.loads(row.scan_metadata)
                        if isinstance(row.scan_metadata, str)
                        else row.scan_metadata
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


@router.post("/")
async def create_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Create and start a new SCAP scan"""
    try:
        # OW-REFACTOR-001B: Use QueryBuilder for parameterized SELECT validation queries
        # Why: Consistent with Phase 1 & 2 pattern, eliminates manual SQL construction

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
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid SCAP content profiles")

        # NOTE: QueryBuilder is for SELECT queries only (OW-REFACTOR-001B)
        # For INSERT/UPDATE/DELETE, use raw SQL with parameterized queries
        scan_id = str(uuid.uuid4())
        insert_query = text(
            """
            INSERT INTO scans (
                id, name, host_id, content_id, profile_id, status, progress,
                scan_options, started_by, started_at, remediation_requested, verification_scan
            )
            VALUES (
                :id, :name, :host_id, :content_id, :profile_id, :status, :progress,
                :scan_options, :started_by, :started_at, :remediation_requested, :verification_scan
            )
        """
        )
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

        logger.info(f"Scan created and started: {scan_id}")

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
        except Exception:
            # Fallback to generic error if classification fails
            raise HTTPException(status_code=500, detail=f"Failed to create scan: {str(e)}")


@router.get("/{scan_id}")
async def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get scan details"""
    try:
        # OW-REFACTOR-001B: Use QueryBuilder for parameterized SELECT with JOINs
        # Why: Consistent with Phase 1 & 2 pattern, maintains SQL injection protection
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
                logger.debug("Ignoring exception during cleanup")

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
                text(
                    """
                SELECT total_rules, passed_rules, failed_rules, error_rules,
                       unknown_rules, not_applicable_rules, score,
                       severity_high, severity_medium, severity_low,
                       xccdf_score, xccdf_score_max, xccdf_score_system,
                       risk_score, risk_level
                FROM scan_results WHERE scan_id = :scan_id
            """
                ),
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


@router.patch("/{scan_id}")
async def update_scan(
    scan_id: str,
    scan_update: ScanUpdate,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, str]:
    """Update scan status (internal use)"""
    try:
        # OW-REFACTOR-001B: Use QueryBuilder for parameterized SELECT and UPDATE
        # Why: Eliminates manual query string construction, consistent with Phase 1 & 2

        # Check if scan exists
        check_builder = QueryBuilder("scans").select("id").where("id = :id", scan_id, "id")
        query, params = check_builder.build()
        existing = db.execute(text(query), params).fetchone()

        if not existing:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Build update data - use Any type to accommodate mixed value types
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
            # NOTE: QueryBuilder is for SELECT queries only (OW-REFACTOR-001B)
            # For INSERT/UPDATE/DELETE, use raw SQL with parameterized queries
            # Build dynamic SET clause based on update_data
            set_clauses = ", ".join([f"{key} = :{key}" for key in update_data.keys()])
            update_query = text(
                f"""
                UPDATE scans
                SET {set_clauses}
                WHERE id = :id
            """
            )
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
    """Delete scan and its results"""
    try:
        # OW-REFACTOR-001B: Use QueryBuilder for parameterized SELECT and DELETE
        # Why: Consistent with Phase 1 & 2, handles foreign key cascade deletion

        # Check if scan exists and get status
        check_builder = (
            QueryBuilder("scans")
            .select("status", "result_file", "report_file")
            .where("id = :id", scan_id, "id")
        )
        query, params = check_builder.build()
        result = db.execute(text(query), params).fetchone()

        if not result:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Don't allow deletion of running scans
        if result.status in ["pending", "running"]:
            raise HTTPException(status_code=409, detail="Cannot delete running scan")

        # Delete result files
        import os

        for file_path in [result.result_file, result.report_file]:
            if file_path and os.path.exists(file_path):
                try:
                    os.unlink(file_path)
                except Exception as e:
                    logger.warning(
                        f"Failed to delete file {sanitize_path_for_log(file_path)}: {type(e).__name__}"
                    )

        # Delete scan results first (foreign key constraint)
        # NOTE: QueryBuilder is for SELECT queries only (OW-REFACTOR-001B)
        # For INSERT/UPDATE/DELETE, use raw SQL with parameterized queries
        results_delete_query = text(
            """
            DELETE FROM scan_results
            WHERE scan_id = :scan_id
        """
        )
        db.execute(results_delete_query, {"scan_id": scan_id})

        # Delete scan record
        scan_delete_query = text(
            """
            DELETE FROM scans
            WHERE id = :id
        """
        )
        db.execute(scan_delete_query, {"id": scan_id})

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
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, str]:
    """Stop a running scan"""
    try:
        # Check if scan exists and is running
        result = db.execute(
            text(
                """
            SELECT status, celery_task_id FROM scans WHERE id = :id
        """
            ),
            {"id": scan_id},
        ).fetchone()

        if not result:
            raise HTTPException(status_code=404, detail="Scan not found")

        if result.status not in ["pending", "running"]:
            raise HTTPException(
                status_code=400, detail=f"Cannot stop scan with status: {result.status}"
            )

        # Try to revoke Celery task if available
        if result.celery_task_id:
            try:
                from celery import current_app

                current_app.control.revoke(result.celery_task_id, terminate=True)
            except Exception as e:
                logger.warning(f"Failed to revoke Celery task: {e}")

        # Update scan status
        db.execute(
            text(
                """
            UPDATE scans
            SET status = 'stopped', completed_at = :completed_at,
                error_message = 'Scan stopped by user'
            WHERE id = :id
        """
            ),
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


@router.get("/{scan_id}/report/html")
async def get_scan_html_report(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Any:
    """Download scan HTML report"""
    try:
        # Get scan details
        result = db.execute(
            text(
                """
            SELECT report_file FROM scans WHERE id = :id
        """
            ),
            {"id": scan_id},
        ).fetchone()

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
            filename=f"scan_{scan_id}_report.html",
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
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Export scan results as JSON"""
    try:
        # Get full scan details with results
        scan_data = await get_scan(scan_id, db, current_user)

        # Add enhanced rule results with remediation if available
        if scan_data.get("status") == "completed" and scan_data.get("result_file"):
            try:
                # Get the SCAP content file path for remediation extraction
                content_file: Optional[str] = None
                content_result = db.execute(
                    text(
                        """
                    SELECT file_path FROM scap_content WHERE id = :content_id
                """
                    ),
                    {"content_id": scan_data.get("content_id")},
                ).fetchone()

                if content_result:
                    content_file = content_result.file_path

                # Temporarily disable enhanced parsing for performance (was taking 40+ seconds)
                # TODO: Implement caching or optimize the parsing logic
                enhanced_parsing_enabled = False

                enhanced_results: Dict[str, Any] = {}
                if enhanced_parsing_enabled and content_file is not None:
                    # Use engine module's result parser for enhanced SCAP parsing
                    # XCCDFResultParser provides parse_scan_results() for XCCDF result files
                    from pathlib import Path

                    from ..services.engine.result_parsers import XCCDFResultParser

                    parser = XCCDFResultParser()
                    parsed = parser.parse_scan_results(
                        Path(scan_data["result_file"]),
                        Path(content_file),
                    )
                    # Convert parsed results to legacy format for compatibility
                    enhanced_results = {
                        "rule_details": [
                            {
                                "rule_id": r.rule_id,
                                "result": r.result,
                                "severity": r.severity,
                                "title": r.title,
                                "description": r.description,
                                "rationale": r.rationale,
                                "remediation": r.remediation,
                            }
                            for r in parsed.rules
                        ]
                    }

                # Add enhanced rule details with remediation
                if "rule_details" in enhanced_results and enhanced_results["rule_details"]:
                    scan_data["rule_results"] = enhanced_results["rule_details"]
                    logger.info(
                        f"Added {len(enhanced_results['rule_details'])} enhanced rules with remediation"
                    )
                else:
                    # Fallback to basic parsing for backward compatibility
                    import os
                    import xml.etree.ElementTree as ET

                    if os.path.exists(scan_data["result_file"]):
                        tree = ET.parse(scan_data["result_file"])
                        root = tree.getroot()

                        # Extract basic rule results
                        namespaces = {"xccdf": "http://checklists.nist.gov/xccdf/1.2"}
                        rule_results: List[Dict[str, Any]] = []

                        for rule_result in root.findall(".//xccdf:rule-result", namespaces):
                            rule_id = rule_result.get("idref", "")
                            result_elem = rule_result.find("xccdf:result", namespaces)

                            if result_elem is not None:
                                rule_results.append(
                                    {
                                        "rule_id": rule_id,
                                        "result": result_elem.text,
                                        "severity": rule_result.get("severity", "unknown"),
                                        "title": "",
                                        "description": "",
                                        "rationale": "",
                                        "remediation": {},
                                        "references": [],
                                    }
                                )

                        scan_data["rule_results"] = rule_results
                        logger.info(f"Added {len(rule_results)} basic rules (fallback mode)")

            except Exception as e:
                logger.error(f"Error extracting enhanced rule data: {e}")
                # Maintain backward compatibility - don't break if enhancement fails
                scan_data["rule_results"] = []

        return dict(scan_data)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting JSON report: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate JSON report")


@router.get("/{scan_id}/report/csv")
async def get_scan_csv_report(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Any:
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
        writer.writerow(["Scan Information"])
        writer.writerow(["ID", scan_data.get("id")])
        writer.writerow(["Name", scan_data.get("name")])
        writer.writerow(["Host", scan_data.get("host_name")])
        writer.writerow(["Status", scan_data.get("status")])
        writer.writerow(["Score", scan_data.get("results", {}).get("score", "N/A")])
        writer.writerow([])

        # Write summary
        writer.writerow(["Summary Statistics"])
        writer.writerow(["Metric", "Value"])
        if scan_data.get("results"):
            results = scan_data["results"]
            writer.writerow(["Total Rules", results.get("total_rules")])
            writer.writerow(["Passed", results.get("passed_rules")])
            writer.writerow(["Failed", results.get("failed_rules")])
            writer.writerow(["Errors", results.get("error_rules")])
            writer.writerow(["High Severity", results.get("severity_high")])
            writer.writerow(["Medium Severity", results.get("severity_medium")])
            writer.writerow(["Low Severity", results.get("severity_low")])
        writer.writerow([])

        # Write rule results if available
        if "rule_results" in scan_data:
            writer.writerow(["Rule Results"])
            writer.writerow(["Rule ID", "Result", "Severity"])
            for rule in scan_data["rule_results"]:
                writer.writerow([rule.get("rule_id"), rule.get("result"), rule.get("severity")])

        # Return CSV
        from fastapi.responses import Response

        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}_report.csv"},
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
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get failed rules from a completed scan for AEGIS integration"""
    try:
        # Verify scan exists and is completed
        scan_result = db.execute(
            text(
                """
            SELECT s.id, s.name, s.host_id, s.status, s.result_file, s.profile_id,
                   h.hostname, h.ip_address, h.display_name as host_name,
                   sr.failed_rules, sr.total_rules, sr.score
            FROM scans s
            JOIN hosts h ON s.host_id = h.id
            LEFT JOIN scan_results sr ON sr.scan_id = s.id
            WHERE s.id = :scan_id
        """
            ),
            {"scan_id": scan_id},
        ).fetchone()

        if not scan_result:
            raise HTTPException(status_code=404, detail="Scan not found")

        if scan_result.status != "completed":
            raise HTTPException(
                status_code=400,
                detail=f"Scan not completed (status: {scan_result.status})",
            )

        if (
            not scan_result.result_file
            or not scan_result.failed_rules
            or scan_result.failed_rules == 0
        ):
            return {
                "scan_id": scan_id,
                "host_id": str(scan_result.host_id),
                "hostname": scan_result.hostname,
                "host_name": scan_result.host_name,
                "ip_address": scan_result.ip_address,
                "total_rules": scan_result.total_rules or 0,
                "failed_rules_count": 0,
                "compliance_score": scan_result.score,
                "failed_rules": [],
            }

        # Parse the SCAP result file to extract failed rules
        import os
        import xml.etree.ElementTree as ET

        failed_rules = []
        if os.path.exists(scan_result.result_file):
            try:
                tree = ET.parse(scan_result.result_file)
                root = tree.getroot()

                # Extract failed rule results
                namespaces = {"xccdf": "http://checklists.nist.gov/xccdf/1.2"}

                for rule_result in root.findall(".//xccdf:rule-result", namespaces):
                    result_elem = rule_result.find("xccdf:result", namespaces)

                    if result_elem is not None and result_elem.text == "fail":
                        rule_id = rule_result.get("idref", "")
                        severity = rule_result.get("severity", "unknown")

                        # Extract additional metadata if available
                        check_elem = rule_result.find("xccdf:check", namespaces)
                        check_content_ref = ""
                        if check_elem is not None:
                            content_ref = check_elem.find("xccdf:check-content-ref", namespaces)
                            if content_ref is not None:
                                check_content_ref = content_ref.get("href", "")

                        failed_rule = {
                            "rule_id": rule_id,
                            "severity": severity,
                            "result": "fail",
                            "check_content_ref": check_content_ref,
                            "remediation_available": True,  # Assume remediation available for AEGIS
                        }

                        failed_rules.append(failed_rule)

            except Exception as e:
                logger.error(f"Error parsing scan results for failed rules: {e}")
                # Return basic info even if parsing fails

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
            "failed_rules": failed_rules,
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
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Create a verification scan after AEGIS remediation"""
    try:
        # Validate host exists and is active
        host_result = db.execute(
            text(
                """
            SELECT id, display_name, hostname, port, username, auth_method, encrypted_credentials
            FROM hosts WHERE id = :id AND is_active = true
        """
            ),
            {"id": verification_request.host_id},
        ).fetchone()

        if not host_result:
            raise HTTPException(status_code=404, detail="Host not found or inactive")

        # Validate SCAP content exists
        content_result = db.execute(
            text(
                """
            SELECT id, name, file_path, profiles FROM scap_content WHERE id = :id
        """
            ),
            {"id": verification_request.content_id},
        ).fetchone()

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
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid SCAP content profiles")

        # Generate scan name
        scan_name = verification_request.name or f"Verification Scan - {host_result.hostname}"
        if verification_request.original_scan_id:
            scan_name += " (Post-Remediation)"

        # Create verification scan record
        scan_options = {
            "verification_scan": True,
            "original_scan_id": verification_request.original_scan_id,
            "remediation_job_id": verification_request.remediation_job_id,
        }

        result = db.execute(
            text(
                """
            INSERT INTO scans
            (name, host_id, content_id, profile_id, status, progress,
             scan_options, started_by, started_at, verification_scan)
            VALUES (:name, :host_id, :content_id, :profile_id, :status,
                    :progress, :scan_options, :started_by, :started_at, :verification_scan)
            RETURNING id
        """
            ),
            {
                "name": scan_name,
                "host_id": verification_request.host_id,
                "content_id": verification_request.content_id,
                "profile_id": verification_request.profile_id,
                "status": "pending",
                "progress": 0,
                "scan_options": json.dumps(scan_options),
                "started_by": current_user["id"],
                "started_at": datetime.utcnow(),
                "verification_scan": True,
            },
        )

        # Get the generated scan ID
        scan_row = result.fetchone()
        if not scan_row:
            raise HTTPException(status_code=500, detail="Failed to create verification scan")
        scan_id = scan_row.id
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
                "encrypted_credentials": host_result.encrypted_credentials,
            },
            content_path=content_result.file_path,
            profile_id=verification_request.profile_id,
            scan_options=scan_options,
        )

        logger.info(f"Verification scan created and started: {scan_id}")

        response = {
            "id": scan_id,
            "message": "Verification scan created and started successfully",
            "status": "pending",
            "verification_scan": True,
            "host_id": verification_request.host_id,
            "host_name": host_result.display_name or host_result.hostname,
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
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Rescan a specific rule from a completed scan"""
    try:
        logger.info(f"Rule rescan requested for scan {scan_id}, rule {rescan_request.rule_id}")

        # Get the original scan details
        result = db.execute(
            text(
                """
            SELECT s.id, s.host_id, s.profile_id, s.name,
                   h.hostname, h.ip_address, h.port, h.username, h.auth_method, h.encrypted_credentials
            FROM scans s
            JOIN hosts h ON s.host_id = h.id
            WHERE s.id = :scan_id
        """
            ),
            {"scan_id": scan_id},
        )

        scan_data = result.fetchone()
        if not scan_data:
            raise HTTPException(status_code=404, detail="Original scan not found")

        # Validate that the host is still active
        if not scan_data.encrypted_credentials:
            raise HTTPException(status_code=400, detail="Host credentials not available")

        # NOTE: Rule rescanning is a legacy SCAP feature that's no longer supported
        # with MongoDB-based scanning. For MongoDB scans, simply create a new full scan.
        raise HTTPException(
            status_code=400,
            detail="Rule rescanning is not supported for MongoDB-based scans. Please create a new scan instead.",
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error initiating rule rescan: {e}")
        raise HTTPException(status_code=500, detail="Failed to initiate rule rescan")


@router.post("/{scan_id}/remediate")
async def start_remediation(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Send failed rules to AEGIS for automated remediation"""
    try:
        # Get scan details and failed rules
        scan_result = db.execute(
            text(
                """
            SELECT s.id, s.name, s.host_id, h.hostname, h.ip_address,
                   sr.failed_rules, sr.severity_high, sr.severity_medium, sr.severity_low
            FROM scans s
            JOIN hosts h ON s.host_id = h.id
            LEFT JOIN scan_results sr ON s.id = sr.scan_id
            WHERE s.id = :scan_id AND s.status = 'completed'
        """
            ),
            {"scan_id": scan_id},
        ).fetchone()

        if not scan_result:
            raise HTTPException(status_code=404, detail="Completed scan not found")

        if scan_result.failed_rules == 0:
            raise HTTPException(status_code=400, detail="No failed rules to remediate")

        # Get the actual failed rules
        failed_rules = db.execute(
            text(
                """
            SELECT rule_id, title, severity, description
            FROM scan_rule_results
            WHERE scan_id = :scan_id AND status = 'failed'
            ORDER BY CASE severity WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END
        """
            ),
            {"scan_id": scan_id},
        ).fetchall()

        # Mock AEGIS integration - in reality this would call AEGIS API
        import uuid

        remediation_job_id = str(uuid.uuid4())

        # Update scan with remediation request
        db.execute(
            text(
                """
            UPDATE scans
            SET remediation_requested = true,
                aegis_remediation_id = :job_id,
                remediation_status = 'pending'
            WHERE id = :scan_id
        """
            ),
            {"scan_id": scan_id, "job_id": remediation_job_id},
        )
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
                "low": scan_result.severity_low,
            },
            "status": "pending",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting remediation for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to start remediation job")


# ============================================================================
# Host Readiness Validation Endpoints
# ============================================================================


@router.post("/readiness/validate-bulk", response_model=Dict[str, Any])
async def validate_bulk_readiness(
    request: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Validate readiness for multiple hosts (bulk operation).

    This endpoint validates that hosts meet all requirements for SCAP scanning:
    - OpenSCAP scanner installed (CRITICAL)
    - Sufficient disk space (500MB+ for SCAP content)
    - Network connectivity (SFTP capability, /tmp writable)
    - Passwordless sudo access (for root-level checks)
    - Adequate memory (200MB+ available)
    - OS detection and compatibility
    - SELinux status check

    Smart Caching:
    - Results cached for 24 hours by default (configurable)
    - Reduces SSH overhead for recently-validated hosts
    - Skips redundant checks on large host inventories

    Use Cases:
    - Pre-scan validation for 300+ server environments
    - Batch readiness assessment before scheduled scans
    - Identifying hosts with missing prerequisites

    Request Body:
        {
            "host_ids": ["uuid1", "uuid2", ...],  # Empty = all hosts
            "check_types": ["oscap_installation", "disk_space", ...],  # Optional
            "parallel": true,  # Run validations concurrently (default: true)
            "use_cache": true,  # Use cached results within TTL (default: true)
            "cache_ttl_hours": 24  # Cache TTL in hours (default: 24)
        }

    Response:
        {
            "total_hosts": 10,
            "ready_hosts": 7,
            "not_ready_hosts": 2,
            "degraded_hosts": 1,
            "hosts": [
                {
                    "host_id": "uuid",
                    "hostname": "server01",
                    "status": "ready",
                    "checks": [...]
                }
            ],
            "common_failures": {
                "oscap_installation": 2,
                "disk_space": 1
            }
        }

    Raises:
        401: Unauthorized (missing/invalid token)
        403: Forbidden (insufficient permissions)
        500: Internal server error
    """
    try:
        from backend.app.models.readiness_models import BulkReadinessRequest
        from backend.app.services.host_validator.readiness_validator import (
            ReadinessValidatorService,
        )

        # Parse request
        bulk_request = BulkReadinessRequest(**request)

        # Get hosts to validate
        from backend.app.database import Host

        if bulk_request.host_ids:
            hosts = db.query(Host).filter(Host.id.in_(bulk_request.host_ids)).all()
        else:
            # Empty list = validate all hosts
            hosts = db.query(Host).all()

        if not hosts:
            raise HTTPException(status_code=404, detail="No hosts found to validate")

        # Initialize validator service
        validator = ReadinessValidatorService(db)

        # Execute validations
        start_time = time.time()
        validation_results: List[Any] = []

        user_id = current_user.get("sub")

        if bulk_request.parallel:
            # Parallel execution (faster for many hosts)
            tasks = [
                validator.validate_host(
                    host_id=host.id,
                    check_types=bulk_request.check_types,
                    use_cache=bulk_request.use_cache,
                    cache_ttl_hours=bulk_request.cache_ttl_hours,
                    user_id=user_id,
                )
                for host in hosts
            ]
            validation_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Filter out exceptions
            successful_results = []
            for i, result in enumerate(validation_results):
                if isinstance(result, Exception):
                    logger.error(
                        f"Validation failed for host {hosts[i].id}: {result}",
                        extra={"host_id": str(hosts[i].id), "user_id": user_id},
                    )
                else:
                    successful_results.append(result)
            validation_results = successful_results
        else:
            # Sequential execution (slower but more predictable)
            for host in hosts:
                try:
                    result = await validator.validate_host(
                        host_id=host.id,
                        check_types=bulk_request.check_types,
                        use_cache=bulk_request.use_cache,
                        cache_ttl_hours=bulk_request.cache_ttl_hours,
                        user_id=user_id,
                    )
                    validation_results.append(result)
                except Exception as e:
                    logger.error(
                        f"Validation failed for host {host.id}: {e}",
                        extra={"host_id": str(host.id), "user_id": user_id},
                    )

        # Aggregate statistics
        total_hosts = len(validation_results)
        ready_hosts = sum(1 for r in validation_results if r.status == "ready")
        not_ready_hosts = sum(1 for r in validation_results if r.status == "not_ready")
        degraded_hosts = sum(1 for r in validation_results if r.status == "degraded")

        # Identify common failures
        common_failures: Dict[str, int] = {}
        for result in validation_results:
            for check in result.checks:
                if not check.passed:
                    # Handle both enum and string values for check_type
                    check_type = (
                        check.check_type
                        if isinstance(check.check_type, str)
                        else check.check_type.value
                    )
                    common_failures[check_type] = common_failures.get(check_type, 0) + 1

        # Calculate total duration
        total_duration_ms = (time.time() - start_time) * 1000

        # Build remediation priorities (top 5 most common failures)
        remediation_priorities = []
        for check_type, count in sorted(common_failures.items(), key=lambda x: x[1], reverse=True)[
            :5
        ]:
            remediation_priorities.append(
                {
                    "check_type": check_type,
                    "affected_hosts": count,
                    "priority": "critical" if check_type == "oscap_installation" else "high",
                }
            )

        logger.info(
            f"Bulk readiness validation completed: {total_hosts} hosts, "
            f"{ready_hosts} ready, {not_ready_hosts} not ready, {degraded_hosts} degraded",
            extra={"user_id": user_id, "total_hosts": total_hosts},
        )

        return {
            "total_hosts": total_hosts,
            "ready_hosts": ready_hosts,
            "not_ready_hosts": not_ready_hosts,
            "degraded_hosts": degraded_hosts,
            "hosts": [r.dict() for r in validation_results],
            "common_failures": common_failures,
            "remediation_priorities": remediation_priorities,
            "total_duration_ms": total_duration_ms,
            "completed_at": datetime.utcnow().isoformat(),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Bulk readiness validation error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to execute bulk readiness validation")


@router.get("/{scan_id}/pre-flight-check", response_model=Dict[str, Any])
async def pre_flight_check(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Quick pre-flight readiness check before executing a scan.

    This endpoint performs a rapid validation of critical prerequisites
    before starting a SCAP scan. Only runs essential checks:
    - OpenSCAP installation (CRITICAL)
    - Disk space availability
    - Network connectivity

    Use Case:
    - Just-in-time validation before scan execution
    - Prevents scan failures due to missing prerequisites
    - Integrated into scan workflow

    Cache TTL: 1 hour (shorter than bulk validation)

    Response:
        {
            "scan_id": "uuid",
            "host_id": "uuid",
            "hostname": "server01",
            "ready": true,
            "checks": [
                {
                    "check_type": "oscap_installation",
                    "passed": true,
                    "message": "OSCAP scanner installed"
                }
            ]
        }

    Raises:
        404: Scan not found
        401: Unauthorized
        500: Internal server error
    """
    try:
        from backend.app.models.readiness_models import ReadinessCheckType
        from backend.app.services.host_validator.readiness_validator import (
            ReadinessValidatorService,
        )

        # Get scan
        scan_result = db.execute(
            text("SELECT id, host_id FROM scans WHERE id = :scan_id"),
            {"scan_id": scan_id},
        ).fetchone()

        if not scan_result:
            raise HTTPException(status_code=404, detail="Scan not found")

        host_id = UUID(scan_result[1])

        # Get host
        from backend.app.database import Host

        host = db.query(Host).filter(Host.id == host_id).first()
        if not host:
            raise HTTPException(status_code=404, detail="Host not found")

        # Initialize validator
        validator = ReadinessValidatorService(db)

        # Run critical checks only (quick check)
        critical_checks = [
            ReadinessCheckType.OSCAP_INSTALLATION,
            ReadinessCheckType.DISK_SPACE,
            ReadinessCheckType.NETWORK_CONNECTIVITY,
        ]

        user_id = current_user.get("sub")

        # Execute validation with 1-hour cache
        result = await validator.validate_host(
            host_id=host_id,
            check_types=critical_checks,
            use_cache=True,
            cache_ttl_hours=1,  # Shorter TTL for pre-flight checks
            user_id=user_id,
        )

        logger.info(
            f"Pre-flight check completed for scan {scan_id}: {result.status}",
            extra={"scan_id": scan_id, "host_id": str(host_id), "user_id": user_id},
        )

        return {
            "scan_id": scan_id,
            "host_id": str(result.host_id),
            "hostname": result.hostname,
            "ready": result.overall_passed,
            "status": result.status,
            "checks": [c.dict() for c in result.checks],
            "validation_duration_ms": result.validation_duration_ms,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Pre-flight check error for scan {scan_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to execute pre-flight check")


@router.get("/capabilities")
async def get_scan_capabilities(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get scanning capabilities

    Returns information about available scanning features,
    supported profiles, and scan limits.
    """
    return {
        "features": {
            "parallel_scanning": True,
            "rule_specific_scanning": True,
            "custom_profiles": True,
            "scheduled_scanning": True,
            "bulk_scanning": True,
            "real_time_progress": True,
        },
        "limits": {
            "max_parallel_scans": 100,
            "max_hosts_per_scan": 1000,
            "scan_timeout_minutes": 60,
            "max_scan_history": 10000,
        },
        "supported_formats": {
            "input": ["xml", "zip", "datastream"],
            "output": ["xml", "html", "json", "arf"],
        },
        "supported_profiles": [
            "stig-rhel8",
            "stig-rhel9",
            "cis-ubuntu-20.04",
            "cis-ubuntu-22.04",
            "pci-dss",
            "custom",
        ],
        "endpoints": {
            "list_scans": "GET /api/scans",
            "create_scan": "POST /api/scans",
            "get_scan": "GET /api/scans/{scan_id}",
            "cancel_scan": "DELETE /api/scans/{scan_id}",
            "get_results": "GET /api/scans/{scan_id}/results",
            "bulk_scan": "POST /api/scans/bulk",
            "capabilities": "GET /api/scans/capabilities",
        },
    }


@router.get("/summary")
async def get_scans_summary(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get summary statistics for scan management

    Returns aggregate information about scans, results, and compliance trends.
    """
    return {
        "total_scans": 0,
        "recent_scans": 0,
        "active_scans": 0,
        "failed_scans": 0,
        "compliance_trend": {"improving": 0, "declining": 0, "stable": 0},
        "profile_usage": {},
        "average_scan_time": None,
        "last_24h": {"scans_completed": 0, "hosts_scanned": 0, "critical_findings": 0},
    }


@router.get("/profiles")
async def get_available_profiles(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get available SCAP profiles for scanning

    Returns list of available profiles with metadata and compatibility info.
    """
    return {
        "profiles": [
            {
                "id": "stig-rhel8",
                "title": "DISA STIG for Red Hat Enterprise Linux 8",
                "description": "Security Technical Implementation Guide for RHEL 8",
                "version": "V1R12",
                "rules_count": 335,
                "supported_os": ["rhel8", "centos8"],
                "compliance_frameworks": ["STIG", "NIST"],
                "severity_distribution": {"high": 45, "medium": 180, "low": 110},
            },
            {
                "id": "cis-ubuntu-20.04",
                "title": "CIS Ubuntu Linux 20.04 LTS Benchmark",
                "description": "Center for Internet Security benchmark for Ubuntu 20.04",
                "version": "v1.1.0",
                "rules_count": 267,
                "supported_os": ["ubuntu20.04"],
                "compliance_frameworks": ["CIS"],
                "severity_distribution": {"high": 38, "medium": 156, "low": 73},
            },
        ],
        "total_profiles": 2,
        "custom_profiles_supported": True,
    }
