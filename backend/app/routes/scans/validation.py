"""
Scan Validation and Readiness Endpoints

This module provides endpoints for scan validation, host readiness checking,
pre-flight verification, and system capabilities discovery.

Endpoints:
    POST /validate                        - Pre-flight validation (LEGACY)
    POST /hosts/{host_id}/quick-scan      - Quick scan with defaults (LEGACY)
    POST /verify                          - Verification scan (LEGACY)
    POST /{scan_id}/rescan/rule           - Rescan specific rule (DISABLED)
    POST /{scan_id}/remediate             - Start AEGIS remediation
    POST /readiness/validate-bulk         - Bulk host readiness validation
    GET  /{scan_id}/pre-flight-check      - Pre-flight readiness check
    GET  /capabilities                    - Get scanning capabilities
    GET  /summary                         - Get scan summary statistics
    GET  /profiles                        - Get available SCAP profiles

Architecture Notes:
    - ReadinessValidatorService handles host prerequisite validation
    - Error classification provides user-friendly error messages
    - QueryBuilder used for SELECT queries (SQL injection prevention)
    - Parameterized raw SQL for INSERT/UPDATE operations
    - Background tasks for async scan execution

Security Notes:
    - All endpoints require JWT authentication
    - Error messages sanitized to prevent information disclosure
    - Credential resolution via AuthService only
    - Audit logging for security-relevant operations

Legacy Endpoints:
    Endpoints marked (LEGACY) use SCAP content files instead of the
    compliance rules database. For compliance scanning, use /api/scans/ endpoints.
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.auth import get_current_user
from backend.app.database import get_db
from backend.app.models.enums import ScanPriority
from backend.app.models.error_models import ValidationResultResponse
from backend.app.routes.scans.helpers import add_deprecation_header, sanitize_http_error
from backend.app.routes.scans.models import (
    QuickScanRequest,
    QuickScanResponse,
    RuleRescanRequest,
    ValidationRequest,
    VerificationScanRequest,
)
from backend.app.services.error_classification import get_error_classification_service
from backend.app.services.error_sanitization import get_error_sanitization_service
from backend.app.services.scan_intelligence import RecommendedScanProfile, ScanIntelligenceService
from backend.app.tasks.scan_tasks import execute_scan_task
from backend.app.utils.query_builder import QueryBuilder

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Scan Validation"])

# Initialize error services (lazy loaded)
error_service = get_error_classification_service()


# =============================================================================
# VALIDATION ENDPOINTS (Legacy SCAP Content)
# =============================================================================


@router.post("/validate")
async def validate_scan_configuration(
    validation_request: ValidationRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> ValidationResultResponse:
    """
    Pre-flight validation for scan configuration.

    Supports two validation modes:
    1. Legacy SCAP content: Validates against SCAP content files
    2. MongoDB scanning: Validates host readiness for MongoDB-based scans

    Validates that a host is ready for scanning by checking:
    - Host exists and is active
    - SCAP content exists and contains requested profile (legacy mode)
    - Compliance rules exist for platform/framework (MongoDB mode)
    - Credentials are available and valid
    - SSH connectivity and prerequisites

    Args:
        validation_request: Host, content/profile OR platform/framework to validate.
        request: FastAPI request for client context.
        response: FastAPI response for deprecation headers.
        db: Database session.
        current_user: Authenticated user from JWT.

    Returns:
        ValidationResultResponse with pass/fail status and any issues.

    Raises:
        HTTPException 404: Host or SCAP content not found.
        HTTPException 400: Profile not in content or credentials unavailable.
        HTTPException 500: Validation system error.

    Example (Legacy):
        POST /api/scans/validate
        {
            "host_id": "550e8400-e29b-41d4-a716-446655440000",
            "content_id": 1,
            "profile_id": "xccdf_org.ssgproject.content_profile_stig"
        }

    Example (MongoDB):
        POST /api/scans/validate
        {
            "host_id": "550e8400-e29b-41d4-a716-446655440000",
            "platform": "rhel",
            "platform_version": "8",
            "framework": "disa_stig"
        }

    Security:
        - Requires authenticated user
        - Credentials resolved via AuthService (never exposed)
        - Error messages sanitized for non-admin users
    """
    # Detect validation mode
    is_mongodb_mode = (
        validation_request.platform is not None
        and validation_request.platform_version is not None
        and validation_request.framework is not None
    )

    # Add deprecation header only for legacy SCAP content mode
    if not is_mongodb_mode:
        add_deprecation_header(response, "validate_scan_configuration")

    try:
        logger.info(
            "Pre-flight validation requested",
            extra={
                "host_id": validation_request.host_id,
                "mode": "mongodb" if is_mongodb_mode else "legacy",
            },
        )

        # Get host details using QueryBuilder for consistent parameterization
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
            .where("id = :id", validation_request.host_id, "id")
            .where("is_active = :is_active", True, "is_active")
        )
        query, params = host_builder.build()
        host_result = db.execute(text(query), params).fetchone()

        if not host_result:
            raise HTTPException(status_code=404, detail="Host not found or inactive")

        # Mode-specific validation
        if is_mongodb_mode:
            # MongoDB mode: Validate compliance rules exist for platform/framework
            from backend.app.repositories.compliance_repository import ComplianceRuleRepository

            try:
                repo = ComplianceRuleRepository()
                # Check if rules exist for the specified framework
                rule_count = await repo.count({f"frameworks.{validation_request.framework}": {"$exists": True}})

                if rule_count == 0:
                    raise HTTPException(
                        status_code=400,
                        detail=f"No compliance rules found for framework: {validation_request.framework}",
                    )

                logger.info(
                    f"MongoDB validation: Found {rule_count} rules for " f"framework={validation_request.framework}"
                )
            except HTTPException:
                raise
            except Exception as e:
                logger.warning(
                    f"MongoDB rule lookup failed (non-critical): {e}. " "Proceeding with host validation only."
                )
        else:
            # Legacy mode: Get SCAP content details using QueryBuilder
            content_builder = (
                QueryBuilder("scap_content")
                .select("id", "name", "file_path", "profiles")
                .where("id = :id", validation_request.content_id, "id")
            )
            query, params = content_builder.build()
            content_result = db.execute(text(query), params).fetchone()

            if not content_result:
                raise HTTPException(status_code=404, detail="SCAP content not found")

            # Validate profile exists in content
            if content_result.profiles:
                try:
                    profiles = json.loads(content_result.profiles)
                    profile_ids = [p.get("id") for p in profiles if p.get("id")]
                    if validation_request.profile_id not in profile_ids:
                        raise HTTPException(status_code=400, detail="Profile not found in SCAP content")
                except json.JSONDecodeError:
                    raise HTTPException(status_code=400, detail="Invalid SCAP content profiles")

        # Resolve credentials using auth service
        try:
            from backend.app.config import get_settings
            from backend.app.encryption import EncryptionConfig, create_encryption_service
            from backend.app.services.auth import get_auth_service

            settings = get_settings()
            encryption_service = create_encryption_service(master_key=settings.master_key, config=EncryptionConfig())
            auth_service = get_auth_service(db, encryption_service)

            use_default = host_result.auth_method in ["default", "system_default"]
            target_id = str(host_result.id) if not use_default and host_result.id else ""

            credential_data = auth_service.resolve_credential(target_id=target_id, use_default=use_default)

            if not credential_data:
                raise HTTPException(status_code=400, detail="No credentials available for host")

            # Extract credential value based on authentication method
            if credential_data.auth_method.value == "password":
                credential_value = credential_data.password
            elif credential_data.auth_method.value in ["ssh_key", "ssh-key"]:
                credential_value = credential_data.private_key
            else:
                credential_value = credential_data.password or ""

        except HTTPException:
            raise
        except Exception as e:
            logger.error(
                "Credential resolution failed for validation",
                extra={"host_id": validation_request.host_id, "error": str(e)},
            )
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
        # Pass host_id and db to enable ReadinessValidatorService delegation
        internal_result = await error_service.validate_scan_prerequisites(
            hostname=host_result.hostname,
            port=host_result.port,
            username=credential_data.username,
            auth_method=credential_data.auth_method.value,
            credential=credential_value or "",
            host_id=str(host_result.id),
            db=db,
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

        # Build context based on validation mode
        error_context: Dict[str, Any] = {
            "operation": "scan_validation",
            "host_id": validation_request.host_id,
        }
        if validation_request.content_id is not None:
            error_context["content_id"] = validation_request.content_id
        if validation_request.framework is not None:
            error_context["framework"] = validation_request.framework
            error_context["platform"] = validation_request.platform

        classified_error = await error_service.classify_error(
            e,
            error_context,
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
    response: Response,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> QuickScanResponse:
    """
    Start scan with intelligent defaults (LEGACY).

    DEPRECATION NOTICE: This endpoint uses SCAP content files for scanning.
    For compliance scanning, use POST /api/scans/ instead.

    Provides "Zero to Scan in 3 Clicks" experience by auto-detecting
    the best profile based on host OS and previous scan history.

    Args:
        host_id: UUID of the target host.
        quick_scan_request: Optional template and priority settings.
        background_tasks: FastAPI background task manager.
        response: FastAPI response for deprecation headers.
        db: Database session.
        current_user: Authenticated user from JWT.

    Returns:
        QuickScanResponse with scan ID, status, and suggested profile.

    Raises:
        HTTPException 404: Host or SCAP content not found.
        HTTPException 400: No profiles available in SCAP content.
        HTTPException 500: Scan creation error.

    Example:
        POST /api/scans/hosts/550e8400-e29b-41d4-a716-446655440000/quick-scan
        {
            "template_id": "auto",
            "priority": "normal"
        }

    Security:
        - Requires authenticated user
        - Credentials resolved via AuthService
        - Background task executes scan asynchronously
    """
    # Add deprecation header for legacy SCAP content endpoint
    add_deprecation_header(response, "quick_scan")

    try:
        logger.info(f"Quick scan requested for host {host_id} with template {quick_scan_request.template_id}")

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

        # Get host details for validation using QueryBuilder
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
            .where("id = :id", host_id, "id")
            .where("is_active = :is_active", True, "is_active")
        )
        query, params = host_builder.build()
        host_result = db.execute(text(query), params).fetchone()

        if not host_result:
            raise HTTPException(status_code=404, detail="Host not found or inactive")

        # Get SCAP content details using QueryBuilder (LEGACY: scap_content table)
        content_builder = (
            QueryBuilder("scap_content")
            .select("id", "name", "file_path", "profiles")
            .where("id = :id", content_id, "id")
        )
        query, params = content_builder.build()
        content_result = db.execute(text(query), params).fetchone()

        if not content_result:
            raise HTTPException(status_code=404, detail="SCAP content not found")

        # Validate profile exists in content
        if content_result.profiles:
            try:
                profiles = json.loads(content_result.profiles)
                profile_ids = [p.get("id") for p in profiles if p.get("id")]
                if template_id not in profile_ids:
                    # Fall back to first available profile
                    if profile_ids:
                        template_id = profile_ids[0]
                        logger.warning(f"Requested profile not found, using fallback: {template_id}")
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
            from backend.app.config import get_settings
            from backend.app.encryption import EncryptionConfig, create_encryption_service
            from backend.app.services.auth import get_auth_service

            settings = get_settings()
            encryption_service = create_encryption_service(master_key=settings.master_key, config=EncryptionConfig())
            auth_service = get_auth_service(db, encryption_service)

            use_default = host_result.auth_method in ["default", "system_default"]
            target_id = str(host_result.id) if not use_default and host_result.id else ""

            credential_data = auth_service.resolve_credential(target_id=target_id, use_default=use_default)

            if credential_data:
                # Queue async validation (placeholder - function not yet implemented)
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
                    :progress, :scan_options, :started_by, :started_at,
                    :remediation_requested, :verification_scan)
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
                logger.debug("Ignoring exception during duration parsing")

        return QuickScanResponse(
            id=scan_id,
            message="Scan created and started successfully",
            status="pending",
            suggested_profile=suggested_profile
            or RecommendedScanProfile(
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


@router.post("/verify")
async def create_verification_scan(
    verification_request: VerificationScanRequest,
    background_tasks: BackgroundTasks,
    response: Response,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Create a verification scan after AEGIS remediation (LEGACY).

    DEPRECATION NOTICE: This endpoint uses SCAP content files for scanning.
    For compliance scanning, use /api/scans/ endpoints instead.

    Verification scans re-run the same profile to confirm that remediation
    actions successfully resolved previously failing rules.

    Args:
        verification_request: Host, content, profile, and original scan reference.
        background_tasks: FastAPI background task manager.
        response: FastAPI response for deprecation headers.
        db: Database session.
        current_user: Authenticated user from JWT.

    Returns:
        Dict with scan_id, message, status, and optional references.

    Raises:
        HTTPException 404: Host or SCAP content not found.
        HTTPException 400: Invalid profile or configuration.
        HTTPException 500: Scan creation error.

    Example:
        POST /api/scans/verify
        {
            "host_id": "550e8400-e29b-41d4-a716-446655440000",
            "content_id": 1,
            "profile_id": "xccdf_org.ssgproject.content_profile_stig",
            "original_scan_id": "another-uuid",
            "remediation_job_id": "aegis-job-id"
        }

    Security:
        - Requires authenticated user
        - Links verification to original scan for audit trail
    """
    # Add deprecation header for legacy SCAP content endpoint
    add_deprecation_header(response, "create_verification_scan")

    try:
        # Validate host exists and is active using QueryBuilder
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
            .where("id = :id", verification_request.host_id, "id")
            .where("is_active = :is_active", True, "is_active")
        )
        query, params = host_builder.build()
        host_result = db.execute(text(query), params).fetchone()

        if not host_result:
            raise HTTPException(status_code=404, detail="Host not found or inactive")

        # Validate SCAP content exists using QueryBuilder (LEGACY: scap_content table)
        content_builder = (
            QueryBuilder("scap_content")
            .select("id", "name", "file_path", "profiles")
            .where("id = :id", verification_request.content_id, "id")
        )
        query, params = content_builder.build()
        content_result = db.execute(text(query), params).fetchone()

        if not content_result:
            raise HTTPException(status_code=404, detail="SCAP content not found")

        # Validate profile exists in content
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

        response_data = {
            "id": scan_id,
            "message": "Verification scan created and started successfully",
            "status": "pending",
            "verification_scan": True,
            "host_id": verification_request.host_id,
            "host_name": host_result.display_name or host_result.hostname,
        }

        # Add reference info if provided
        if verification_request.original_scan_id:
            response_data["original_scan_id"] = verification_request.original_scan_id
        if verification_request.remediation_job_id:
            response_data["remediation_job_id"] = verification_request.remediation_job_id

        return response_data

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating verification scan: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to create verification scan: {str(e)}")


# =============================================================================
# RULE RESCAN AND REMEDIATION ENDPOINTS
# =============================================================================


@router.post("/{scan_id}/rescan/rule")
async def rescan_rule(
    scan_id: str,
    rescan_request: RuleRescanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Rescan a specific rule from a completed scan (DISABLED).

    This endpoint is no longer supported for MongoDB-based scanning.
    For MongoDB scans, create a new full scan instead.

    Args:
        scan_id: UUID of the original scan.
        rescan_request: Rule ID to rescan.
        background_tasks: FastAPI background task manager.
        db: Database session.
        current_user: Authenticated user from JWT.

    Raises:
        HTTPException 404: Original scan not found.
        HTTPException 400: Rule rescanning not supported (always raised).
        HTTPException 500: System error.

    Note:
        Rule-specific rescanning is a legacy feature that required SCAP
        content files. MongoDB-based scanning evaluates rules differently,
        making single-rule rescanning impractical. Create a new scan instead.
    """
    try:
        logger.info(f"Rule rescan requested for scan {scan_id}, rule {rescan_request.rule_id}")

        # Get the original scan details
        result = db.execute(
            text(
                """
            SELECT s.id, s.host_id, s.profile_id, s.name,
                   h.hostname, h.ip_address, h.port, h.username,
                   h.auth_method, h.encrypted_credentials
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

        # Validate that the host has credentials
        if not scan_data.encrypted_credentials:
            raise HTTPException(status_code=400, detail="Host credentials not available")

        # Rule rescanning is a legacy SCAP feature that's no longer supported
        # with MongoDB-based scanning. For MongoDB scans, create a new full scan.
        raise HTTPException(
            status_code=400,
            detail="Rule rescanning is not supported for MongoDB-based scans. " "Please create a new scan instead.",
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
    """
    Send failed rules to AEGIS for automated remediation.

    Initiates remediation workflow for all failed rules from a completed scan.
    Requires AEGIS integration to be configured.

    Args:
        scan_id: UUID of the completed scan with failed rules.
        db: Database session.
        current_user: Authenticated user from JWT.

    Returns:
        Dict with job_id, message, scan reference, and severity breakdown.

    Raises:
        HTTPException 404: Completed scan not found.
        HTTPException 400: No failed rules to remediate.
        HTTPException 500: Remediation job creation error.

    Example:
        POST /api/scans/550e8400-e29b-41d4-a716-446655440000/remediate

    Response:
        {
            "job_id": "remediation-job-uuid",
            "message": "Remediation job created for 15 failed rules",
            "scan_id": "scan-uuid",
            "host": "server01.example.com",
            "failed_rules_count": 15,
            "severity_breakdown": {"high": 5, "medium": 7, "low": 3},
            "status": "pending"
        }

    Security:
        - Requires authenticated user
        - Audit trail created via aegis_remediation_id
    """
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

        # Get the actual failed rules for logging
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

        # Create remediation job (in production, this calls AEGIS API)
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


# =============================================================================
# HOST READINESS VALIDATION ENDPOINTS
# =============================================================================


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

    Args:
        request: Dict with host_ids, check_types, parallel, use_cache, cache_ttl_hours.
        db: Database session.
        current_user: Authenticated user from JWT.

    Returns:
        Dict with total_hosts, ready/not_ready/degraded counts, host details,
        common_failures, remediation_priorities, and timing.

    Raises:
        HTTPException 404: No hosts found to validate.
        HTTPException 500: Validation system error.

    Example:
        POST /api/scans/readiness/validate-bulk
        {
            "host_ids": ["uuid1", "uuid2"],
            "check_types": ["oscap_installation", "disk_space"],
            "parallel": true,
            "use_cache": true,
            "cache_ttl_hours": 24
        }

    Security:
        - Requires authenticated user
        - SSH operations via UnifiedSSHService (audit logged)
    """
    try:
        from backend.app.models.readiness_models import BulkReadinessRequest
        from backend.app.services.host_validator.readiness_validator import ReadinessValidatorService

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
                    check_type = check.check_type if isinstance(check.check_type, str) else check.check_type.value
                    common_failures[check_type] = common_failures.get(check_type, 0) + 1

        # Calculate total duration
        total_duration_ms = (time.time() - start_time) * 1000

        # Build remediation priorities (top 5 most common failures)
        remediation_priorities = []
        for check_type, count in sorted(common_failures.items(), key=lambda x: x[1], reverse=True)[:5]:
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

    Args:
        scan_id: UUID of the scan to check prerequisites for.
        db: Database session.
        current_user: Authenticated user from JWT.

    Returns:
        Dict with scan_id, host_id, hostname, ready status, and checks.

    Raises:
        HTTPException 404: Scan or host not found.
        HTTPException 500: Pre-flight check error.

    Example:
        GET /api/scans/550e8400-e29b-41d4-a716-446655440000/pre-flight-check

    Response:
        {
            "scan_id": "uuid",
            "host_id": "uuid",
            "hostname": "server01",
            "ready": true,
            "status": "ready",
            "checks": [
                {
                    "check_type": "oscap_installation",
                    "passed": true,
                    "message": "OSCAP scanner installed"
                }
            ],
            "validation_duration_ms": 1523.4
        }

    Security:
        - Requires authenticated user
        - SSH operations via UnifiedSSHService
    """
    try:
        from backend.app.models.readiness_models import ReadinessCheckType
        from backend.app.services.host_validator.readiness_validator import ReadinessValidatorService

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


# =============================================================================
# CAPABILITIES AND DISCOVERY ENDPOINTS
# =============================================================================


@router.get("/capabilities")
async def get_scan_capabilities(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get scanning capabilities and system configuration.

    Returns information about available scanning features,
    supported profiles, format support, and scan limits.

    Args:
        current_user: Authenticated user from JWT.

    Returns:
        Dict with features, limits, supported_formats, supported_profiles,
        and endpoint documentation.

    Example:
        GET /api/scans/capabilities

    Response:
        {
            "features": {
                "parallel_scanning": true,
                "bulk_scanning": true,
                ...
            },
            "limits": {
                "max_parallel_scans": 100,
                ...
            },
            "supported_formats": {...},
            "supported_profiles": [...],
            "endpoints": {...}
        }

    Security:
        - Requires authenticated user
        - Read-only endpoint (no sensitive data)
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
    Get summary statistics for scan management.

    Returns aggregate information about scans, results, and compliance trends.
    Useful for dashboard widgets and overview displays.

    Args:
        current_user: Authenticated user from JWT.

    Returns:
        Dict with scan counts, compliance trends, profile usage, and
        last 24-hour statistics.

    Example:
        GET /api/scans/summary

    Response:
        {
            "total_scans": 1250,
            "recent_scans": 45,
            "active_scans": 3,
            "failed_scans": 12,
            "compliance_trend": {"improving": 8, "declining": 2, "stable": 15},
            "profile_usage": {"stig-rhel8": 450, ...},
            "average_scan_time": "12.5 min",
            "last_24h": {"scans_completed": 15, ...}
        }

    Security:
        - Requires authenticated user
        - Returns aggregate data only (no sensitive details)

    Note:
        Currently returns placeholder data. Full implementation requires
        aggregation queries across scans and scan_results tables.
    """
    # Placeholder implementation - full version would query database
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
    Get available SCAP profiles for scanning.

    Returns list of available profiles with metadata and compatibility info.
    Includes rule counts, severity distributions, and supported operating systems.

    Args:
        current_user: Authenticated user from JWT.

    Returns:
        Dict with profiles array, total_profiles count, and custom profile support.

    Example:
        GET /api/scans/profiles

    Response:
        {
            "profiles": [
                {
                    "id": "stig-rhel8",
                    "title": "DISA STIG for Red Hat Enterprise Linux 8",
                    "version": "V1R12",
                    "rules_count": 335,
                    "supported_os": ["rhel8", "centos8"],
                    "compliance_frameworks": ["STIG", "NIST"],
                    "severity_distribution": {"high": 45, "medium": 180, "low": 110}
                }
            ],
            "total_profiles": 2,
            "custom_profiles_supported": true
        }

    Security:
        - Requires authenticated user
        - Read-only profile metadata

    Note:
        Currently returns static profile data. Full implementation would
        query SCAP content and MongoDB compliance rules.
    """
    # Placeholder implementation - full version would query databases
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


# =============================================================================
# PUBLIC API EXPORTS
# =============================================================================

__all__ = [
    "router",
    "validate_scan_configuration",
    "quick_scan",
    "create_verification_scan",
    "rescan_rule",
    "start_remediation",
    "validate_bulk_readiness",
    "pre_flight_check",
    "get_scan_capabilities",
    "get_scans_summary",
    "get_available_profiles",
]
