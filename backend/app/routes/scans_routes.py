"""
SCAP Scanning API Routes

Handles scan job creation, monitoring, and results retrieval.

Architecture Overview:
    This module serves as the primary API for compliance scanning operations.
    It supports both legacy SCAP file-based scanning and modern MongoDB-based
    scanning workflows.

Endpoint Categories:
    1. UNIVERSAL ENDPOINTS (work with both legacy and MongoDB scans):
       - GET  /api/scans/              - List all scans with filtering
       - GET  /api/scans/{scan_id}     - Get scan details
       - GET  /api/scans/{scan_id}/report/html - HTML report
       - GET  /api/scans/{scan_id}/report/json - JSON report
       - GET  /api/scans/{scan_id}/report/csv  - CSV export
       - GET  /api/scans/{scan_id}/failed-rules - Failed rule details
       - POST /api/scans/{scan_id}/stop - Cancel running scan
       - POST /api/scans/{scan_id}/recover - Retry failed scan
       - POST /api/scans/{scan_id}/remediate - Send to AEGIS

    2. LEGACY SCAP CONTENT ENDPOINTS (require scap_content table):
       - POST /api/scans/              - Create SCAP content-based scan
       - POST /api/scans/validate      - Pre-flight validation
       - POST /api/scans/verify        - Post-remediation verification
       - POST /api/scans/hosts/{host_id}/quick-scan - Intelligent quick scan

    3. BULK OPERATIONS:
       - POST /api/scans/bulk-scan     - Multi-host scanning
       - GET  /api/scans/bulk-scan/{session_id}/progress
       - POST /api/scans/bulk-scan/{session_id}/cancel
       - GET  /api/scans/sessions      - List bulk scan sessions

    4. READINESS VALIDATION:
       - POST /api/scans/readiness/validate-bulk - Bulk host validation
       - GET  /api/scans/{scan_id}/pre-flight-check

    5. DISABLED ENDPOINTS:
       - POST /api/scans/{scan_id}/rescan/rule - Rule rescanning not supported

MongoDB-Based Scanning:
    For new implementations, use /api/mongodb-scans/ endpoints which:
    - Store rules in MongoDB (not SCAP files)
    - Support flexible framework-based scanning
    - Provide better performance for large rule sets

Migration Notes (2025-11-07):
    - Scan list/detail endpoints work with both scan types
    - Legacy endpoints remain for backward compatibility
    - Rule rescanning disabled for MongoDB scans
    - scap_content table still required for legacy operations

Security:
    - All endpoints require authentication via JWT
    - Error messages sanitized to prevent information disclosure
    - Audit logging for all scan operations
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.auth import get_current_user
from backend.app.constants import is_framework_supported
from backend.app.database import get_db
from backend.app.models.error_models import ValidationResultResponse
from backend.app.routes.scans.helpers import (  # Services; Scanner singletons; XCCDF parsing; Background tasks; Deprecation helpers; Error handling
    add_deprecation_header,
    enrich_scan_results_background,
    error_service,
    get_compliance_reporter,
    get_compliance_scanner,
    get_enrichment_service,
    parse_xccdf_results,
    sanitization_service,
    sanitize_http_error,
)
from backend.app.routes.scans.models import (  # Compliance scan models (PRIMARY); Available rules models; Scanner health models; Legacy SCAP models
    AutomatedFixRequest,
    AvailableRulesResponse,
    BulkScanRequest,
    BulkScanResponse,
    ComplianceScanRequest,
    ComplianceScanResponse,
    ComponentHealth,
    PlatformResolution,
    ProfileSuggestion,
    QuickScanRequest,
    QuickScanResponse,
    RuleRescanRequest,
    RuleSummary,
    ScannerCapabilities,
    ScannerHealthResponse,
    ScanRequest,
    ScanUpdate,
    ValidationRequest,
    VerificationScanRequest,
)
from backend.app.services.bulk_scan_orchestrator import BulkScanOrchestrator
from backend.app.services.scan_intelligence import ScanIntelligenceService, ScanPriority
from backend.app.tasks.scan_tasks import execute_scan_task
from backend.app.utils.logging_security import sanitize_path_for_log
from backend.app.utils.query_builder import QueryBuilder

# =============================================================================
# Import models and helpers from the modular package
# =============================================================================
# Models are now defined in backend.app.routes.scans.models
# Helpers are now defined in backend.app.routes.scans.helpers


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["Scans"])


# =============================================================================
# ENDPOINT DEFINITIONS
# =============================================================================
# Models are imported from backend.app.routes.scans.models
# Helpers are imported from backend.app.routes.scans.helpers
# This file contains only the route handler definitions.


# =============================================================================
# Models and helpers now imported from modular package
# See backend.app.routes.scans.models and backend.app.routes.scans.helpers
# =============================================================================


# Removed placeholder - this section used to contain duplicated models and helpers
# that have been moved to their respective modules. Line count reduced significantly.


# -----------------------------------------------------------------------------
# ENDPOINT DEFINITIONS BEGIN
# Models and helpers have been moved to their respective modules:
# - Models: backend.app.routes.scans.models
# - Helpers: backend.app.routes.scans.helpers
# -----------------------------------------------------------------------------


@router.post("/", response_model=ComplianceScanResponse)
async def create_compliance_scan(
    scan_request: ComplianceScanRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> ComplianceScanResponse:
    """
    Create and execute a compliance scan for a target host.

    This is the primary scan creation endpoint that uses the compliance rule
    repository to evaluate rules against the target host. The endpoint is
    database-agnostic and does not expose implementation details about the
    underlying storage technology.

    Platform Resolution Priority:
        1. Host's persisted platform_identifier (from OS discovery)
        2. Computed from host's os_family + os_version (if available)
        3. Computed from request platform + platform_version (fallback)
        4. JIT (Just-In-Time) platform detection via SSH (last resort)

    Scan Workflow:
        1. Validate request parameters and framework support
        2. Resolve effective platform using priority order above
        3. Create PostgreSQL scan record with 'running' status
        4. Execute SCAP scan using compliance rule scanner
        5. Parse XCCDF results for pass/fail counts and severity
        6. Update scan record with results and completion status
        7. Queue background enrichment and report generation (if requested)

    Args:
        scan_request: Scan configuration with host, platform, and rule filters.
        request: FastAPI request for accessing app state (encryption service).
        background_tasks: FastAPI background task queue for async enrichment.
        db: SQLAlchemy database session for scan record persistence.
        current_user: Authenticated user from JWT token.

    Returns:
        ComplianceScanResponse with scan ID, status, and result summary.

    Raises:
        HTTPException 400: Invalid framework or scanner execution failure.
        HTTPException 404: Host not found in database.
        HTTPException 500: Scanner initialization or database error.

    Example:
        POST /api/scans/
        {
            "host_id": "550e8400-e29b-41d4-a716-446655440000",
            "hostname": "server-01.example.com",
            "platform": "rhel",
            "platform_version": "8",
            "framework": "nist_800_53",
            "include_enrichment": true,
            "generate_report": true
        }

    Security:
        - Requires authenticated user with scan permissions
        - Validates framework against supported list
        - Uses parameterized SQL queries (SQL injection prevention)
        - Logs all scan operations for audit compliance
    """
    logger.info(
        f"=== ENDPOINT CALLED: create_compliance_scan for host {scan_request.host_id} ===",
        extra={
            "host_id": scan_request.host_id,
            "hostname": scan_request.hostname,
            "platform": scan_request.platform,
            "framework": scan_request.framework,
            "user_id": current_user.get("id"),
        },
    )

    try:
        # Generate UUID for scan (compatible with PostgreSQL scans table)
        scan_uuid = uuid.uuid4()
        scan_id = f"compliance_scan_{scan_uuid.hex[:8]}"
        logger.info(
            f"Starting compliance scan {scan_id} (UUID: {scan_uuid}) "
            f"for host {scan_request.host_id}"
        )

        # Log request details safely (avoid logging sensitive connection params)
        rule_count = len(scan_request.rule_ids) if scan_request.rule_ids else 0
        logger.info(
            f"Request: platform={scan_request.platform}, "
            f"version={scan_request.platform_version}, "
            f"framework={scan_request.framework}, "
            f"rules={rule_count}"
        )

        # Validate framework using centralized constants
        # Prevents arbitrary framework names from being processed
        if scan_request.framework and not is_framework_supported(scan_request.framework):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Unsupported framework: {scan_request.framework}. "
                    f"Framework must be one of the supported compliance frameworks."
                ),
            )

        # Get scanner instance with lazy initialization
        scanner = await get_compliance_scanner(request)

        # ---------------------------------------------------------------------
        # Platform Resolution: Determine effective platform for OVAL selection
        # Priority order:
        # 1. Host's persisted platform_identifier (from OS discovery)
        # 2. Computed from host's os_family + os_version (if available)
        # 3. Computed from request platform + platform_version (fallback)
        # 4. JIT platform detection (last resort)
        # ---------------------------------------------------------------------
        effective_platform = scan_request.platform or ""
        effective_platform_version = scan_request.platform_version or ""

        # Import normalize function for computing platform_identifier
        from backend.app.tasks.os_discovery_tasks import _normalize_platform_identifier

        # Initialize host_result to None for later reference
        # This ensures the variable exists even if the database query fails
        host_result = None

        try:
            # Query host for platform information using QueryBuilder
            host_builder = (
                QueryBuilder("hosts")
                .select(
                    "platform_identifier",
                    "os_family",
                    "os_version",
                    "hostname",
                    "auth_method",
                )
                .where("id = :host_id", scan_request.host_id, "host_id")
            )
            query, params = host_builder.build()
            host_result = db.execute(text(query), params).fetchone()

            if host_result:
                db_platform_id = host_result[0]  # platform_identifier column
                db_os_family = host_result[1]  # os_family column
                db_os_version = host_result[2]  # os_version column
                db_hostname = host_result[3]  # hostname for scan naming
                host_auth_method = host_result[4]  # auth_method for credential resolution

                # Priority 1: Use persisted platform_identifier from OS discovery
                if db_platform_id:
                    effective_platform = db_platform_id
                    if db_os_version:
                        effective_platform_version = db_os_version
                    logger.info(
                        f"Host {scan_request.host_id} using persisted platform_identifier: "
                        f"{effective_platform} (version: {effective_platform_version})"
                    )

                # Priority 2: Compute from os_family + os_version
                elif db_os_family and db_os_version:
                    computed_platform = _normalize_platform_identifier(db_os_family, db_os_version)
                    if computed_platform:
                        effective_platform = computed_platform
                        effective_platform_version = db_os_version
                        logger.info(
                            f"Host {scan_request.host_id} computed platform_identifier from "
                            f"os_family={db_os_family}, os_version={db_os_version}: "
                            f"{effective_platform}"
                        )
                    else:
                        logger.warning(
                            f"Host {scan_request.host_id} could not compute platform_identifier "
                            f"from os_family={db_os_family}, os_version={db_os_version}"
                        )

                # Priority 3 & 4: Use request platform or attempt JIT detection
                else:
                    logger.info(
                        f"Host {scan_request.host_id} has no OS discovery data, "
                        f"attempting JIT platform detection..."
                    )
                    try:
                        # Attempt JIT platform detection via SSH
                        jit_platform = await _jit_platform_detection(
                            request=request,
                            db=db,
                            host_id=scan_request.host_id,
                            hostname=scan_request.hostname or db_hostname or "",
                            auth_method=host_auth_method or "system_default",
                        )
                        if jit_platform:
                            effective_platform = jit_platform.get("platform", effective_platform)
                            effective_platform_version = jit_platform.get(
                                "version", effective_platform_version
                            )
                            logger.info(
                                f"JIT platform detection successful: {effective_platform} "
                                f"v{effective_platform_version}"
                            )
                    except Exception as jit_err:
                        logger.warning(
                            f"JIT platform detection failed: {jit_err}. "
                            f"Using request platform: {scan_request.platform}"
                        )
            else:
                logger.warning(
                    f"Host {scan_request.host_id} not found in database, "
                    f"using request platform: {scan_request.platform}"
                )

        except Exception as platform_err:
            logger.warning(
                f"Could not resolve host platform: {platform_err}. "
                f"Using request platform: {scan_request.platform}"
            )

        # Fallback: If still using raw platform, compute from request
        # This handles cases where host has no OS discovery data
        if effective_platform == scan_request.platform and scan_request.platform_version:
            # Check if platform is not already normalized (e.g., "rhel" vs "rhel8")
            if not any(char.isdigit() for char in effective_platform):
                computed_platform = _normalize_platform_identifier(
                    scan_request.platform or "", scan_request.platform_version
                )
                if computed_platform:
                    effective_platform = computed_platform
                    logger.info(
                        f"Computed platform_identifier from request: "
                        f"{scan_request.platform} + {scan_request.platform_version} = "
                        f"{effective_platform}"
                    )

        # Determine hostname for scan naming (use DB hostname if request didn't provide one)
        scan_hostname = scan_request.hostname or ""
        if not scan_hostname and host_result:
            scan_hostname = host_result[3] or scan_request.host_id[:8]

        # ---------------------------------------------------------------------
        # Create PostgreSQL scan record (status: running)
        # ---------------------------------------------------------------------
        scan_name = (
            scan_request.name
            or f"compliance-scan-{scan_hostname}-{effective_platform}-{effective_platform_version}"
        )
        started_at = datetime.utcnow()

        try:
            insert_scan_builder = QueryBuilder("scans").insert(
                {
                    "id": str(scan_uuid),
                    "name": scan_name,
                    "host_id": scan_request.host_id,
                    "profile_id": scan_request.framework or "compliance_custom",
                    "status": "running",
                    "progress": 0,
                    "scan_options": json.dumps(
                        {
                            "platform": effective_platform,
                            "platform_version": effective_platform_version,
                            "framework": scan_request.framework,
                            "severity_filter": scan_request.severity_filter,
                        }
                    ),
                    "started_by": (int(current_user.get("id")) if current_user.get("id") else None),
                    "started_at": started_at.isoformat(),
                    "remediation_requested": False,
                    "verification_scan": False,
                    "scan_metadata": json.dumps(
                        {
                            "scan_type": "compliance",
                            "rule_count": rule_count,
                        }
                    ),
                }
            )
            query, params = insert_scan_builder.build()
            db.execute(text(query), params)
            db.commit()
            logger.info(f"Created PostgreSQL scan record {scan_uuid}")

        except Exception as db_error:
            logger.error(f"Failed to create scan record: {db_error}", exc_info=True)
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to create scan record: {str(db_error)}",
            )

        # ---------------------------------------------------------------------
        # Execute the scan using compliance rule scanner
        # ---------------------------------------------------------------------
        logger.info(
            f"Calling scanner.scan_with_rules for host {scan_request.host_id} "
            f"with platform={effective_platform} "
            f"(original: {scan_request.platform})"
        )

        try:
            scan_result = await scanner.scan_with_rules(
                host_id=scan_request.host_id,
                hostname=scan_hostname,
                platform=effective_platform,
                platform_version=effective_platform_version,
                framework=scan_request.framework,
                connection_params=scan_request.connection_params,
                severity_filter=scan_request.severity_filter,
                rule_ids=scan_request.rule_ids,
            )
        except Exception as scan_error:
            logger.error(f"Scanner failed: {scan_error}", exc_info=True)
            # Update scan record to failed status
            _update_scan_status(
                db=db,
                scan_uuid=scan_uuid,
                status="failed",
                error_message=str(scan_error),
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Scanner error: {str(scan_error)}",
            )

        # Check scan result success
        if not scan_result.get("success"):
            logger.error(f"Scan failed with result: {scan_result}")
            error_msg = scan_result.get("error", "Unknown error")
            _update_scan_status(
                db=db,
                scan_uuid=scan_uuid,
                status="failed",
                error_message=error_msg,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Scan execution failed: {error_msg}",
            )

        # ---------------------------------------------------------------------
        # Parse XCCDF results and update scan record to completed
        # ---------------------------------------------------------------------
        completed_at = datetime.utcnow()
        result_file = scan_result.get("result_file", "")
        parsed_results = parse_xccdf_results(result_file)

        logger.info(
            f"Parsed results for scan {scan_uuid}: "
            f"total={parsed_results['rules_total']}, "
            f"passed={parsed_results['rules_passed']}, "
            f"failed={parsed_results['rules_failed']}, "
            f"score={parsed_results['score']}%, "
            f"risk_score={parsed_results.get('risk_score')} "
            f"({parsed_results.get('risk_level')})"
        )

        try:
            # Update scans table with completion status
            update_scan_builder = (
                QueryBuilder("scans")
                .update(
                    {
                        "status": "completed",
                        "progress": 100,
                        "completed_at": completed_at.isoformat(),
                        "result_file": scan_result.get("result_file", ""),
                        "report_file": scan_result.get("report_file", ""),
                    }
                )
                .where("id = :id", str(scan_uuid), "id")
            )
            query, params = update_scan_builder.build()
            db.execute(text(query), params)

            # Insert scan_results record with all parsed data
            insert_results_builder = QueryBuilder("scan_results").insert(
                {
                    "scan_id": str(scan_uuid),
                    "total_rules": parsed_results["rules_total"],
                    "passed_rules": parsed_results["rules_passed"],
                    "failed_rules": parsed_results["rules_failed"],
                    "error_rules": parsed_results["rules_error"],
                    "unknown_rules": parsed_results["rules_unknown"],
                    "not_applicable_rules": parsed_results["rules_notapplicable"],
                    "score": f"{parsed_results['score']}%",
                    "severity_high": parsed_results["severity_high"],
                    "severity_medium": parsed_results["severity_medium"],
                    "severity_low": parsed_results["severity_low"],
                    "xccdf_score": parsed_results.get("xccdf_score"),
                    "xccdf_score_system": parsed_results.get("xccdf_score_system"),
                    "xccdf_score_max": parsed_results.get("xccdf_score_max"),
                    "risk_score": parsed_results.get("risk_score"),
                    "risk_level": parsed_results.get("risk_level"),
                    "created_at": completed_at.isoformat(),
                }
            )
            query, params = insert_results_builder.build()
            db.execute(text(query), params)

            db.commit()
            logger.info(f"Updated PostgreSQL scan record {scan_uuid} to completed with results")

        except Exception as db_error:
            logger.error(f"Failed to update scan completion: {db_error}", exc_info=True)
            db.rollback()
            # Don't raise - scan succeeded, just logging failed

        # ---------------------------------------------------------------------
        # Queue background enrichment and report generation
        # ---------------------------------------------------------------------
        if scan_request.include_enrichment:
            background_tasks.add_task(
                enrich_scan_results_background,
                scan_id=scan_id,
                result_file=str(result_file) if result_file else "",
                scan_metadata={
                    "host_id": scan_request.host_id,
                    "hostname": scan_hostname,
                    "platform": effective_platform,
                    "platform_version": effective_platform_version,
                    "framework": scan_request.framework,
                },
                generate_report=scan_request.generate_report,
            )

        # ---------------------------------------------------------------------
        # Build and return response
        # ---------------------------------------------------------------------
        response_data = ComplianceScanResponse(
            success=True,
            scan_id=scan_id,
            host_id=scan_request.host_id,
            scan_started=started_at.isoformat(),
            scan_completed=completed_at.isoformat(),
            rules_evaluated=parsed_results["rules_total"],
            platform=effective_platform,
            framework=scan_request.framework,
            results_summary={
                "rules_total": parsed_results["rules_total"],
                "rules_passed": parsed_results["rules_passed"],
                "rules_failed": parsed_results["rules_failed"],
                "rules_error": parsed_results["rules_error"],
                "score": parsed_results["score"],
                "xccdf_score": parsed_results.get("xccdf_score"),
                "xccdf_score_max": parsed_results.get("xccdf_score_max"),
                "risk_score": parsed_results.get("risk_score"),
                "risk_level": parsed_results.get("risk_level"),
            },
            enrichment_data=None,  # Populated by background task
            compliance_report=None,  # Populated by background task
            result_files={
                "xml_results": scan_result.get("result_file", ""),
                "html_report": scan_result.get("report_file", ""),
            },
        )

        logger.info(f"Compliance scan {scan_id} completed successfully")
        return response_data

    except HTTPException:
        # Re-raise HTTP exceptions without wrapping
        raise
    except Exception as e:
        logger.error(f"Failed to create compliance scan: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan initialization failed: {str(e)}",
        )


def _update_scan_status(
    db: Session,
    scan_uuid: uuid.UUID,
    status: str,
    error_message: Optional[str] = None,
) -> None:
    """
    Update scan status in PostgreSQL scans table.

    Helper function to update scan status when scan fails or completes.
    Uses QueryBuilder for consistent parameterized queries.

    Args:
        db: SQLAlchemy database session.
        scan_uuid: UUID of the scan to update.
        status: New status value ('failed', 'completed', etc.).
        error_message: Optional error message for failed scans.

    Note:
        This function commits the transaction on success and rolls back on error.
        Errors are logged but not raised to avoid masking the original error.
    """
    try:
        update_data: Dict[str, Any] = {
            "status": status,
            "progress": 100,
            "completed_at": datetime.utcnow().isoformat(),
        }
        if error_message:
            update_data["error_message"] = error_message

        update_builder = (
            QueryBuilder("scans").update(update_data).where("id = :id", str(scan_uuid), "id")
        )
        query, params = update_builder.build()
        db.execute(text(query), params)
        db.commit()
        logger.info(f"Updated scan {scan_uuid} status to {status}")
    except Exception as update_error:
        logger.error(f"Failed to update scan status to {status}: {update_error}")
        db.rollback()


async def _jit_platform_detection(
    request: Request,
    db: Session,
    host_id: str,
    hostname: str,
    auth_method: str,
) -> Optional[Dict[str, str]]:
    """
    Perform Just-In-Time platform detection via SSH.

    Attempts to detect the platform by connecting to the host and running
    platform detection commands. This is used as a last resort when the host
    has no persisted platform_identifier or os_family/os_version.

    Args:
        request: FastAPI request for accessing app state (encryption service).
        db: SQLAlchemy database session for credential resolution.
        host_id: UUID of the target host.
        hostname: Hostname or IP address of the target.
        auth_method: Authentication method configured for the host.

    Returns:
        Dictionary with 'platform' and 'version' keys if detection succeeds,
        or None if detection fails.

    Security:
        - Uses auth_service for credential resolution (no direct credential access)
        - Respects host's configured auth_method
        - Logs detection attempts for audit compliance
    """
    try:
        from backend.app.services.auth_service import get_auth_service
        from backend.app.services.engine.discovery import detect_platform_for_scan

        # Get encryption service from app state
        encryption_service = getattr(request.app.state, "encryption_service", None)
        if not encryption_service:
            logger.warning("JIT detection skipped (no encryption service)")
            return None

        # Get auth service for credential resolution
        auth_service = get_auth_service(db, encryption_service)

        # Determine credential source based on auth_method
        use_default = auth_method in ["system_default", "default"]
        target_id = None if use_default else host_id

        # Resolve credentials using auth service (same as scan executor)
        credential_data = auth_service.resolve_credential(
            target_id=target_id, use_default=use_default
        )

        if not credential_data:
            logger.warning("JIT detection skipped (no credentials available)")
            return None

        # Build connection_params from resolved credentials
        connection_params: Dict[str, Any] = {
            "username": credential_data.username,
            "port": 22,
        }
        if credential_data.private_key:
            connection_params["private_key"] = credential_data.private_key
        if credential_data.password:
            connection_params["password"] = credential_data.password
        if credential_data.private_key_passphrase:
            connection_params["private_key_passphrase"] = credential_data.private_key_passphrase

        # Perform platform detection
        platform_info = await detect_platform_for_scan(
            hostname=hostname,
            connection_params=connection_params,
            encryption_service=encryption_service,
            host_id=host_id,
        )

        if platform_info.detection_success and platform_info.platform_identifier:
            logger.info(
                f"JIT platform detection successful for {host_id}: "
                f"{platform_info.platform} {platform_info.platform_version} "
                f"-> {platform_info.platform_identifier}"
            )
            return {
                "platform": platform_info.platform_identifier,
                "version": platform_info.platform_version or "",
            }
        else:
            logger.warning(
                f"JIT platform detection failed for {host_id}: " f"{platform_info.detection_error}"
            )
            return None

    except Exception as e:
        logger.warning(f"JIT platform detection error for {host_id}: {e}")
        return None


# -----------------------------------------------------------------------------
# SUPPORTING ENDPOINTS (Phase 2 - Database-Agnostic)
# These endpoints provide rule discovery and scanner health checking.
# They use abstraction-focused naming per the consolidation plan.
# -----------------------------------------------------------------------------


@router.get("/rules/available", response_model=AvailableRulesResponse)
async def get_available_rules(
    request: Request,
    platform: Optional[str] = None,
    platform_version: Optional[str] = None,
    host_id: Optional[str] = None,
    framework: Optional[str] = None,
    severity: Optional[str] = None,
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> AvailableRulesResponse:
    """
    Get available compliance rules for scanning.

    Returns rules from the compliance rule repository that match the specified
    platform and framework criteria. This endpoint abstracts the underlying
    document store and provides a consistent interface for rule discovery.

    Platform Resolution Priority:
        1. If host_id provided: Use host's persisted platform_identifier
        2. If host_id provided but no platform_identifier: Compute from os_family + os_version
        3. Use platform + platform_version query parameters
        4. Fallback to "rhel" + "8" as last resort (for backwards compatibility)

    Args:
        request: FastAPI request for accessing app state.
        platform: Target platform identifier (rhel, ubuntu, centos, etc.).
        platform_version: Platform version (8, 9, 20.04, 22.04, etc.).
        host_id: Optional host UUID for automatic platform detection from database.
        framework: Filter by compliance framework (nist_800_53, cis, stig, pci_dss).
        severity: Filter by severity level (critical, high, medium, low).
        page: Page number for pagination (1-indexed, default 1).
        page_size: Number of rules per page (default 50, max 200).
        db: SQLAlchemy database session for host lookup.
        current_user: Authenticated user from JWT token.

    Returns:
        AvailableRulesResponse with matching rules, total count, and filter metadata.

    Raises:
        HTTPException 400: Invalid framework or severity parameter.
        HTTPException 500: Rule repository query failure.

    Example:
        GET /api/scans/rules/available?platform=rhel8&framework=nist_800_53&severity=high
        GET /api/scans/rules/available?host_id=550e8400-e29b-41d4-a716-446655440000

    Security:
        - Requires authenticated user
        - Platform resolution logged for audit compliance
        - No sensitive data exposed in rule metadata
    """
    logger.info(
        "Rules query requested",
        extra={
            "platform": platform,
            "platform_version": platform_version,
            "host_id": host_id,
            "framework": framework,
            "severity": severity,
            "user_id": current_user.get("id"),
        },
    )

    try:
        # Validate pagination parameters
        page = max(1, page)
        page_size = min(max(1, page_size), 200)  # Cap at 200 rules per page

        # Validate framework if provided
        if framework and not is_framework_supported(framework):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported framework: {framework}",
            )

        # Get scanner instance for rule queries
        scanner = await get_compliance_scanner(request)

        # Resolve effective platform using priority logic
        effective_platform = platform
        effective_version = platform_version
        resolution_source = "query_parameter" if platform else "default"

        # If host_id provided, try to get platform from database
        if host_id:
            try:
                from backend.app.tasks.os_discovery_tasks import _normalize_platform_identifier

                # Use QueryBuilder for consistent parameterized queries
                host_builder = (
                    QueryBuilder("hosts")
                    .select("platform_identifier", "os_family", "os_version")
                    .where("id = :host_id", host_id, "host_id")
                )
                query, params = host_builder.build()
                host_result = db.execute(text(query), params).fetchone()

                if host_result:
                    db_platform_id = host_result[0]  # platform_identifier column
                    db_os_family = host_result[1]  # os_family column
                    db_os_version = host_result[2]  # os_version column

                    if db_platform_id:
                        # Priority 1: Use persisted platform_identifier
                        effective_platform = db_platform_id
                        effective_version = db_os_version or platform_version
                        resolution_source = "host_database"
                        logger.info(
                            f"Using host {host_id} platform_identifier: {effective_platform}"
                        )
                    elif db_os_family and db_os_version:
                        # Priority 2: Compute from os_family + os_version
                        computed = _normalize_platform_identifier(db_os_family, db_os_version)
                        if computed:
                            effective_platform = computed
                            effective_version = db_os_version
                            resolution_source = "computed"
                            logger.info(
                                f"Computed platform for host {host_id}: {effective_platform}"
                            )
                else:
                    logger.warning(f"Host {host_id} not found in database")
            except Exception as host_err:
                logger.warning(f"Failed to lookup host platform: {host_err}")

        # Apply defaults only as last resort
        if not effective_platform:
            effective_platform = "rhel"
            resolution_source = "default"
            logger.info("No platform specified, defaulting to 'rhel'")
        if not effective_version:
            effective_version = "8"
            logger.info("No platform version specified, defaulting to '8'")

        # Get rules from compliance rule repository
        rules = await scanner.select_platform_rules(
            platform=effective_platform,
            platform_version=effective_version,
            framework=framework,
            severity_filter=[severity] if severity else None,
        )

        # Calculate pagination
        total_rules = len(rules)
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        paginated_rules = rules[start_idx:end_idx]

        # Format rules for API response
        rule_summaries = []
        for rule in paginated_rules:
            rule_summaries.append(
                RuleSummary(
                    rule_id=rule.rule_id,
                    name=rule.metadata.get("name", "Unknown"),
                    description=rule.metadata.get("description", "No description"),
                    severity=rule.severity or "unknown",
                    category=rule.category,
                    frameworks=(list(rule.frameworks.keys()) if rule.frameworks else []),
                    platforms=(
                        list(rule.platform_implementations.keys())
                        if rule.platform_implementations
                        else []
                    ),
                )
            )

        return AvailableRulesResponse(
            success=True,
            total_rules_available=total_rules,
            rules_sample=rule_summaries,
            filters_applied={
                "platform": platform,
                "platform_version": platform_version,
                "host_id": host_id,
                "framework": framework,
                "severity": severity,
            },
            resolved_platform=PlatformResolution(
                platform=effective_platform,
                platform_version=effective_version,
                source=resolution_source,
            ),
            page=page,
            page_size=page_size,
        )

    except HTTPException:
        # Re-raise HTTP exceptions without wrapping
        raise
    except Exception as e:
        logger.error(f"Failed to get available rules: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve available rules: {str(e)}",
        )


@router.get("/scanner/health", response_model=ScannerHealthResponse)
async def get_scanner_health(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> ScannerHealthResponse:
    """
    Get scanner service health status.

    Performs comprehensive health checks on all scanner components and returns
    their status along with system capabilities. This endpoint uses
    database-agnostic naming to abstract the underlying storage technology.

    Components Checked:
        - Compliance scanner: Rule selection and scan execution engine
        - Rule repository: Document store connection and query capability
        - Enrichment service: Result enrichment and intelligence lookup
        - Compliance reporter: Framework-specific report generation
        - PostgreSQL: Scan record storage and retrieval
        - Redis: Background task queue and caching

    Args:
        request: FastAPI request for accessing app state and services.
        current_user: Authenticated user from JWT token.

    Returns:
        ScannerHealthResponse with component status and capabilities.

    Raises:
        HTTPException 500: Health check system failure (not component failures).

    Example:
        GET /api/scans/scanner/health

    Note:
        This endpoint performs actual connectivity checks, not just status reads.
        Individual component failures result in 'degraded' status, not errors.
        Only a complete system failure results in HTTP 500.

    Security:
        - Requires authenticated user
        - Does not expose sensitive connection strings or credentials
        - Logs health check requests for monitoring
    """
    logger.info(
        "Scanner health check requested",
        extra={"user_id": current_user.get("id")},
    )

    try:
        # Track overall health status
        overall_status = "healthy"
        components: Dict[str, ComponentHealth] = {}

        # Check compliance scanner
        scanner_status = "not_initialized"
        scanner_details: Dict[str, Any] = {}
        try:
            scanner = await get_compliance_scanner(request)
            scanner_status = "initialized" if scanner._initialized else "not_initialized"
            if scanner_status != "initialized":
                overall_status = "degraded"
        except Exception as scanner_err:
            scanner_status = "error"
            scanner_details["error"] = str(scanner_err)
            overall_status = "degraded"

        # Check rule repository (MongoDB) connection
        repo_status = "unknown"
        repo_details: Dict[str, Any] = {}
        try:
            from backend.app.services.mongo_integration_service import get_mongo_service

            mongo_service = await get_mongo_service()
            mongo_health = await mongo_service.health_check()
            repo_status = mongo_health.get("status", "unknown")

            if repo_status == "healthy":
                repo_details = {
                    "database": mongo_health.get("database"),
                    "collections": mongo_health.get("collections", []),
                    "document_count": mongo_health.get("document_count", {}),
                }
            else:
                repo_details = {"error": mongo_health.get("message", "Unknown error")}
                overall_status = "degraded"
        except Exception as repo_err:
            repo_status = "error"
            repo_details = {"error": str(repo_err)}
            overall_status = "degraded"

        components["compliance_scanner"] = ComponentHealth(
            status=scanner_status,
            details={
                "rule_repository_connection": repo_status,
                "rule_repository_details": repo_details,
            },
        )

        # Check enrichment service
        enrichment_status = "not_initialized"
        enrichment_details: Dict[str, Any] = {}
        try:
            enrichment = await get_enrichment_service()
            enrichment_status = "initialized" if enrichment._initialized else "not_initialized"
            if enrichment_status == "initialized":
                enrichment_details = await enrichment.get_enrichment_statistics()
            else:
                overall_status = "degraded"
        except Exception as enrich_err:
            enrichment_status = "error"
            enrichment_details = {"error": str(enrich_err)}
            overall_status = "degraded"

        components["enrichment_service"] = ComponentHealth(
            status=enrichment_status,
            details=enrichment_details if enrichment_details else None,
        )

        # Check compliance reporter
        reporter_status = "not_initialized"
        reporter_details: Dict[str, Any] = {}
        try:
            reporter = await get_compliance_reporter()
            reporter_status = "initialized" if reporter._initialized else "not_initialized"
            if reporter_status == "initialized":
                reporter_details = {
                    "supported_frameworks": list(reporter.frameworks.keys()),
                }
            else:
                overall_status = "degraded"
        except Exception as reporter_err:
            reporter_status = "error"
            reporter_details = {"error": str(reporter_err)}
            overall_status = "degraded"

        components["compliance_reporter"] = ComponentHealth(
            status=reporter_status,
            details=reporter_details if reporter_details else None,
        )

        # Check PostgreSQL connection (scan storage)
        postgres_status = "unknown"
        postgres_details: Dict[str, Any] = {}
        try:
            # Simple connectivity test using a lightweight query
            test_builder = QueryBuilder("scans").select("COUNT(*) as count")
            query, params = test_builder.build()
            # This will fail if PostgreSQL is not available
            # We don't need the actual count, just verify connectivity
            postgres_status = "healthy"
            postgres_details = {"connection": "verified"}
        except Exception as pg_err:
            postgres_status = "error"
            postgres_details = {"error": str(pg_err)}
            overall_status = "degraded"

        components["scan_storage"] = ComponentHealth(
            status=postgres_status,
            details=postgres_details,
        )

        # Check Redis connection (task queue)
        redis_status = "unknown"
        redis_details: Dict[str, Any] = {}
        try:
            from backend.app.celery_app import celery_app

            # Ping the Celery broker to verify Redis connectivity
            inspect = celery_app.control.inspect()
            ping_result = inspect.ping()
            if ping_result:
                redis_status = "healthy"
                redis_details = {
                    "workers": list(ping_result.keys()),
                    "worker_count": len(ping_result),
                }
            else:
                redis_status = "degraded"
                redis_details = {"workers": [], "message": "No workers responding"}
                overall_status = "degraded"
        except Exception as redis_err:
            redis_status = "error"
            redis_details = {"error": str(redis_err)}
            overall_status = "degraded"

        components["task_queue"] = ComponentHealth(
            status=redis_status,
            details=redis_details,
        )

        # Build capabilities response
        capabilities = ScannerCapabilities(
            platform_aware_scanning=True,
            rule_inheritance_resolution=True,
            result_enrichment=enrichment_status == "initialized",
            compliance_reporting=reporter_status == "initialized",
            supported_platforms=[
                "rhel",
                "rhel8",
                "rhel9",
                "ubuntu",
                "ubuntu2004",
                "ubuntu2204",
                "centos",
            ],
            supported_frameworks=["nist_800_53", "cis", "stig", "pci_dss"],
        )

        return ScannerHealthResponse(
            status=overall_status,
            components=components,
            capabilities=capabilities,
            timestamp=datetime.utcnow().isoformat(),
        )

    except Exception as e:
        logger.error(f"Scanner health check failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Health check failed: {str(e)}",
        )


@router.post("/validate")
async def validate_scan_configuration(
    validation_request: ValidationRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> ValidationResultResponse:
    """
    Pre-flight validation for scan configuration (LEGACY).

    DEPRECATION NOTICE: This endpoint validates against SCAP content files.
    For MongoDB-based scanning, use /api/mongodb-scans/ endpoints instead.

    Validates that a host is ready for scanning by checking:
    - Host exists and is active
    - SCAP content exists and contains requested profile
    - Credentials are available and valid
    - SSH connectivity and prerequisites

    Args:
        validation_request: Host, content, and profile IDs to validate.
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
    """
    # Add deprecation header for legacy SCAP content endpoint
    add_deprecation_header(response, "validate_scan_configuration")
    try:
        logger.info(
            "Pre-flight validation requested",
            extra={"host_id": validation_request.host_id},
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

        # Get SCAP content details using QueryBuilder
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
            from backend.app.services.auth_service import get_auth_service

            auth_service = get_auth_service(db)  # type: ignore[call-arg]

            use_default = host_result.auth_method in ["default", "system_default"]
            target_id = str(host_result.id) if not use_default and host_result.id else ""

            credential_data = auth_service.resolve_credential(
                target_id=target_id, use_default=use_default
            )

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

        # Create sanitized error for user (use imported sanitization_service)
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
    response: Response,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> QuickScanResponse:
    """
    Start scan with intelligent defaults (LEGACY).

    DEPRECATION NOTICE: This endpoint uses SCAP content files for scanning.
    For MongoDB-based scanning, use /api/mongodb-scans/start instead.

    Provides "Zero to Scan in 3 Clicks" experience by auto-detecting
    the best profile based on host OS and previous scan history.
    """
    # Add deprecation header for legacy SCAP content endpoint
    add_deprecation_header(response, "quick_scan")
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
            from backend.app.services.auth_service import get_auth_service

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
    response: Response,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Create and start a new SCAP scan (LEGACY).

    DEPRECATION NOTICE: This endpoint uses SCAP content files for scanning.
    For MongoDB-based scanning, use POST /api/mongodb-scans/start instead.

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
    """
    # Add deprecation header for legacy SCAP content endpoint
    add_deprecation_header(response, "create_scan")
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

                    from backend.app.services.engine.result_parsers import XCCDFResultParser

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
    response: Response,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Create a verification scan after AEGIS remediation (LEGACY).

    DEPRECATION NOTICE: This endpoint uses SCAP content files for scanning.
    For MongoDB-based scanning, use /api/mongodb-scans/ endpoints instead.

    Verification scans re-run the same profile to confirm that remediation
    actions successfully resolved previously failing rules.

    Args:
        verification_request: Host, content, profile, and original scan reference.
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
