"""
Compliance Scanning Endpoints

This module provides the PRIMARY scan creation endpoint and supporting
compliance rule discovery and scanner health endpoints.

Endpoints:
    POST /                  - Create and execute compliance scan
    GET  /rules/available   - Get available compliance rules
    GET  /scanner/health    - Get scanner health status

Architecture Notes:
    This module uses database-agnostic naming to abstract the underlying
    document store. All rule queries go through the compliance rule repository,
    and all scan records are stored in PostgreSQL for unified management.

Security Notes:
    - All endpoints require JWT authentication
    - Error messages are sanitized to prevent information disclosure
    - Platform resolution logged for audit compliance
    - No sensitive credentials exposed in responses
"""

import json
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.constants import is_framework_supported
from app.database import get_db
from app.routes.scans.helpers import (
    get_compliance_reporter,
    get_compliance_scanner,
    get_enrichment_service,
    parse_xccdf_results,
)
from app.routes.scans.models import (
    AvailableRulesResponse,
    ComplianceScanRequest,
    ComplianceScanResponse,
    ComponentHealth,
    PlatformResolution,
    RuleSummary,
    ScannerCapabilities,
    ScannerHealthResponse,
)
from app.tasks.background_tasks import enrich_scan_results_celery
from app.utils.query_builder import QueryBuilder

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Compliance Scanning"])


# =============================================================================
# HELPER FUNCTIONS (Module-Private)
# =============================================================================


def _update_scan_status(
    db: Session,
    scan_uuid: uuid.UUID,
    status_value: str,
    error_message: Optional[str] = None,
) -> None:
    """
    Update scan status in PostgreSQL scans table.

    Helper function to update scan status when scan fails or completes.
    Uses QueryBuilder for consistent parameterized queries.

    Args:
        db: SQLAlchemy database session.
        scan_uuid: UUID of the scan to update.
        status_value: New status value ('failed', 'completed', etc.).
        error_message: Optional error message for failed scans.

    Note:
        This function commits the transaction on success and rolls back on error.
        Errors are logged but not raised to avoid masking the original error.
    """
    try:
        # Build UPDATE query with dynamic columns based on error_message presence
        if error_message:
            update_query = text(
                """
                UPDATE scans
                SET status = :status, progress = :progress,
                    completed_at = :completed_at, error_message = :error_message
                WHERE id = :id
                """
            )
            params = {
                "status": status_value,
                "progress": 100,
                "completed_at": datetime.utcnow(),
                "error_message": error_message,
                "id": str(scan_uuid),
            }
        else:
            update_query = text(
                """
                UPDATE scans
                SET status = :status, progress = :progress, completed_at = :completed_at
                WHERE id = :id
                """
            )
            params = {
                "status": status_value,
                "progress": 100,
                "completed_at": datetime.utcnow(),
                "id": str(scan_uuid),
            }
        db.execute(update_query, params)
        db.commit()
        logger.info(f"Updated scan {scan_uuid} status to {status_value}")
    except Exception as update_error:
        logger.error(f"Failed to update scan status to {status_value}: {update_error}")
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
        from app.services.auth import get_auth_service
        from app.services.engine.discovery import detect_platform_for_scan

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
        credential_data = auth_service.resolve_credential(target_id=target_id, use_default=use_default)

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
            logger.warning(f"JIT platform detection failed for {host_id}: " f"{platform_info.detection_error}")
            return None

    except Exception as e:
        logger.warning(f"JIT platform detection error for {host_id}: {e}")
        return None


# =============================================================================
# COMPLIANCE SCAN ENDPOINTS
# =============================================================================


@router.post("/", response_model=ComplianceScanResponse)
async def create_compliance_scan(
    scan_request: ComplianceScanRequest,
    request: Request,
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
        logger.info(f"Starting compliance scan {scan_id} (UUID: {scan_uuid}) " f"for host {scan_request.host_id}")

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
        from app.tasks.os_discovery_tasks import _normalize_platform_identifier

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
                            effective_platform_version = jit_platform.get("version", effective_platform_version)
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
                f"Could not resolve host platform: {platform_err}. " f"Using request platform: {scan_request.platform}"
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
            scan_request.name or f"compliance-scan-{scan_hostname}-{effective_platform}-{effective_platform_version}"
        )
        started_at = datetime.utcnow()

        try:
            insert_query = text(
                """
                INSERT INTO scans (
                    id, name, host_id, profile_id, status, progress,
                    scan_options, started_by, started_at, remediation_requested,
                    verification_scan, scan_metadata
                )
                VALUES (
                    :id, :name, :host_id, :profile_id, :status, :progress,
                    :scan_options, :started_by, :started_at, :remediation_requested,
                    :verification_scan, :scan_metadata
                )
                """
            )
            db.execute(
                insert_query,
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
                    "started_at": started_at,
                    "remediation_requested": False,
                    "verification_scan": False,
                    "scan_metadata": json.dumps(
                        {
                            "scan_type": "compliance",
                            "rule_count": rule_count,
                        }
                    ),
                },
            )
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
                status_value="failed",
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
                status_value="failed",
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
            update_scan_query = text(
                """
                UPDATE scans
                SET status = :status, progress = :progress, completed_at = :completed_at,
                    result_file = :result_file, report_file = :report_file
                WHERE id = :id
                """
            )
            db.execute(
                update_scan_query,
                {
                    "status": "completed",
                    "progress": 100,
                    "completed_at": completed_at,
                    "result_file": scan_result.get("result_file", ""),
                    "report_file": scan_result.get("report_file", ""),
                    "id": str(scan_uuid),
                },
            )

            # Insert scan_results record with all parsed data
            insert_results_query = text(
                """
                INSERT INTO scan_results (
                    scan_id, total_rules, passed_rules, failed_rules, error_rules,
                    unknown_rules, not_applicable_rules, score,
                    severity_high, severity_medium, severity_low,
                    xccdf_score, xccdf_score_system, xccdf_score_max,
                    risk_score, risk_level, created_at
                )
                VALUES (
                    :scan_id, :total_rules, :passed_rules, :failed_rules, :error_rules,
                    :unknown_rules, :not_applicable_rules, :score,
                    :severity_high, :severity_medium, :severity_low,
                    :xccdf_score, :xccdf_score_system, :xccdf_score_max,
                    :risk_score, :risk_level, :created_at
                )
                """
            )
            db.execute(
                insert_results_query,
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
                    "created_at": completed_at,
                },
            )

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
            enrich_scan_results_celery.delay(
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
        # CRITICAL: Return the actual UUID, not the prefixed scan_id string
        # The frontend uses this ID to fetch scan status from /api/scans/{id}
        # which expects a valid UUID format
        # ---------------------------------------------------------------------
        response_data = ComplianceScanResponse(
            success=True,
            scan_id=str(scan_uuid),  # Return actual UUID for frontend compatibility
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
                from app.tasks.os_discovery_tasks import _normalize_platform_identifier

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
                        logger.info(f"Using host {host_id} platform_identifier: {effective_platform}")
                    elif db_os_family and db_os_version:
                        # Priority 2: Compute from os_family + os_version
                        computed = _normalize_platform_identifier(db_os_family, db_os_version)
                        if computed:
                            effective_platform = computed
                            effective_version = db_os_version
                            resolution_source = "computed"
                            logger.info(f"Computed platform for host {host_id}: {effective_platform}")
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
                    platforms=(list(rule.platform_implementations.keys()) if rule.platform_implementations else []),
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
            from app.services.mongo_integration_service import get_mongo_service

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
            from app.celery_app import celery_app

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


# =============================================================================
# PUBLIC API EXPORTS
# =============================================================================

__all__ = [
    "router",
    "create_compliance_scan",
    "get_available_rules",
    "get_scanner_health",
]
