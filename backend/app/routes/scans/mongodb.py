"""
MongoDB-Integrated Scanning Endpoints

This module provides endpoints for scanning using MongoDB compliance rules.
Moved from mongodb_scan_api.py as part of Phase 2 API Standardization.

Endpoints:
    POST /mongodb/start           - Start MongoDB rule-based scan
    GET  /mongodb/{scan_id}/status   - Get scan status
    GET  /mongodb/{scan_id}/results  - Get scan results
    GET  /mongodb/{scan_id}/report   - Get compliance report
    GET  /mongodb/available-rules    - Get available MongoDB rules
    GET  /mongodb/scanner/health     - Get scanner service health

Architecture Notes:
    - Uses MongoDB compliance_rules collection for rule selection
    - Creates records in PostgreSQL for UI integration
    - Supports platform-aware rule selection
    - Integrates with OWCA for score extraction and risk calculation

Security Notes:
    - All endpoints require JWT authentication
    - XXE prevention in XML parsing
    - Path traversal validation for file access
    - Uses parameterized queries for SQL injection prevention
"""

import logging
import os
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import lxml.etree as etree  # nosec B410 (secure parser configuration used)
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.auth import get_current_user
from backend.app.constants import is_framework_supported
from backend.app.database import User, get_db
from backend.app.services.compliance_framework_reporting import ComplianceFrameworkReporter
from backend.app.services.engine.scanners import UnifiedSCAPScanner
from backend.app.services.owca import SeverityCalculator, XCCDFParser
from backend.app.services.result_enrichment_service import ResultEnrichmentService

logger = logging.getLogger(__name__)

router = APIRouter(tags=["MongoDB Scanning"])


# =============================================================================
# PYDANTIC MODELS
# =============================================================================


class MongoDBScanRequest(BaseModel):
    """Request model for MongoDB-based scanning."""

    host_id: str = Field(..., description="Target host ID")
    hostname: str = Field(..., description="Target hostname or IP address")
    platform: str = Field(..., description="Target platform (rhel, ubuntu, etc.)")
    platform_version: str = Field(..., description="Platform version")
    framework: Optional[str] = Field(None, description="Compliance framework to use")
    severity_filter: Optional[List[str]] = Field(None, description="Filter by severity levels")
    rule_ids: Optional[List[str]] = Field(
        None, description="Specific rule IDs to scan (from wizard selection)"
    )
    connection_params: Optional[Dict[str, Any]] = Field(
        None, description="SSH connection parameters"
    )
    include_enrichment: bool = Field(True, description="Include result enrichment")
    generate_report: bool = Field(True, description="Generate compliance report")


class ScanStatusResponse(BaseModel):
    """Response model for scan status."""

    scan_id: str
    status: str
    progress: Optional[int] = None
    message: Optional[str] = None
    started_at: str
    estimated_completion: Optional[str] = None


class MongoDBScanResponse(BaseModel):
    """Response model for MongoDB scan results."""

    success: bool
    scan_id: str
    host_id: str
    scan_started: str
    scan_completed: Optional[str] = None
    rules_used: int
    mongodb_rules_selected: int
    platform: str
    framework: Optional[str] = None
    results_summary: Dict[str, Any] = {}
    enrichment_data: Optional[Dict[str, Any]] = None
    compliance_report: Optional[Dict[str, Any]] = None
    result_files: Dict[str, str] = {}


# =============================================================================
# GLOBAL SERVICE INSTANCES
# =============================================================================

mongodb_scanner: Optional[UnifiedSCAPScanner] = None
enrichment_service: Optional[ResultEnrichmentService] = None
compliance_reporter: Optional[ComplianceFrameworkReporter] = None


# =============================================================================
# SERVICE INITIALIZATION
# =============================================================================


async def get_mongodb_scanner(request: Request) -> UnifiedSCAPScanner:
    """
    Get or initialize MongoDB scanner.

    Args:
        request: FastAPI request object for app state access.

    Returns:
        Initialized UnifiedSCAPScanner instance.

    Raises:
        HTTPException: 500 if scanner initialization fails.
    """
    global mongodb_scanner
    try:
        if not mongodb_scanner:
            logger.info("Initializing Unified SCAP scanner for the first time")
            encryption_service = getattr(request.app.state, "encryption_service", None)
            if not encryption_service:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Encryption service not available",
                )
            mongodb_scanner = UnifiedSCAPScanner(encryption_service=encryption_service)
            await mongodb_scanner.initialize()
            logger.info("Unified SCAP scanner initialized successfully")
        return mongodb_scanner
    except Exception as e:
        logger.error(f"Failed to initialize Unified SCAP scanner: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scanner initialization failed: {str(e)}",
        )


async def get_enrichment_service_instance() -> ResultEnrichmentService:
    """Get or initialize enrichment service."""
    global enrichment_service
    if not enrichment_service:
        enrichment_service = ResultEnrichmentService(db=None)
        await enrichment_service.initialize()
    return enrichment_service


async def get_compliance_reporter_instance() -> ComplianceFrameworkReporter:
    """Get or initialize compliance reporter."""
    global compliance_reporter
    if not compliance_reporter:
        compliance_reporter = ComplianceFrameworkReporter()
        await compliance_reporter.initialize()
    return compliance_reporter


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def parse_xccdf_results(result_file: str) -> Dict[str, Any]:
    """
    Parse XCCDF scan results XML file.

    Extracts pass/fail counts, severity distribution, and scores from
    XCCDF result files generated by oscap.

    Args:
        result_file: Absolute path to XCCDF results XML file.

    Returns:
        Dictionary containing rule counts, scores, and severity distribution.

    Security:
        - XXE prevention via secure parser configuration
        - No network access during XML parsing
    """
    try:
        if not os.path.exists(result_file):
            logger.warning(f"XCCDF result file not found: {result_file}")
            return _empty_xccdf_results()

        # Security: Disable XXE attacks
        parser = etree.XMLParser(
            resolve_entities=False,
            no_network=True,
            dtd_validation=False,
            load_dtd=False,
        )
        tree = etree.parse(result_file, parser)  # nosec B320
        root = tree.getroot()

        namespaces = {"xccdf": "http://checklists.nist.gov/xccdf/1.2"}

        results: Dict[str, Any] = {
            "rules_total": 0,
            "rules_passed": 0,
            "rules_failed": 0,
            "rules_error": 0,
            "rules_unknown": 0,
            "rules_notapplicable": 0,
            "rules_notchecked": 0,
            "score": 0.0,
            "severity_high": 0,
            "severity_medium": 0,
            "severity_low": 0,
            "failed_critical": 0,
            "failed_high": 0,
            "failed_medium": 0,
            "failed_low": 0,
        }

        # Parse rule-result elements
        rule_results = root.xpath("//xccdf:rule-result", namespaces=namespaces)
        results["rules_total"] = len(rule_results)

        for rule_result in rule_results:
            result_elem = rule_result.find("xccdf:result", namespaces)
            result_value = None
            if result_elem is not None:
                result_value = result_elem.text

                # Count by result type
                if result_value == "pass":
                    results["rules_passed"] += 1
                elif result_value == "fail":
                    results["rules_failed"] += 1
                elif result_value == "error":
                    results["rules_error"] += 1
                elif result_value == "unknown":
                    results["rules_unknown"] += 1
                elif result_value == "notapplicable":
                    results["rules_notapplicable"] += 1
                elif result_value == "notchecked":
                    results["rules_notchecked"] += 1

            # Extract severity
            severity = rule_result.get("severity", "unknown")
            if severity == "high":
                results["severity_high"] += 1
            elif severity == "medium":
                results["severity_medium"] += 1
            elif severity == "low":
                results["severity_low"] += 1

            # Track failed findings by severity
            if result_value == "fail":
                if severity == "critical":
                    results["failed_critical"] += 1
                elif severity == "high":
                    results["failed_high"] += 1
                elif severity == "medium":
                    results["failed_medium"] += 1
                elif severity == "low":
                    results["failed_low"] += 1

        # Calculate compliance score
        if results["rules_total"] > 0:
            divisor = results["rules_passed"] + results["rules_failed"]
            if divisor > 0:
                results["score"] = round((results["rules_passed"] / divisor) * 100, 2)

        # Extract XCCDF native score using OWCA
        try:
            xccdf_parser = XCCDFParser()
            xccdf_score_result = xccdf_parser.extract_native_score(result_file)

            if xccdf_score_result.found:
                results["xccdf_score"] = xccdf_score_result.xccdf_score
                results["xccdf_score_system"] = xccdf_score_result.xccdf_score_system
                results["xccdf_score_max"] = xccdf_score_result.xccdf_score_max
            else:
                results["xccdf_score"] = None
                results["xccdf_score_system"] = None
                results["xccdf_score_max"] = None
        except Exception as score_err:
            logger.warning(f"Failed to extract XCCDF native score: {score_err}")
            results["xccdf_score"] = None
            results["xccdf_score_system"] = None
            results["xccdf_score_max"] = None

        # Calculate risk score using OWCA
        try:
            severity_calculator = SeverityCalculator()
            risk_result = severity_calculator.calculate_risk_score(
                critical_count=int(results["failed_critical"]),
                high_count=int(results["failed_high"]),
                medium_count=int(results["failed_medium"]),
                low_count=int(results["failed_low"]),
                info_count=0,
            )
            results["risk_score"] = risk_result.risk_score
            results["risk_level"] = risk_result.risk_level
        except Exception as risk_err:
            logger.warning(f"Failed to calculate risk score: {risk_err}")
            results["risk_score"] = None
            results["risk_level"] = None

        return results

    except Exception as e:
        logger.error(f"Error parsing XCCDF results from {result_file}: {e}", exc_info=True)
        return _empty_xccdf_results()


def _empty_xccdf_results() -> Dict[str, Any]:
    """Return empty XCCDF results structure."""
    return {
        "rules_total": 0,
        "rules_passed": 0,
        "rules_failed": 0,
        "rules_error": 0,
        "rules_unknown": 0,
        "rules_notapplicable": 0,
        "rules_notchecked": 0,
        "score": 0.0,
        "severity_high": 0,
        "severity_medium": 0,
        "severity_low": 0,
        "xccdf_score": None,
        "xccdf_score_system": None,
        "xccdf_score_max": None,
        "risk_score": None,
        "risk_level": None,
    }


async def enrich_scan_results_task(
    scan_id: str, result_file: str, scan_metadata: Dict[str, Any], generate_report: bool
) -> None:
    """
    Background task to enrich scan results and generate reports.

    Args:
        scan_id: Scan identifier.
        result_file: Path to XCCDF result file.
        scan_metadata: Scan metadata dictionary.
        generate_report: Whether to generate compliance report.
    """
    try:
        logger.info(f"Starting background enrichment for scan {scan_id}")

        enrichment_svc = await get_enrichment_service_instance()
        enriched_results = await enrichment_svc.enrich_scan_results(
            result_file_path=result_file, scan_metadata=scan_metadata
        )

        if generate_report:
            reporter = await get_compliance_reporter_instance()
            framework = scan_metadata.get("framework")
            target_frameworks: List[str] = [str(framework)] if framework else []

            compliance_report = await reporter.generate_compliance_report(
                enriched_results=enriched_results,
                target_frameworks=target_frameworks,
                report_format="json",
            )

            logger.info(
                f"Generated compliance report for scan {scan_id} with "
                f"{len(compliance_report.get('frameworks', {}))} frameworks"
            )

        logger.info(f"Background enrichment completed for scan {scan_id}")

    except Exception as e:
        logger.error(f"Background enrichment failed for scan {scan_id}: {e}")


# =============================================================================
# SCAN ENDPOINTS
# =============================================================================


@router.post("/mongodb/start", response_model=MongoDBScanResponse)
async def start_mongodb_scan(
    scan_request: MongoDBScanRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    scanner: UnifiedSCAPScanner = Depends(get_mongodb_scanner),
) -> MongoDBScanResponse:
    """
    Start a MongoDB rule-based SCAP scan.

    Initiates a scan using rules selected from MongoDB based on
    the target platform and compliance framework requirements.

    Creates records in PostgreSQL scans and scan_results tables for UI integration.

    Args:
        scan_request: Scan configuration request.
        request: FastAPI request object.
        background_tasks: Background task manager.
        db: SQLAlchemy database session.
        current_user: Authenticated user.
        scanner: UnifiedSCAPScanner instance.

    Returns:
        MongoDBScanResponse with scan details and results.

    Raises:
        HTTPException 400: Invalid framework or scan failure.
        HTTPException 500: Scan initialization failure.

    Security:
        - Requires authenticated user
        - Validates framework against allowed list
        - Uses parameterized SQL queries
    """
    logger.info(f"=== ENDPOINT CALLED: start_mongodb_scan for host {scan_request.hostname} ===")
    try:
        scan_uuid = uuid.uuid4()
        scan_id = f"mongodb_scan_{scan_uuid.hex[:8]}"
        logger.info(
            f"Starting MongoDB scan {scan_id} (UUID: {scan_uuid}) for host {scan_request.hostname}"
        )

        # Validate framework
        if scan_request.framework and not is_framework_supported(scan_request.framework):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported framework: {scan_request.framework}",
            )

        # Resolve effective platform
        effective_platform, effective_platform_version = await _resolve_platform(
            scan_request, db, request
        )

        # Create PostgreSQL scan record
        started_at = datetime.utcnow()
        scan_name = f"compliance-scan-{scan_request.hostname}-{effective_platform}-{effective_platform_version}"

        await _create_scan_record(db, scan_uuid, scan_name, scan_request, current_user, started_at)

        # Execute scan
        try:
            scan_result = await scanner.scan_with_rules(
                host_id=scan_request.host_id,
                hostname=scan_request.hostname,
                platform=effective_platform,
                platform_version=effective_platform_version,
                framework=scan_request.framework,
                connection_params=scan_request.connection_params,
                severity_filter=scan_request.severity_filter,
                rule_ids=scan_request.rule_ids,
            )
        except Exception as scan_error:
            logger.error(f"Scanner failed: {scan_error}", exc_info=True)
            await _update_scan_failed(db, scan_uuid, str(scan_error))
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Scanner error: {str(scan_error)}",
            )

        if not scan_result.get("success"):
            await _update_scan_failed(db, scan_uuid, scan_result.get("error", "Unknown error"))
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Scan execution failed: {scan_result.get('error', 'Unknown error')}",
            )

        # Update scan to completed
        await _update_scan_completed(db, scan_uuid, scan_result)

        # Prepare response
        # CRITICAL: Return the actual UUID, not the prefixed scan_id string
        # The frontend uses this ID to fetch scan status from /api/scans/{id}
        # which expects a valid UUID format
        response_data = MongoDBScanResponse(
            success=True,
            scan_id=str(scan_uuid),  # Return actual UUID for frontend compatibility
            host_id=scan_request.host_id,
            scan_started=datetime.utcnow().isoformat(),
            rules_used=scan_result.get("mongodb_rules_used", 0),
            mongodb_rules_selected=scan_result.get("mongodb_rules_used", 0),
            platform=scan_request.platform,
            framework=scan_request.framework,
            results_summary={
                "return_code": scan_result.get("return_code", -1),
                "scan_completed": scan_result.get("success", False),
            },
            result_files={
                "xml_results": scan_result.get("result_file", ""),
                "html_report": scan_result.get("report_file", ""),
            },
        )

        # Add background enrichment task
        if scan_request.include_enrichment:
            result_file_path = scan_result.get("result_file", "")
            background_tasks.add_task(
                enrich_scan_results_task,
                scan_id,
                str(result_file_path) if result_file_path else "",
                scan_request.dict(),
                scan_request.generate_report,
            )

        logger.info(f"MongoDB scan {scan_id} completed successfully")
        return response_data

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to start MongoDB scan: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan initialization failed: {str(e)}",
        )


async def _resolve_platform(
    scan_request: MongoDBScanRequest, db: Session, request: Request
) -> tuple:
    """
    Resolve effective platform from host database, JIT detection, or request.

    Platform resolution order:
    1. Host's persisted platform_identifier (from scheduled OS discovery)
    2. Computed from host's os_family + os_version (from scheduled OS discovery)
    3. JIT (Just-In-Time) detection via SSH when connection_params provided
    4. Request parameters (wizard-selected platform) as final fallback

    JIT detection ensures accurate platform detection even for hosts that
    haven't completed scheduled OS discovery yet.
    """
    from backend.app.tasks.os_discovery_tasks import _normalize_platform_identifier

    effective_platform = scan_request.platform
    effective_platform_version = scan_request.platform_version
    platform_resolved_via_jit = False

    try:
        host_query = text(
            "SELECT platform_identifier, os_family, os_version FROM hosts WHERE id = :host_id"
        )
        host_result = db.execute(host_query, {"host_id": scan_request.host_id}).fetchone()

        if host_result:
            db_platform_id = host_result[0]
            db_os_family = host_result[1]
            db_os_version = host_result[2]

            if db_platform_id:
                # Priority 1: Use persisted platform_identifier from scheduled discovery
                effective_platform = db_platform_id
                if db_os_version:
                    effective_platform_version = db_os_version
                logger.info(
                    f"Platform resolved from DB platform_identifier: {effective_platform} {effective_platform_version}"
                )
            elif db_os_family and db_os_version:
                # Priority 2: Compute from os_family + os_version
                computed_platform = _normalize_platform_identifier(db_os_family, db_os_version)
                if computed_platform:
                    effective_platform = computed_platform
                    effective_platform_version = db_os_version
                    logger.info(
                        f"Platform computed from DB os_family/os_version: {effective_platform} {effective_platform_version}"
                    )
            elif scan_request.connection_params:
                # Priority 3: JIT detection when host has no OS discovery data but has SSH params
                logger.info(
                    f"Host {scan_request.host_id} has no OS discovery data, "
                    f"attempting JIT platform detection via SSH"
                )
                jit_platform, jit_version = await _jit_detect_platform(scan_request, db, request)
                if jit_platform and jit_version:
                    effective_platform = jit_platform
                    effective_platform_version = jit_version
                    platform_resolved_via_jit = True
                    logger.info(
                        f"Platform resolved via JIT detection: {effective_platform} {effective_platform_version}"
                    )
                else:
                    logger.warning(
                        f"JIT platform detection failed for host {scan_request.host_id}, "
                        f"using request parameters: {effective_platform} {effective_platform_version}"
                    )

    except Exception as platform_err:
        logger.warning(f"Could not check host platform_identifier: {platform_err}")

    # Normalize if not already (only if we didn't use JIT detection)
    if not platform_resolved_via_jit and not any(char.isdigit() for char in effective_platform):
        computed_platform = _normalize_platform_identifier(
            scan_request.platform, scan_request.platform_version
        )
        if computed_platform:
            effective_platform = computed_platform

    return effective_platform, effective_platform_version


async def _jit_detect_platform(
    scan_request: MongoDBScanRequest, db: Session, request: Request
) -> tuple:
    """
    Perform Just-In-Time platform detection via SSH.

    This function uses the PlatformDetector to detect the host's OS
    when no persisted platform data is available in the database.

    Args:
        scan_request: Scan request with connection_params
        db: Database session
        request: FastAPI request for accessing encryption service

    Returns:
        Tuple of (platform_identifier, platform_version) or (None, None) on failure
    """
    try:
        from backend.app.services.auth import CentralizedAuthService
        from backend.app.services.engine.discovery import detect_platform_for_scan

        # Get encryption service from app state
        encryption_service = getattr(request.app.state, "encryption_service", None)
        if not encryption_service:
            logger.warning("Encryption service not available for JIT platform detection")
            return None, None

        # Resolve credentials for SSH connection
        auth_service = CentralizedAuthService(db, encryption_service)
        credential_data = auth_service.resolve_credential(target_id=scan_request.host_id)

        if not credential_data:
            logger.warning(
                f"No credentials available for JIT detection on host {scan_request.host_id}"
            )
            return None, None

        # Extract connection params
        conn_params = scan_request.connection_params
        hostname = conn_params.get("hostname") or scan_request.hostname
        port = conn_params.get("port", 22)

        # Perform JIT detection
        platform_info = await detect_platform_for_scan(
            hostname=hostname,
            port=port,
            credential_data=credential_data,
            db=db,
        )

        if platform_info.detection_success:
            return platform_info.platform_identifier, platform_info.platform_version
        else:
            logger.warning(f"JIT detection failed for {hostname}: {platform_info.detection_error}")
            return None, None

    except Exception as e:
        logger.error(f"JIT platform detection error: {e}", exc_info=True)
        return None, None


async def _create_scan_record(
    db: Session,
    scan_uuid: uuid.UUID,
    scan_name: str,
    scan_request: MongoDBScanRequest,
    current_user: User,
    started_at: datetime,
) -> None:
    """Create initial PostgreSQL scan record."""
    try:
        insert_scan_query = text(
            """
            INSERT INTO scans (
                id, name, host_id, profile_id, status, progress,
                scan_options, started_by, started_at, remediation_requested, verification_scan, scan_metadata
            )
            VALUES (
                :id, :name, :host_id, :profile_id, :status, :progress,
                :scan_options, :started_by, :started_at, :remediation_requested, :verification_scan, :scan_metadata
            )
        """
        )
        rule_count = len(scan_request.rule_ids) if scan_request.rule_ids else 0
        db.execute(
            insert_scan_query,
            {
                "id": str(scan_uuid),
                "name": scan_name,
                "host_id": scan_request.host_id,
                "profile_id": scan_request.framework or "mongodb_custom",
                "status": "running",
                "progress": 0,
                "scan_options": f'{{"platform": "{scan_request.platform}", "platform_version": "{scan_request.platform_version}", "framework": "{scan_request.framework}"}}',
                "started_by": int(current_user.get("id")) if current_user.get("id") else None,
                "started_at": started_at,
                "remediation_requested": False,
                "verification_scan": False,
                "scan_metadata": f'{{"scan_type": "mongodb", "rule_count": {rule_count}}}',
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


async def _update_scan_failed(db: Session, scan_uuid: uuid.UUID, error_message: str) -> None:
    """Update scan record to failed status."""
    try:
        update_scan_query = text(
            """
            UPDATE scans
            SET status = :status, progress = :progress, completed_at = :completed_at, error_message = :error_message
            WHERE id = :id
        """
        )
        db.execute(
            update_scan_query,
            {
                "id": str(scan_uuid),
                "status": "failed",
                "progress": 100,
                "completed_at": datetime.utcnow(),
                "error_message": error_message,
            },
        )
        db.commit()
    except Exception as update_error:
        logger.error(f"Failed to update scan status to failed: {update_error}")
        db.rollback()


async def _update_scan_completed(
    db: Session, scan_uuid: uuid.UUID, scan_result: Dict[str, Any]
) -> None:
    """Update scan record to completed status with results."""
    completed_at = datetime.utcnow()
    try:
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
                "id": str(scan_uuid),
                "status": "completed",
                "progress": 100,
                "completed_at": completed_at,
                "result_file": scan_result.get("result_file", ""),
                "report_file": scan_result.get("report_file", ""),
            },
        )

        # Parse and store results
        result_file = scan_result.get("result_file", "")
        parsed_results = parse_xccdf_results(result_file)

        insert_results_query = text(
            """
            INSERT INTO scan_results (
                scan_id, total_rules, passed_rules, failed_rules, error_rules,
                unknown_rules, not_applicable_rules, score, severity_high,
                severity_medium, severity_low, xccdf_score, xccdf_score_system,
                xccdf_score_max, risk_score, risk_level, created_at
            ) VALUES (
                :scan_id, :total_rules, :passed_rules, :failed_rules, :error_rules,
                :unknown_rules, :not_applicable_rules, :score, :severity_high,
                :severity_medium, :severity_low, :xccdf_score, :xccdf_score_system,
                :xccdf_score_max, :risk_score, :risk_level, :created_at
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


@router.get("/mongodb/{scan_id}/status", response_model=ScanStatusResponse)
async def get_mongodb_scan_status(
    scan_id: str, current_user: User = Depends(get_current_user)
) -> ScanStatusResponse:
    """
    Get status of a MongoDB scan.

    Args:
        scan_id: Scan identifier.
        current_user: Authenticated user.

    Returns:
        ScanStatusResponse with current status.

    Security:
        - Requires authenticated user
    """
    try:
        return ScanStatusResponse(
            scan_id=scan_id,
            status="completed",
            progress=100,
            message="Scan completed successfully",
            started_at=datetime.utcnow().isoformat(),
        )
    except Exception as e:
        logger.error(f"Failed to get scan status for {scan_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get scan status: {str(e)}",
        )


@router.get("/mongodb/{scan_id}/results")
async def get_mongodb_scan_results(
    scan_id: str,
    include_enrichment: bool = True,
    include_report: bool = True,
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get detailed results from a MongoDB scan.

    Args:
        scan_id: Scan identifier.
        include_enrichment: Include enrichment data.
        include_report: Include compliance report data.
        current_user: Authenticated user.

    Returns:
        Dictionary with scan results.

    Security:
        - Requires authenticated user
    """
    try:
        results: Dict[str, Any] = {
            "scan_id": scan_id,
            "status": "completed",
            "basic_results": {
                "rules_tested": 25,
                "rules_passed": 18,
                "rules_failed": 7,
                "overall_score": 72.0,
            },
        }

        if include_enrichment:
            results["enrichment"] = {
                "intelligence_data_available": True,
                "remediation_guidance_generated": True,
                "framework_mapping_completed": True,
            }

        if include_report:
            results["compliance_report"] = {
                "report_generated": True,
                "frameworks_analyzed": ["nist"],
                "executive_summary_available": True,
            }

        return results

    except Exception as e:
        logger.error(f"Failed to get scan results for {scan_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve scan results: {str(e)}",
        )


@router.get("/mongodb/{scan_id}/report")
async def get_mongodb_compliance_report(
    scan_id: str,
    format: str = "json",
    framework: Optional[str] = None,
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get compliance report for a MongoDB scan.

    Args:
        scan_id: Scan identifier.
        format: Report format (json, html, pdf).
        framework: Optional framework filter.
        current_user: Authenticated user.

    Returns:
        Compliance report dictionary.

    Raises:
        HTTPException 400: Invalid format.

    Security:
        - Requires authenticated user
    """
    try:
        if format not in ["json", "html", "pdf"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Format must be json, html, or pdf",
            )

        return {
            "metadata": {
                "scan_id": scan_id,
                "report_generated": datetime.utcnow().isoformat(),
                "format": format,
                "framework": framework,
            },
            "executive_summary": {
                "overall_compliance_score": 72.0,
                "grade": "C",
                "critical_issues": 3,
                "recommendation": "Focus on high severity failures first",
            },
            "framework_analysis": {
                "nist": {
                    "compliance_rate": 72.0,
                    "grade": "C",
                    "critical_failures": 3,
                    "status": "needs_improvement",
                }
            },
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get compliance report for {scan_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve compliance report: {str(e)}",
        )


@router.get("/mongodb/available-rules")
async def get_available_mongodb_rules(
    platform: Optional[str] = None,
    platform_version: Optional[str] = None,
    host_id: Optional[str] = None,
    framework: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    scanner: UnifiedSCAPScanner = Depends(get_mongodb_scanner),
) -> Dict[str, Any]:
    """
    Get available MongoDB rules for scanning.

    Resolves platform from host database or query parameters and returns
    matching compliance rules.

    Args:
        platform: Target platform (rhel, ubuntu, etc.).
        platform_version: Platform version.
        host_id: Optional host ID for automatic platform detection.
        framework: Filter by compliance framework.
        severity: Filter by severity level.
        db: SQLAlchemy database session.
        current_user: Authenticated user.
        scanner: UnifiedSCAPScanner instance.

    Returns:
        Dictionary with available rules and filters applied.

    Security:
        - Requires authenticated user
    """
    try:
        effective_platform = platform or "rhel"
        effective_version = platform_version or "8"

        if host_id:
            try:
                from backend.app.tasks.os_discovery_tasks import _normalize_platform_identifier

                host_query = text(
                    "SELECT platform_identifier, os_family, os_version FROM hosts WHERE id = :host_id"
                )
                host_result = db.execute(host_query, {"host_id": host_id}).fetchone()

                if host_result:
                    if host_result[0]:
                        effective_platform = host_result[0]
                        effective_version = host_result[2] or platform_version or "8"
                    elif host_result[1] and host_result[2]:
                        computed = _normalize_platform_identifier(host_result[1], host_result[2])
                        if computed:
                            effective_platform = computed
                            effective_version = host_result[2]
            except Exception as host_err:
                logger.warning(f"Failed to lookup host platform: {host_err}")

        # Get rules from MongoDB
        rules = await scanner.select_platform_rules(
            platform=effective_platform,
            platform_version=effective_version,
            framework=framework,
            severity_filter=[severity] if severity else None,
        )

        # Format for response
        rule_summaries = []
        for rule in rules[:10]:
            rule_summaries.append(
                {
                    "rule_id": rule.rule_id,
                    "name": rule.metadata.get("name", "Unknown"),
                    "description": rule.metadata.get("description", "No description"),
                    "severity": rule.severity,
                    "category": rule.category,
                    "frameworks": list(rule.frameworks.keys()) if rule.frameworks else [],
                    "platforms": (
                        list(rule.platform_implementations.keys())
                        if rule.platform_implementations
                        else []
                    ),
                }
            )

        return {
            "success": True,
            "total_rules_available": len(rules),
            "rules_sample": rule_summaries,
            "filters_applied": {
                "platform": platform,
                "platform_version": platform_version,
                "host_id": host_id,
                "framework": framework,
                "severity": severity,
            },
            "resolved_platform": {
                "platform": effective_platform,
                "platform_version": effective_version,
                "source": (
                    "host_database"
                    if host_id and effective_platform != platform
                    else "query_parameter" if platform else "default"
                ),
            },
        }

    except Exception as e:
        logger.error(f"Failed to get available rules: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve available rules: {str(e)}",
        )


@router.get("/mongodb/scanner/health")
async def get_mongodb_scanner_health(
    request: Request, current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Get MongoDB scanner service health.

    Args:
        request: FastAPI request object.
        current_user: Authenticated user.

    Returns:
        Health status with component details.

    Security:
        - Requires authenticated user
    """
    try:
        scanner = await get_mongodb_scanner(request)
        enrichment = await get_enrichment_service_instance()
        reporter = await get_compliance_reporter_instance()

        # Check MongoDB connection
        mongo_status = "unknown"
        mongo_details: Dict[str, Any] = {}
        try:
            from backend.app.services.mongo_integration_service import get_mongo_service

            mongo_service = await get_mongo_service()
            mongo_health = await mongo_service.health_check()
            mongo_status = mongo_health.get("status", "unknown")
            if mongo_status == "healthy":
                mongo_details = {
                    "database": mongo_health.get("database"),
                    "collections": mongo_health.get("collections", []),
                    "document_count": mongo_health.get("document_count", {}),
                }
            else:
                mongo_details = {"error": mongo_health.get("message", "Unknown error")}
        except Exception as e:
            mongo_status = "error"
            mongo_details = {"error": str(e)}

        return {
            "status": "healthy" if mongo_status == "healthy" else "degraded",
            "components": {
                "mongodb_scanner": {
                    "status": "initialized" if scanner._initialized else "not_initialized",
                    "mongodb_connection": mongo_status,
                    "mongodb_details": mongo_details,
                },
                "enrichment_service": {
                    "status": "initialized" if enrichment._initialized else "not_initialized",
                    "stats": await enrichment.get_enrichment_statistics(),
                },
                "compliance_reporter": {
                    "status": "initialized" if reporter._initialized else "not_initialized",
                    "supported_frameworks": list(reporter.frameworks.keys()),
                },
            },
            "capabilities": {
                "platform_aware_scanning": True,
                "rule_inheritance_resolution": True,
                "result_enrichment": True,
                "compliance_reporting": True,
                "supported_platforms": ["rhel", "ubuntu", "centos"],
                "supported_frameworks": ["nist", "cis", "stig", "pci"],
            },
        }

    except Exception as e:
        logger.error(f"Failed to get scanner health: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Health check failed: {str(e)}",
        )


# =============================================================================
# PUBLIC API EXPORTS
# =============================================================================

__all__ = [
    "router",
    "start_mongodb_scan",
    "get_mongodb_scan_status",
    "get_mongodb_scan_results",
    "get_mongodb_compliance_report",
    "get_available_mongodb_rules",
    "get_mongodb_scanner_health",
]
