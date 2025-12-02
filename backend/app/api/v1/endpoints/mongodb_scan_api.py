"""
MongoDB-Integrated Scanning API Endpoints
Provides endpoints for scanning using MongoDB compliance rules
"""

import logging
import os
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import lxml.etree as etree  # nosec B410 (secure parser configuration on line 187)
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

router = APIRouter(prefix="/mongodb-scans", tags=["MongoDB Scanning"])


class MongoDBScanRequest(BaseModel):
    """Request model for MongoDB-based scanning"""

    host_id: str = Field(..., description="Target host ID")
    hostname: str = Field(..., description="Target hostname or IP address")
    platform: str = Field(..., description="Target platform (rhel, ubuntu, etc.)")
    platform_version: str = Field(..., description="Platform version")
    framework: Optional[str] = Field(None, description="Compliance framework to use")
    severity_filter: Optional[List[str]] = Field(None, description="Filter by severity levels")
    rule_ids: Optional[List[str]] = Field(None, description="Specific rule IDs to scan (from wizard selection)")
    connection_params: Optional[Dict[str, Any]] = Field(None, description="SSH connection parameters")
    include_enrichment: bool = Field(True, description="Include result enrichment")
    generate_report: bool = Field(True, description="Generate compliance report")


class ScanStatusResponse(BaseModel):
    """Response model for scan status"""

    scan_id: str
    status: str
    progress: Optional[int] = None
    message: Optional[str] = None
    started_at: str
    estimated_completion: Optional[str] = None


class MongoDBScanResponse(BaseModel):
    """Response model for MongoDB scan results"""

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


# Global scanner instance
mongodb_scanner = None
enrichment_service = None
compliance_reporter = None


async def get_mongodb_scanner(request: Request) -> UnifiedSCAPScanner:
    """Get or initialize MongoDB scanner"""
    global mongodb_scanner
    try:
        if not mongodb_scanner:
            logger.info("Initializing Unified SCAP scanner for the first time")
            # Get encryption service from app state
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


async def get_enrichment_service() -> ResultEnrichmentService:
    """Get or initialize enrichment service"""
    global enrichment_service
    if not enrichment_service:
        # Note: ResultEnrichmentService requires a db session but this is a singleton
        # for background tasks. The service handles db creation internally.
        enrichment_service = ResultEnrichmentService(db=None)
        await enrichment_service.initialize()
    return enrichment_service


async def get_compliance_reporter() -> ComplianceFrameworkReporter:
    """Get or initialize compliance reporter"""
    global compliance_reporter
    if not compliance_reporter:
        compliance_reporter = ComplianceFrameworkReporter()
        await compliance_reporter.initialize()
    return compliance_reporter


def parse_xccdf_results(result_file: str) -> Dict[str, Any]:
    """
    Parse XCCDF scan results XML file to extract pass/fail counts and severity distribution.

    This function parses the XCCDF results file generated by oscap to extract:
    - Rule result counts (pass, fail, error, unknown, notapplicable, notchecked)
    - Severity distribution (high, medium, low)
    - Compliance score calculation (calculated from pass/fail ratio)
    - XCCDF native score (extracted from TestResult/score element)

    Args:
        result_file: Absolute path to XCCDF results XML file

    Returns:
        Dictionary containing:
        - rules_total: Total number of rules evaluated
        - rules_passed: Number of passing rules
        - rules_failed: Number of failing rules
        - rules_error: Number of rules with errors
        - rules_unknown: Number of rules with unknown status
        - rules_notapplicable: Number of not applicable rules
        - rules_notchecked: Number of unchecked rules
        - score: Compliance score as percentage (0.0-100.0) - calculated
        - severity_high: Count of high severity rules checked
        - severity_medium: Count of medium severity rules checked
        - severity_low: Count of low severity rules checked
        - xccdf_score: Native XCCDF score (if present in XML)
        - xccdf_score_system: XCCDF scoring system URN
        - xccdf_score_max: Maximum XCCDF score

    Example:
        >>> results = parse_xccdf_results("/app/data/results/scan_abc123.xml")
        >>> print(f"Score: {results['score']}%")
        Score: 87.5%
        >>> print(f"XCCDF Native: {results['xccdf_score']}/{results['xccdf_score_max']}")
        XCCDF Native: 87.5/100.0
    """
    try:
        if not os.path.exists(result_file):
            logger.warning(f"XCCDF result file not found: {result_file}")
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

        # Security: Disable XXE (XML External Entity) attacks
        # Prevents malicious XML from reading arbitrary files or performing SSRF
        # Per OWASP XXE Prevention: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
        parser = etree.XMLParser(
            resolve_entities=False,  # Disable entity resolution (prevents XXE)
            no_network=True,  # Disable network access (prevents SSRF)
            dtd_validation=False,  # Disable DTD validation (prevents billion laughs attack)
            load_dtd=False,  # Don't load external DTD
        )
        tree = etree.parse(result_file, parser)  # nosec B320
        root = tree.getroot()

        # XCCDF namespace
        namespaces = {"xccdf": "http://checklists.nist.gov/xccdf/1.2"}

        # Initialize counters with explicit type to allow Optional assignments later
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
            # Track failed findings by severity for risk scoring
            "failed_critical": 0,
            "failed_high": 0,
            "failed_medium": 0,
            "failed_low": 0,
        }

        # Parse rule-result elements
        rule_results = root.xpath("//xccdf:rule-result", namespaces=namespaces)
        results["rules_total"] = len(rule_results)

        for rule_result in rule_results:
            # Extract result value (pass, fail, error, unknown, notapplicable, notchecked)
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

            # Extract severity (high, medium, low, critical, unknown)
            severity = rule_result.get("severity", "unknown")
            if severity == "high":
                results["severity_high"] += 1
            elif severity == "medium":
                results["severity_medium"] += 1
            elif severity == "low":
                results["severity_low"] += 1

            # Track failed findings by severity for risk scoring
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
        # Score = (passed / (passed + failed)) * 100
        # Only count pass/fail rules, exclude N/A, error, unknown, notchecked
        if results["rules_total"] > 0:
            divisor = results["rules_passed"] + results["rules_failed"]
            if divisor > 0:
                results["score"] = round((results["rules_passed"] / divisor) * 100, 2)
            else:
                # No pass/fail rules to calculate score from (all rules are N/A, error, etc.)
                results["score"] = 0.0

        # Extract XCCDF native score using OWCA Extraction Layer
        # This extracts the official <score> element from the TestResult
        try:
            xccdf_parser = XCCDFParser()
            xccdf_score_result = xccdf_parser.extract_native_score(result_file)

            if xccdf_score_result.found:
                results["xccdf_score"] = xccdf_score_result.xccdf_score
                results["xccdf_score_system"] = xccdf_score_result.xccdf_score_system
                results["xccdf_score_max"] = xccdf_score_result.xccdf_score_max
                logger.info(
                    f"Extracted XCCDF native score: {xccdf_score_result.xccdf_score}/{xccdf_score_result.xccdf_score_max} "
                    f"(system: {xccdf_score_result.xccdf_score_system})"
                )
            else:
                # No XCCDF native score found
                results["xccdf_score"] = None
                results["xccdf_score_system"] = None
                results["xccdf_score_max"] = None
                if xccdf_score_result.error:
                    logger.warning(f"XCCDF score extraction error: {xccdf_score_result.error}")
                else:
                    logger.debug("No XCCDF native score element found in result file")
        except Exception as score_err:
            # Extraction failed, but don't block parsing - just log and set to None
            logger.warning(f"Failed to extract XCCDF native score: {score_err}")
            results["xccdf_score"] = None
            results["xccdf_score_system"] = None
            results["xccdf_score_max"] = None

        # Calculate severity-weighted risk score using OWCA Extraction Layer
        try:
            severity_calculator = SeverityCalculator()
            risk_result = severity_calculator.calculate_risk_score(
                critical_count=int(results["failed_critical"]),
                high_count=int(results["failed_high"]),
                medium_count=int(results["failed_medium"]),
                low_count=int(results["failed_low"]),
                info_count=0,  # Informational findings don't affect risk score
            )
            results["risk_score"] = risk_result.risk_score
            results["risk_level"] = risk_result.risk_level
            logger.info(
                f"Calculated risk score: {risk_result.risk_score} ({risk_result.risk_level}) - "
                f"Critical: {results['failed_critical']}, High: {results['failed_high']}, "
                f"Medium: {results['failed_medium']}, Low: {results['failed_low']}"
            )
        except Exception as risk_err:
            # Risk calculation failed, but don't block parsing
            logger.warning(f"Failed to calculate risk score: {risk_err}")
            results["risk_score"] = None
            results["risk_level"] = None

        logger.info(
            f"Parsed XCCDF results: {results['rules_total']} total, "
            f"{results['rules_passed']} passed, {results['rules_failed']} failed, "
            f"calculated score: {results['score']}%, "
            f"XCCDF native score: {results['xccdf_score']}, "
            f"risk score: {results['risk_score']} ({results['risk_level']})"
        )

        return results

    except Exception as e:
        logger.error(f"Error parsing XCCDF results from {result_file}: {e}", exc_info=True)
        # Return empty results on parse failure
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


@router.post("/start", response_model=MongoDBScanResponse)
async def start_mongodb_scan(
    scan_request: MongoDBScanRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    scanner: UnifiedSCAPScanner = Depends(get_mongodb_scanner),
) -> MongoDBScanResponse:
    """
    Start a MongoDB rule-based SCAP scan

    This endpoint initiates a scan using rules selected from MongoDB based on
    the target platform and compliance framework requirements.

    Creates records in PostgreSQL scans and scan_results tables for UI integration.
    """
    logger.info(f"=== ENDPOINT CALLED: start_mongodb_scan for host {scan_request.hostname} ===")
    try:
        # Generate UUID for scan (compatible with PostgreSQL scans table)
        scan_uuid = uuid.uuid4()
        scan_id = f"mongodb_scan_{scan_uuid.hex[:8]}"
        logger.info(f"Starting MongoDB scan {scan_id} (UUID: {scan_uuid}) for host {scan_request.hostname}")

        # Log request details safely
        try:
            rule_count = len(scan_request.rule_ids) if scan_request.rule_ids else 0
            logger.info(
                f"Request: platform={scan_request.platform}, version={scan_request.platform_version}, framework={scan_request.framework}, rules={rule_count}"
            )
        except Exception as log_err:
            logger.warning(f"Could not log request details: {log_err}")

        # Validate framework using centralized constants
        if scan_request.framework and not is_framework_supported(scan_request.framework):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported framework: {scan_request.framework}. Framework must be one of the supported compliance frameworks.",
            )

        # Phase 3/4: Resolve platform_identifier for OVAL selection
        # Priority order:
        # 1. Host's persisted platform_identifier (from OS discovery)
        # 2. Computed from host's os_family + os_version (if available)
        # 3. Computed from scan_request.platform + platform_version (fallback)
        # This ensures we get normalized identifiers like "rhel8" not just "rhel"
        effective_platform = scan_request.platform
        effective_platform_version = scan_request.platform_version

        # Import normalize function for computing platform_identifier
        from backend.app.tasks.os_discovery_tasks import _normalize_platform_identifier

        try:
            host_query = text("SELECT platform_identifier, os_family, os_version FROM hosts WHERE id = :host_id")
            host_result = db.execute(host_query, {"host_id": scan_request.host_id}).fetchone()

            if host_result:
                db_platform_id = host_result[0]  # platform_identifier column
                db_os_family = host_result[1]  # os_family column
                db_os_version = host_result[2]  # os_version column

                if db_platform_id:
                    # Priority 1: Use persisted platform_identifier from OS discovery
                    effective_platform = db_platform_id
                    if db_os_version:
                        effective_platform_version = db_os_version
                    logger.info(
                        f"Host {scan_request.host_id} using persisted platform_identifier: "
                        f"{effective_platform} (version: {effective_platform_version})"
                    )
                elif db_os_family and db_os_version:
                    # Priority 2: Compute from os_family + os_version
                    computed_platform = _normalize_platform_identifier(db_os_family, db_os_version)
                    if computed_platform:
                        effective_platform = computed_platform
                        effective_platform_version = db_os_version
                        logger.info(
                            f"Host {scan_request.host_id} computed platform_identifier from "
                            f"os_family={db_os_family}, os_version={db_os_version}: {effective_platform}"
                        )
                    else:
                        logger.warning(
                            f"Host {scan_request.host_id} could not compute platform_identifier "
                            f"from os_family={db_os_family}, os_version={db_os_version}"
                        )
                else:
                    # Priority 3: JIT (Just-In-Time) platform detection
                    # Host has no OS discovery data, attempt live detection
                    logger.info(
                        f"Host {scan_request.host_id} has no OS discovery data, "
                        f"attempting JIT platform detection..."
                    )
                    try:
                        from backend.app.services.auth_service import get_auth_service
                        from backend.app.services.engine.discovery import detect_platform_for_scan

                        # Get encryption service and resolve credentials using auth service
                        # This uses the same credential resolution as the scan executor
                        encryption_service = getattr(request.app.state, "encryption_service", None)
                        if encryption_service:
                            auth_service = get_auth_service(db, encryption_service)

                            # Check host's auth_method to determine credential source
                            auth_method_query = text("SELECT auth_method FROM hosts WHERE id = :host_id")
                            auth_result = db.execute(auth_method_query, {"host_id": scan_request.host_id}).fetchone()
                            host_auth_method = auth_result[0] if auth_result else "system_default"
                            use_default = host_auth_method in ["system_default", "default"]
                            target_id = None if use_default else scan_request.host_id

                            # Resolve credentials using auth service (same as scan executor)
                            credential_data = auth_service.resolve_credential(
                                target_id=target_id, use_default=use_default
                            )

                            if credential_data:
                                # Build connection_params from resolved credentials
                                connection_params = {
                                    "username": credential_data.username,
                                    "port": 22,
                                }
                                if credential_data.private_key:
                                    connection_params["private_key"] = credential_data.private_key
                                if credential_data.password:
                                    connection_params["password"] = credential_data.password
                                if credential_data.private_key_passphrase:
                                    connection_params["private_key_passphrase"] = credential_data.private_key_passphrase

                                platform_info = await detect_platform_for_scan(
                                    hostname=scan_request.hostname,
                                    connection_params=connection_params,
                                    encryption_service=encryption_service,
                                    host_id=scan_request.host_id,
                                )
                                if platform_info.detection_success and platform_info.platform_identifier:
                                    effective_platform = platform_info.platform_identifier
                                    effective_platform_version = (
                                        platform_info.platform_version or scan_request.platform_version
                                    )
                                    logger.info(
                                        f"JIT platform detection successful for {scan_request.host_id}: "
                                        f"{platform_info.platform} {platform_info.platform_version} "
                                        f"-> {effective_platform}"
                                    )
                                else:
                                    logger.warning(
                                        f"JIT platform detection failed for {scan_request.host_id}: "
                                        f"{platform_info.detection_error}. "
                                        f"Using request platform: {scan_request.platform}"
                                    )
                            else:
                                logger.warning(
                                    f"JIT detection skipped (no credentials available). "
                                    f"Using request platform: {scan_request.platform}"
                                )
                        else:
                            logger.warning(
                                f"JIT detection skipped (no encryption service). "
                                f"Using request platform: {scan_request.platform}"
                            )
                    except Exception as jit_err:
                        logger.warning(
                            f"JIT platform detection error for {scan_request.host_id}: {jit_err}. "
                            f"Using request platform: {scan_request.platform}"
                        )
            else:
                logger.warning(
                    f"Host {scan_request.host_id} not found in database, "
                    f"using request platform: {scan_request.platform}"
                )
        except Exception as platform_err:
            logger.warning(
                f"Could not check host platform_identifier: {platform_err}. "
                f"Using request platform: {scan_request.platform}"
            )

        # Priority 3: If still using raw platform (not normalized), compute from request
        # This handles cases where host has no OS discovery data
        if effective_platform == scan_request.platform and scan_request.platform_version:
            # Check if platform is not already normalized (e.g., "rhel" vs "rhel8")
            # Normalized platforms contain version numbers like "rhel8", "ubuntu2204"
            if not any(char.isdigit() for char in effective_platform):
                computed_platform = _normalize_platform_identifier(scan_request.platform, scan_request.platform_version)
                if computed_platform:
                    effective_platform = computed_platform
                    logger.info(
                        f"Computed platform_identifier from request: "
                        f"{scan_request.platform} + {scan_request.platform_version} = {effective_platform}"
                    )

        # Create initial PostgreSQL scan record (status: running)
        # Use effective_platform (detected/resolved) instead of request parameters
        # Include hostname for uniqueness across hosts with same platform
        scan_name = f"compliance-scan-{scan_request.hostname}-{effective_platform}-{effective_platform_version}"
        started_at = datetime.utcnow()

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
            db.execute(
                insert_scan_query,
                {
                    "id": str(scan_uuid),
                    "name": scan_name,
                    "host_id": scan_request.host_id,
                    "profile_id": scan_request.framework or "mongodb_custom",
                    "status": "running",
                    "progress": 0,
                    "scan_options": f'{{"platform": "{effective_platform}", "platform_version": "{effective_platform_version}", "framework": "{scan_request.framework}"}}',
                    "started_by": int(current_user.get("id")) if current_user.get("id") else None,
                    "started_at": started_at,
                    "remediation_requested": False,
                    "verification_scan": False,
                    "scan_metadata": f'{{"scan_type": "mongodb", "rule_count": {len(scan_request.rule_ids) if scan_request.rule_ids else 0}}}',
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

        # Start the scan process
        # Phase 3: Use effective_platform (from host's platform_identifier if available)
        logger.info(
            f"Calling scanner.scan_with_rules for host {scan_request.host_id} "
            f"with platform={effective_platform} (original: {scan_request.platform})"
        )
        try:
            scan_result = await scanner.scan_with_rules(
                host_id=scan_request.host_id,
                hostname=scan_request.hostname,
                platform=effective_platform,  # Use discovered platform for OVAL selection
                platform_version=effective_platform_version,
                framework=scan_request.framework,
                connection_params=scan_request.connection_params,
                severity_filter=scan_request.severity_filter,
                rule_ids=scan_request.rule_ids,
            )
        except Exception as scan_error:
            logger.error(f"Scanner failed: {scan_error}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Scanner error: {str(scan_error)}",
            )

        if not scan_result.get("success"):
            logger.error(f"Scan failed with result: {scan_result}")
            # Update PostgreSQL scan record to failed status
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
                        "error_message": scan_result.get("error", "Unknown error"),
                    },
                )
                db.commit()
            except Exception as update_error:
                logger.error(f"Failed to update scan status to failed: {update_error}")
                db.rollback()

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Scan execution failed: {scan_result.get('error', 'Unknown error')}",
            )

        # Update PostgreSQL scan record to completed status
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

            # Create scan_results record
            # Parse XCCDF results to extract actual pass/fail counts and severity distribution
            result_file = scan_result.get("result_file", "")
            parsed_results = parse_xccdf_results(result_file)

            # Log parsed results for debugging
            logger.info(
                f"Parsed results for scan {scan_uuid}: "
                f"total={parsed_results['rules_total']}, "
                f"passed={parsed_results['rules_passed']}, "
                f"failed={parsed_results['rules_failed']}, "
                f"calculated_score={parsed_results['score']}%, "
                f"xccdf_score={parsed_results['xccdf_score']}/{parsed_results['xccdf_score_max']}"
            )

            # Insert scan_results record with parameterized SQL
            insert_scan_results_query = text(
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
                insert_scan_results_query,
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
                    "xccdf_score": parsed_results["xccdf_score"],
                    "xccdf_score_system": parsed_results["xccdf_score_system"],
                    "xccdf_score_max": parsed_results["xccdf_score_max"],
                    "risk_score": parsed_results["risk_score"],
                    "risk_level": parsed_results["risk_level"],
                    "created_at": completed_at,
                },
            )

            db.commit()
            logger.info(f"Updated PostgreSQL scan record {scan_uuid} to completed with results")
        except Exception as db_error:
            logger.error(f"Failed to update scan completion: {db_error}", exc_info=True)
            db.rollback()
            # Don't raise - scan succeeded, just logging failed

        # Prepare response data
        response_data = MongoDBScanResponse(
            success=True,
            scan_id=scan_id,
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

        # Add background tasks for enrichment and reporting
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


async def enrich_scan_results_task(
    scan_id: str, result_file: str, scan_metadata: Dict[str, Any], generate_report: bool
) -> None:
    """Background task to enrich scan results and generate reports"""
    try:
        logger.info(f"Starting background enrichment for scan {scan_id}")

        # Get services
        enrichment_svc = await get_enrichment_service()

        # Enrich results
        enriched_results = await enrichment_svc.enrich_scan_results(
            result_file_path=result_file, scan_metadata=scan_metadata
        )

        # Generate compliance report if requested
        if generate_report:
            reporter = await get_compliance_reporter()
            framework = scan_metadata.get("framework")
            target_frameworks: List[str] = [str(framework)] if framework else []

            compliance_report = await reporter.generate_compliance_report(
                enriched_results=enriched_results,
                target_frameworks=target_frameworks,
                report_format="json",
            )

            # Store report (in a real implementation, this would save to database)
            logger.info(
                f"Generated compliance report for scan {scan_id} with "
                f"{len(compliance_report.get('frameworks', {}))} frameworks"
            )

        logger.info(f"Background enrichment completed for scan {scan_id}")

    except Exception as e:
        logger.error(f"Background enrichment failed for scan {scan_id}: {e}")


@router.get("/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str, current_user: User = Depends(get_current_user)) -> ScanStatusResponse:
    """Get status of a MongoDB scan"""
    try:
        # In a real implementation, this would query a database for scan status
        # For now, return a mock response
        return ScanStatusResponse(
            scan_id=scan_id,
            status="completed",  # Mock status
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


@router.get("/{scan_id}/results")
async def get_scan_results(
    scan_id: str,
    include_enrichment: bool = True,
    include_report: bool = True,
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get detailed results from a MongoDB scan"""
    try:
        # In a real implementation, this would retrieve stored results
        # For now, return a mock response structure
        results = {
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


@router.get("/{scan_id}/report")
async def get_compliance_report(
    scan_id: str,
    format: str = "json",
    framework: Optional[str] = None,
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get compliance report for a scan"""
    try:
        if format not in ["json", "html", "pdf"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Format must be json, html, or pdf",
            )

        # In a real implementation, this would retrieve the stored report
        # For now, return mock report data
        mock_report = {
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

        return mock_report

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get compliance report for {scan_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve compliance report: {str(e)}",
        )


@router.get("/available-rules")
async def get_available_rules(
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

    Platform Resolution Priority:
    1. If host_id provided: Use host's persisted platform_identifier
    2. If host_id provided but no platform_identifier: Compute from os_family + os_version
    3. Use platform + platform_version query parameters
    4. Fallback to "rhel" + "8" as last resort (for backwards compatibility)

    Args:
        platform: Target platform (rhel, ubuntu, etc.) - used if host_id not provided
        platform_version: Platform version - used if host_id not provided
        host_id: Optional host ID for automatic platform detection from database
        framework: Filter by compliance framework
        severity: Filter by severity level
        db: Database session for host lookup
        current_user: Authenticated user
        scanner: MongoDB scanner instance

    Returns:
        Dictionary with available rules matching the filters
    """
    try:
        # Resolve effective platform using the same priority logic as /start endpoint
        effective_platform = platform
        effective_version = platform_version

        # If host_id provided, try to get platform from database
        if host_id:
            try:
                from backend.app.tasks.os_discovery_tasks import _normalize_platform_identifier

                host_query = text("SELECT platform_identifier, os_family, os_version FROM hosts WHERE id = :host_id")
                host_result = db.execute(host_query, {"host_id": host_id}).fetchone()

                if host_result:
                    db_platform_id = host_result[0]  # platform_identifier column
                    db_os_family = host_result[1]  # os_family column
                    db_os_version = host_result[2]  # os_version column

                    if db_platform_id:
                        # Priority 1: Use persisted platform_identifier
                        effective_platform = db_platform_id
                        effective_version = db_os_version or platform_version
                        logger.info(f"Using host {host_id} platform_identifier: {effective_platform}")
                    elif db_os_family and db_os_version:
                        # Priority 2: Compute from os_family + os_version
                        computed = _normalize_platform_identifier(db_os_family, db_os_version)
                        if computed:
                            effective_platform = computed
                            effective_version = db_os_version
                            logger.info(f"Computed platform for host {host_id}: {effective_platform}")
                else:
                    logger.warning(f"Host {host_id} not found in database")
            except Exception as host_err:
                logger.warning(f"Failed to lookup host platform: {host_err}")

        # Apply defaults only as last resort
        if not effective_platform:
            effective_platform = "rhel"
            logger.info("No platform specified, defaulting to 'rhel'")
        if not effective_version:
            effective_version = "8"
            logger.info("No platform version specified, defaulting to '8'")

        # Get rules from MongoDB based on filters
        rules = await scanner.select_platform_rules(
            platform=effective_platform,
            platform_version=effective_version,
            framework=framework,
            severity_filter=[severity] if severity else None,
        )

        # Format rules for API response
        rule_summaries = []
        for rule in rules[:10]:  # Limit to first 10 for demo
            rule_summaries.append(
                {
                    "rule_id": rule.rule_id,
                    "name": rule.metadata.get("name", "Unknown"),
                    "description": rule.metadata.get("description", "No description"),
                    "severity": rule.severity,
                    "category": rule.category,
                    "frameworks": (list(rule.frameworks.keys()) if rule.frameworks else []),
                    "platforms": (list(rule.platform_implementations.keys()) if rule.platform_implementations else []),
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


@router.get("/scanner/health")
async def get_scanner_health(request: Request, current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """Get MongoDB scanner service health"""
    try:
        scanner = await get_mongodb_scanner(request)
        enrichment = await get_enrichment_service()
        reporter = await get_compliance_reporter()

        # Check actual MongoDB connection
        mongo_status = "unknown"
        mongo_details = {}
        try:
            from ....services.mongo_integration_service import get_mongo_service

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
                    "status": ("initialized" if scanner._initialized else "not_initialized"),
                    "mongodb_connection": mongo_status,
                    "mongodb_details": mongo_details,
                },
                "enrichment_service": {
                    "status": ("initialized" if enrichment._initialized else "not_initialized"),
                    "stats": await enrichment.get_enrichment_statistics(),
                },
                "compliance_reporter": {
                    "status": ("initialized" if reporter._initialized else "not_initialized"),
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
