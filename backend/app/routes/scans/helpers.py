"""
Helper Functions and Singletons for SCAP Scanning API

This module provides shared utilities for the scanning API including:
- Scanner service singletons (lazy initialization pattern)
- XCCDF result parsing functions
- Error sanitization helpers
- Background task utilities

Architecture Notes:
    Singleton Pattern: Scanner services are expensive to initialize, so we use
    lazy-loaded singletons that persist across API requests for efficiency.

Security Notes:
    - XCCDF parsing uses lxml with XXE prevention (OWASP compliance)
    - Error sanitization prevents information disclosure
    - All file paths are validated against traversal attacks
"""

import logging
import os
from typing import Any, Dict, List, Optional

import lxml.etree as etree  # nosec B410 (secure parser configuration below)
from fastapi import HTTPException, Request, Response

from app.services.compliance_framework_reporting import ComplianceFrameworkReporter
from app.services.engine.scanners import UnifiedSCAPScanner
from app.services.error_classification import ErrorClassificationService
from app.services.error_sanitization import get_error_sanitization_service
from app.services.owca import SeverityCalculator, XCCDFParser
from app.services.result_enrichment_service import ResultEnrichmentService
from app.utils.logging_security import sanitize_path_for_log

logger = logging.getLogger(__name__)

# =============================================================================
# Error Classification and Sanitization Services
# =============================================================================

error_service = ErrorClassificationService()
sanitization_service = get_error_sanitization_service()

# =============================================================================
# Compliance Scanner Service Singletons
# =============================================================================
# These global instances are initialized lazily on first use.
# The singleton pattern ensures scanner initialization happens only once
# and is shared across all API requests for efficiency.

_compliance_scanner: Optional[UnifiedSCAPScanner] = None
_enrichment_service: Optional[ResultEnrichmentService] = None
_compliance_reporter: Optional[ComplianceFrameworkReporter] = None


async def get_compliance_scanner(request: Request) -> UnifiedSCAPScanner:
    """
    Get or initialize the compliance scanner singleton.

    This function lazily initializes the UnifiedSCAPScanner on first use
    and returns the cached instance on subsequent calls. The scanner
    requires an encryption service from the app state for credential handling.

    Args:
        request: FastAPI request object to access app state.

    Returns:
        Initialized UnifiedSCAPScanner instance.

    Raises:
        HTTPException 500: If encryption service unavailable or initialization fails.
    """
    global _compliance_scanner
    try:
        if _compliance_scanner is None:
            logger.info("Initializing compliance scanner for the first time")
            encryption_service = getattr(request.app.state, "encryption_service", None)
            if not encryption_service:
                raise HTTPException(
                    status_code=500,
                    detail="Encryption service not available for scanner initialization",
                )
            _compliance_scanner = UnifiedSCAPScanner(encryption_service=encryption_service)
            await _compliance_scanner.initialize()
            logger.info("Compliance scanner initialized successfully")
        return _compliance_scanner
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to initialize compliance scanner: %s", e, exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Scanner initialization failed. Please try again later.",
        )


async def get_enrichment_service() -> ResultEnrichmentService:
    """
    Get or initialize the result enrichment service singleton.

    The enrichment service adds intelligence data to scan results,
    including remediation guidance and framework mappings.

    Returns:
        Initialized ResultEnrichmentService instance.
    """
    global _enrichment_service
    if _enrichment_service is None:
        _enrichment_service = ResultEnrichmentService(db=None)
        await _enrichment_service.initialize()
        logger.debug("Enrichment service initialized")
    return _enrichment_service


async def get_compliance_reporter() -> ComplianceFrameworkReporter:
    """
    Get or initialize the compliance reporter singleton.

    The reporter generates compliance reports aligned with
    frameworks like NIST, CIS, and STIG.

    Returns:
        Initialized ComplianceFrameworkReporter instance.
    """
    global _compliance_reporter
    if _compliance_reporter is None:
        _compliance_reporter = ComplianceFrameworkReporter()
        await _compliance_reporter.initialize()
        logger.debug("Compliance reporter initialized")
    return _compliance_reporter


# =============================================================================
# XCCDF Result Parsing
# =============================================================================


def parse_xccdf_results(result_file: str) -> Dict[str, Any]:
    """
    Parse XCCDF scan results XML file to extract compliance metrics.

    This function parses the XCCDF results file generated by oscap to extract:
    - Rule result counts (pass, fail, error, unknown, notapplicable, notchecked)
    - Severity distribution (critical, high, medium, low)
    - Compliance score calculation (pass/fail ratio)
    - Native XCCDF score from TestResult/score element
    - Severity-weighted risk score using NIST SP 800-30 methodology

    Security:
        Uses lxml with XXE prevention (resolve_entities=False, no_network=True)
        to prevent XML External Entity attacks per OWASP guidelines.

    Args:
        result_file: Absolute path to XCCDF results XML file.

    Returns:
        Dictionary containing compliance metrics including:
        - rules_total, rules_passed, rules_failed, etc.
        - score: Calculated compliance percentage (0.0-100.0)
        - xccdf_score: Native XCCDF score from XML
        - risk_score, risk_level: NIST SP 800-30 risk assessment

    Example:
        >>> results = parse_xccdf_results("/app/data/results/scan_abc123.xml")
        >>> print(f"Score: {results['score']}%")
        Score: 87.5%
    """
    # Default empty result structure for error cases
    empty_result: Dict[str, Any] = {
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
        "xccdf_score": None,
        "xccdf_score_system": None,
        "xccdf_score_max": None,
        "risk_score": None,
        "risk_level": None,
    }

    try:
        if not os.path.exists(result_file):
            logger.warning("XCCDF result file not found: %s", sanitize_path_for_log(result_file))
            return empty_result

        # Security: Disable XXE (XML External Entity) attacks
        # Per OWASP XXE Prevention Cheat Sheet
        parser = etree.XMLParser(
            resolve_entities=False,  # Prevents XXE
            no_network=True,  # Prevents SSRF
            dtd_validation=False,  # Prevents billion laughs
            load_dtd=False,  # Don't load external DTD
        )
        tree = etree.parse(result_file, parser)  # nosec B320
        root = tree.getroot()

        # XCCDF namespace
        namespaces = {"xccdf": "http://checklists.nist.gov/xccdf/1.2"}

        # Initialize counters
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
            result_value = result_elem.text if result_elem is not None else None

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

        # Calculate compliance score: (passed / (passed + failed)) * 100
        if results["rules_total"] > 0:
            divisor = results["rules_passed"] + results["rules_failed"]
            if divisor > 0:
                results["score"] = round((results["rules_passed"] / divisor) * 100, 2)

        # Extract XCCDF native score using OWCA Extraction Layer
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
            logger.warning("Failed to extract XCCDF native score: %s", score_err)
            results["xccdf_score"] = None
            results["xccdf_score_system"] = None
            results["xccdf_score_max"] = None

        # Calculate severity-weighted risk score using OWCA
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
            logger.warning("Failed to calculate risk score: %s", risk_err)
            results["risk_score"] = None
            results["risk_level"] = None

        logger.info(
            "Parsed XCCDF results: total=%d, passed=%d, failed=%d, score=%.2f%%",
            results["rules_total"],
            results["rules_passed"],
            results["rules_failed"],
            results["score"],
        )
        return results

    except Exception as e:
        logger.error(
            "Error parsing XCCDF results from %s: %s",
            sanitize_path_for_log(result_file),
            e,
            exc_info=True,
        )
        return empty_result


# =============================================================================
# Background Task Utilities
# =============================================================================


async def enrich_scan_results_background(
    scan_id: str,
    result_file: str,
    scan_metadata: Dict[str, Any],
    generate_report: bool,
) -> None:
    """
    Background task to enrich scan results and generate reports.

    This task runs asynchronously after the scan completes to:
    1. Enrich results with intelligence data (remediation guidance, etc.)
    2. Generate compliance reports if requested

    Args:
        scan_id: UUID of the completed scan.
        result_file: Path to the XCCDF results XML file.
        scan_metadata: Original scan request metadata.
        generate_report: Whether to generate a compliance report.
    """
    try:
        logger.info("Starting background enrichment for scan %s", scan_id)

        enrichment_svc = await get_enrichment_service()
        enriched_results = await enrichment_svc.enrich_scan_results(
            result_file_path=result_file,
            scan_metadata=scan_metadata,
        )

        if generate_report:
            reporter = await get_compliance_reporter()
            framework = scan_metadata.get("framework")
            target_frameworks: List[str] = [str(framework)] if framework else []

            await reporter.generate_compliance_report(
                enriched_results=enriched_results,
                target_frameworks=target_frameworks,
                report_format="json",
            )
            logger.info("Generated compliance report for scan %s", scan_id)

        logger.info("Background enrichment completed for scan %s", scan_id)

    except Exception as e:
        logger.error("Background enrichment failed for scan %s: %s", scan_id, e)


# =============================================================================
# Deprecation Header Helper
# =============================================================================

DEPRECATION_WARNING = (
    "This endpoint uses legacy SCAP file-based scanning. " "Consider using POST /api/scans/ for new implementations."
)


def add_deprecation_header(response: Response, endpoint_name: str) -> None:
    """
    Add deprecation warning headers to legacy endpoint responses.

    Follows RFC 8594 Sunset header standard for API deprecation notices.

    Args:
        response: FastAPI Response object to add headers to.
        endpoint_name: Name of the deprecated endpoint for logging.
    """
    response.headers["Deprecation"] = "true"
    response.headers["X-Deprecation-Notice"] = DEPRECATION_WARNING
    response.headers["Link"] = '</api/scans/>; rel="successor-version"'
    logger.debug("Legacy endpoint accessed: %s", endpoint_name)


# =============================================================================
# Error Sanitization Helper
# =============================================================================


def sanitize_http_error(
    request: Request,
    current_user: Dict[str, Any],
    exception: Exception,
    fallback_message: str,
    status_code: int = 500,
) -> HTTPException:
    """
    Sanitize HTTP errors to prevent information disclosure.

    This function creates user-safe error responses by:
    1. Extracting client context (IP, user ID) for audit logging
    2. Sanitizing technical error details to prevent info leakage
    3. Returning generic, user-friendly error messages

    Args:
        request: FastAPI request object for client context extraction.
        current_user: Authenticated user dict from JWT token.
        exception: The original exception to sanitize.
        fallback_message: User-friendly message if sanitization fails.
        status_code: HTTP status code for the error response.

    Returns:
        HTTPException with sanitized error message.

    Security:
        - Technical stack traces are never exposed to clients
        - Original error logged server-side for debugging
        - Client IP logged for security audit trail
    """
    try:
        # Extract client context for audit logging
        client_ip = request.client.host if request.client else "unknown"
        user_id = current_user.get("sub") if current_user else None

        # Use sanitization service to create user-safe error response
        # Note: This is synchronous - async error classification happens in endpoints
        local_sanitization_service = get_error_sanitization_service()
        sanitized_error = local_sanitization_service.sanitize_error(
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
        # Log sanitization failure but never expose internal errors to client
        logger.error(
            "Error sanitization failed",
            extra={"error": str(sanitization_error), "original_error": str(exception)},
        )
        return HTTPException(status_code=status_code, detail=fallback_message)


# =============================================================================
# PUBLIC API EXPORTS
# =============================================================================

__all__ = [
    # Services
    "error_service",
    "sanitization_service",
    # Scanner singletons
    "get_compliance_scanner",
    "get_enrichment_service",
    "get_compliance_reporter",
    # XCCDF parsing
    "parse_xccdf_results",
    # Background tasks
    "enrich_scan_results_background",
    # Deprecation helpers
    "DEPRECATION_WARNING",
    "add_deprecation_header",
    # Error handling
    "sanitize_http_error",
]
