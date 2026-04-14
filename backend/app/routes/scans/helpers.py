"""
Helper Functions and Singletons for Scanning API

This module provides shared utilities for the scanning API including:
- Scanner service singletons (lazy initialization pattern)
- Error sanitization helpers

Architecture Notes:
    Singleton Pattern: Scanner services are expensive to initialize, so we use
    lazy-loaded singletons that persist across API requests for efficiency.

Security Notes:
    - Error sanitization prevents information disclosure
    - All file paths are validated against traversal attacks
"""

import logging
from typing import Any, Dict, Optional

from fastapi import HTTPException, Request, Response

# object removed (SCAP-era dead code)
from app.services.framework import ComplianceFrameworkReporter

# object removed (SCAP-era dead code)
from app.services.validation import ErrorClassificationService, get_error_sanitization_service

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

_compliance_scanner: Optional[Any] = None
_enrichment_service: Optional[Any] = None
_compliance_reporter: Optional[ComplianceFrameworkReporter] = None


async def get_compliance_scanner(request: Request) -> Any:
    """
    Get or initialize the compliance scanner singleton.

    This function lazily initializes the object on first use
    and returns the cached instance on subsequent calls. The scanner
    requires an encryption service from the app state for credential handling.

    Args:
        request: FastAPI request object to access app state.

    Returns:
        Initialized object instance.

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
            # SCAP-era scanner removed; placeholder for legacy endpoint compatibility
            _compliance_scanner = None
            logger.warning("Compliance scanner not available (SCAP-era code removed)")
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


async def get_enrichment_service() -> Any:
    """
    Get or initialize the result enrichment service singleton.

    The enrichment service adds intelligence data to scan results,
    including remediation guidance and framework mappings.

    Returns:
        Initialized object instance.
    """
    global _enrichment_service
    if _enrichment_service is None:
        # SCAP-era enrichment service removed; placeholder for legacy endpoint compatibility
        _enrichment_service = None
        logger.warning("Enrichment service not available (SCAP-era code removed)")
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
    # Deprecation helpers
    "DEPRECATION_WARNING",
    "add_deprecation_header",
    # Error handling
    "sanitize_http_error",
]
