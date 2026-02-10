"""
Compliance Scanning API Package

This package provides the REST API for compliance scanning operations.
The package follows a modular architecture for maintainability.

Package Structure:
    scans/
    ├── __init__.py         # This file - public API and router aggregation
    ├── models.py           # Pydantic request/response models
    ├── helpers.py          # Utility functions and scanner singletons
    ├── aegis.py            # Aegis compliance engine (PRIMARY)
    ├── compliance.py       # Primary compliance scan endpoints
    ├── crud.py             # Basic CRUD operations
    ├── reports.py          # Report generation endpoints
    ├── bulk.py             # Bulk scan operations
    ├── validation.py       # Readiness/validation endpoints
    ├── config.py           # Framework discovery and configuration
    └── templates.py        # Scan template management

Migration Status:
    Phase 1-6: API Standardization (COMPLETE)
    Phase 7: MongoDB Deprecation (2026-02-10)
    - Removed mongodb.py (1,115 LOC) - Legacy MongoDB SCAP scanning
    - Removed rules.py (721 LOC) - MongoDB rule scanning
    - Replaced by Aegis native compliance scanning at /aegis/*

Usage:
    # Import the router in main.py
    from app.routes.scans import router
    app.include_router(router, prefix="/api/scans")

    # Import models directly
    from app.routes.scans.models import ComplianceScanRequest

    # Import helpers
    from app.routes.scans.helpers import get_compliance_scanner

Router Organization:
    The main router aggregates all sub-routers with their endpoints:

    Compliance Router (compliance.py):
        POST /                          - Create compliance scan
        GET  /rules/available           - Get available rules
        GET  /scanner/health            - Get scanner health

    CRUD Router (crud.py):
        GET  /                          - List scans
        GET  /{scan_id}                 - Get scan details
        POST /legacy                    - Create legacy SCAP scan
        PATCH /{scan_id}                - Update scan
        DELETE /{scan_id}               - Delete scan
        POST /{scan_id}/stop            - Stop running scan
        POST /{scan_id}/cancel          - Cancel running scan (alias for /stop)
        POST /{scan_id}/recover         - Recover failed scan
        POST /hosts/{host_id}/apply-fix - Apply automated fix

    Reports Router (reports.py):
        GET  /{scan_id}/results         - Get scan results (primary endpoint)
        GET  /{scan_id}/report/html     - Get HTML report
        GET  /{scan_id}/report/json     - Get JSON report
        GET  /{scan_id}/report/csv      - Get CSV report
        GET  /{scan_id}/failed-rules    - Get failed rules

    Bulk Router (bulk.py):
        POST /bulk-scan                     - Create bulk scan session
        GET  /bulk-scan/{session_id}/progress - Get bulk scan progress
        POST /bulk-scan/{session_id}/cancel   - Cancel bulk scan
        GET  /sessions                        - List scan sessions

    Validation Router (validation.py):
        POST /validate                      - Pre-flight validation (legacy)
        POST /hosts/{host_id}/quick-scan    - Quick scan (legacy)
        POST /verify                        - Verification scan (legacy)
        POST /{scan_id}/rescan/rule         - Rescan rule (disabled)
        POST /{scan_id}/remediate           - Start AEGIS remediation
        POST /readiness/validate-bulk       - Bulk host readiness
        GET  /{scan_id}/pre-flight-check    - Pre-flight check
        GET  /capabilities                  - Get scan capabilities
        GET  /summary                       - Get scan summary
        GET  /profiles                      - Get available profiles

    Config Router (config.py) - Phase 2:
        GET  /config/frameworks                              - List frameworks
        GET  /config/frameworks/{framework}/{version}        - Get framework details
        GET  /config/frameworks/{framework}/{version}/variables - Get framework variables
        POST /config/frameworks/{framework}/{version}/validate  - Validate configuration
        GET  /config/statistics                              - Get framework statistics

    Templates Router (templates.py):
        GET  /templates/quick                    - Get quick/static templates
        GET  /templates                          - List templates
        POST /templates                          - Create template
        GET  /templates/{template_id}            - Get template details
        PUT  /templates/{template_id}            - Update template
        DELETE /templates/{template_id}          - Delete template
        POST /templates/{template_id}/apply      - Apply template to hosts
        POST /templates/{template_id}/clone      - Clone template
        POST /templates/{template_id}/set-default - Set as default template

    Aegis Router (aegis.py) - Primary Compliance Engine:
        POST /aegis                              - Execute Aegis compliance scan
        GET  /aegis/frameworks                   - List available frameworks
        GET  /aegis/health                       - Aegis engine health check
"""

from fastapi import APIRouter

# Create main router that aggregates all sub-routers
# Note: prefix="/scans" ensures all endpoints are under /api/scans/*
router = APIRouter(prefix="/scans", tags=["Scans"])

# Import sub-routers from modular files
# Note: These imports must come after router definition to avoid circular imports
# Core scan routers (Phase 1-2)
from app.routes.scans.bulk import router as bulk_router  # noqa: E402
from app.routes.scans.compliance import router as compliance_router  # noqa: E402

# API Standardization routers (Phase 3)
from app.routes.scans.config import router as config_router  # noqa: E402
from app.routes.scans.crud import router as crud_router  # noqa: E402
from app.routes.scans.reports import router as reports_router  # noqa: E402
from app.routes.scans.templates import router as templates_router  # noqa: E402
from app.routes.scans.validation import router as validation_router  # noqa: E402

# Include all sub-routers into main router
# Order matters for route matching - more specific routes first
# Phase 3 routers have specific prefixes, so include them first
router.include_router(config_router)
router.include_router(templates_router)

# NOTE: MongoDB routes removed during MongoDB deprecation (2026-02-10)
# - mongodb.py (1,115 LOC) - Legacy MongoDB SCAP scanning - Replaced by Aegis
# - rules.py (721 LOC) - MongoDB rule scanning - Replaced by Aegis frameworks

# Aegis compliance engine router (E0-S5 API Endpoints)
from app.routes.scans.aegis import router as aegis_router  # noqa: E402

router.include_router(aegis_router)

# Core routers (more generic patterns)
router.include_router(compliance_router)
router.include_router(crud_router)
router.include_router(reports_router)
router.include_router(bulk_router)
router.include_router(validation_router)


# Re-export helpers for convenient access
from app.routes.scans.helpers import (  # noqa: E402
    DEPRECATION_WARNING,
    add_deprecation_header,
    get_compliance_reporter,
    get_compliance_scanner,
    get_enrichment_service,
    parse_xccdf_results,
    sanitize_http_error,
)

# Re-export models for convenient access
from app.routes.scans.models import (  # noqa: E402
    AutomatedFixRequest,
    AvailableRulesResponse,
    BulkScanRequest,
    BulkScanResponse,
    ComplianceScanRequest,
    ComplianceScanResponse,
    ComponentHealth,
    PlatformResolution,
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

__all__ = [
    # Router
    "router",
    # Compliance scan models (PRIMARY)
    "ComplianceScanRequest",
    "ComplianceScanResponse",
    # Available rules models
    "RuleSummary",
    "PlatformResolution",
    "AvailableRulesResponse",
    # Scanner health models
    "ComponentHealth",
    "ScannerCapabilities",
    "ScannerHealthResponse",
    # Legacy SCAP models
    "ScanRequest",
    "ScanUpdate",
    "RuleRescanRequest",
    "VerificationScanRequest",
    "ValidationRequest",
    "AutomatedFixRequest",
    "QuickScanRequest",
    "QuickScanResponse",
    "BulkScanRequest",
    "BulkScanResponse",
    # Scanner singletons
    "get_compliance_scanner",
    "get_enrichment_service",
    "get_compliance_reporter",
    # XCCDF parsing
    "parse_xccdf_results",
    # Deprecation helpers
    "DEPRECATION_WARNING",
    "add_deprecation_header",
    # Error handling
    "sanitize_http_error",
]
