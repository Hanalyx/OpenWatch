"""
SCAP Scanning API Package

This package provides the REST API for compliance scanning operations.
The package follows a modular architecture for maintainability.

Package Structure:
    scans/
    ├── __init__.py         # This file - public API and router aggregation
    ├── models.py           # Pydantic request/response models
    ├── helpers.py          # Utility functions and scanner singletons
    ├── compliance.py       # Primary compliance scan endpoints
    ├── crud.py             # Basic CRUD operations
    ├── reports.py          # Report generation endpoints
    ├── bulk.py             # Bulk scan operations
    ├── validation.py       # Readiness/validation endpoints
    ├── config.py           # Framework discovery and configuration (Phase 2)
    ├── templates.py        # Scan template management (Phase 2)
    ├── rules.py            # Rule-specific scanning operations (Phase 2)
    └── mongodb.py          # MongoDB-integrated scanning (Phase 2)

Migration Status (API Standardization):
    Phase 1: Extract models and helpers (COMPLETE)
    - All Pydantic models moved to models.py
    - All helper functions moved to helpers.py

    Phase 2: Route separation (COMPLETE)
    - compliance.py: Primary scan creation, rules, scanner health
    - crud.py: List, get, create, update, delete, stop, cancel, recover, apply-fix
    - reports.py: HTML, JSON, CSV reports, failed-rules, results
    - bulk.py: Bulk scan create, progress, cancel, sessions
    - validation.py: Validate, quick-scan, verify, remediate, readiness

    Phase 3: API Standardization Consolidation (COMPLETE)
    - config.py: Framework discovery (from scan_config_api.py)
    - templates.py: Template management (from scan_config_api.py + scan_templates.py)
    - rules.py: Rule-specific scanning (from rule_scanning.py)
    - mongodb.py: MongoDB-integrated scanning (from mongodb_scan_api.py)

    Phase 4: Integration (CURRENT)
    - Aggregate all routers into single main router
    - Update main.py to use unified scans package
    - Remove legacy route files

Usage:
    # Import the router in main.py
    from backend.app.routes.scans import router
    app.include_router(router, prefix="/api/scans")

    # Import models directly
    from backend.app.routes.scans.models import ComplianceScanRequest

    # Import helpers
    from backend.app.routes.scans.helpers import get_compliance_scanner

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

    Templates Router (templates.py) - Phase 2:
        GET  /templates/quick                    - Get quick/static templates
        GET  /templates                          - List MongoDB templates
        POST /templates                          - Create template
        GET  /templates/{template_id}            - Get template details
        PUT  /templates/{template_id}            - Update template
        DELETE /templates/{template_id}          - Delete template
        POST /templates/{template_id}/apply      - Apply template to hosts
        POST /templates/{template_id}/clone      - Clone template
        POST /templates/{template_id}/set-default - Set as default template

    Rules Router (rules.py) - Phase 2:
        POST /rules/scan                         - Execute rule-specific scan
        POST /rules/rescan-failed                - Rescan failed rules
        POST /rules/verify-remediation           - Verify remediation
        GET  /rules/{rule_id}/history            - Get rule scan history
        GET  /rules/{rule_id}/compliance-info    - Get rule compliance info
        POST /rules/remediation-plan             - Generate remediation plan

    MongoDB Router (mongodb.py) - Phase 2:
        POST /mongodb/start                      - Start MongoDB-integrated scan
        GET  /mongodb/{scan_id}/status           - Get scan status
        GET  /mongodb/{scan_id}/results          - Get scan results
        GET  /mongodb/{scan_id}/report           - Get scan report
        GET  /mongodb/available-rules            - Get available rules
        GET  /mongodb/scanner/health             - Get scanner health
"""

from fastapi import APIRouter

# Create main router that aggregates all sub-routers
# Note: prefix="/scans" ensures all endpoints are under /api/scans/*
router = APIRouter(prefix="/scans", tags=["Scans"])

# Import sub-routers from modular files
# Using try/except for graceful fallback during migration
_modules_loaded = False

try:
    # Core scan routers (Phase 1-2)
    from backend.app.routes.scans.bulk import router as bulk_router
    from backend.app.routes.scans.compliance import router as compliance_router

    # API Standardization routers (Phase 3)
    from backend.app.routes.scans.config import router as config_router
    from backend.app.routes.scans.crud import router as crud_router
    from backend.app.routes.scans.mongodb import router as mongodb_router
    from backend.app.routes.scans.reports import router as reports_router
    from backend.app.routes.scans.rules import router as rules_router
    from backend.app.routes.scans.templates import router as templates_router
    from backend.app.routes.scans.validation import router as validation_router

    # Include all sub-routers into main router
    # Order matters for route matching - more specific routes first
    # Phase 3 routers have specific prefixes, so include them first
    router.include_router(config_router)
    router.include_router(templates_router)
    router.include_router(rules_router)
    router.include_router(mongodb_router)

    # Core routers (more generic patterns)
    router.include_router(compliance_router)
    router.include_router(crud_router)
    router.include_router(reports_router)
    router.include_router(bulk_router)
    router.include_router(validation_router)

    _modules_loaded = True

except ImportError as e:
    # Fall back to legacy monolithic router during migration
    import logging

    logger = logging.getLogger(__name__)
    logger.warning(f"Failed to load modular scan routers, falling back to scans_routes.py: {e}")

    try:
        from backend.app.routes.scans_routes import router as legacy_router

        router = legacy_router
    except ImportError:
        # If even legacy fails, create empty router (should not happen in production)
        logger.error("Failed to load any scan router - API will be incomplete")


# Re-export helpers for convenient access
from backend.app.routes.scans.helpers import (  # noqa: E402
    DEPRECATION_WARNING,
    add_deprecation_header,
    enrich_scan_results_background,
    get_compliance_reporter,
    get_compliance_scanner,
    get_enrichment_service,
    parse_xccdf_results,
    sanitize_http_error,
)

# Re-export models for convenient access
from backend.app.routes.scans.models import (  # noqa: E402
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
    # Background tasks
    "enrich_scan_results_background",
    # Deprecation helpers
    "DEPRECATION_WARNING",
    "add_deprecation_header",
    # Error handling
    "sanitize_http_error",
]
