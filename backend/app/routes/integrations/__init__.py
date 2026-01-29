"""
Integrations API Package

This package provides the REST API for external integrations.
The package follows a modular architecture for maintainability.

Package Structure:
    integrations/
    ├── __init__.py         # This file - public API and router aggregation
    ├── webhooks.py         # Webhook management endpoints
    └── plugins.py          # Plugin management endpoints

Migration Status (API Standardization - Phase 4):
    Phase 4: System & Integrations
    - webhooks.py endpoints consolidated under /webhooks
    - plugin_management.py endpoints consolidated under /plugins

Usage:
    # Import the router in main.py
    from app.routes.integrations import router
    app.include_router(router, prefix="/api")

Router Organization:
    The main router aggregates all sub-routers with their endpoints:

    Webhooks Router (webhooks.py):
        GET    /webhooks/                      - List webhook endpoints
        POST   /webhooks/                      - Create webhook endpoint
        GET    /webhooks/{webhook_id}          - Get webhook details
        PUT    /webhooks/{webhook_id}          - Update webhook endpoint
        DELETE /webhooks/{webhook_id}          - Delete webhook endpoint
        GET    /webhooks/{webhook_id}/deliveries - Get delivery history
        POST   /webhooks/{webhook_id}/test     - Test webhook endpoint

    Plugins Router (plugins.py):
        POST   /plugins/import                 - Import plugin from file
        GET    /plugins/                       - List plugins
        GET    /plugins/statistics/overview    - Get plugin statistics
        GET    /plugins/{plugin_id}            - Get plugin details
        DELETE /plugins/{plugin_id}            - Delete plugin
        POST   /plugins/{plugin_id}/execute    - Execute plugin
        GET    /plugins/{plugin_id}/executions - Get execution history
"""

from fastapi import APIRouter

# Create main router that aggregates all sub-routers
# Note: prefix="/integrations" ensures all endpoints are under /api/integrations/*
router = APIRouter(prefix="/integrations", tags=["Integrations"])

# Import sub-routers from modular files
# Using try/except for graceful fallback during migration
_modules_loaded = False

try:
    # Core integration routers - use relative imports within package
    from .plugins import router as plugins_router
    from .webhooks import router as webhooks_router

    # Include all sub-routers into main router
    router.include_router(webhooks_router)
    router.include_router(plugins_router)

    _modules_loaded = True

except ImportError as e:
    # Fall back to legacy routers during migration
    import logging

    logger = logging.getLogger(__name__)
    logger.warning(f"Failed to load modular integration routers, falling back to legacy: {e}")

    try:
        from ..plugin_management_legacy import router as plugins_legacy_router
        from ..webhooks_legacy import router as webhooks_legacy_router

        router.include_router(webhooks_legacy_router)
        router.include_router(plugins_legacy_router)
    except ImportError:
        # If even legacy fails, create empty router
        logger.error("Failed to load any integration router - API will be incomplete")


__all__ = [
    "router",
]
