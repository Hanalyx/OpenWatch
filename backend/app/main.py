"""
OpenWatch FastAPI Application - FIPS Compliant Security Scanner
Main application with comprehensive security middleware
"""

import asyncio
import logging
import os
import time
import types
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Callable, Dict, Optional

import uvicorn
from fastapi import Depends, FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.responses import Response

# Note: These were previously in api/v1/endpoints/ and have been
# consolidated into routes/ as part of the API unification effort.
# OpenWatch uses unified /api prefix (no URL-based versioning).
from .audit_db import log_security_event
from .auth import audit_logger, require_admin
from .config import SECURITY_HEADERS, get_settings
from .database import get_db_session
from .middleware.metrics import PrometheusMiddleware, background_updater
from .middleware.rate_limiting import get_rate_limiting_middleware
from .routes import (  # noqa: E501; REMOVED route consolidation notes:; - api_keys, auth, mfa: Consolidated into routes/auth/ (E1-S4); - hosts, host_*_discovery: Consolidated into routes/hosts/ (Phase 3); - mongodb_scan_api, rule_scanning, scan_config_api, scan_templates: Consolidated into routes/scans/ (Phase 2); - compliance, drift_events, owca: Consolidated into routes/compliance/ (Phase 4); - plugin_management, webhooks: Consolidated into routes/integrations/ (Phase 4); - ssh_debug, ssh_settings: Consolidated into routes/ssh/ (Phase 4); - bulk_remediation_routes, remediation_api: Moved to SecureOps/AEGIS (ORSA subsystem)
    adaptive_scheduler,
    baselines,
    bulk_operations,
    capabilities,
    health_monitoring,
    integration_metrics,
    mongodb_test,
    monitoring,
    os_discovery,
    remediation_callback,
    remediation_provider,
    scans,
    version,
)

# Import admin from new modular package (E1-S6 Route Consolidation)
# This package consolidates users.py, audit.py, and credentials.py
from .routes.admin import router as admin_router

# Import auth from new modular package (E1-S4 Route Consolidation)
# This package consolidates auth.py, mfa.py, and api_keys.py into a single
# modular package with login, MFA, and API key endpoints
from .routes.auth import router as auth_router

# Import compliance from new modular package (Phase 4 API Standardization)
# This package consolidates compliance.py, owca.py, and drift_events.py into a single
# modular package with intelligence, OWCA, and drift endpoints
from .routes.compliance import router as compliance_router

# Import content from new modular package (E1-S7 Route Consolidation)
# This package consolidates content.py, scap_import.py, and xccdf_api.py
from .routes.content import router as content_pkg_router

# Import host_groups from new modular package (Phase 1 API Standardization)
# This package consolidates host_groups.py and group_compliance.py into a single
# modular package with CRUD and scanning endpoints aligned with frontend scanService.ts
from .routes.host_groups import router as host_groups_router

# Import hosts from new modular package (Phase 3 API Standardization)
# This package consolidates hosts.py, host_discovery.py, host_network_discovery.py,
# host_security_discovery.py, and host_compliance_discovery.py into a single
# modular package with CRUD and discovery endpoints
from .routes.hosts import router as hosts_router

# Import integrations from new modular package (Phase 4 API Standardization)
# This package consolidates webhooks.py and plugin_management.py into a single
# modular package with webhooks and plugins endpoints
from .routes.integrations import router as integrations_router

# Import rules from new modular package (E1-S5 Route Consolidation)
# This package consolidates rule_management.py, rule_scanning.py, and
# compliance_rules_api.py into a single modular package
from .routes.rules import router as rules_router

# Import SSH from new modular package (Phase 4 API Standardization)
# This package consolidates ssh_settings.py and ssh_debug.py into a single
# modular package with settings and debug endpoints
from .routes.ssh import router as ssh_router
from .routes.system_settings_unified import router as system_settings_router
from .services.prometheus_metrics import get_metrics_instance

# Import security routes only if available
# Type declarations for optional modules
automated_fixes: Optional[types.ModuleType]
authorization: Optional[types.ModuleType]
security_config: Optional[types.ModuleType]

try:
    from .routes import automated_fixes
except ImportError:
    print("automated_fixes not available")
    automated_fixes = None

try:
    from .routes import authorization, security_config
except ImportError:
    print("authorization/security_config not available")
    authorization = None
    security_config = None

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan management."""
    # Startup
    logger.info("Starting OpenWatch application...")

    # Initialize encryption service with dependency injection (NEW)
    logger.info("Initializing encryption service...")
    from .encryption import EncryptionConfig, create_encryption_service

    # Create encryption service with production config
    encryption_config = EncryptionConfig()  # Uses secure defaults (100k iterations, SHA256)
    encryption_service = create_encryption_service(master_key=settings.master_key, config=encryption_config)

    # Store in app state for dependency injection
    app.state.encryption_service = encryption_service
    logger.info(
        f"Encryption service initialized " f"(AES-256-GCM, PBKDF2 with {encryption_config.kdf_iterations} iterations)"
    )

    # Verify FIPS mode if required
    if settings.fips_mode:
        try:
            from security.config.fips_config import FIPSConfig

            if not FIPSConfig.validate_fips_mode():
                logger.warning("FIPS mode is not enabled in the system")
            else:
                logger.info("FIPS mode validated successfully")
        except ImportError:
            logger.warning("FIPS configuration module not found - using development mode")

    # Create database tables with retry logic (skip in development if fails)
    max_retries = 3
    retry_delay = 5

    for attempt in range(max_retries):
        try:
            # Initialize complete database schema (includes tables without ORM models)
            from .init_database_schema import initialize_database_schema

            schema_success = initialize_database_schema()

            if not schema_success:
                logger.error("Critical database schema initialization failed!")
                logger.error("Application cannot start without required tables.")
                if attempt < max_retries - 1:
                    logger.info(f"Retrying in {retry_delay} seconds... (attempt {attempt + 1}/{max_retries})")
                    await asyncio.sleep(retry_delay)
                    continue
                else:
                    raise Exception("Database schema initialization failed after all retries")

            logger.info("Complete database schema initialized successfully")

            # Run SQL migrations automatically
            try:
                from .database import SessionLocal
                from .services.migration_runner import run_startup_migrations

                db = SessionLocal()
                try:
                    migrations_success = run_startup_migrations(db)
                    if migrations_success:
                        logger.info("Automatic migrations completed successfully")
                    else:
                        logger.error("Some migrations failed - check logs for details")
                        if not settings.debug:
                            raise Exception("Critical migrations failed")
                finally:
                    db.close()
            except Exception as migration_error:
                logger.error(f"Migration runner error: {migration_error}")
                if not settings.debug:
                    raise

            # Initialize RBAC system
            try:
                from .init_roles import initialize_rbac_system

                await initialize_rbac_system()
                logger.info("RBAC system initialized successfully")
            except Exception as rbac_error:
                logger.warning(f"RBAC initialization failed: {rbac_error}")
                if not settings.debug:
                    raise

            # Legacy APScheduler disabled - using Celery Beat for adaptive monitoring
            # The new adaptive scheduler runs via Celery Beat with state-based intervals
            # See: backend/app/tasks/adaptive_monitoring_dispatcher.py
            logger.info("Legacy APScheduler disabled - using Celery Beat adaptive monitoring")

            break
        except Exception as e:
            if attempt < max_retries - 1:
                logger.warning(
                    f"Database connection attempt {attempt + 1} failed: {e}. Retrying in {retry_delay} seconds..."
                )
                import asyncio as async_sleep_module

                await async_sleep_module.sleep(retry_delay)
            else:
                if settings.debug:
                    logger.warning(f"Database connection failed in debug mode, continuing without DB: {e}")
                else:
                    logger.error(f"Failed to connect to database after {max_retries} attempts: {e}")
                    raise

    # Initialize JWT keys
    logger.info("JWT manager initialized with RSA keys")

    # Initialize MongoDB
    try:
        from .services.mongo_integration_service import get_mongo_service

        _ = await get_mongo_service()  # Initialize but don't store reference
        logger.info("MongoDB integration service initialized successfully")

        # Health monitoring models are initialized with other Beanie models
        logger.info("Health monitoring models ready")

    except Exception as mongo_error:
        logger.warning(f"MongoDB initialization failed: {mongo_error}")
        if not settings.debug:
            raise

    # Distributed tracing disabled for initial deployment
    logger.info("Distributed tracing disabled for initial deployment")

    # Background metrics collection disabled for debugging
    logger.info("Background metrics collection disabled for debugging")

    logger.info("OpenWatch application started successfully")

    yield

    # Shutdown
    logger.info("Shutting down OpenWatch application...")
    background_updater.stop_background_updates()
    logger.info("Background metrics collection stopped")


# Create FastAPI application
app = FastAPI(
    title="OpenWatch - SCAP Security Scanner",
    description="FIPS-compliant web-based OpenSCAP security scanner",
    version="1.2.0",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    lifespan=lifespan,
)


# Rate Limiting Middleware with Token Bucket Algorithm
# Environment-controlled: Set OPENWATCH_RATE_LIMITING=false to disable for development
# Uses industry-standard token bucket algorithm with proper burst handling and recovery times
rate_limiter = get_rate_limiting_middleware()
app.middleware("http")(rate_limiter)


# Security Middleware
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next: Callable[[Request], Any]) -> Response:
    """Add FIPS-compliant security headers to all responses."""
    response = await call_next(request)

    # Add security headers with development modifications
    for header, value in SECURITY_HEADERS.items():
        if header == "Content-Security-Policy" and settings.debug:
            # More permissive CSP for development
            dev_csp = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "connect-src 'self' http://localhost:8000 http://localhost:8002 ws://localhost:3000; "
                "font-src 'self'; "
                "frame-src 'none'; "
                "object-src 'none'"
            )
            response.headers[header] = dev_csp
        else:
            response.headers[header] = value

    return response


def _log_audit_event(db: Any, event_type: str, request: Request, response: Response, client_ip: str) -> None:
    """Helper function to log audit events to both file and database."""
    details = f"Path: {request.url.path}, Method: {request.method}, Status: {response.status_code}"

    # Log to file
    audit_logger.log_security_event(event_type, details, client_ip)

    # Log to database
    log_security_event(db=db, event_type=event_type, ip_address=client_ip, details=details)


@app.middleware("http")
async def audit_middleware(request: Request, call_next: Callable[[Request], Any]) -> Response:
    """Log security-relevant requests for audit purposes."""
    # Get client IP
    client_ip = request.client.host
    if "x-forwarded-for" in request.headers:
        client_ip = request.headers["x-forwarded-for"].split(",")[0].strip()

    # Process request
    response = await call_next(request)

    # Get database session for audit logging
    db = get_db_session()

    try:
        # Map URL path prefixes to event types
        path_event_map = {
            "/api/scans": "SCAN_OPERATION",
            "/api/hosts": "HOST_OPERATION",
            "/api/users": "USER_OPERATION",
            "/api/webhooks": "WEBHOOK_OPERATION",
        }

        # Log based on path prefix
        for path_prefix, event_type in path_event_map.items():
            if request.url.path.startswith(path_prefix):
                _log_audit_event(db, event_type, request, response, client_ip)
                break

        # Log HTTP errors (independently of path-based logging)
        if response.status_code >= 400:
            _log_audit_event(db, "HTTP_ERROR", request, response, client_ip)

    except Exception as e:
        logger.error(f"Error in audit middleware: {e}")
    finally:
        db.close()

    return response


@app.middleware("http")
async def request_size_limit_middleware(request: Request, call_next: Callable[[Request], Any]) -> Response:
    """Enforce request size limits to prevent DoS attacks."""
    max_size = settings.max_upload_size  # 100MB default

    # Check Content-Length header if present
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > max_size:
        logger.warning(
            f"Request too large: {content_length} bytes from {request.client.host if request.client else 'unknown'}"
        )
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={"detail": f"Request body too large. Maximum size: {max_size // (1024*1024)}MB"},
        )

    return await call_next(request)


@app.middleware("http")
async def https_redirect_middleware(request: Request, call_next: Callable[[Request], Any]) -> Response:
    """Enforce HTTPS in production."""
    if settings.require_https and not settings.debug:
        if request.url.scheme != "https":
            https_url = request.url.replace(scheme="https")
            return JSONResponse(
                status_code=status.HTTP_301_MOVED_PERMANENTLY,
                headers={"Location": str(https_url)},
            )

    return await call_next(request)


# CORS Middleware (restrictive for security)
cors_origins = settings.allowed_origins
if settings.debug:
    # Allow HTTP localhost for development
    cors_origins = cors_origins + ["http://localhost:3001"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    expose_headers=["X-Total-Count"],
)

# Trusted Host Middleware
trusted_hosts = ["localhost", "127.0.0.1"]
if settings.debug or os.environ.get("TESTING"):
    # Allow FastAPI TestClient default host header
    trusted_hosts.append("testserver")
if not settings.debug:
    # Add production domains from allowed origins
    for origin in settings.allowed_origins:
        if origin.startswith("https://"):
            host = origin.replace("https://", "").split(":")[0]
            trusted_hosts.append(host)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=trusted_hosts)

# Add Prometheus metrics middleware
app.add_middleware(PrometheusMiddleware, service_name="openwatch")


# Health Check Endpoint
@app.get("/health")
async def health_check() -> JSONResponse:
    """Health check endpoint for container orchestration."""
    try:
        # Basic health checks
        health_status = {
            "status": "healthy",
            "timestamp": time.time(),
            "version": "1.2.0",
            "fips_mode": settings.fips_mode,
        }

        # Helper function for synchronous DB check
        def check_database_sync() -> tuple[bool, str]:
            db = None
            try:
                from sqlalchemy import text

                from .database import SessionLocal

                db = SessionLocal()
                db.execute(text("SELECT 1"))
                return True, "healthy"
            except Exception as e:
                logger.error(f"Database health check failed - inline version: {e}")
                return False, "unhealthy"
            finally:
                if db:
                    db.close()

        # Helper function for synchronous Redis check
        def check_redis_sync() -> tuple[bool, str]:
            redis_client = None
            try:
                import urllib.parse

                import redis

                parsed = urllib.parse.urlparse(settings.redis_url)
                redis_client = redis.Redis(
                    host=parsed.hostname or "localhost",
                    port=parsed.port or 6379,
                    password=parsed.password,
                    socket_timeout=5,
                    socket_connect_timeout=5,
                )
                redis_client.ping()
                return True, "healthy"
            except Exception as e:
                logger.error(f"Redis health check failed - inline version: {e}")
                return False, "unhealthy"
            finally:
                if redis_client:
                    redis_client.close()

        # Run synchronous checks in thread pool to avoid blocking async event loop
        loop = asyncio.get_event_loop()
        db_healthy, db_status = await loop.run_in_executor(None, check_database_sync)
        health_status["database"] = db_status
        if db_healthy:
            logger.info("Database health check successful - inline version")

        redis_healthy, redis_status = await loop.run_in_executor(None, check_redis_sync)
        health_status["redis"] = redis_status
        if redis_healthy:
            logger.info("Redis health check successful - inline version")

        # Check MongoDB connectivity
        mongodb_configured = bool(settings.mongodb_url and "mongodb://" in settings.mongodb_url)
        mongodb_healthy = True

        if mongodb_configured:
            try:
                from .services.mongo_integration_service import get_mongo_service

                mongo_service = await get_mongo_service()
                mongo_health = await mongo_service.health_check()
                health_status["mongodb"] = mongo_health.get("status", "unknown")
                mongodb_healthy = mongo_health.get("status") == "healthy"
                if mongodb_healthy:
                    logger.info("MongoDB health check successful")
                else:
                    logger.warning(f"MongoDB health check failed: {mongo_health.get('message', 'Unknown error')}")
            except Exception as e:
                # Return actual error status
                health_status["mongodb"] = "unhealthy"
                health_status["mongodb_error"] = str(e)
                logger.error(f"MongoDB health check failed: {e}")
                mongodb_healthy = False
        else:
            # MongoDB not configured - this is acceptable
            health_status["mongodb"] = "not_configured"
            logger.info("MongoDB not configured - skipping health check")
            mongodb_healthy = True  # Don't fail overall health for unconfigured service

        # Overall status
        if not (db_healthy and redis_healthy and mongodb_healthy):
            health_status["status"] = "degraded"
            return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content=health_status)

        return JSONResponse(status_code=status.HTTP_200_OK, content=health_status)

    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "unhealthy", "error": str(e), "timestamp": time.time()},
        )


# Security Info Endpoint
@app.get("/security-info")
async def security_info(current_user: Dict[str, Any] = Depends(require_admin)) -> JSONResponse:
    """Provide security configuration information (admin only)."""
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "fips_mode": settings.fips_mode,
            "https_required": settings.require_https,
            "jwt_algorithm": "RS256",
            "encryption": "AES-256-GCM",
            "hash_algorithm": "Argon2id",
            "tls_version": "1.3",
        },
    )


# Prometheus Metrics Endpoint
@app.get("/metrics")
async def metrics() -> PlainTextResponse:
    """Prometheus metrics endpoint."""
    metrics_instance = get_metrics_instance()
    metrics_data = metrics_instance.get_metrics()

    return PlainTextResponse(content=metrics_data, media_type="text/plain; version=0.0.4; charset=utf-8")


# Include API routes - Unified API at /api prefix
# Version endpoint (public, no auth required)
app.include_router(version.router, prefix="/api", tags=["Version"])

# Capabilities and system information
app.include_router(capabilities.router, prefix="/api", tags=["System Capabilities"])

# MongoDB and SCAP endpoints (consolidated from v1)
app.include_router(mongodb_test.router, prefix="/api/mongodb", tags=["MongoDB Integration Test"])
app.include_router(rules_router, prefix="/api", tags=["Rules"])
app.include_router(content_pkg_router, prefix="/api", tags=["Content"])
# mongodb_scan_api - REMOVED: Consolidated into routes/scans/mongodb.py (Phase 2)
# Endpoints now available at /api/scans/mongodb/*

# remediation_api - REMOVED: Moved to SecureOps/AEGIS (ORSA subsystem)
# scan_config_api - REMOVED: Consolidated into routes/scans/config.py and templates.py (Phase 2)
# Endpoints now available at /api/scans/config/* and /api/scans/templates/*
app.include_router(health_monitoring.router, prefix="/api/health-monitoring", tags=["Health Monitoring"])

# Remediation provider (registration interface for ORSA adapters)
app.include_router(remediation_provider.router, prefix="/api/remediation", tags=["Remediation Provider"])

# Core API routes
# auth - Modular package (E1-S4) - consolidates login, MFA, API keys
app.include_router(auth_router, prefix="/api/auth", tags=["Authentication"])
# Hosts - Modular package with all host-related endpoints (Phase 3 API Standardization)
# Includes: crud, discovery (basic, network, security, compliance)
# The router already has prefix="/hosts" defined in routes/hosts/__init__.py
app.include_router(hosts_router, prefix="/api", tags=["Hosts"])
app.include_router(baselines.router, tags=["Baseline Management"])
# drift_events - REMOVED: Consolidated into routes/compliance/drift.py (Phase 4)
# Endpoints now available at /api/compliance/drift/*
# Scans - Modular package with all scan-related endpoints (Phase 2 API Standardization)
# Includes: compliance, crud, reports, bulk, validation, config, templates, rules, mongodb
# The router already has prefix="/scans" defined in routes/scans/__init__.py
app.include_router(scans.router, prefix="/api", tags=["Security Scans"])
# owca - REMOVED: Consolidated into routes/compliance/owca.py (Phase 4)
# Endpoints now available at /api/compliance/owca/*
app.include_router(monitoring.router, prefix="/api", tags=["Host Monitoring"])
app.include_router(adaptive_scheduler.router, prefix="/api", tags=["Adaptive Scheduler"])
app.include_router(os_discovery.router, prefix="/api", tags=["OS Discovery"])
app.include_router(system_settings_router, prefix="/api", tags=["System Settings"])
app.include_router(admin_router, prefix="/api", tags=["Administration"])
# Host Groups - Modular package with CRUD and scanning endpoints
# The router already has prefix="/host-groups" defined in the package
app.include_router(host_groups_router, prefix="/api", tags=["Host Groups"])
# scan_templates - REMOVED: Consolidated into routes/scans/templates.py (Phase 2)
# Endpoints now available at /api/scans/templates/*
# webhooks - REMOVED: Consolidated into routes/integrations/webhooks.py (Phase 4)
# Endpoints now available at /api/integrations/webhooks/*
# credentials - REMOVED: Consolidated into routes/admin/ (E1-S6)
# api_keys - REMOVED: Consolidated into auth_router (E1-S4)
app.include_router(remediation_callback.router, prefix="/api", tags=["AEGIS Integration"])
app.include_router(
    integration_metrics.router,
    prefix="/api/integration/metrics",
    tags=["Integration Metrics"],
)
app.include_router(bulk_operations.router, prefix="/api/bulk", tags=["Bulk Operations"])
# app.include_router(terminal.router, tags=["Terminal"])  # Terminal module not available
# Compliance - Modular package with all compliance-related endpoints (Phase 4 API Standardization)
# Includes: intelligence (semantic rules, framework data), owca (scoring), drift (detection)
# The router already has prefix="/compliance" defined in routes/compliance/__init__.py
app.include_router(compliance_router, prefix="/api", tags=["Compliance"])
# rule_scanning - REMOVED: Consolidated into routes/scans/rules.py (Phase 2)
# Endpoints now available at /api/scans/rules/*
# SSH - Modular package with all SSH-related endpoints (Phase 4 API Standardization)
# Includes: settings (policy, known-hosts), debug (test-authentication, paramiko-log)
# The router already has prefix="/ssh" defined in routes/ssh/__init__.py
app.include_router(ssh_router, prefix="/api", tags=["SSH"])
# ssh_settings - REMOVED: Consolidated into routes/ssh/settings.py (Phase 4)
# Endpoints now available at /api/ssh/settings/*
# ssh_debug - REMOVED: Consolidated into routes/ssh/debug.py (Phase 4)
# Endpoints now available at /api/ssh/debug/*
# host_network_discovery - REMOVED: Consolidated into routes/hosts/discovery.py (Phase 3)
# Endpoints now available at /api/hosts/{host_id}/discovery/network/*
# group_compliance.py removed - functionality consolidated into host_groups package
# See: routes/host_groups/scans.py for group scanning endpoints
# host_compliance_discovery - REMOVED: Consolidated into routes/hosts/discovery.py (Phase 3)
# Endpoints now available at /api/hosts/{host_id}/discovery/compliance/*
# host_discovery - REMOVED: Consolidated into routes/hosts/discovery.py (Phase 3)
# Endpoints now available at /api/hosts/{host_id}/discovery/basic/*
# host_security_discovery - REMOVED: Consolidated into routes/hosts/discovery.py (Phase 3)
# Endpoints now available at /api/hosts/{host_id}/discovery/security/*
# Integrations - Modular package with all integration-related endpoints (Phase 4 API Standardization)
# Includes: webhooks (CRUD, deliveries, test), plugins (import, execute, statistics)
# The router already has prefix="/integrations" defined in routes/integrations/__init__.py
app.include_router(integrations_router, prefix="/api", tags=["Integrations"])
# plugin_management - REMOVED: Consolidated into routes/integrations/plugins.py (Phase 4)
# Endpoints now available at /api/integrations/plugins/*
# bulk_remediation_routes - REMOVED: Moved to SecureOps/AEGIS (ORSA subsystem)

# QueryBuilder validation endpoints (temporary testing) - DISABLED: module not available
# app.include_router(test_querybuilder.router, prefix="/api", tags=["QueryBuilder Validation"])

# Register security routes if available
if automated_fixes:
    app.include_router(automated_fixes.router, prefix="/api", tags=["Secure Automated Fixes"])
if authorization:
    app.include_router(authorization.router, prefix="/api", tags=["Authorization Management"])
if security_config:
    app.include_router(security_config.router, prefix="/api", tags=["Security Configuration"])


# Global Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Global exception handler for security and logging."""
    client_ip = request.client.host
    if "x-forwarded-for" in request.headers:
        client_ip = request.headers["x-forwarded-for"].split(",")[0].strip()

    # Log the exception
    logger.error(f"Unhandled exception: {exc}", exc_info=True)

    # Log security event
    audit_logger.log_security_event(
        "EXCEPTION",
        f"Path: {request.url.path}, Exception: {type(exc).__name__}",
        client_ip,
    )

    # Return generic error response (don't expose internal details)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error", "error_id": f"{int(time.time())}"},
    )


if __name__ == "__main__":
    # Development server configuration
    uvicorn.run(
        "main:app",
        host="0.0.0.0",  # nosec B104 - Intentional for Docker container binding
        port=8000,
        ssl_keyfile=settings.tls_key_file if settings.require_https else None,
        ssl_certfile=settings.tls_cert_file if settings.require_https else None,
        log_level=settings.log_level.lower(),
        reload=settings.debug,
    )
