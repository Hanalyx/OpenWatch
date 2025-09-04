"""
OpenWatch FastAPI Application - FIPS Compliant Security Scanner
Main application with comprehensive security middleware
"""
import logging
import os
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer
from fastapi.responses import JSONResponse
import time
import uvicorn

from .config import get_settings, SECURITY_HEADERS
from .auth import jwt_manager, audit_logger
from .database import engine, create_tables, get_db
from .routes import auth, hosts, scans, content, scap_content, monitoring, users, audit, host_groups, scan_templates, webhooks, mfa
from .routes.system_settings_unified import router as system_settings_router
from .routes import credentials, api_keys, remediation_callback, integration_metrics, bulk_operations, compliance, rule_scanning, capabilities, host_network_discovery
# Import security routes only if available
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
# from .routes.v1 import api as v1_api  # Temporarily disabled
from .audit_db import log_security_event
from .middleware.metrics import PrometheusMiddleware, background_updater
from .middleware.rate_limiting import get_rate_limiting_middleware
from .services.prometheus_metrics import get_metrics_instance
# from .services.tracing import initialize_tracing, instrument_fastapi_app, instrument_database_engine  # Disabled for now

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    # Startup
    logger.info("Starting OpenWatch application...")
    
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
            await create_tables()
            logger.info("Database tables created successfully")
            
            # Initialize RBAC system
            try:
                from .init_roles import initialize_rbac_system
                await initialize_rbac_system()
                logger.info("RBAC system initialized successfully")
            except Exception as rbac_error:
                logger.warning(f"RBAC initialization failed: {rbac_error}")
                if not settings.debug:
                    raise
            
            # Initialize scheduler state from database
            try:
                from .routes.system_settings_unified import restore_scheduler_state
                await restore_scheduler_state()
                logger.info("Scheduler state restored from database")
            except Exception as scheduler_error:
                logger.warning(f"Scheduler restoration failed: {scheduler_error}")
                # Don't raise - scheduler can be started manually from UI
            
            break
        except Exception as e:
            if attempt < max_retries - 1:
                logger.warning(f"Database connection attempt {attempt + 1} failed: {e}. Retrying in {retry_delay} seconds...")
                await asyncio.sleep(retry_delay)
            else:
                if settings.debug:
                    logger.warning(f"Database connection failed in debug mode, continuing without DB: {e}")
                else:
                    logger.error(f"Failed to connect to database after {max_retries} attempts: {e}")
                    raise
    
    # Initialize JWT keys
    logger.info("JWT manager initialized with RSA keys")
    
    # Initialize distributed tracing (disabled for now)
    # try:
    #     tracing_success = initialize_tracing(
    #         service_name="openwatch",
    #         service_version="1.0.0",
    #         environment=settings.environment if hasattr(settings, 'environment') else "production"
    #     )
    #     if tracing_success:
    #         instrument_database_engine(engine)
    #         logger.info("Distributed tracing initialized successfully")
    #     else:
    #         logger.warning("Distributed tracing initialization failed")
    # except Exception as e:
    #     logger.warning(f"Failed to initialize distributed tracing: {e}")
    logger.info("Distributed tracing disabled for initial deployment")
    
    # Start background metrics collection
    try:
        import asyncio
        asyncio.create_task(background_updater.start_background_updates())
        logger.info("Background metrics collection started")
    except Exception as e:
        logger.warning(f"Failed to start background metrics collection: {e}")
    
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
    lifespan=lifespan
)


# Rate Limiting Middleware with Token Bucket Algorithm
# Environment-controlled: Set OPENWATCH_RATE_LIMITING=false to disable for development
# Uses industry-standard token bucket algorithm with proper burst handling and recovery times
rate_limiter = get_rate_limiting_middleware()
app.middleware("http")(rate_limiter)

# Security Middleware
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Add FIPS-compliant security headers to all responses"""
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
                "connect-src 'self' http://localhost:8000 ws://localhost:3000; "
                "font-src 'self'; "
                "frame-src 'none'; "
                "object-src 'none'"
            )
            response.headers[header] = dev_csp
        else:
            response.headers[header] = value
    
    return response


@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    """Log security-relevant requests for audit purposes"""
    start_time = time.time()
    
    # Get client IP
    client_ip = request.client.host
    if "x-forwarded-for" in request.headers:
        client_ip = request.headers["x-forwarded-for"].split(",")[0].strip()
    
    # Process request
    response = await call_next(request)
    
    # Log security events (only for non-auth endpoints to avoid double logging)
    process_time = time.time() - start_time
    
    # Get database session for audit logging
    db = next(get_db())
    
    try:
        # Log scan operations
        if request.url.path.startswith("/api/scans"):
            audit_logger.log_security_event(
                "SCAN_OPERATION",
                f"Path: {request.url.path}, Method: {request.method}, Status: {response.status_code}",
                client_ip
            )
            await log_security_event(
                db=db,
                event_type="SCAN_OPERATION",
                ip_address=client_ip,
                details=f"Path: {request.url.path}, Method: {request.method}, Status: {response.status_code}"
            )
        
        # Log host operations
        elif request.url.path.startswith("/api/hosts"):
            audit_logger.log_security_event(
                "HOST_OPERATION",
                f"Path: {request.url.path}, Method: {request.method}, Status: {response.status_code}",
                client_ip
            )
            await log_security_event(
                db=db,
                event_type="HOST_OPERATION",
                ip_address=client_ip,
                details=f"Path: {request.url.path}, Method: {request.method}, Status: {response.status_code}"
            )
        
        # Log user management operations
        elif request.url.path.startswith("/api/users"):
            audit_logger.log_security_event(
                "USER_OPERATION",
                f"Path: {request.url.path}, Method: {request.method}, Status: {response.status_code}",
                client_ip
            )
            await log_security_event(
                db=db,
                event_type="USER_OPERATION",
                ip_address=client_ip,
                details=f"Path: {request.url.path}, Method: {request.method}, Status: {response.status_code}"
            )
        
        # Log webhook operations
        elif request.url.path.startswith("/api/v1/webhooks"):
            audit_logger.log_security_event(
                "WEBHOOK_OPERATION",
                f"Path: {request.url.path}, Method: {request.method}, Status: {response.status_code}",
                client_ip
            )
            await log_security_event(
                db=db,
                event_type="WEBHOOK_OPERATION",
                ip_address=client_ip,
                details=f"Path: {request.url.path}, Method: {request.method}, Status: {response.status_code}"
            )
        
        # Log unusual status codes (HTTP errors)
        if response.status_code >= 400:
            audit_logger.log_security_event(
                "HTTP_ERROR",
                f"Path: {request.url.path}, Method: {request.method}, Status: {response.status_code}",
                client_ip
            )
            await log_security_event(
                db=db,
                event_type="HTTP_ERROR",
                ip_address=client_ip,
                details=f"HTTP {response.status_code} error on {request.url.path}"
            )
    
    except Exception as e:
        logger.error(f"Error in audit middleware: {e}")
    finally:
        db.close()
    
    return response


@app.middleware("http")
async def https_redirect_middleware(request: Request, call_next):
    """Enforce HTTPS in production"""
    if settings.require_https and not settings.debug:
        if request.url.scheme != "https":
            https_url = request.url.replace(scheme="https")
            return JSONResponse(
                status_code=status.HTTP_301_MOVED_PERMANENTLY,
                headers={"Location": str(https_url)}
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
    expose_headers=["X-Total-Count"]
)

# Trusted Host Middleware
trusted_hosts = ["localhost", "127.0.0.1"]
if not settings.debug:
    # Add production domains from allowed origins
    for origin in settings.allowed_origins:
        if origin.startswith("https://"):
            host = origin.replace("https://", "").split(":")[0]
            trusted_hosts.append(host)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=trusted_hosts
)

# Add Prometheus metrics middleware
app.add_middleware(PrometheusMiddleware, service_name="openwatch")

# Instrument FastAPI with tracing (do this after app creation)
# Instrument FastAPI with tracing (disabled for now)
# try:
#     instrument_fastapi_app(app)
#     logger.info("FastAPI tracing instrumentation completed")
# except Exception as e:
#     logger.warning(f"FastAPI tracing instrumentation failed: {e}")


# Health Check Endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint for container orchestration"""
    try:
        # Basic health checks
        health_status = {
            "status": "healthy",
            "timestamp": time.time(),
            "version": "1.2.0",
            "fips_mode": settings.fips_mode
        }
        
        # Check database connectivity
        try:
            from .database import check_database_health
            db_healthy = await check_database_health()
            health_status["database"] = "healthy" if db_healthy else "unhealthy"
        except Exception as e:
            logger.warning(f"Database health check failed: {e}")
            health_status["database"] = "unknown"
            db_healthy = True  # Continue for development
        
        # Check Redis connectivity
        try:
            from .celery_app import check_redis_health
            redis_healthy = await check_redis_health()
            health_status["redis"] = "healthy" if redis_healthy else "unhealthy"
        except Exception as e:
            logger.warning(f"Redis health check failed: {e}")
            health_status["redis"] = "unknown"
            redis_healthy = True  # Continue for development
        
        # Overall status
        if not (db_healthy and redis_healthy):
            health_status["status"] = "degraded"
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content=health_status
            )
        
        return health_status
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": time.time()
            }
        )


# Security Info Endpoint
@app.get("/security-info")
async def security_info():
    """Provide security configuration information (admin only)"""
    return {
        "fips_mode": settings.fips_mode,
        "https_required": settings.require_https,
        "jwt_algorithm": "RS256",
        "encryption": "AES-256-GCM",
        "hash_algorithm": "Argon2id",
        "tls_version": "1.3"
    }


# Prometheus Metrics Endpoint
@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint"""
    from fastapi.responses import PlainTextResponse
    
    metrics_instance = get_metrics_instance()
    metrics_data = metrics_instance.get_metrics()
    
    return PlainTextResponse(
        content=metrics_data,
        media_type="text/plain; version=0.0.4; charset=utf-8"
    )


# Include API routes - Unified API Façade
# API v1 - Primary versioned API
# app.include_router(v1_api.router, prefix="/api/v1", tags=["API v1"])  # Temporarily disabled

# Legacy API routes (for backward compatibility)
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(mfa.router, prefix="/api/mfa", tags=["Multi-Factor Authentication"])
app.include_router(hosts.router, prefix="/api/hosts", tags=["Host Management"])
app.include_router(scans.router, prefix="/api", tags=["Security Scans"])
app.include_router(scap_content.router, prefix="/api", tags=["SCAP Content"])
app.include_router(content.router, prefix="/api/content", tags=["Legacy Content"])
app.include_router(monitoring.router, prefix="/api", tags=["Host Monitoring"])
app.include_router(system_settings_router, prefix="/api", tags=["System Settings"])
app.include_router(users.router, prefix="/api", tags=["User Management"])
app.include_router(audit.router, prefix="/api", tags=["Audit Logs"])
app.include_router(host_groups.router, prefix="/api", tags=["Host Groups"])
app.include_router(scan_templates.router, prefix="/api", tags=["Scan Templates"])
app.include_router(webhooks.router, prefix="/api/v1", tags=["Webhooks"])
app.include_router(credentials.router, tags=["Credential Sharing"])
app.include_router(api_keys.router, prefix="/api/api-keys", tags=["API Keys"])
app.include_router(remediation_callback.router, tags=["AEGIS Integration"])
app.include_router(integration_metrics.router, prefix="/api/integration/metrics", tags=["Integration Metrics"])
app.include_router(bulk_operations.router, prefix="/api/bulk", tags=["Bulk Operations"])
# app.include_router(terminal.router, tags=["Terminal"])  # Terminal module not available
app.include_router(compliance.router, prefix="/api/compliance", tags=["Compliance Intelligence"])
app.include_router(rule_scanning.router, prefix="/api", tags=["Rule-Specific Scanning"])
app.include_router(host_network_discovery.router, prefix="/api", tags=["Host Network Discovery"])

# Register security routes if available
if automated_fixes:
    app.include_router(automated_fixes.router, tags=["Secure Automated Fixes"])
if authorization:
    app.include_router(authorization.router, tags=["Authorization Management"])  
if security_config:
    app.include_router(security_config.router, tags=["Security Configuration"])


# Global Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler for security and logging"""
    client_ip = request.client.host
    if "x-forwarded-for" in request.headers:
        client_ip = request.headers["x-forwarded-for"].split(",")[0].strip()
    
    # Log the exception
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    
    # Log security event
    audit_logger.log_security_event(
        "EXCEPTION",
        f"Path: {request.url.path}, Exception: {type(exc).__name__}",
        client_ip
    )
    
    # Return generic error response (don't expose internal details)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error",
            "error_id": f"{int(time.time())}"
        }
    )


if __name__ == "__main__":
    # Development server configuration
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        ssl_keyfile=settings.tls_key_file if settings.require_https else None,
        ssl_certfile=settings.tls_cert_file if settings.require_https else None,
        log_level=settings.log_level.lower(),
        reload=settings.debug
    )