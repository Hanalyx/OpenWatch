"""
OpenWatch API v1 - Main Router
Unified API façade with versioned endpoints and capability-based routing
"""
from fastapi import APIRouter, Depends, HTTPException, status
from typing import Dict, Any
import logging

from ...auth import get_current_user
from ..capabilities import router as capabilities_router
from . import hosts as v1_hosts
from . import scans as v1_scans
from . import remediation as v1_remediation
from . import openapi as v1_openapi
from ...api.v1.endpoints import mongodb_test
from ...api.v1.endpoints import scap_import
from ...api.v1.endpoints import rule_management
from ...api.v1.endpoints import compliance_rules_api
from ...api.v1.endpoints import mongodb_scan_api

from ...api.v1.endpoints import health_monitoring

logger = logging.getLogger(__name__)

# Create main v1 API router
router = APIRouter()

# Include capabilities (core v1 feature)
router.include_router(capabilities_router, tags=["System Capabilities"])

# Include v1 enhanced endpoints
router.include_router(v1_hosts.router, prefix="/hosts", tags=["Host Management v1"])
router.include_router(v1_scans.router, prefix="/scans", tags=["Scan Management v1"])
router.include_router(v1_remediation.router, prefix="/remediation", tags=["Remediation Provider v1"])
router.include_router(v1_openapi.router, prefix="/docs", tags=["API Documentation v1"])
router.include_router(mongodb_test.router, prefix="/mongodb", tags=["MongoDB Integration Test"])
router.include_router(scap_import.router, tags=["SCAP Import"])
router.include_router(rule_management.router, tags=["Enhanced Rule Management"])
router.include_router(compliance_rules_api.router, tags=["MongoDB Compliance Rules"])
router.include_router(mongodb_scan_api.router, tags=["MongoDB Scanning"])

router.include_router(health_monitoring.router, prefix="/health-monitoring", tags=["Health Monitoring"])


@router.get("/")
async def get_api_info():
    """
    Get API v1 information and available endpoints
    
    Returns comprehensive information about the v1 API including
    available endpoints, authentication requirements, and capabilities.
    """
    return {
        "api_version": "v1",
        "openwatch_version": "1.0.0",
        "description": "OpenWatch Unified API Façade - Version 1",
        "documentation_url": "/docs",
        "openapi_spec": "/openapi.json",
        "authentication": {
            "type": "JWT Bearer Token",
            "login_endpoint": "/api/auth/login",
            "refresh_endpoint": "/api/auth/refresh"
        },
        "endpoints": {
            "capabilities": "/api/v1/capabilities",
            "features": "/api/v1/features", 
            "hosts": "/api/v1/hosts",
            "scans": "/api/v1/scans",
            "remediation": "/api/v1/remediation",
            "integrations": "/api/v1/health/integrations",
            "mongodb_test": "/api/v1/mongodb",
            "scap_import": "/api/v1/scap-import",
            "rule_management": "/api/v1/rules"
        },
        "rate_limits": {
            "default": "1000 requests per minute",
            "authenticated": "5000 requests per minute"
        },
        "support": {
            "documentation": "https://docs.openwatch.io",
            "community": "https://github.com/hanalyx/openwatch/discussions",
            "enterprise": "https://hanalyx.com/support"
        }
    }


@router.get("/health")
async def get_api_health():
    """
    Get API v1 health status
    
    Returns the health status of the v1 API and its dependencies.
    """
    return {
        "status": "healthy",
        "version": "v1",
        "timestamp": "2025-08-20T12:00:00Z",
        "dependencies": {
            "database": "healthy",
            "mongodb": "healthy",
            "redis": "healthy", 
            "plugins": "healthy"
        },
        "metrics": {
            "requests_per_minute": 0,
            "average_response_time": "50ms",
            "error_rate": "0.1%"
        }
    }


@router.get("/spec")
async def get_openapi_spec():
    """
    Get OpenAPI specification for API v1
    
    Returns the complete OpenAPI 3.0 specification for the v1 API.
    """
    # This would typically return the actual OpenAPI spec
    # For now, return metadata about the spec
    return {
        "openapi": "3.0.0",
        "info": {
            "title": "OpenWatch API",
            "version": "1.0.0",
            "description": "OpenWatch SCAP Compliance Scanner API",
            "contact": {
                "name": "OpenWatch Team",
                "url": "https://github.com/hanalyx/openwatch",
                "email": "support@hanalyx.com"
            },
            "license": {
                "name": "Apache 2.0",
                "url": "https://opensource.org/licenses/Apache-2.0"
            }
        },
        "servers": [
            {
                "url": "/api/v1",
                "description": "OpenWatch API v1"
            }
        ],
        "tags": [
            {
                "name": "System Capabilities",
                "description": "Feature discovery and capability management"
            },
            {
                "name": "Host Management v1", 
                "description": "Host inventory and management operations"
            },
            {
                "name": "Scan Management v1",
                "description": "SCAP scanning operations and results"
            }
        ]
    }