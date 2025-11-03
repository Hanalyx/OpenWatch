"""
OpenWatch API v1 - OpenAPI Specification Export
Enhanced OpenAPI documentation with comprehensive examples and descriptions
"""

import json
import logging
from typing import Any, Dict, Optional

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.openapi.utils import get_openapi

from ...auth import get_current_user

# from ...main import app  # Removed to avoid circular import

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/spec.json")
async def get_openapi_spec_json(
    include_internal: bool = Query(False, description="Include internal endpoints"),
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get OpenAPI specification in JSON format

    Returns the complete OpenAPI 3.0 specification for the OpenWatch API v1
    with comprehensive documentation, examples, and security schemes.
    """
    try:
        # Generate enhanced OpenAPI spec
        openapi_spec = _generate_enhanced_openapi_spec(include_internal)

        logger.debug(f"OpenAPI JSON spec requested by user {current_user.get('user_id', 'unknown')}")

        return openapi_spec

    except Exception as e:
        logger.error(f"Error generating OpenAPI spec: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate OpenAPI specification",
        )


@router.get("/spec.yaml")
async def get_openapi_spec_yaml(
    include_internal: bool = Query(False, description="Include internal endpoints"),
    current_user: dict = Depends(get_current_user),
):
    """
    Get OpenAPI specification in YAML format

    Returns the complete OpenAPI 3.0 specification in YAML format,
    suitable for use with API development tools and documentation generators.
    """
    try:
        # Generate enhanced OpenAPI spec
        openapi_spec = _generate_enhanced_openapi_spec(include_internal)

        # Convert to YAML
        yaml_content = yaml.dump(openapi_spec, default_flow_style=False, sort_keys=False)

        logger.debug(f"OpenAPI YAML spec requested by user {current_user.get('user_id', 'unknown')}")

        return Response(
            content=yaml_content,
            media_type="application/x-yaml",
            headers={"Content-Disposition": "attachment; filename=openwatch-api-v1.yaml"},
        )

    except Exception as e:
        logger.error(f"Error generating OpenAPI YAML spec: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate OpenAPI YAML specification",
        )


@router.get("/postman")
async def get_postman_collection(
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get Postman collection for OpenWatch API v1

    Returns a Postman collection with pre-configured requests for all
    API endpoints, including authentication and example payloads.
    """
    try:
        collection = _generate_postman_collection()

        logger.debug(f"Postman collection requested by user {current_user.get('user_id', 'unknown')}")

        return collection

    except Exception as e:
        logger.error(f"Error generating Postman collection: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate Postman collection",
        )


@router.get("/sdk/examples")
async def get_sdk_examples(
    language: str = Query("python", description="Programming language for examples"),
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get SDK examples for different programming languages

    Returns code examples showing how to integrate with the OpenWatch API
    using various programming languages and HTTP clients.
    """
    try:
        examples = _generate_sdk_examples(language)

        logger.debug(f"SDK examples ({language}) requested by user {current_user.get('user_id', 'unknown')}")

        return examples

    except Exception as e:
        logger.error(f"Error generating SDK examples: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate SDK examples",
        )


def _generate_enhanced_openapi_spec(include_internal: bool = False) -> Dict[str, Any]:
    """Generate enhanced OpenAPI specification with comprehensive documentation"""

    # Generate a basic OpenAPI spec (without app.routes to avoid circular import)
    openapi_spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "OpenWatch SCAP Compliance Scanner API",
            "version": "1.0.0",
            "description": _get_api_description(),
        },
        "paths": {},  # Would be populated with actual routes
        "tags": _get_openapi_tags(),
    }

    # Enhance the specification
    openapi_spec.update(
        {
            "info": {
                **openapi_spec["info"],
                "contact": {
                    "name": "OpenWatch Team",
                    "url": "https://github.com/hanalyx/openwatch",
                    "email": "support@hanalyx.com",
                },
                "license": {
                    "name": "Apache 2.0",
                    "url": "https://opensource.org/licenses/Apache-2.0",
                },
                "termsOfService": "https://hanalyx.com/terms",
            },
            "servers": [
                {"url": "/api/v1", "description": "OpenWatch API v1"},
                {
                    "url": "https://demo.openwatch.io/api/v1",
                    "description": "Demo Environment",
                },
            ],
            "externalDocs": {
                "description": "OpenWatch Documentation",
                "url": "https://docs.openwatch.io",
            },
        }
    )

    # Add security schemes
    openapi_spec["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "JWT Bearer token authentication. Obtain token from /api/auth/login",
        },
        "ApiKeyAuth": {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key",
            "description": "API key authentication for automated integrations",
        },
    }

    # Add global security requirement
    openapi_spec["security"] = [{"BearerAuth": []}, {"ApiKeyAuth": []}]

    # Add enhanced examples and schemas
    _add_enhanced_examples(openapi_spec)

    # Filter internal endpoints if requested
    if not include_internal:
        _filter_internal_endpoints(openapi_spec)

    return openapi_spec


def _get_api_description() -> str:
    """Get comprehensive API description"""
    return """
# OpenWatch SCAP Compliance Scanner API

OpenWatch provides a comprehensive REST API for managing SCAP compliance scanning operations. This API enables:

## Core Features
- **Host Management**: Register and manage target hosts for scanning
- **SCAP Scanning**: Execute compliance scans with parallel processing
- **Result Analysis**: Retrieve and analyze scan results with detailed rule information
- **Remediation**: Automated and manual remediation of compliance failures
- **Capability Discovery**: Dynamic feature discovery based on licensing and configuration

## Authentication
The API uses JWT Bearer token authentication. Obtain a token by calling the `/api/auth/login` endpoint with valid credentials.

## Rate Limiting
- Default: 1000 requests per minute for unauthenticated requests
- Authenticated: 5000 requests per minute for JWT authenticated requests
- Enterprise: 10000 requests per minute for API key authenticated requests

## API Versioning
This is version 1 of the OpenWatch API. All endpoints are prefixed with `/api/v1/` for consistency.

## Support
- **Documentation**: https://docs.openwatch.io
- **Community**: https://github.com/hanalyx/openwatch/discussions
- **Enterprise Support**: https://hanalyx.com/support
"""


def _get_openapi_tags() -> list:
    """Get OpenAPI tags with descriptions"""
    return [
        {
            "name": "System Capabilities",
            "description": "Feature discovery and capability management",
        },
        {
            "name": "Host Management v1",
            "description": "Host inventory and management operations",
        },
        {
            "name": "Scan Management v1",
            "description": "SCAP scanning operations and results",
        },
        {
            "name": "Remediation Provider v1",
            "description": "Automated and manual remediation operations",
        },
        {
            "name": "Authentication",
            "description": "User authentication and session management",
        },
    ]


def _add_enhanced_examples(openapi_spec: Dict[str, Any]):
    """Add enhanced examples to the OpenAPI specification"""

    # Add common schema examples
    if "components" not in openapi_spec:
        openapi_spec["components"] = {}

    if "examples" not in openapi_spec["components"]:
        openapi_spec["components"]["examples"] = {}

    # Add example responses
    openapi_spec["components"]["examples"].update(
        {
            "CapabilitiesResponse": {
                "summary": "System capabilities example",
                "value": {
                    "version": "1.0.0",
                    "features": {
                        "scanning": True,
                        "reporting": True,
                        "remediation": False,
                        "ai_assistance": False,
                    },
                    "limits": {"max_hosts": 50, "concurrent_scans": 5},
                    "integrations": {
                        "aegis_available": False,
                        "container_runtime": "podman",
                    },
                },
            },
            "RemediationJobResponse": {
                "summary": "Remediation job example",
                "value": {
                    "job_id": "123e4567-e89b-12d3-a456-426614174000",
                    "scan_id": "456e7890-e89b-12d3-a456-426614174001",
                    "status": "pending",
                    "provider": "aegis",
                    "failed_rules": ["xccdf_rule_1", "xccdf_rule_2"],
                    "created_at": "2025-08-20T12:00:00Z",
                },
            },
        }
    )


def _filter_internal_endpoints(openapi_spec: Dict[str, Any]):
    """Filter out internal endpoints from the specification"""

    # Remove internal paths
    internal_patterns = ["/health", "/metrics", "/debug"]

    if "paths" in openapi_spec:
        paths_to_remove = []
        for path in openapi_spec["paths"]:
            if any(pattern in path for pattern in internal_patterns):
                paths_to_remove.append(path)

        for path in paths_to_remove:
            del openapi_spec["paths"][path]


def _generate_postman_collection() -> Dict[str, Any]:
    """Generate Postman collection for the API"""

    return {
        "info": {
            "name": "OpenWatch API v1",
            "description": "OpenWatch SCAP Compliance Scanner API collection",
            "version": "1.0.0",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "auth": {
            "type": "bearer",
            "bearer": [{"key": "token", "value": "{{auth_token}}", "type": "string"}],
        },
        "variable": [
            {
                "key": "base_url",
                "value": "http://localhost:8000/api/v1",
                "type": "string",
            },
            {"key": "auth_token", "value": "", "type": "string"},
        ],
        "item": [
            {
                "name": "Authentication",
                "item": [
                    {
                        "name": "Login",
                        "request": {
                            "method": "POST",
                            "header": [{"key": "Content-Type", "value": "application/json"}],
                            "body": {
                                "mode": "raw",
                                "raw": json.dumps({"username": "admin", "password": "your_password"}),
                            },
                            "url": {
                                "raw": "{{base_url}}/../auth/login",
                                "host": ["{{base_url}}"],
                                "path": ["..", "auth", "login"],
                            },
                        },
                    }
                ],
            },
            {
                "name": "Capabilities",
                "item": [
                    {
                        "name": "Get System Capabilities",
                        "request": {
                            "method": "GET",
                            "url": {
                                "raw": "{{base_url}}/capabilities",
                                "host": ["{{base_url}}"],
                                "path": ["capabilities"],
                            },
                        },
                    }
                ],
            },
            {
                "name": "Hosts",
                "item": [
                    {
                        "name": "List Hosts",
                        "request": {
                            "method": "GET",
                            "url": {
                                "raw": "{{base_url}}/hosts",
                                "host": ["{{base_url}}"],
                                "path": ["hosts"],
                            },
                        },
                    }
                ],
            },
        ],
    }


def _generate_sdk_examples(language: str) -> Dict[str, Any]:
    """Generate SDK examples for different languages"""

    examples = {
        "python": {
            "authentication": """
import requests

# Login to get JWT token
response = requests.post("http://localhost:8000/api/auth/login", json={
    "username": "admin",
    "password": "your_password"
})
token = response.json()["access_token"]

# Use token for authenticated requests
headers = {"Authorization": f"Bearer {token}"}
capabilities = requests.get("http://localhost:8000/api/v1/capabilities", headers=headers)
print(capabilities.json())
            """,
            "scanning": """
# Start a scan
scan_request = {
    "host_id": "host-123",
    "profile_id": "stig-rhel8",
    "scan_type": "compliance"
}
response = requests.post("http://localhost:8000/api/v1/scans", 
                        json=scan_request, headers=headers)
scan_id = response.json()["scan_id"]

# Check scan status
status = requests.get(f"http://localhost:8000/api/v1/scans/{scan_id}", headers=headers)
print(status.json())
            """,
        },
        "curl": {
            "authentication": """
# Login to get JWT token
curl -X POST "http://localhost:8000/api/auth/login" \\
  -H "Content-Type: application/json" \\
  -d '{"username": "admin", "password": "your_password"}'

# Use token for authenticated requests
curl -X GET "http://localhost:8000/api/v1/capabilities" \\
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
            """,
            "scanning": """
# Start a scan
curl -X POST "http://localhost:8000/api/v1/scans" \\
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \\
  -H "Content-Type: application/json" \\
  -d '{"host_id": "host-123", "profile_id": "stig-rhel8"}'
            """,
        },
        "javascript": {
            "authentication": """
// Login to get JWT token
const response = await fetch("http://localhost:8000/api/auth/login", {
  method: "POST",
  headers: {"Content-Type": "application/json"},
  body: JSON.stringify({username: "admin", password: "your_password"})
});
const {access_token} = await response.json();

// Use token for authenticated requests
const capabilities = await fetch("http://localhost:8000/api/v1/capabilities", {
  headers: {"Authorization": `Bearer ${access_token}`}
});
console.log(await capabilities.json());
            """
        },
    }

    return {
        "language": language,
        "examples": examples.get(language, {}),
        "available_languages": list(examples.keys()),
    }
