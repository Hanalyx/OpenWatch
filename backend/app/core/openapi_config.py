"""
Enhanced OpenAPI Configuration for OpenWatch
Provides comprehensive API documentation with examples, security schemes, and version management
"""

from typing import Any, Dict, Optional

from fastapi import FastAPI
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse


def create_openapi_schema(
    app: FastAPI,
    title: str = "OpenWatch API",
    version: str = "1.0.0",
    description: str = None,
    include_examples: bool = True,
) -> Dict[str, Any]:
    """Create enhanced OpenAPI schema with comprehensive documentation"""

    if description is None:
        description = """
## OpenWatch SCAP Compliance Scanner API

OpenWatch provides comprehensive SCAP-based compliance scanning and management capabilities
for enterprise security and compliance requirements.

### Key Features

* **Enhanced Rule Management**: Advanced rule querying with inheritance and parameter overrides
* **Platform Capability Detection**: Multi-platform capability detection and baseline comparison
* **Full-Text Search**: Advanced rule search with relevance scoring and filtering
* **Dependency Resolution**: Complete rule dependency graph building and conflict detection
* **Caching & Performance**: Intelligent caching with priority-based TTL management
* **Rate Limiting**: Industry-standard rate limiting with token bucket algorithm
* **Comprehensive Security**: JWT authentication, RBAC, MFA support, and audit logging

### API Versions

This API supports multiple versions with backward compatibility:

* **v1**: Basic compliance scanning and rule management
* **v2**: Enhanced rule management with inheritance, dependencies, and advanced caching
* **v3**: AI-powered insights and predictive compliance (coming soon)

### Authentication

The API uses JWT Bearer tokens for authentication:

```
Authorization: Bearer <your-jwt-token>
```

Obtain tokens via the `/api/auth/login` endpoint.

### Rate Limiting

API requests are rate-limited based on authentication status:

* **Anonymous**: 100 requests/minute
* **Authenticated**: 1000 requests/minute
* **Admin**: 5000 requests/minute

Rate limit headers are included in all responses:

* `X-RateLimit-Limit`: Request limit per window
* `X-RateLimit-Remaining`: Requests remaining in current window
* `X-RateLimit-Reset`: Timestamp when the window resets

### Error Handling

All errors follow a standardized format:

```json
{
  "success": false,
  "error": "error_type",
  "message": "Human-readable error message",
  "details": [
    {
      "field": "field_name",
      "message": "Specific error detail",
      "type": "validation_error"
    }
  ],
  "error_id": "abc12345",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### Caching

Enhanced rule endpoints support intelligent caching:

* Cache headers indicate freshness and expiration
* ETags support conditional requests
* Cache can be invalidated via management endpoints

### Webhook Support

OpenWatch supports webhooks for real-time notifications:

* Scan completion events
* Rule updates and changes
* Security alerts and findings
"""

    # Generate base OpenAPI schema
    schema = get_openapi(title=title, version=version, description=description, routes=app.routes)

    # Add comprehensive server information
    schema["servers"] = [
        {"url": "/api", "description": "OpenWatch API (Unified)"},
        {"url": "https://api.openwatch.io", "description": "Production API"},
        {"url": "https://staging.openwatch.io", "description": "Staging API"},
    ]

    # Enhanced security schemes
    schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "JWT Bearer token obtained from /api/auth/login",
        },
        "ApiKeyAuth": {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key",
            "description": "API key for service-to-service authentication",
        },
        "BasicAuth": {
            "type": "http",
            "scheme": "basic",
            "description": "HTTP Basic authentication (deprecated, use Bearer tokens)",
        },
    }

    # Add comprehensive tags with descriptions
    schema["tags"] = [
        {
            "name": "Authentication",
            "description": "JWT authentication, MFA, and session management",
        },
        {
            "name": "Enhanced Rule Management",
            "description": "Advanced rule querying with inheritance, dependencies, and caching",
        },
        {
            "name": "Platform Capabilities",
            "description": "Platform capability detection and baseline comparison",
        },
        {
            "name": "Rule Search & Discovery",
            "description": "Full-text search and rule discovery with relevance scoring",
        },
        {
            "name": "Rule Dependencies",
            "description": "Rule dependency graphs and conflict resolution",
        },
        {
            "name": "Import & Export",
            "description": "Rule import/export in multiple formats (JSON, CSV, XML)",
        },
        {
            "name": "Cache Management",
            "description": "Cache warming, invalidation, and performance monitoring",
        },
        {
            "name": "SCAP Scanning",
            "description": "SCAP-based compliance scanning and assessment",
        },
        {
            "name": "Host Management",
            "description": "Target host inventory and credential management",
        },
        {
            "name": "Audit & Monitoring",
            "description": "Audit logs, metrics, and security monitoring",
        },
        {
            "name": "System Administration",
            "description": "System health, configuration, and administrative functions",
        },
    ]

    # Add external documentation links
    schema["externalDocs"] = {
        "description": "OpenWatch Documentation",
        "url": "https://docs.openwatch.io",
    }

    # Add comprehensive examples if requested
    if include_examples:
        schema = add_openapi_examples(schema)

    # Add custom extensions
    schema["x-logo"] = {
        "url": "https://openwatch.io/logo.png",
        "altText": "OpenWatch Logo",
    }

    schema["x-api-id"] = "openwatch-api"
    schema["x-audience"] = "public"

    return schema


def add_openapi_examples(schema: Dict[str, Any]) -> Dict[str, Any]:
    """Add comprehensive examples to OpenAPI schema"""

    # Rule examples
    rule_example = {
        "rule_id": "ow-sshd-root-login-disabled",
        "scap_rule_id": "xccdf_org.ssgproject.content_rule_sshd_disable_root_login",
        "metadata": {
            "name": "Disable SSH Root Login",
            "description": "The root user should never be allowed to login to a system directly over a network",
            "rationale": "Disallowing root logins over SSH requires system admins to authenticate using their own individual account",
            "source": "SCAP",
        },
        "abstract": False,
        "severity": "high",
        "category": "authentication",
        "security_function": "access_control",
        "tags": ["ssh", "authentication", "root_access"],
        "frameworks": {
            "nist": {"800-53r5": ["AC-6", "IA-2"]},
            "cis": {"rhel8_v2.0.0": ["5.2.8"]},
        },
        "platform_implementations": {
            "rhel": {
                "versions": ["8", "9"],
                "check_command": "grep '^PermitRootLogin no' /etc/ssh/sshd_config",
                "enable_command": "sed -i 's/^#?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl restart sshd",
                "config_files": ["/etc/ssh/sshd_config"],
            }
        },
        "dependencies": {
            "requires": ["ow-ssh-service-enabled"],
            "conflicts": [],
            "related": ["ow-ssh-protocol-version", "ow-ssh-key-based-auth"],
        },
        "created_at": "2024-01-01T12:00:00Z",
        "updated_at": "2024-01-01T12:00:00Z",
    }

    # Search results example
    search_results_example = {
        "results": [
            {
                "rule_id": "ow-firewall-enabled",
                "metadata": {
                    "name": "Enable Firewall",
                    "description": "A firewall should be enabled to control network traffic",
                },
                "severity": "high",
                "category": "network_security",
                "platforms": ["rhel", "ubuntu"],
                "frameworks": {"nist": {"800-53r5": ["SC-7"]}},
                "abstract": False,
                "updated_at": "2024-01-01T12:00:00Z",
            }
        ],
        "total_count": 1,
        "offset": 0,
        "limit": 50,
        "has_next": False,
        "has_prev": False,
        "search_query": "firewall",
    }

    # Platform capabilities example
    platform_capabilities_example = {
        "platform": "rhel",
        "platform_version": "8",
        "detection_timestamp": "2024-01-01T12:00:00Z",
        "target_host": None,
        "capabilities": {
            "package": {
                "detected": True,
                "results": {
                    "firewalld": {"version": "0.9.3", "installed": True},
                    "openssh-server": {"version": "8.0p1", "installed": True},
                },
            },
            "service": {
                "detected": True,
                "results": {
                    "firewalld": {"state": "enabled", "enabled": True},
                    "sshd": {"state": "enabled", "enabled": True},
                },
            },
            "security": {
                "detected": True,
                "results": {
                    "selinux": {"stdout": "Enforcing"},
                    "firewall": {"stdout": "running"},
                },
            },
        },
        "baseline_comparison": {
            "missing": ["aide"],
            "matched": ["firewalld", "openssh-server", "systemd"],
            "analysis": {"baseline_coverage": 0.85, "platform_health": "good"},
        },
    }

    # Add examples to components
    if "components" not in schema:
        schema["components"] = {}
    if "examples" not in schema["components"]:
        schema["components"]["examples"] = {}

    schema["components"]["examples"].update(
        {
            "RuleDetailExample": {
                "summary": "Complete rule with inheritance and dependencies",
                "value": rule_example,
            },
            "SearchResultsExample": {
                "summary": "Rule search results with pagination",
                "value": search_results_example,
            },
            "PlatformCapabilitiesExample": {
                "summary": "Platform capabilities with baseline comparison",
                "value": platform_capabilities_example,
            },
            "ErrorResponseExample": {
                "summary": "Standardized error response",
                "value": {
                    "success": False,
                    "error": "validation_error",
                    "message": "Invalid request data provided",
                    "details": [
                        {
                            "field": "platform_version",
                            "message": "Platform version is required when platform is specified",
                            "type": "missing_field",
                        }
                    ],
                    "error_id": "abc12345",
                    "timestamp": "2024-01-01T12:00:00Z",
                    "path": "/api/rules",
                    "method": "GET",
                },
            },
            "RateLimitResponseExample": {
                "summary": "Rate limit exceeded response",
                "value": {
                    "error": "Rate limit exceeded",
                    "message": "Too many requests. Try again in 60 seconds.",
                    "details": {
                        "limit_exceeded": True,
                        "remaining_requests": 0,
                        "reset_time": 1704110400,
                        "retry_after": 60,
                    },
                },
            },
        }
    )

    return schema


def create_custom_swagger_ui(
    openapi_url: str = "/openapi.json",
    title: str = "OpenWatch API Documentation",
    swagger_css_url: Optional[str] = None,
    swagger_js_url: Optional[str] = None,
) -> HTMLResponse:
    """Create customized Swagger UI with OpenWatch branding"""

    swagger_ui_html = get_swagger_ui_html(
        openapi_url=openapi_url,
        title=title,
        swagger_js_url=swagger_js_url or "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.9.0/swagger-ui-bundle.js",
        swagger_css_url=swagger_css_url or "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.9.0/swagger-ui.css",
    ).body.decode()

    # Add custom CSS and branding
    custom_css = """
    <style>
        .swagger-ui .topbar {
            background-color: #1e40af;
        }
        .swagger-ui .topbar .download-url-wrapper {
            display: none;
        }
        .swagger-ui .info .title {
            color: #1e40af;
        }
        .swagger-ui .scheme-container {
            background-color: #f8fafc;
            border: 1px solid #e2e8f0;
        }
        .swagger-ui .info .markdown p {
            color: #374151;
        }
        .swagger-ui .btn.authorize {
            background-color: #10b981;
            border-color: #10b981;
        }
        .swagger-ui .btn.authorize:hover {
            background-color: #059669;
        }
        .swagger-ui .opblock.opblock-get .opblock-summary-path {
            background-color: #10b981;
        }
        .swagger-ui .opblock.opblock-post .opblock-summary-path {
            background-color: #3b82f6;
        }
        .swagger-ui .opblock.opblock-delete .opblock-summary-path {
            background-color: #ef4444;
        }
    </style>
    """

    # Add custom JavaScript for enhanced functionality
    custom_js = """
    <script>
        // Add version selector
        window.addEventListener('DOMContentLoaded', function() {
            // Version selector removed - OpenWatch now uses unified /api prefix
            // No URL-based versioning needed
        });
    </script>
    """

    # Inject custom styles and scripts
    enhanced_html = swagger_ui_html.replace("</head>", f"{custom_css}{custom_js}</head>")

    return HTMLResponse(content=enhanced_html)


def create_custom_redoc(
    openapi_url: str = "/openapi.json",
    title: str = "OpenWatch API Documentation",
    redoc_js_url: Optional[str] = None,
) -> HTMLResponse:
    """Create customized ReDoc documentation"""

    redoc_html = get_redoc_html(
        openapi_url=openapi_url,
        title=title,
        redoc_js_url=redoc_js_url or "https://cdn.jsdelivr.net/npm/redoc@2.1.3/bundles/redoc.standalone.js",
    ).body.decode()

    # Add custom ReDoc configuration
    redoc_config = """
    <script>
        window.addEventListener('DOMContentLoaded', function() {
            Redoc.init('/openapi.json', {
                theme: {
                    colors: {
                        primary: {
                            main: '#1e40af'
                        }
                    },
                    typography: {
                        fontSize: '14px',
                        fontFamily: '"Inter", "Helvetica Neue", Helvetica, Arial, sans-serif'
                    }
                },
                scrollYOffset: 60,
                hideDownloadButton: false,
                disableSearch: false,
                nativeScrollbars: true,
                pathInMiddlePanel: true,
                menuToggle: true
            }, document.getElementById('redoc-container'));
        });
    </script>
    """

    enhanced_redoc = redoc_html.replace("</head>", f"{redoc_config}</head>")

    return HTMLResponse(content=enhanced_redoc)


def setup_openapi_docs(app: FastAPI):
    """Setup enhanced OpenAPI documentation for the FastAPI app"""

    # Configure OpenAPI schema
    app.openapi_schema = None  # Reset to regenerate

    def custom_openapi():
        if app.openapi_schema:
            return app.openapi_schema

        app.openapi_schema = create_openapi_schema(
            app=app, title="OpenWatch API", version="2.0.0", include_examples=True
        )
        return app.openapi_schema

    app.openapi = custom_openapi

    # Custom documentation endpoints
    @app.get("/docs", include_in_schema=False)
    async def custom_swagger_ui_html():
        return create_custom_swagger_ui(
            openapi_url=app.openapi_url,
            title="OpenWatch API - Interactive Documentation",
        )

    @app.get("/redoc", include_in_schema=False)
    async def custom_redoc_html():
        return create_custom_redoc(openapi_url=app.openapi_url, title="OpenWatch API - Reference Documentation")

    return app
