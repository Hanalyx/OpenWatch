#!/usr/bin/env python3
"""
Phase 4 Demonstration Server
Minimal FastAPI server to showcase Phase 4 API implementation without database dependencies
"""
import sys
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import json

# Add app to Python path
sys.path.append('/home/rracine/hanalyx/openwatch/backend')

app = FastAPI(
    title="OpenWatch Phase 4 API Demo",
    description="Demonstration server for Phase 4 Enhanced Rule Management APIs",
    version="2.0.0-phase4",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mock authentication
def mock_auth(request: Request):
    """Mock authentication for demo purposes"""
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return {"user_id": "demo_user", "authenticated": False}
    return {"user_id": "demo_user", "authenticated": True}

# Response models
class APIResponse(BaseModel):
    success: bool = True
    data: Any = None
    message: str = "Success"
    timestamp: datetime = Field(default_factory=datetime.now)

class ErrorResponse(BaseModel):
    success: bool = False
    error: str
    message: str
    error_id: str
    timestamp: datetime = Field(default_factory=datetime.now)

# Sample rule data for demonstration
SAMPLE_RULES = [
    {
        "rule_id": "ow-ssh-root-login-disabled",
        "scap_rule_id": "xccdf_org.ssgproject.content_rule_sshd_disable_root_login",
        "metadata": {
            "name": "Disable SSH Root Login",
            "description": "The root user should never be allowed to login to a system directly over a network",
            "rationale": "Disallowing root logins over SSH requires system admins to authenticate using their own individual account",
            "source": "SCAP"
        },
        "abstract": False,
        "severity": "high",
        "category": "authentication",
        "security_function": "access_control",
        "tags": ["ssh", "authentication", "root_access"],
        "frameworks": {
            "nist": {"800-53r5": ["AC-6", "IA-2"]},
            "cis": {"rhel8_v2.0.0": ["5.2.8"]}
        },
        "platform_implementations": {
            "rhel": {
                "versions": ["8", "9"],
                "check_command": "grep '^PermitRootLogin no' /etc/ssh/sshd_config",
                "enable_command": "sed -i 's/^#?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl restart sshd"
            }
        },
        "dependencies": {
            "requires": ["ow-ssh-service-enabled"],
            "conflicts": [],
            "related": ["ow-ssh-protocol-version"]
        },
        "created_at": "2025-01-01T12:00:00Z",
        "updated_at": "2025-09-04T19:00:00Z"
    },
    {
        "rule_id": "ow-firewall-enabled",
        "scap_rule_id": "xccdf_org.ssgproject.content_rule_firewalld_enabled",
        "metadata": {
            "name": "Enable Firewall",
            "description": "A firewall should be enabled to control network traffic",
            "rationale": "Firewalls provide network access control and logging capabilities",
            "source": "SCAP"
        },
        "abstract": False,
        "severity": "high",
        "category": "network_security",
        "security_function": "boundary_protection",
        "tags": ["firewall", "network", "security"],
        "frameworks": {
            "nist": {"800-53r5": ["SC-7"]},
            "cis": {"rhel8_v2.0.0": ["3.4.1"]}
        },
        "platform_implementations": {
            "rhel": {
                "versions": ["8", "9"],
                "check_command": "systemctl is-enabled firewalld",
                "enable_command": "systemctl enable --now firewalld"
            }
        },
        "dependencies": {
            "requires": [],
            "conflicts": ["ow-iptables-enabled"],
            "related": ["ow-network-hardening"]
        },
        "created_at": "2025-01-01T12:00:00Z",
        "updated_at": "2025-09-04T19:00:00Z"
    }
]

@app.get("/", response_model=Dict[str, Any])
async def root():
    """Welcome endpoint with Phase 4 information"""
    return {
        "message": "OpenWatch Phase 4 API Demo Server",
        "phase": "Phase 4: API Implementation",
        "status": "✅ COMPLETED",
        "implementation_date": "2025-09-04",
        "endpoints": {
            "documentation": "/docs",
            "api_info": "/api/v1/",
            "rules": "/api/v1/rules",
            "search": "/api/v1/rules/search",
            "dependencies": "/api/v1/rules/dependencies",
            "capabilities": "/api/v1/rules/platform-capabilities"
        },
        "features": [
            "Enhanced Rule Management",
            "API Versioning",
            "Error Handling Middleware", 
            "Rate Limiting",
            "OpenAPI Documentation",
            "Full-text Search",
            "Platform Capability Detection",
            "Rule Dependencies",
            "Import/Export"
        ]
    }

@app.get("/api/v1/", response_model=APIResponse)
async def get_api_v1_info():
    """Get API v1 information and available endpoints"""
    return APIResponse(
        data={
            "api_version": "v1",
            "phase": "Phase 4 Implementation",
            "description": "Enhanced Rule Management API with comprehensive features",
            "endpoints": {
                "rules": "/api/v1/rules",
                "search": "/api/v1/rules/search",
                "dependencies": "/api/v1/rules/dependencies",
                "platform_capabilities": "/api/v1/rules/platform-capabilities",
                "export": "/api/v1/rules/export",
                "import": "/api/v1/rules/import",
                "cache": "/api/v1/rules/cache/*"
            },
            "features": {
                "filtering": "Advanced rule filtering by platform, severity, category",
                "inheritance": "Rule inheritance information and parameter overrides",
                "search": "Full-text search with relevance scoring",
                "dependencies": "Rule dependency graphs with conflict detection",
                "capabilities": "Platform capability detection and baseline comparison",
                "caching": "Intelligent caching with invalidation strategies",
                "versioning": "API versioning with multiple detection methods"
            }
        }
    )

@app.get("/api/v1/rules", response_model=APIResponse)
async def list_rules(
    request: Request,
    platform: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    offset: int = 0,
    limit: int = 50,
    user: dict = Depends(mock_auth)
):
    """Enhanced rule listing with filters - Phase 4 Implementation"""
    
    # Add API version header
    request.state.api_version = "v1"
    
    # Filter rules based on parameters
    filtered_rules = SAMPLE_RULES.copy()
    
    if platform:
        filtered_rules = [
            rule for rule in filtered_rules 
            if platform in rule.get("platform_implementations", {})
        ]
    
    if severity:
        filtered_rules = [
            rule for rule in filtered_rules 
            if rule.get("severity") == severity
        ]
    
    if category:
        filtered_rules = [
            rule for rule in filtered_rules 
            if rule.get("category") == category
        ]
    
    # Apply pagination
    total_count = len(filtered_rules)
    paginated_rules = filtered_rules[offset:offset + limit]
    
    return APIResponse(
        data={
            "rules": paginated_rules,
            "total_count": total_count,
            "offset": offset,
            "limit": limit,
            "has_next": offset + limit < total_count,
            "has_prev": offset > 0,
            "filters_applied": {
                "platform": platform,
                "severity": severity, 
                "category": category
            }
        },
        message=f"Retrieved {len(paginated_rules)} rules with filters"
    )

@app.get("/api/v1/rules/{rule_id}", response_model=APIResponse)
async def get_rule_details(
    rule_id: str,
    request: Request,
    include_inheritance: bool = False,
    user: dict = Depends(mock_auth)
):
    """Get rule details with inheritance information - Phase 4 Implementation"""
    
    # Find rule by ID
    rule = next((r for r in SAMPLE_RULES if r["rule_id"] == rule_id), None)
    
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "message": f"Rule not found: {rule_id}",
                "resource": "rule",
                "identifier": rule_id,
                "type": "not_found_error"
            }
        )
    
    # Enhance with inheritance information if requested
    if include_inheritance:
        rule = {
            **rule,
            "inheritance": {
                "parent_rule": "ow-base-ssh-rule" if "ssh" in rule_id else None,
                "overridden_parameters": ["check_command", "enable_command"],
                "inherited_frameworks": ["nist"] if rule.get("frameworks", {}).get("nist") else []
            },
            "parameter_overrides": {
                "check_command": f"Enhanced command for {rule_id}",
                "timeout": 30
            }
        }
    
    return APIResponse(
        data=rule,
        message=f"Rule details retrieved for {rule_id}"
    )

class SearchRequest(BaseModel):
    query: str = Field(..., min_length=1, description="Search query string")
    filters: Optional[Dict[str, List[str]]] = None
    sort_by: str = "relevance"
    limit: int = Field(default=20, ge=1, le=100)

@app.post("/api/v1/rules/search", response_model=APIResponse)
async def search_rules(
    search_request: SearchRequest,
    request: Request,
    user: dict = Depends(mock_auth)
):
    """Full-text rule search with relevance scoring - Phase 4 Implementation"""
    
    query = search_request.query.lower()
    
    # Simple relevance scoring based on query matches
    results = []
    for rule in SAMPLE_RULES:
        score = 0
        matched_fields = []
        
        # Check name
        if query in rule["metadata"]["name"].lower():
            score += 10
            matched_fields.append("metadata.name")
        
        # Check description
        if query in rule["metadata"]["description"].lower():
            score += 8
            matched_fields.append("metadata.description")
        
        # Check tags
        for tag in rule.get("tags", []):
            if query in tag.lower():
                score += 5
                matched_fields.append("tags")
                break
        
        # Check category
        if query in rule.get("category", "").lower():
            score += 7
            matched_fields.append("category")
        
        if score > 0:
            results.append({
                **rule,
                "relevance_score": score / 10.0,  # Normalize to 0-1 scale
                "matched_fields": matched_fields
            })
    
    # Sort by relevance
    results.sort(key=lambda x: x["relevance_score"], reverse=True)
    
    # Apply limit
    results = results[:search_request.limit]
    
    return APIResponse(
        data={
            "results": results,
            "total_count": len(results),
            "search_query": search_request.query,
            "search_time_ms": 42,  # Mock timing
            "filters_applied": search_request.filters or {}
        },
        message=f"Found {len(results)} rules matching '{search_request.query}'"
    )

class DependencyRequest(BaseModel):
    rule_ids: List[str] = Field(..., min_items=1)
    include_transitive: bool = False
    max_depth: int = Field(default=5, ge=1, le=10)

@app.post("/api/v1/rules/dependencies", response_model=APIResponse)
async def get_rule_dependencies(
    dependency_request: DependencyRequest,
    request: Request,
    user: dict = Depends(mock_auth)
):
    """Get rule dependency graph - Phase 4 Implementation"""
    
    rule_id = dependency_request.rule_ids[0]  # Use first rule for demo
    
    # Find rule
    rule = next((r for r in SAMPLE_RULES if r["rule_id"] == rule_id), None)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule not found: {rule_id}")
    
    # Mock dependency analysis
    dependency_graph = {
        "rule_id": rule_id,
        "dependency_graph": {
            "direct_dependencies": rule.get("dependencies", {}),
            "transitive_dependencies": {
                "ow-ssh-service-enabled": {
                    "requires": ["ow-systemd-enabled"],
                    "depth": 2
                }
            } if dependency_request.include_transitive else {}
        },
        "conflict_analysis": {
            "has_conflicts": len(rule.get("dependencies", {}).get("conflicts", [])) > 0,
            "conflict_details": [
                {
                    "conflicting_rule": conflict,
                    "reason": f"{rule_id} and {conflict} cannot be enabled simultaneously"
                }
                for conflict in rule.get("dependencies", {}).get("conflicts", [])
            ]
        },
        "dependency_count": len(rule.get("dependencies", {}).get("requires", []))
    }
    
    return APIResponse(
        data=dependency_graph,
        message=f"Dependency analysis complete for {rule_id}"
    )

class CapabilityRequest(BaseModel):
    platform: str
    platform_version: str
    target_host: Optional[str] = None
    compare_baseline: bool = True
    capability_types: List[str] = ["package", "service", "security"]

@app.post("/api/v1/rules/platform-capabilities", response_model=APIResponse)
async def detect_platform_capabilities(
    capability_request: CapabilityRequest,
    request: Request,
    user: dict = Depends(mock_auth)
):
    """Platform capability detection - Phase 4 Implementation"""
    
    # Mock capability detection
    capabilities_result = {
        "platform": capability_request.platform,
        "platform_version": capability_request.platform_version,
        "detection_timestamp": datetime.now().isoformat(),
        "target_host": capability_request.target_host,
        "capabilities": {}
    }
    
    # Add mock capabilities based on requested types
    for cap_type in capability_request.capability_types:
        if cap_type == "package":
            capabilities_result["capabilities"]["package"] = {
                "detected": True,
                "results": {
                    "firewalld": {"version": "0.9.3", "installed": True},
                    "openssh-server": {"version": "8.0p1", "installed": True},
                    "aide": {"version": None, "installed": False}
                }
            }
        elif cap_type == "service":
            capabilities_result["capabilities"]["service"] = {
                "detected": True,
                "results": {
                    "firewalld": {"state": "enabled", "enabled": True},
                    "sshd": {"state": "enabled", "enabled": True}
                }
            }
        elif cap_type == "security":
            capabilities_result["capabilities"]["security"] = {
                "detected": True,
                "results": {
                    "selinux": {"stdout": "Enforcing"},
                    "firewall": {"stdout": "running"}
                }
            }
    
    # Add baseline comparison if requested
    if capability_request.compare_baseline:
        capabilities_result["baseline_comparison"] = {
            "missing": ["aide"],
            "matched": ["firewalld", "openssh-server", "systemd"],
            "analysis": {
                "baseline_coverage": 0.85,
                "platform_health": "good"
            }
        }
    
    return APIResponse(
        data=capabilities_result,
        message=f"Platform capabilities detected for {capability_request.platform} {capability_request.platform_version}"
    )

# Add version headers middleware
@app.middleware("http")
async def add_version_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-API-Version"] = getattr(request.state, "api_version", "v1")
    response.headers["X-API-Version-Status"] = "stable"
    response.headers["X-Phase4-Implementation"] = "completed"
    return response

# Error handling
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": "http_error",
            "message": exc.detail if isinstance(exc.detail, str) else str(exc.detail),
            "error_id": "demo123",
            "timestamp": datetime.now().isoformat(),
            "path": str(request.url.path),
            "method": request.method
        }
    )

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting OpenWatch Phase 4 Demo Server...")
    print("📖 Documentation: http://localhost:8000/docs")
    print("🔍 API Info: http://localhost:8000/api/v1/")
    print("📋 Rules: http://localhost:8000/api/v1/rules")
    print()
    uvicorn.run(app, host="0.0.0.0", port=8000)