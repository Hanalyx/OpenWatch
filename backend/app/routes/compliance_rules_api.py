"""
Direct MongoDB Compliance Rules API for Frontend

Simplified API endpoints that connect directly to MongoDB for compliance rules.
Provides filtering, pagination, and statistics for compliance rule management.

This module implements:
- List compliance rules with filtering and pagination
- Get rule details by ID
- Get platform and framework statistics
- Provide filter options for frontend UI

OW-REFACTOR-002: Uses Repository Pattern for all MongoDB operations
per CLAUDE.md best practices for centralized query logic and type safety.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

# Type alias for mongo service to support both real and mock implementations
MongoServiceType = Any  # Union of MongoIntegrationService and MockMongoService

try:
    from ..repositories import ComplianceRuleRepository
    from ..services.mongo_integration_service import MongoIntegrationService, get_mongo_service

    MONGO_AVAILABLE = True
except ImportError:
    # Fallback when MongoDB dependencies are not available
    MONGO_AVAILABLE = False
    ComplianceRuleRepository = None  # type: ignore[misc, assignment]

    class MockMongoService:
        """Mock MongoDB service for when MongoDB dependencies are unavailable."""

        async def get_platform_statistics(self) -> Dict[str, Any]:
            return {
                "platforms": [
                    {
                        "name": "RHEL",
                        "version": "8",
                        "ruleCount": 1245,
                        "categories": [
                            {
                                "name": "Authentication",
                                "count": 156,
                                "percentage": 12.5,
                            },
                            {
                                "name": "Network Security",
                                "count": 234,
                                "percentage": 18.8,
                            },
                            {
                                "name": "System Hardening",
                                "count": 189,
                                "percentage": 15.2,
                            },
                            {"name": "Audit & Logging", "count": 98, "percentage": 7.9},
                            {
                                "name": "Access Control",
                                "count": 145,
                                "percentage": 11.6,
                            },
                            {"name": "Other", "count": 423, "percentage": 34.0},
                        ],
                        "frameworks": ["nist", "cis", "stig"],
                        "coverage": 84.2,
                    },
                    {
                        "name": "Ubuntu",
                        "version": "20.04",
                        "ruleCount": 876,
                        "categories": [
                            {
                                "name": "Authentication",
                                "count": 134,
                                "percentage": 15.3,
                            },
                            {
                                "name": "Network Security",
                                "count": 198,
                                "percentage": 22.6,
                            },
                            {
                                "name": "System Hardening",
                                "count": 156,
                                "percentage": 17.8,
                            },
                            {"name": "Audit & Logging", "count": 87, "percentage": 9.9},
                            {
                                "name": "Access Control",
                                "count": 112,
                                "percentage": 12.8,
                            },
                            {"name": "Other", "count": 189, "percentage": 21.6},
                        ],
                        "frameworks": ["nist", "cis"],
                        "coverage": 72.4,
                    },
                    {
                        "name": "Windows Server",
                        "version": "2019",
                        "ruleCount": 543,
                        "categories": [
                            {"name": "Authentication", "count": 89, "percentage": 16.4},
                            {
                                "name": "Network Security",
                                "count": 112,
                                "percentage": 20.6,
                            },
                            {
                                "name": "System Hardening",
                                "count": 98,
                                "percentage": 18.0,
                            },
                            {"name": "Access Control", "count": 76, "percentage": 14.0},
                            {"name": "Audit & Logging", "count": 54, "percentage": 9.9},
                            {"name": "Other", "count": 114, "percentage": 21.0},
                        ],
                        "frameworks": ["nist", "stig"],
                        "coverage": 68.9,
                    },
                ],
                "total_platforms": 3,
                "total_rules_analyzed": 2664,
                "source": "mock_data",
            }

        async def get_framework_statistics(self) -> Dict[str, Any]:
            """Return mock framework statistics when MongoDB is unavailable."""
            return {
                "frameworks": [],
                "total_frameworks": 0,
                "total_rules_analyzed": 0,
                "source": "mock_data",
            }

        async def get_rule_with_intelligence(self, rule_id: str) -> Dict[str, Any]:
            """Return mock rule intelligence when MongoDB is unavailable."""
            return {"error": f"Rule {rule_id} not found (MongoDB unavailable)"}

    # Note: This function shadows the imported get_mongo_service when MongoDB is unavailable
    # The signature differs (returns MockMongoService instead of MongoIntegrationService)
    # but both implement the same interface used by the endpoints
    async def get_mongo_service() -> Any:  # type: ignore[misc]
        """Get mock MongoDB service when real service is unavailable."""
        return MockMongoService()

    # Type alias for MongoIntegrationService when not available
    MongoIntegrationService = MockMongoService  # type: ignore[misc, assignment]

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/compliance-rules", tags=["Compliance Rules MongoDB"])


class ComplianceRuleResponse(BaseModel):
    """
    Frontend-compatible rule response model.

    Represents a single compliance rule with all metadata,
    framework mappings, and platform implementations.
    """

    rule_id: str
    scap_rule_id: Optional[str] = None
    metadata: Dict[str, Any] = {}
    severity: str = "medium"
    category: str = "system"
    tags: List[str] = []
    frameworks: Dict[str, Any] = {}
    platform_implementations: Dict[str, Any] = {}
    dependencies: Dict[str, List[str]] = {
        "requires": [],
        "conflicts": [],
        "related": [],
    }
    created_at: str
    updated_at: str


class ComplianceRulesListResponse(BaseModel):
    """
    Paginated rules list response model.

    Used for all compliance rules API responses with pagination,
    filtering metadata, and success/error information.
    """

    success: bool = True
    data: Dict[str, Any] = {}
    message: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


@router.get("/", response_model=ComplianceRulesListResponse)
async def get_compliance_rules(
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(25, ge=1, le=100, description="Number of rules to return"),
    framework: Optional[str] = Query(None, description="Filter by framework (nist, cis, stig)"),
    severity: Optional[str] = Query(
        None, description="Filter by severity (high, medium, low, info)"
    ),
    category: Optional[str] = Query(None, description="Filter by category"),
    platform: Optional[str] = Query(None, description="Filter by platform (rhel, ubuntu)"),
    search: Optional[str] = Query(None, description="Search in rule name, description, or ID"),
    is_latest: bool = Query(True, description="Filter by latest version of rules (default: True)"),
    view_mode: Optional[str] = Query(
        None, description="Special view mode: 'platform_statistics' for platform stats"
    ),
    mongo_service: MongoServiceType = Depends(get_mongo_service),
) -> ComplianceRulesListResponse:
    """
    Get compliance rules directly from MongoDB with filtering and pagination.

    Special view_mode='platform_statistics' returns platform statistics instead
    of the rule list. Supports filtering by framework, severity, category,
    platform, and free-text search.

    Args:
        offset: Pagination offset (starting index)
        limit: Number of rules to return (max 100)
        framework: Filter by compliance framework (nist, cis, stig)
        severity: Filter by rule severity (high, medium, low, info)
        category: Filter by rule category
        platform: Filter by target platform (rhel, ubuntu)
        search: Free-text search in rule name, description, or ID
        is_latest: Filter to only latest versions (default True)
        view_mode: Special modes like 'platform_statistics'
        mongo_service: Injected MongoDB service

    Returns:
        ComplianceRulesListResponse with rules data or statistics
    """
    try:
        # Handle special view mode requests
        if view_mode == "platform_statistics":
            try:
                result = await mongo_service.get_platform_statistics()
                return ComplianceRulesListResponse(
                    success=True,
                    data=result,
                    message=f"Retrieved statistics for {result.get('total_platforms', 0)} platforms",
                )
            except Exception as e:
                logger.warning(
                    f"MongoDB platform statistics failed, using converted rules fallback: {e}"
                )
                # Fallback to analyzing converted rules directly
                result = await get_platform_statistics_from_files()
                return ComplianceRulesListResponse(
                    success=True,
                    data=result,
                    message=f"Retrieved statistics for {result.get('total_platforms', 0)} platforms (from converted files)",
                )

        # Handle framework statistics request
        if view_mode == "framework_statistics":
            try:
                # Use MongoDB service for framework statistics
                # Note: get_framework_statistics may not exist on all service implementations
                # This is handled by the mock service when MongoDB is unavailable
                framework_service = await get_mongo_service()
                result = await framework_service.get_framework_statistics()  # type: ignore[attr-defined]
                return ComplianceRulesListResponse(
                    success=True,
                    data=result,
                    message=f"Retrieved statistics for {result.get('total_frameworks', 0)} frameworks",
                )
            except Exception as e:
                logger.error(f"Framework statistics failed: {e}")
                return ComplianceRulesListResponse(
                    success=False,
                    data={
                        "frameworks": [],
                        "total_frameworks": 0,
                        "total_rules_analyzed": 0,
                    },
                    message="Failed to retrieve framework statistics",
                )

        # Build MongoDB query with explicit Dict[str, Any] type to support mixed value types
        query: Dict[str, Any] = {}

        # Filter by latest version (default behavior)
        if is_latest:
            query["is_latest"] = True

        # Apply filters
        if framework:
            query[f"frameworks.{framework}"] = {"$exists": True}

        if severity:
            query["severity"] = severity

        if category:
            query["category"] = category

        if platform:
            query[f"platform_implementations.{platform}"] = {"$exists": True}

        if search:
            # Search in multiple fields using MongoDB $or operator
            query["$or"] = [
                {"rule_id": {"$regex": search, "$options": "i"}},
                {"metadata.name": {"$regex": search, "$options": "i"}},
                {"metadata.description": {"$regex": search, "$options": "i"}},
                {"tags": {"$regex": search, "$options": "i"}},
            ]

        # Get total count and rules (fallback if MongoDB not available)
        if MONGO_AVAILABLE:
            # OW-REFACTOR-002: Use Repository Pattern for all MongoDB operations
            # Why: Centralized query logic, automatic performance monitoring, type safety
            # Consistent with CLAUDE.md best practices for MongoDB access
            logger.info("Using ComplianceRuleRepository for get_compliance_rules endpoint")
            repo = ComplianceRuleRepository()

            # Get total count using repository
            total_count = await repo.count(query)

            # Get paginated results using repository
            rules = await repo.find_many(query, skip=offset, limit=limit)
        else:
            # Return mock rules if MongoDB not available
            mock_rules = [
                {
                    "rule_id": "ow-ssh-root-login-disabled",
                    "scap_rule_id": "xccdf_org.ssgproject.content_rule_sshd_disable_root_login",
                    "metadata": {
                        "name": "Disable SSH Root Login",
                        "description": "The root user should never be allowed to login to a system directly over a network",
                        "rationale": "Disallowing root logins over SSH requires system admins to authenticate using their own individual account",
                        "source": "MongoDB Compliance Database",
                    },
                    "severity": "high",
                    "category": "authentication",
                    "tags": ["ssh", "authentication", "root_access"],
                    "frameworks": {
                        "nist": {"800-53r5": ["AC-6", "IA-2"]},
                        "cis": {"rhel8_v2.0.0": ["5.2.8"]},
                    },
                    "platform_implementations": {
                        "rhel": {
                            "versions": ["8", "9"],
                            "check_command": "grep '^PermitRootLogin no' /etc/ssh/sshd_config",
                            "enable_command": "sed -i 's/^#?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
                        }
                    },
                    "dependencies": {
                        "requires": ["ow-ssh-service-enabled"],
                        "conflicts": [],
                        "related": ["ow-ssh-protocol-version"],
                    },
                    "created_at": "2025-01-01T12:00:00Z",
                    "updated_at": "2025-09-05T19:00:00Z",
                },
                {
                    "rule_id": "ow-firewall-enabled",
                    "scap_rule_id": "xccdf_org.ssgproject.content_rule_firewalld_enabled",
                    "metadata": {
                        "name": "Enable Firewall Service",
                        "description": "A firewall should be enabled to control network traffic",
                        "rationale": "Firewalls provide network access control and logging capabilities",
                        "source": "MongoDB Compliance Database",
                    },
                    "severity": "high",
                    "category": "network_security",
                    "tags": ["firewall", "network", "security"],
                    "frameworks": {
                        "nist": {"800-53r5": ["SC-7"]},
                        "cis": {"rhel8_v2.0.0": ["3.4.1"]},
                    },
                    "platform_implementations": {
                        "rhel": {
                            "versions": ["8", "9"],
                            "check_command": "systemctl is-enabled firewalld",
                            "enable_command": "systemctl enable --now firewalld",
                        },
                        "ubuntu": {
                            "versions": ["20.04", "22.04"],
                            "check_command": "ufw status | grep 'Status: active'",
                            "enable_command": "ufw --force enable",
                        },
                    },
                    "dependencies": {
                        "requires": [],
                        "conflicts": ["ow-iptables-enabled"],
                        "related": ["ow-network-hardening"],
                    },
                    "created_at": "2025-01-01T12:00:00Z",
                    "updated_at": "2025-09-05T19:00:00Z",
                },
                {
                    "rule_id": "ow-password-complexity",
                    "scap_rule_id": "xccdf_org.ssgproject.content_rule_password_complexity",
                    "metadata": {
                        "name": "Configure Password Complexity",
                        "description": "Password complexity requirements should be enforced to prevent weak passwords",
                        "rationale": "Complex passwords are harder to crack and provide better security",
                        "source": "MongoDB Compliance Database",
                    },
                    "severity": "medium",
                    "category": "authentication",
                    "tags": ["password", "authentication", "complexity"],
                    "frameworks": {
                        "nist": {"800-53r5": ["IA-5"]},
                        "cis": {"rhel8_v2.0.0": ["5.3.1"]},
                    },
                    "platform_implementations": {
                        "rhel": {
                            "versions": ["8", "9"],
                            "check_command": "grep pam_pwquality /etc/pam.d/password-auth",
                            "enable_command": "authconfig --enablereqlower --enablerequpper --enablereqdigit --update",
                        }
                    },
                    "dependencies": {
                        "requires": [],
                        "conflicts": [],
                        "related": ["ow-password-history"],
                    },
                    "created_at": "2025-01-01T12:00:00Z",
                    "updated_at": "2025-09-05T19:00:00Z",
                },
                {
                    "rule_id": "ow-audit-logging-enabled",
                    "scap_rule_id": "xccdf_org.ssgproject.content_rule_audit_enabled",
                    "metadata": {
                        "name": "Enable System Audit Logging",
                        "description": "System audit logging should be enabled and configured properly",
                        "rationale": "Audit logs provide accountability and help with incident response",
                        "source": "MongoDB Compliance Database",
                    },
                    "severity": "medium",
                    "category": "audit_logging",
                    "tags": ["audit", "logging", "accountability"],
                    "frameworks": {
                        "nist": {"800-53r5": ["AU-2", "AU-3", "AU-12"]},
                        "cis": {"rhel8_v2.0.0": ["4.1.1"]},
                        "pci": {"v4.0": ["10.2", "10.3"]},
                    },
                    "platform_implementations": {
                        "rhel": {
                            "versions": ["8", "9"],
                            "check_command": "systemctl is-enabled auditd",
                            "enable_command": "systemctl enable --now auditd",
                        }
                    },
                    "dependencies": {
                        "requires": [],
                        "conflicts": [],
                        "related": ["ow-log-rotation", "ow-rsyslog-config"],
                    },
                    "created_at": "2025-01-01T12:00:00Z",
                    "updated_at": "2025-09-05T19:00:00Z",
                },
                {
                    "rule_id": "ow-selinux-enforcing",
                    "scap_rule_id": "xccdf_org.ssgproject.content_rule_selinux_enforcing",
                    "metadata": {
                        "name": "Configure SELinux Enforcing Mode",
                        "description": "SELinux should be configured in enforcing mode for mandatory access control",
                        "rationale": "SELinux enforcing mode provides mandatory access control and prevents unauthorized access",
                        "source": "MongoDB Compliance Database",
                    },
                    "severity": "high",
                    "category": "access_control",
                    "tags": ["selinux", "mandatory_access_control", "kernel"],
                    "frameworks": {
                        "nist": {"800-53r5": ["AC-3", "SC-3"]},
                        "cis": {"rhel8_v2.0.0": ["1.7.1"]},
                        "stig": {"rhel8_v1r6": ["SV-230223r743937_rule"]},
                    },
                    "platform_implementations": {
                        "rhel": {
                            "versions": ["7", "8", "9"],
                            "check_command": "getenforce",
                            "enable_command": "setenforce 1 && sed -i s/SELINUX=.*/SELINUX=enforcing/ /etc/selinux/config",
                        }
                    },
                    "dependencies": {
                        "requires": [],
                        "conflicts": [],
                        "related": ["ow-selinux-policy"],
                    },
                    "created_at": "2025-01-01T12:00:00Z",
                    "updated_at": "2025-09-05T19:00:00Z",
                },
            ]

            # Apply simple filtering for mock data with explicit typing
            filtered_rules: List[Dict[str, Any]] = list(mock_rules)

            if search:
                search_lower = search.lower()
                # Filter rules containing search term in name, description, or rule_id
                filtered_result: List[Dict[str, Any]] = []
                for rule in filtered_rules:
                    metadata = rule.get("metadata", {})
                    rule_name = str(metadata.get("name", ""))
                    rule_desc = str(metadata.get("description", ""))
                    rule_id_val = str(rule.get("rule_id", ""))
                    if (
                        search_lower in rule_name.lower()
                        or search_lower in rule_desc.lower()
                        or search_lower in rule_id_val.lower()
                    ):
                        filtered_result.append(rule)
                filtered_rules = filtered_result

            if severity:
                filtered_rules = [
                    rule for rule in filtered_rules if rule.get("severity") == severity
                ]

            if category:
                filtered_rules = [
                    rule for rule in filtered_rules if rule.get("category") == category
                ]

            if framework:
                filtered_rules = [
                    rule for rule in filtered_rules if framework in rule.get("frameworks", {})
                ]

            if platform:
                filtered_rules = [
                    rule
                    for rule in filtered_rules
                    if platform in rule.get("platform_implementations", {})
                ]

            # Apply pagination to mock rules
            start = offset
            end = offset + limit
            rules_list: List[Dict[str, Any]] = filtered_rules[start:end]
            rules = rules_list  # type: ignore[assignment]
            total_count = len(filtered_rules)

        # Convert to frontend format with explicit typing
        rule_list: List[Dict[str, Any]] = []
        for rule in rules:
            # Convert Beanie Document to dict if needed, or use as-is for mock data
            # Mock data is already a dict, Beanie Documents have .dict() method
            if hasattr(rule, "dict"):
                rule_dict: Dict[str, Any] = rule.dict()
            else:
                # Mock data is already Dict[str, Any], safe conversion
                rule_dict = dict(rule)

            # Extract and format timestamps with proper null handling
            created_at_raw = rule_dict.get("created_at")
            updated_at_raw = rule_dict.get("updated_at")

            created_at_str = (
                created_at_raw.isoformat()
                if isinstance(created_at_raw, datetime)
                else str(created_at_raw or "")
            )
            updated_at_str = (
                updated_at_raw.isoformat()
                if isinstance(updated_at_raw, datetime)
                else str(updated_at_raw or "")
            )

            # Ensure required fields exist with safe defaults
            rule_response = ComplianceRuleResponse(
                rule_id=str(rule_dict.get("rule_id", "unknown")),
                scap_rule_id=rule_dict.get("scap_rule_id"),
                metadata=rule_dict.get("metadata") or {},
                severity=str(rule_dict.get("severity", "medium")),
                category=str(rule_dict.get("category", "system")),
                tags=rule_dict.get("tags") or [],
                frameworks=rule_dict.get("frameworks") or {},
                platform_implementations=rule_dict.get("platform_implementations") or {},
                dependencies=rule_dict.get("dependencies")
                or {
                    "requires": [],
                    "conflicts": [],
                    "related": [],
                },
                created_at=created_at_str,
                updated_at=updated_at_str,
            )
            rule_list.append(rule_response.model_dump())

        # Calculate pagination info
        has_next = (offset + limit) < total_count
        has_prev = offset > 0

        return ComplianceRulesListResponse(
            success=True,
            data={
                "rules": rule_list,
                "total_count": total_count,
                "offset": offset,
                "limit": limit,
                "has_next": has_next,
                "has_prev": has_prev,
                "filters_applied": {
                    "framework": framework,
                    "severity": severity,
                    "category": category,
                    "platform": platform,
                    "search": search,
                },
            },
            message=f"MongoDB Connected: {total_count} compliance rules in database{' (mock data)' if not MONGO_AVAILABLE else ''}",
        )

    except Exception as e:
        logger.error(f"Failed to get compliance rules: {e}")

        # Return mock data as fallback
        mock_rules = [
            {
                "rule_id": "ow-ssh-root-login-disabled",
                "scap_rule_id": "xccdf_org.ssgproject.content_rule_sshd_disable_root_login",
                "metadata": {
                    "name": "Disable SSH Root Login",
                    "description": "The root user should never be allowed to login to a system directly over a network",
                    "rationale": "Disallowing root logins over SSH requires system admins to authenticate using their own individual account",
                    "source": "MongoDB",
                },
                "severity": "high",
                "category": "authentication",
                "tags": ["ssh", "authentication", "root_access"],
                "frameworks": {
                    "nist": {"800-53r5": ["AC-6", "IA-2"]},
                    "cis": {"rhel8_v2.0.0": ["5.2.8"]},
                },
                "platform_implementations": {
                    "rhel": {
                        "versions": ["8", "9"],
                        "check_command": "grep '^PermitRootLogin no' /etc/ssh/sshd_config",
                    }
                },
                "dependencies": {
                    "requires": ["ow-ssh-service-enabled"],
                    "conflicts": [],
                    "related": ["ow-ssh-protocol-version"],
                },
                "created_at": "2025-01-01T12:00:00Z",
                "updated_at": "2025-09-05T19:00:00Z",
            },
            {
                "rule_id": "ow-firewall-enabled",
                "scap_rule_id": "xccdf_org.ssgproject.content_rule_firewalld_enabled",
                "metadata": {
                    "name": "Enable Firewall",
                    "description": "A firewall should be enabled to control network traffic",
                    "rationale": "Firewalls provide network access control and logging capabilities",
                    "source": "MongoDB",
                },
                "severity": "high",
                "category": "network_security",
                "tags": ["firewall", "network", "security"],
                "frameworks": {
                    "nist": {"800-53r5": ["SC-7"]},
                    "cis": {"rhel8_v2.0.0": ["3.4.1"]},
                },
                "platform_implementations": {
                    "rhel": {
                        "versions": ["8", "9"],
                        "check_command": "systemctl is-enabled firewalld",
                    },
                    "ubuntu": {
                        "versions": ["20.04", "22.04"],
                        "check_command": 'ufw status | grep "Status: active"',
                    },
                },
                "dependencies": {
                    "requires": [],
                    "conflicts": ["ow-iptables-enabled"],
                    "related": ["ow-network-hardening"],
                },
                "created_at": "2025-01-01T12:00:00Z",
                "updated_at": "2025-09-05T19:00:00Z",
            },
            {
                "rule_id": "ow-password-complexity",
                "scap_rule_id": "xccdf_org.ssgproject.content_rule_password_complexity",
                "metadata": {
                    "name": "Configure Password Complexity",
                    "description": "Password complexity requirements should be enforced",
                    "rationale": "Complex passwords are harder to crack and provide better security",
                    "source": "MongoDB",
                },
                "severity": "medium",
                "category": "authentication",
                "tags": ["password", "authentication", "complexity"],
                "frameworks": {
                    "nist": {"800-53r5": ["IA-5"]},
                    "cis": {"rhel8_v2.0.0": ["5.3.1"]},
                },
                "platform_implementations": {
                    "rhel": {
                        "versions": ["8", "9"],
                        "check_command": "grep pam_pwquality /etc/pam.d/password-auth",
                    }
                },
                "dependencies": {
                    "requires": [],
                    "conflicts": [],
                    "related": ["ow-password-history"],
                },
                "created_at": "2025-01-01T12:00:00Z",
                "updated_at": "2025-09-05T19:00:00Z",
            },
        ]

        return ComplianceRulesListResponse(
            success=True,
            data={
                "rules": mock_rules[:limit],
                "total_count": len(mock_rules),
                "offset": offset,
                "limit": limit,
                "has_next": False,
                "has_prev": False,
                "filters_applied": {
                    "framework": framework,
                    "severity": severity,
                    "category": category,
                    "platform": platform,
                    "search": search,
                },
            },
            message=f"Retrieved {len(mock_rules[:limit])} rules from MongoDB (fallback data due to connection error)",
        )


@router.get("/semantic-rules")
async def get_semantic_rules_for_scan(
    framework: Optional[str] = Query(None, description="Filter by framework (nist, cis, stig)"),
    business_impact: Optional[str] = Query(None, description="Filter by business impact/severity"),
    platform: Optional[str] = Query(None, description="Filter by platform"),
    limit: int = Query(1000, ge=1, le=5000, description="Maximum number of rules to return"),
) -> Dict[str, Any]:
    """
    Get compliance rules for scan creation wizard (ComplianceScans.tsx).

    Returns rules in format expected by frontend with semantic intelligence
    for rule selection during scan configuration.

    Args:
        framework: Filter by compliance framework (nist, cis, stig)
        business_impact: Filter by business impact/severity level
        platform: Filter by target platform
        limit: Maximum number of rules to return (max 5000)

    Returns:
        Dict with rules list and total count
    """
    try:
        if not MONGO_AVAILABLE or ComplianceRuleRepository is None:
            logger.warning("MongoDB not available, returning empty rules list")
            return {"rules": [], "total": 0}

        repo = ComplianceRuleRepository()

        # Build MongoDB query with explicit typing
        query: Dict[str, Any] = {"is_latest": True}

        # Apply framework filter
        if framework:
            query[f"frameworks.{framework}"] = {"$exists": True}

        # Apply platform filter
        if platform:
            query[f"platform_implementations.{platform}"] = {"$exists": True}

        # Map business_impact to severity if provided
        if business_impact:
            # Map business impact terms to severity levels
            severity_map: Dict[str, str] = {
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
            }
            mapped_severity = severity_map.get(business_impact.lower(), business_impact.lower())
            query["severity"] = mapped_severity

        # Fetch rules from MongoDB
        rules = await repo.find_many(query, limit=limit)

        # Transform to frontend-expected format
        # Frontend expects: {rules: [{id, scap_rule_id, title, compliance_intent, risk_level, frameworks}]}
        transformed_rules = []
        for rule in rules:
            transformed_rule = {
                "id": str(rule.id),
                "scap_rule_id": rule.rule_id,  # OpenWatch rule ID used as SCAP rule ID
                "title": rule.metadata.get("name", rule.rule_id),
                "compliance_intent": rule.metadata.get("description", ""),
                "risk_level": rule.severity.upper(),  # Frontend expects uppercase
                "frameworks": list(rule.frameworks.keys()) if rule.frameworks else [],
            }
            transformed_rules.append(transformed_rule)

        logger.info(
            f"Retrieved {len(transformed_rules)} semantic rules for scan wizard (framework={framework}, platform={platform}, business_impact={business_impact})"
        )

        return {"rules": transformed_rules, "total": len(transformed_rules)}

    except Exception as e:
        logger.error(f"Failed to get semantic rules for scan: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve semantic rules: {str(e)}",
        )


@router.get("/{rule_id}", response_model=ComplianceRulesListResponse)
async def get_compliance_rule_detail(
    rule_id: str,
    mongo_service: MongoServiceType = Depends(get_mongo_service),
) -> ComplianceRulesListResponse:
    """
    Get detailed information for a specific compliance rule from MongoDB.

    Retrieves full rule data including intelligence metadata, framework
    mappings, and platform implementations.

    Args:
        rule_id: Unique identifier for the compliance rule
        mongo_service: Injected MongoDB service

    Returns:
        ComplianceRulesListResponse with rule details

    Raises:
        HTTPException: 404 if rule not found, 500 on internal error
    """
    try:
        # Get rule with full details from MongoDB
        result = await mongo_service.get_rule_with_intelligence(rule_id)

        if "error" in result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Rule {rule_id} not found in MongoDB",
            )

        return ComplianceRulesListResponse(
            success=True,
            data=result,
            message=f"Retrieved detailed information for rule {rule_id}",
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get rule {rule_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve rule {rule_id} from MongoDB: {str(e)}",
        )


@router.get("/frameworks/available")
async def get_available_frameworks() -> Dict[str, Any]:
    """
    Get list of available frameworks from MongoDB compliance rules.

    Returns the top frameworks found in the database for scan wizard filtering.
    Each framework includes a value (internal ID) and label (display name).

    Returns:
        Dict with frameworks list and total count
    """
    try:
        if not MONGO_AVAILABLE or ComplianceRuleRepository is None:
            logger.warning("MongoDB not available, returning empty frameworks list")
            return {"frameworks": []}

        repo = ComplianceRuleRepository()

        # Get all latest rules to extract frameworks
        rules = await repo.find_many({"is_latest": True}, limit=2000)

        # Extract unique frameworks with explicit type annotation
        frameworks_set: set[str] = set()
        for rule in rules:
            if rule.frameworks:
                frameworks_set.update(rule.frameworks.keys())

        # Convert to list and sort
        frameworks_list = sorted(list(frameworks_set))

        # Create display-friendly framework list with proper names
        framework_display_map = {
            "nist_800_53": "NIST 800-53",
            "nist-csf": "NIST CSF",
            "cis": "CIS",
            "cis-csc": "CIS CSC",
            "stig": "STIG",
            "disa_stig": "DISA STIG",
            "pci_dss": "PCI-DSS",
            "pci_dss_v4": "PCI-DSS v4",
            "hipaa": "HIPAA",
            "iso_27001": "ISO 27001",
            "anssi": "ANSSI",
            "bsi": "BSI",
            "cobit5": "COBIT 5",
            "cui": "CUI",
            "ism": "ISM",
            "ospp": "OSPP",
            "srg": "SRG",
            "cjis": "CJIS",
            "isa-62443-2009": "ISA-62443-2009",
            "isa-62443-2013": "ISA-62443-2013",
            "nerc-cip": "NERC-CIP",
        }

        frameworks_with_display = [
            {"value": fw, "label": framework_display_map.get(fw, fw.upper())}
            for fw in frameworks_list
        ]

        logger.info(f"Retrieved {len(frameworks_with_display)} available frameworks from MongoDB")

        return {
            "frameworks": frameworks_with_display,
            "total": len(frameworks_with_display),
        }

    except Exception as e:
        logger.error(f"Failed to get available frameworks: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve available frameworks: {str(e)}",
        )


@router.get("/filters/options", response_model=ComplianceRulesListResponse)
async def get_filter_options(
    mongo_service: MongoServiceType = Depends(get_mongo_service),
) -> ComplianceRulesListResponse:
    """
    Get available filter options for the frontend.

    Returns lists of available values for framework, severity, category,
    platform, and compliance status filters in the compliance rules UI.

    Args:
        mongo_service: Injected MongoDB service (unused but required for consistency)

    Returns:
        ComplianceRulesListResponse with filter options
    """
    try:
        # Get all unique values for filter options
        # This would typically be done with MongoDB aggregation
        # For now, return static options based on common values

        filter_options: Dict[str, List[str]] = {
            "frameworks": ["nist", "cis", "stig", "pci", "hipaa"],
            "severities": ["high", "medium", "low", "info"],
            "categories": [
                "authentication",
                "network_security",
                "system_hardening",
                "access_control",
                "audit_logging",
                "encryption",
                "vulnerability_management",
                "configuration_management",
            ],
            "platforms": ["rhel", "ubuntu", "centos", "debian", "windows"],
            "compliance_statuses": [
                "compliant",
                "non_compliant",
                "not_applicable",
                "unknown",
            ],
        }

        return ComplianceRulesListResponse(
            success=True,
            data=filter_options,
            message="Retrieved filter options for compliance rules",
        )

    except Exception as e:
        logger.error(f"Failed to get filter options: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve filter options: {str(e)}",
        )


@router.get("/statistics/platforms", response_model=ComplianceRulesListResponse)
async def get_platform_statistics(
    mongo_service: MongoServiceType = Depends(get_mongo_service),
) -> ComplianceRulesListResponse:
    """
    Get compliance rule statistics grouped by platform.

    Returns platform names with rule counts and category breakdowns
    for compliance dashboard visualization.

    Args:
        mongo_service: Injected MongoDB service

    Returns:
        ComplianceRulesListResponse with platform statistics
    """
    try:
        # Use the mongo service to get platform statistics
        result = await mongo_service.get_platform_statistics()

        return ComplianceRulesListResponse(
            success=True,
            data=result,
            message=f"Retrieved statistics for {result.get('total_platforms', 0)} platforms",
        )

    except Exception as e:
        logger.error(f"Failed to get platform statistics: {e}")

        # Return fallback data on error
        fallback_platforms = [
            {
                "name": "RHEL",
                "version": "8",
                "ruleCount": 1245,
                "categories": [
                    {"name": "Authentication", "count": 156, "percentage": 12.5},
                    {"name": "Network Security", "count": 234, "percentage": 18.8},
                    {"name": "System Hardening", "count": 189, "percentage": 15.2},
                ],
                "frameworks": ["nist", "cis", "stig"],
                "coverage": 84.2,
            }
        ]

        return ComplianceRulesListResponse(
            success=True,
            data={
                "platforms": fallback_platforms,
                "total_platforms": 1,
                "total_rules_analyzed": 1584,
            },
            message="Retrieved platform statistics (fallback data)",
        )


async def get_platform_statistics_from_files() -> Dict[str, Any]:
    """
    DEPRECATED: Return empty platform statistics when MongoDB is empty.
    This function previously analyzed file-based rules but now only serves
    as a fallback to return empty data.
    """
    logger.info("MongoDB has no rules - returning empty platform statistics")
    return {
        "platforms": [],
        "total_platforms": 0,
        "total_rules_analyzed": 0,
        "source": "mongodb_empty",
    }


async def get_framework_statistics_from_files() -> Dict[str, Any]:
    """
    DEPRECATED: Return empty framework statistics when MongoDB is empty.
    This function previously analyzed file-based rules but now only serves
    as a fallback to return empty data.
    """
    logger.info("MongoDB has no rules - returning empty framework statistics")
    return {
        "frameworks": [],
        "total_frameworks": 0,
        "total_rules_analyzed": 0,
        "source": "mongodb_empty",
    }
