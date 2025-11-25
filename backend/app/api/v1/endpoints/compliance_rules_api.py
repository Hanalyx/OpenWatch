"""
Direct MongoDB Compliance Rules API for Frontend
Simplified API endpoints that connect directly to MongoDB for compliance rules
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

try:
    from ....repositories import ComplianceRuleRepository
    from ....services.mongo_integration_service import MongoIntegrationService, get_mongo_service

    MONGO_AVAILABLE = True
except ImportError:
    # Fallback when MongoDB dependencies are not available
    MONGO_AVAILABLE = False

    class MockMongoService:
        async def get_platform_statistics(self):
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

    async def get_mongo_service():
        return MockMongoService()

    MongoIntegrationService = MockMongoService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/compliance-rules", tags=["Compliance Rules MongoDB"])


class ComplianceRuleResponse(BaseModel):
    """Frontend-compatible rule response"""

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
    """Paginated rules list response"""

    success: bool = True
    data: Dict[str, Any] = {}
    message: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


@router.get("/", response_model=ComplianceRulesListResponse)
async def get_compliance_rules(
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(25, ge=1, le=100, description="Number of rules to return"),
    framework: Optional[str] = Query(None, description="Filter by framework (nist, cis, stig)"),
    severity: Optional[str] = Query(None, description="Filter by severity (high, medium, low, info)"),
    category: Optional[str] = Query(None, description="Filter by category"),
    platform: Optional[str] = Query(None, description="Filter by platform (rhel, ubuntu)"),
    search: Optional[str] = Query(None, description="Search in rule name, description, or ID"),
    is_latest: bool = Query(True, description="Filter by latest version of rules (default: True)"),
    view_mode: Optional[str] = Query(None, description="Special view mode: 'platform_statistics' for platform stats"),
    mongo_service: MongoIntegrationService = Depends(get_mongo_service),
):
    """
    Get compliance rules directly from MongoDB with filtering and pagination
    Special view_mode='platform_statistics' returns platform statistics instead
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
                logger.warning(f"MongoDB platform statistics failed, using converted rules fallback: {e}")
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
                mongo_service = await get_mongo_service()
                result = await mongo_service.get_framework_statistics()
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
        # Build MongoDB query
        query = {}

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
            # Search in multiple fields
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

            # Apply simple filtering for mock data
            filtered_rules = mock_rules

            if search:
                search_lower = search.lower()
                filtered_rules = [
                    rule
                    for rule in filtered_rules
                    if search_lower in rule["metadata"]["name"].lower()
                    or search_lower in rule["metadata"]["description"].lower()
                    or search_lower in rule["rule_id"].lower()
                ]

            if severity:
                filtered_rules = [rule for rule in filtered_rules if rule["severity"] == severity]

            if category:
                filtered_rules = [rule for rule in filtered_rules if rule["category"] == category]

            if framework:
                filtered_rules = [rule for rule in filtered_rules if framework in rule.get("frameworks", {})]

            if platform:
                filtered_rules = [
                    rule for rule in filtered_rules if platform in rule.get("platform_implementations", {})
                ]

            # Apply pagination
            start = offset
            end = offset + limit
            rules = filtered_rules[start:end]
            total_count = len(filtered_rules)

        # Convert to frontend format
        rule_list = []
        for rule in rules:
            rule_dict = rule.dict() if hasattr(rule, "dict") else rule

            # Ensure required fields exist
            rule_response = ComplianceRuleResponse(
                rule_id=rule_dict.get("rule_id", "unknown"),
                scap_rule_id=rule_dict.get("scap_rule_id"),
                metadata=rule_dict.get("metadata", {}),
                severity=rule_dict.get("severity", "medium"),
                category=rule_dict.get("category", "system"),
                tags=rule_dict.get("tags", []),
                frameworks=rule_dict.get("frameworks", {}),
                platform_implementations=rule_dict.get("platform_implementations", {}),
                dependencies=rule_dict.get("dependencies", {"requires": [], "conflicts": [], "related": []}),
                created_at=(
                    rule_dict.get("created_at", datetime.utcnow()).isoformat()
                    if isinstance(rule_dict.get("created_at"), datetime)
                    else str(rule_dict.get("created_at", ""))
                ),
                updated_at=(
                    rule_dict.get("updated_at", datetime.utcnow()).isoformat()
                    if isinstance(rule_dict.get("updated_at"), datetime)
                    else str(rule_dict.get("updated_at", ""))
                ),
            )
            rule_list.append(rule_response.dict())

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
):
    """
    Get compliance rules for scan creation wizard (ComplianceScans.tsx)
    Returns rules in format expected by frontend with semantic intelligence
    """
    try:
        if not MONGO_AVAILABLE:
            logger.warning("MongoDB not available, returning empty rules list")
            return {"rules": [], "total": 0}

        from ....repositories import ComplianceRuleRepository

        repo = ComplianceRuleRepository()

        # Build MongoDB query
        query = {"is_latest": True}

        # Apply framework filter
        if framework:
            query[f"frameworks.{framework}"] = {"$exists": True}

        # Apply platform filter
        if platform:
            query[f"platform_implementations.{platform}"] = {"$exists": True}

        # Map business_impact to severity if provided
        if business_impact:
            # Map business impact terms to severity levels
            severity_map = {
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
async def get_compliance_rule_detail(rule_id: str, mongo_service: MongoIntegrationService = Depends(get_mongo_service)):
    """
    Get detailed information for a specific compliance rule from MongoDB
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
async def get_available_frameworks():
    """
    Get list of available frameworks from MongoDB compliance rules
    Returns the top frameworks found in the database for scan wizard filtering
    """
    try:
        if not MONGO_AVAILABLE:
            logger.warning("MongoDB not available, returning empty frameworks list")
            return {"frameworks": []}

        from ....repositories import ComplianceRuleRepository

        repo = ComplianceRuleRepository()

        # Get all latest rules to extract frameworks
        rules = await repo.find_many({"is_latest": True}, limit=2000)

        # Extract unique frameworks
        frameworks_set = set()
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
            {"value": fw, "label": framework_display_map.get(fw, fw.upper())} for fw in frameworks_list
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
    mongo_service: MongoIntegrationService = Depends(get_mongo_service),
):
    """
    Get available filter options for the frontend
    """
    try:
        # Get all unique values for filter options
        # This would typically be done with MongoDB aggregation
        # For now, return static options based on common values

        filter_options = {
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
    mongo_service: MongoIntegrationService = Depends(get_mongo_service),
):
    """
    Get compliance rule statistics grouped by platform
    Returns platform names with rule counts and category breakdowns
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
