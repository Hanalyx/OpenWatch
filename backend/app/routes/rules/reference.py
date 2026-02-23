"""
Rule Reference API Endpoints

API endpoints for browsing Kensa compliance rules in the Rule Reference UI.
Provides a user-friendly interface for Auditors, System Administrators,
and Kensa developers to explore rules, framework mappings, and configuration.

Endpoint Structure:
    GET /api/rules/reference           - List rules with search/filter
    GET /api/rules/reference/stats     - Get rule statistics
    GET /api/rules/reference/{rule_id} - Get single rule details
    GET /api/rules/reference/frameworks - List frameworks
    GET /api/rules/reference/categories - List categories
    GET /api/rules/reference/variables  - List configurable variables
    GET /api/rules/reference/capabilities - List capability probes
"""

import logging
from math import ceil
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi import status as http_status

from ...auth import get_current_user
from ...database import User
from ...schemas.rule_reference_schemas import (
    CapabilityListResponse,
    CapabilityProbe,
    CategoryInfo,
    CategoryListResponse,
    CheckDefinition,
    FrameworkInfo,
    FrameworkListResponse,
    FrameworkReferences,
    Implementation,
    RemediationDefinition,
    RuleDetail,
    RuleDetailResponse,
    RuleListResponse,
    RuleSummary,
    VariableDefinition,
    VariableListResponse,
)
from ...services.rule_reference_service import get_rule_reference_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/reference", tags=["Rule Reference"])


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def rule_to_summary(rule: Dict[str, Any]) -> RuleSummary:
    """Convert a rule dict to RuleSummary."""
    # Count framework references
    refs = rule.get("references", {})
    framework_count = len(refs)

    # Check for remediation
    implementations = rule.get("implementations", [])
    has_remediation = any(impl.get("remediation") for impl in implementations)

    # Extract platform strings
    platforms = []
    for p in rule.get("platforms", []):
        family = p.get("family", "unknown")
        min_ver = p.get("min_version")
        if min_ver:
            platforms.append(f"{family}{min_ver}+")
        else:
            platforms.append(family)

    return RuleSummary(
        id=rule.get("id", ""),
        title=rule.get("title", ""),
        severity=rule.get("severity", "medium"),
        category=rule.get("category", "unknown"),
        tags=rule.get("tags", []),
        platforms=platforms,
        framework_count=framework_count,
        has_remediation=has_remediation,
    )


def rule_to_detail(rule: Dict[str, Any]) -> RuleDetail:
    """Convert a rule dict to RuleDetail."""
    # Parse framework references
    refs = rule.get("references", {})
    framework_refs = FrameworkReferences(
        cis={
            ver: {
                "section": ref.get("section", ""),
                "level": ref.get("level", ""),
                "type": ref.get("type", "Automated"),
            }
            for ver, ref in refs.get("cis", {}).items()
        },
        stig={
            ver: {
                "vuln_id": ref.get("vuln_id", ""),
                "stig_id": ref.get("stig_id", ""),
                "severity": ref.get("severity", ""),
                "cci": ref.get("cci", []),
            }
            for ver, ref in refs.get("stig", {}).items()
        },
        nist_800_53=refs.get("nist_800_53", []),
        pci_dss_4=refs.get("pci_dss_4", []),
        srg=refs.get("srg", []),
    )

    # Parse implementations
    implementations = []
    for impl in rule.get("implementations", []):
        check_data = impl.get("check", {})
        check = CheckDefinition(
            method=check_data.get("method", "unknown"),
            path=check_data.get("path"),
            key=check_data.get("key"),
            expected=check_data.get("expected"),
            comparator=check_data.get("comparator"),
            rule=check_data.get("rule"),
        )

        remediation = None
        remed_data = impl.get("remediation")
        if remed_data:
            remediation = RemediationDefinition(
                mechanism=remed_data.get("mechanism", "unknown"),
                path=remed_data.get("path"),
                key=remed_data.get("key"),
                value=remed_data.get("value"),
                reload=remed_data.get("reload"),
                command=remed_data.get("command"),
            )

        implementations.append(
            Implementation(
                capability_required=impl.get("when"),
                is_default=impl.get("default", False),
                check=check,
                remediation=remediation,
            )
        )

    return RuleDetail(
        id=rule.get("id", ""),
        title=rule.get("title", ""),
        description=rule.get("description", ""),
        rationale=rule.get("rationale", ""),
        severity=rule.get("severity", "medium"),
        category=rule.get("category", "unknown"),
        tags=rule.get("tags", []),
        platforms=rule.get("platforms", []),
        references=framework_refs,
        implementations=implementations,
        depends_on=rule.get("depends_on", []),
        conflicts_with=rule.get("conflicts_with", []),
    )


# =============================================================================
# API ENDPOINTS
# =============================================================================


@router.get("", response_model=RuleListResponse)
async def list_rules(
    search: Optional[str] = Query(None, description="Search in title, description, tags"),
    framework: Optional[str] = Query(None, description="Filter by framework (cis, stig, nist_800_53)"),
    category: Optional[str] = Query(None, description="Filter by category (access-control, audit)"),
    severity: Optional[str] = Query(None, description="Filter by severity (critical, high, medium, low)"),
    capability: Optional[str] = Query(None, description="Filter by required capability"),
    tags: Optional[str] = Query(None, description="Filter by tags (comma-separated)"),
    platform: Optional[str] = Query(None, description="Filter by platform (rhel8, rhel9)"),
    has_remediation: Optional[bool] = Query(None, description="Filter by remediation availability"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=200, description="Items per page"),
    current_user: User = Depends(get_current_user),
) -> RuleListResponse:
    """
    List Kensa compliance rules with search and filtering.

    This endpoint provides the main rule browser functionality for the
    Rule Reference UI. Supports full-text search and multiple filters.

    Args:
        search: Free-text search in title, description, ID, and tags
        framework: Filter by compliance framework
        category: Filter by rule category
        severity: Filter by severity level
        capability: Filter by required host capability
        tags: Comma-separated list of tags to filter by
        platform: Filter by supported platform
        has_remediation: Filter by remediation availability
        page: Page number (1-indexed)
        per_page: Number of items per page (max 200)
        current_user: Authenticated user

    Returns:
        Paginated list of rule summaries
    """
    try:
        service = get_rule_reference_service()

        # Parse tags
        tag_list = None
        if tags:
            tag_list = [t.strip() for t in tags.split(",") if t.strip()]

        rules, total = service.list_rules(
            search=search,
            framework=framework,
            category=category,
            severity=severity,
            capability=capability,
            tags=tag_list,
            platform=platform,
            has_remediation=has_remediation,
            page=page,
            per_page=per_page,
        )

        total_pages = ceil(total / per_page) if total > 0 else 1

        return RuleListResponse(
            rules=[rule_to_summary(r) for r in rules],
            total=total,
            page=page,
            per_page=per_page,
            total_pages=total_pages,
        )

    except Exception as e:
        logger.exception("Failed to list rules: %s", e)
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve rules",
        )


@router.get("/stats")
async def get_rule_statistics(
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get rule statistics.

    Returns counts by severity, category, framework, and remediation availability.

    Args:
        current_user: Authenticated user

    Returns:
        Statistics dictionary
    """
    try:
        service = get_rule_reference_service()
        return service.get_statistics()

    except Exception as e:
        logger.exception("Failed to get statistics: %s", e)
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve statistics",
        )


@router.get("/frameworks", response_model=FrameworkListResponse)
async def list_frameworks(
    current_user: User = Depends(get_current_user),
) -> FrameworkListResponse:
    """
    List available compliance frameworks.

    Returns all frameworks that Kensa rules map to, along with
    rule counts and version information.

    Args:
        current_user: Authenticated user

    Returns:
        List of frameworks with metadata
    """
    try:
        service = get_rule_reference_service()
        frameworks = service.list_frameworks()

        return FrameworkListResponse(
            frameworks=[
                FrameworkInfo(
                    id=fw["id"],
                    name=fw["name"],
                    description=fw["description"],
                    versions=fw["versions"],
                    rule_count=fw["rule_count"],
                )
                for fw in frameworks
            ],
            total=len(frameworks),
        )

    except Exception as e:
        logger.exception("Failed to list frameworks: %s", e)
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve frameworks",
        )


@router.get("/categories", response_model=CategoryListResponse)
async def list_categories(
    current_user: User = Depends(get_current_user),
) -> CategoryListResponse:
    """
    List rule categories.

    Returns all categories with descriptions and rule counts.

    Args:
        current_user: Authenticated user

    Returns:
        List of categories
    """
    try:
        service = get_rule_reference_service()
        categories = service.list_categories()

        return CategoryListResponse(
            categories=[
                CategoryInfo(
                    id=cat["id"],
                    name=cat["name"],
                    description=cat["description"],
                    rule_count=cat["rule_count"],
                )
                for cat in categories
            ],
            total=len(categories),
        )

    except Exception as e:
        logger.exception("Failed to list categories: %s", e)
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve categories",
        )


@router.get("/variables", response_model=VariableListResponse)
async def list_variables(
    current_user: User = Depends(get_current_user),
) -> VariableListResponse:
    """
    List configurable variables.

    Returns all variables defined in defaults.yml along with their
    default values, framework-specific overrides, and which rules use them.

    Args:
        current_user: Authenticated user

    Returns:
        List of variable definitions
    """
    try:
        service = get_rule_reference_service()
        variables = service.list_variables()

        return VariableListResponse(
            variables=[
                VariableDefinition(
                    name=var["name"],
                    default_value=var["default_value"],
                    description=var["description"],
                    framework_overrides=var["framework_overrides"],
                    used_by_rules=var["used_by_rules"],
                )
                for var in variables
            ],
            total=len(variables),
        )

    except Exception as e:
        logger.exception("Failed to list variables: %s", e)
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve variables",
        )


@router.get("/capabilities", response_model=CapabilityListResponse)
async def list_capabilities(
    current_user: User = Depends(get_current_user),
) -> CapabilityListResponse:
    """
    List capability probes.

    Returns the 22 capability probes that Kensa uses to detect host
    configuration, along with descriptions and rule counts.

    Args:
        current_user: Authenticated user

    Returns:
        List of capability probes
    """
    try:
        service = get_rule_reference_service()
        capabilities = service.list_capabilities()

        return CapabilityListResponse(
            capabilities=[
                CapabilityProbe(
                    id=cap["id"],
                    name=cap["name"],
                    description=cap["description"],
                    detection_method=cap["detection_method"],
                    rules_requiring=cap["rules_requiring"],
                )
                for cap in capabilities
            ],
            total=len(capabilities),
        )

    except Exception as e:
        logger.exception("Failed to list capabilities: %s", e)
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve capabilities",
        )


@router.get("/{rule_id}", response_model=RuleDetailResponse)
async def get_rule(
    rule_id: str,
    current_user: User = Depends(get_current_user),
) -> RuleDetailResponse:
    """
    Get detailed information about a specific rule.

    Returns full rule details including description, rationale,
    framework mappings, implementations, and remediation steps.

    Args:
        rule_id: The rule ID (e.g., 'ssh-disable-root-login')
        current_user: Authenticated user

    Returns:
        Full rule details

    Raises:
        HTTPException: 404 if rule not found
    """
    try:
        service = get_rule_reference_service()
        rule = service.get_rule(rule_id)

        if not rule:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND,
                detail=f"Rule not found: {rule_id}",
            )

        return RuleDetailResponse(rule=rule_to_detail(rule))

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to get rule %s: %s", rule_id, e)
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve rule",
        )


@router.post("/refresh")
async def refresh_rules_cache(
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Refresh the rules cache.

    Forces a reload of all Kensa YAML rules from disk. Use this after
    updating rule files to see the changes immediately.

    Args:
        current_user: Authenticated user

    Returns:
        Success message
    """
    try:
        service = get_rule_reference_service()
        service.clear_cache()

        # Trigger reload
        stats = service.get_statistics()

        return {
            "status": "success",
            "message": f"Reloaded {stats['total_rules']} rules",
        }

    except Exception as e:
        logger.exception("Failed to refresh cache: %s", e)
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to refresh rules cache",
        )


__all__ = ["router"]
