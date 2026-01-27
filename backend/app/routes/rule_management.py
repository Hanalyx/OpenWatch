"""
Enhanced Rule Management API Endpoints for OpenWatch
Provides advanced rule querying, inheritance resolution, and platform-aware operations
"""

import csv
import io
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import User, get_db
from ..services.platform_capability_service import PlatformCapabilityService
from ..services.rules import QueryPriority, RuleCacheService, RuleService

router = APIRouter(prefix="/rules", tags=["Enhanced Rule Management"])

# Initialize services (singleton pattern)
rule_service = None
cache_service = None
platform_service = None


async def get_rule_service() -> RuleService:
    """Get or initialize rule service"""
    global rule_service, cache_service
    if not rule_service:
        cache_service = RuleCacheService()
        await cache_service.initialize()
        rule_service = RuleService(cache_service=cache_service)
        await rule_service.initialize()
    return rule_service


async def get_platform_service() -> PlatformCapabilityService:
    """Get or initialize platform capability service"""
    global platform_service
    if not platform_service:
        platform_service = PlatformCapabilityService()
        await platform_service.initialize()
    return platform_service


# Request/Response Models


class RuleQuery(BaseModel):
    """Rule query parameters with advanced filtering"""

    platform: Optional[str] = Field(None, description="Target platform (rhel, ubuntu, windows, etc.)")
    platform_version: Optional[str] = Field(None, description="Platform version (8, 20.04, etc.)")
    framework: Optional[str] = Field(None, description="Compliance framework (nist, cis, stig, etc.)")
    framework_version: Optional[str] = Field(None, description="Framework version (800-53r5, v8, etc.)")
    severity: Optional[List[str]] = Field(None, description="Severity levels to include")
    category: Optional[List[str]] = Field(None, description="Rule categories to include")
    priority: QueryPriority = Field(QueryPriority.NORMAL, description="Query priority for caching")
    include_abstract: bool = Field(False, description="Include abstract/base rules")
    include_inheritance: bool = Field(True, description="Resolve rule inheritance")


class RuleSearchQuery(BaseModel):
    """Full-text search parameters"""

    query: str = Field(..., description="Search query text")
    platform_filter: Optional[str] = Field(None, description="Platform to filter by")
    framework_filter: Optional[str] = Field(None, description="Framework to filter by")
    limit: int = Field(50, ge=1, le=500, description="Maximum results to return")
    offset: int = Field(0, ge=0, description="Results offset for pagination")


class RuleDependencyQuery(BaseModel):
    """Rule dependency resolution parameters"""

    rule_id: str = Field(..., description="Rule ID to resolve dependencies for")
    resolve_depth: int = Field(3, ge=1, le=10, description="Maximum dependency resolution depth")
    include_conflicts: bool = Field(True, description="Include conflicting rules")


class PlatformCapabilityQuery(BaseModel):
    """Platform capability detection parameters"""

    platform: str = Field(..., description="Platform name")
    platform_version: str = Field(..., description="Platform version")
    target_host: Optional[str] = Field(None, description="Target host for remote detection")


class ApplicableRulesQuery(BaseModel):
    """Query for rules applicable to specific capabilities"""

    platform: str = Field(..., description="Platform name")
    platform_version: str = Field(..., description="Platform version")
    capabilities: Dict[str, Any] = Field(..., description="Detected platform capabilities")
    framework: Optional[str] = Field(None, description="Compliance framework filter")
    minimum_severity: str = Field("low", description="Minimum rule severity")


class RuleExportOptions(BaseModel):
    """Rule export configuration"""

    format: str = Field("json", pattern="^(json|csv|xml)$", description="Export format")
    include_inheritance: bool = Field(True, description="Include resolved inheritance")
    include_dependencies: bool = Field(False, description="Include dependency information")
    filters: Optional[RuleQuery] = Field(None, description="Query filters to apply")


# Response Models


class RuleSummary(BaseModel):
    """Rule summary for list responses"""

    rule_id: str
    metadata: Dict[str, Any]
    severity: str
    category: str
    platforms: List[str]
    frameworks: Dict[str, Any]
    abstract: bool
    updated_at: datetime


class RuleDetail(BaseModel):
    """Detailed rule information"""

    rule_id: str
    scap_rule_id: Optional[str]
    metadata: Dict[str, Any]
    abstract: bool
    severity: str
    category: str
    security_function: Optional[str]
    tags: List[str]
    frameworks: Dict[str, Any]
    platform_implementations: Dict[str, Any]
    platform_requirements: Optional[Dict[str, Any]]
    inherits_from: Optional[str]
    derived_rules: List[str]
    dependencies: Optional[Dict[str, List[str]]]
    parameter_overrides: Optional[Dict[str, Any]]
    inheritance_resolved: bool
    created_at: datetime
    updated_at: datetime


class RuleDependencyGraph(BaseModel):
    """Rule with complete dependency information"""

    rule: RuleDetail
    dependencies: Dict[str, List[Dict[str, Any]]]
    resolution_depth: int
    total_dependencies: int
    total_conflicts: int
    resolution_time: str


class PlatformCapabilities(BaseModel):
    """Platform capability detection results"""

    platform: str
    platform_version: str
    detection_timestamp: str
    target_host: Optional[str]
    capabilities: Dict[str, Any]
    baseline_comparison: Optional[Dict[str, Any]]


class RuleSearchResults(BaseModel):
    """Rule search results with pagination"""

    results: List[RuleSummary]
    total_count: int
    offset: int
    limit: int
    has_next: bool
    has_prev: bool
    search_query: str


class RuleStatistics(BaseModel):
    """Rule statistics and metrics"""

    totals: Dict[str, int]
    severity_distribution: Dict[str, int]
    platform_coverage: Dict[str, int]
    framework_coverage: Dict[str, int]
    query_performance: Dict[str, Any]
    cache_performance: Dict[str, Any]
    last_updated: str


class APIResponse(BaseModel):
    """Standard API response wrapper"""

    success: bool
    data: Any
    message: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# API Endpoints


@router.get("/", response_model=APIResponse, summary="List rules with advanced filtering")
async def list_rules(
    query: RuleQuery = Depends(),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    service: RuleService = Depends(get_rule_service),
) -> APIResponse:
    """
    List compliance rules with advanced filtering capabilities.

    Supports filtering by platform, framework, severity, and category.
    Includes caching and inheritance resolution.
    """
    try:
        # Get rules with filters - provide defaults for Optional parameters
        rules = await service.get_rules_by_platform(
            platform=query.platform or "",
            platform_version=query.platform_version,
            framework=query.framework,
            framework_version=query.framework_version,
            severity_filter=query.severity,
            category_filter=query.category,
            priority=query.priority,
        )

        # Filter out abstract rules if not requested
        if not query.include_abstract:
            rules = [rule for rule in rules if not rule.get("abstract", False)]

        # Convert to summary format
        rule_summaries = [
            RuleSummary(
                rule_id=rule["rule_id"],
                metadata=rule.get("metadata", {}),
                severity=rule.get("severity", "medium"),
                category=rule.get("category", "unknown"),
                platforms=list(rule.get("platform_implementations", {}).keys()),
                frameworks=rule.get("frameworks", {}),
                abstract=rule.get("abstract", False),
                updated_at=rule.get("updated_at", datetime.utcnow()),
            )
            for rule in rules
        ]

        return APIResponse(
            success=True,
            data=rule_summaries,
            message=f"Retrieved {len(rule_summaries)} rules",
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve rules: {str(e)}",
        )


@router.get(
    "/{rule_id}",
    response_model=APIResponse,
    summary="Get rule details with inheritance",
)
async def get_rule_detail(
    rule_id: str = Path(..., description="Rule ID"),
    resolve_inheritance: bool = Query(True, description="Resolve rule inheritance"),
    include_dependencies: bool = Query(False, description="Include dependency information"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    service: RuleService = Depends(get_rule_service),
) -> APIResponse:
    """
    Get detailed information for a specific rule.

    Optionally resolves inheritance chain and includes dependency information.
    """
    try:
        if include_dependencies:
            # Get rule with full dependency graph
            result = await service.get_rule_with_dependencies(rule_id=rule_id, resolve_depth=3, include_conflicts=True)

            rule_data = result["rule"]
            dependency_data = RuleDependencyGraph(
                rule=RuleDetail(**rule_data),
                dependencies=result["dependencies"],
                resolution_depth=result["resolution_depth"],
                total_dependencies=result["total_dependencies"],
                total_conflicts=result["total_conflicts"],
                resolution_time=result["resolution_time"],
            )

            return APIResponse(
                success=True,
                data=dependency_data,
                message=f"Retrieved rule {rule_id} with dependencies",
            )
        else:
            # Get basic rule details (would need database integration)
            # For now, return a mock response structure
            rule_data = {
                "rule_id": rule_id,
                "scap_rule_id": f"scap_{rule_id}",
                "metadata": {
                    "name": f"Rule {rule_id}",
                    "description": f"Description for rule {rule_id}",
                    "source": "OpenWatch",
                },
                "abstract": False,
                "severity": "medium",
                "category": "system",
                "security_function": "configuration",
                "tags": ["security", "compliance"],
                "frameworks": {"nist": {"800-53r5": ["AC-2"]}},
                "platform_implementations": {"rhel": {"versions": ["8", "9"]}},
                "platform_requirements": None,
                "inherits_from": None,
                "derived_rules": [],
                "dependencies": {"requires": [], "conflicts": [], "related": []},
                "parameter_overrides": None,
                "inheritance_resolved": resolve_inheritance,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
            }

            rule_detail = RuleDetail(**rule_data)

            return APIResponse(success=True, data=rule_detail, message=f"Retrieved rule {rule_id}")

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule {rule_id} not found: {str(e)}",
        )


@router.post("/search", response_model=APIResponse, summary="Full-text rule search")
async def search_rules(
    search_query: RuleSearchQuery,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    service: RuleService = Depends(get_rule_service),
) -> APIResponse:
    """
    Perform full-text search across rules with advanced filtering.

    Supports relevance ranking, platform filtering, and pagination.
    """
    try:
        # Perform search
        search_results = await service.search_rules(
            search_query=search_query.query,
            platform_filter=search_query.platform_filter,
            framework_filter=search_query.framework_filter,
            limit=search_query.limit,
            offset=search_query.offset,
        )

        # Convert results to summaries
        rule_summaries = []
        for rule in search_results["results"]:
            rule_summaries.append(
                RuleSummary(
                    rule_id=rule.get("rule_id", "unknown"),
                    metadata=rule.get("metadata", {}),
                    severity=rule.get("severity", "medium"),
                    category=rule.get("category", "unknown"),
                    platforms=list(rule.get("platform_implementations", {}).keys()),
                    frameworks=rule.get("frameworks", {}),
                    abstract=rule.get("abstract", False),
                    updated_at=rule.get("updated_at", datetime.utcnow()),
                )
            )

        results = RuleSearchResults(
            results=rule_summaries,
            total_count=search_results["total_count"],
            offset=search_results["offset"],
            limit=search_results["limit"],
            has_next=search_results["has_next"],
            has_prev=search_results["has_prev"],
            search_query=search_query.query,
        )

        return APIResponse(
            success=True,
            data=results,
            message=f"Found {len(rule_summaries)} rules matching '{search_query.query}'",
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Search failed: {str(e)}",
        )


@router.post("/dependencies", response_model=APIResponse, summary="Get rule dependency graph")
async def get_rule_dependencies(
    dependency_query: RuleDependencyQuery,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    service: RuleService = Depends(get_rule_service),
) -> APIResponse:
    """
    Get complete dependency graph for a rule.

    Resolves dependencies, conflicts, and related rules with configurable depth.
    """
    try:
        result = await service.get_rule_with_dependencies(
            rule_id=dependency_query.rule_id,
            resolve_depth=dependency_query.resolve_depth,
            include_conflicts=dependency_query.include_conflicts,
        )

        dependency_graph = RuleDependencyGraph(
            rule=RuleDetail(**result["rule"]),
            dependencies=result["dependencies"],
            resolution_depth=result["resolution_depth"],
            total_dependencies=result["total_dependencies"],
            total_conflicts=result["total_conflicts"],
            resolution_time=result["resolution_time"],
        )

        return APIResponse(
            success=True,
            data=dependency_graph,
            message=f"Retrieved dependency graph for rule {dependency_query.rule_id}",
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Failed to resolve dependencies for rule {dependency_query.rule_id}: {str(e)}",
        )


@router.post(
    "/platform-capabilities",
    response_model=APIResponse,
    summary="Detect platform capabilities",
)
async def detect_platform_capabilities(
    capability_query: PlatformCapabilityQuery,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    platform_svc: PlatformCapabilityService = Depends(get_platform_service),
) -> APIResponse:
    """
    Detect platform capabilities for rule applicability assessment.

    Supports local and remote capability detection with baseline comparison.
    """
    try:
        # Detect capabilities
        capabilities = await platform_svc.detect_capabilities(
            platform=capability_query.platform,
            platform_version=capability_query.platform_version,
            target_host=capability_query.target_host,
        )

        # Get baseline for comparison
        baseline = await platform_svc.get_platform_baseline(
            capability_query.platform, capability_query.platform_version
        )

        baseline_comparison = None
        if baseline:
            baseline_comparison = await platform_svc.compare_with_baseline(capabilities, baseline)

        result = PlatformCapabilities(
            platform=capabilities["platform"],
            platform_version=capabilities["platform_version"],
            detection_timestamp=capabilities["detection_timestamp"],
            target_host=capabilities.get("target_host"),
            capabilities=capabilities["capabilities"],
            baseline_comparison=baseline_comparison,
        )

        return APIResponse(
            success=True,
            data=result,
            message=f"Detected capabilities for {capability_query.platform} {capability_query.platform_version}",
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Capability detection failed: {str(e)}",
        )


@router.post(
    "/applicable",
    response_model=APIResponse,
    summary="Get applicable rules for capabilities",
)
async def get_applicable_rules(
    applicable_query: ApplicableRulesQuery,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    service: RuleService = Depends(get_rule_service),
) -> APIResponse:
    """
    Get rules applicable to specific platform capabilities.

    Filters rules based on detected capabilities and minimum severity.
    """
    try:
        applicable_rules = await service.get_applicable_rules(
            platform=applicable_query.platform,
            platform_version=applicable_query.platform_version,
            detected_capabilities=applicable_query.capabilities,
            framework=applicable_query.framework,
            minimum_severity=applicable_query.minimum_severity,
        )

        # Convert to summaries
        rule_summaries = [
            RuleSummary(
                rule_id=rule["rule_id"],
                metadata=rule.get("metadata", {}),
                severity=rule.get("severity", "medium"),
                category=rule.get("category", "unknown"),
                platforms=list(rule.get("platform_implementations", {}).keys()),
                frameworks=rule.get("frameworks", {}),
                abstract=rule.get("abstract", False),
                updated_at=rule.get("updated_at", datetime.utcnow()),
            )
            for rule in applicable_rules
        ]

        return APIResponse(
            success=True,
            data=rule_summaries,
            message=(  # noqa: E501
                f"Found {len(rule_summaries)} applicable rules for "
                f"{applicable_query.platform} {applicable_query.platform_version}"
            ),
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get applicable rules: {str(e)}",
        )


@router.get("/statistics", response_model=APIResponse, summary="Get rule statistics and metrics")
async def get_rule_statistics(
    include_cache_stats: bool = Query(True, description="Include cache performance statistics"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    service: RuleService = Depends(get_rule_service),
) -> APIResponse:
    """
    Get comprehensive rule statistics and performance metrics.

    Includes rule counts, distribution, and cache performance data.
    """
    try:
        stats = await service.get_rule_statistics()

        # Get cache statistics if requested
        cache_performance = {}
        if include_cache_stats and service.cache_service:
            cache_info = await service.cache_service.get_cache_info()
            cache_performance = cache_info

        statistics = RuleStatistics(
            totals=stats["totals"],
            severity_distribution=stats["severity_distribution"],
            platform_coverage=stats["platform_coverage"],
            framework_coverage=stats["framework_coverage"],
            query_performance=stats["query_performance"],
            cache_performance=cache_performance,
            last_updated=stats["last_updated"],
        )

        return APIResponse(success=True, data=statistics, message="Retrieved rule statistics")

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get statistics: {str(e)}",
        )


@router.post("/export", summary="Export rules in various formats")
async def export_rules(
    export_options: RuleExportOptions,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    service: RuleService = Depends(get_rule_service),
) -> Response:
    """
    Export rules in JSON, CSV, or XML format.

    Supports filtering and includes inheritance resolution options.
    """
    try:
        # Apply filters if provided - provide defaults for Optional parameters
        if export_options.filters:
            rules = await service.get_rules_by_platform(
                platform=export_options.filters.platform or "",
                platform_version=export_options.filters.platform_version,
                framework=export_options.filters.framework,
                framework_version=export_options.filters.framework_version,
                severity_filter=export_options.filters.severity,
                category_filter=export_options.filters.category,
                priority=export_options.filters.priority,
            )
        else:
            # Get all rules (would need proper implementation)
            rules = []

        # Generate filename
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"openwatch_rules_{timestamp}.{export_options.format}"

        if export_options.format == "json":
            # JSON export
            export_data = json.dumps(rules, indent=2, default=str)
            media_type = "application/json"

        elif export_options.format == "csv":
            # CSV export
            output = io.StringIO()
            if rules:
                # Flatten rules for CSV
                fieldnames = [
                    "rule_id",
                    "severity",
                    "category",
                    "platforms",
                    "frameworks",
                ]
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()

                for rule in rules:
                    writer.writerow(
                        {
                            "rule_id": rule.get("rule_id", ""),
                            "severity": rule.get("severity", ""),
                            "category": rule.get("category", ""),
                            "platforms": ",".join(rule.get("platform_implementations", {}).keys()),
                            "frameworks": ",".join(rule.get("frameworks", {}).keys()),
                        }
                    )

            export_data = output.getvalue()
            media_type = "text/csv"

        else:  # XML
            # Basic XML export
            xml_lines = ['<?xml version="1.0" encoding="UTF-8"?>', "<rules>"]
            for rule in rules:
                xml_lines.append(f'  <rule id="{rule.get("rule_id", "")}">')
                xml_lines.append(f'    <severity>{rule.get("severity", "")}</severity>')
                xml_lines.append(f'    <category>{rule.get("category", "")}</category>')
                xml_lines.append("  </rule>")
            xml_lines.append("</rules>")

            export_data = "\n".join(xml_lines)
            media_type = "application/xml"

        # Return streaming response
        return StreamingResponse(
            io.BytesIO(export_data.encode("utf-8")),
            media_type=media_type,
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Export failed: {str(e)}",
        )


# Cache Management Endpoints


@router.post("/cache/warm", response_model=APIResponse, summary="Warm rule cache")
async def warm_cache(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    service: RuleService = Depends(get_rule_service),
) -> APIResponse:
    """Warm the rule cache with common queries."""
    try:
        if service.cache_service:
            await service.cache_service.warm_cache()
            cache_info = await service.cache_service.get_cache_info()

            return APIResponse(success=True, data=cache_info, message="Cache warming completed")
        else:
            return APIResponse(success=False, data=None, message="Cache service not available")

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Cache warming failed: {str(e)}",
        )


@router.delete("/cache/invalidate", response_model=APIResponse, summary="Invalidate rule cache")
async def invalidate_cache(
    tags: Optional[List[str]] = Query(None, description="Cache tags to invalidate"),
    pattern: Optional[str] = Query(None, description="Cache key pattern to invalidate"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    service: RuleService = Depends(get_rule_service),
) -> APIResponse:
    """Invalidate rule cache by tags or patterns."""
    try:
        if not service.cache_service:
            return APIResponse(success=False, data=None, message="Cache service not available")

        invalidated = 0

        if tags:
            invalidated += await service.cache_service.invalidate_by_tags(tags)

        if pattern:
            invalidated += await service.cache_service.invalidate_pattern(pattern)

        return APIResponse(
            success=True,
            data={"invalidated_entries": invalidated},
            message=f"Invalidated {invalidated} cache entries",
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Cache invalidation failed: {str(e)}",
        )


@router.get("/cache/info", response_model=APIResponse, summary="Get cache information")
async def get_cache_info(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    service: RuleService = Depends(get_rule_service),
) -> APIResponse:
    """Get detailed cache performance information."""
    try:
        if service.cache_service:
            cache_info = await service.cache_service.get_cache_info()

            return APIResponse(success=True, data=cache_info, message="Retrieved cache information")
        else:
            return APIResponse(
                success=False,
                data={"status": "unavailable"},
                message="Cache service not available",
            )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get cache info: {str(e)}",
        )
