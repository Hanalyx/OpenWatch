"""
Kensa Compliance Scanning Endpoints

This module provides API endpoints for the Kensa compliance engine integration.
Kensa provides SSH-based compliance scanning with 338 canonical YAML rules.

Scan Endpoints:
    POST /kensa                      - Execute Kensa compliance scan
    GET  /kensa/health               - Kensa engine health check
    GET  /kensa/compliance-state/{host_id} - Get compliance state for host

Framework Mapping Endpoints (PostgreSQL):
    GET  /kensa/frameworks           - List available frameworks (static)
    GET  /kensa/frameworks/db        - List frameworks from database
    GET  /kensa/rules/framework/{framework} - Get rules for a framework
    GET  /kensa/framework/{framework}/coverage - Get framework coverage stats
    GET  /kensa/rules/{rule_id}/framework-refs - Get framework refs for rule
    GET  /kensa/controls/search      - Search controls across frameworks
    GET  /kensa/controls/{framework}/{control_id} - Get rules for control

Sync Endpoints:
    GET  /kensa/sync-stats           - Get sync statistics
    POST /kensa/sync                 - Trigger manual rule sync

Frameworks Supported:
    - CIS RHEL 9 v2.0.0 (95.1% coverage)
    - STIG RHEL 9 V2R7 (75.8% coverage)
    - NIST 800-53 Rev 5 mappings
    - PCI-DSS v4.0 mappings
    - SRG mappings

Security Notes:
    - All endpoints require JWT authentication
    - Credentials retrieved securely from OpenWatch
    - Private keys written to secure temp files (cleaned up after use)
"""

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.plugins.kensa.evidence import serialize_evidence, serialize_framework_refs
from app.utils.mutation_builders import InsertBuilder, UpdateBuilder

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/kensa", tags=["Kensa Scanning"])


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================


class KensaScanRequest(BaseModel):
    """Request model for Kensa compliance scan."""

    host_id: str = Field(
        ...,
        description="UUID of the target host",
        min_length=1,
    )
    framework: Optional[str] = Field(
        None,
        description="Framework filter (cis-rhel9-v2.0.0, stig-rhel9-v2r7, nist-800-53)",
    )
    severity: Optional[List[str]] = Field(
        None,
        description="Severity filter (critical, high, medium, low)",
    )
    category: Optional[str] = Field(
        None,
        description="Category filter (access-control, audit, services, etc.)",
    )
    name: Optional[str] = Field(
        None,
        description="Custom scan name (auto-generated if not provided)",
    )


class KensaScanResponse(BaseModel):
    """Response model for Kensa compliance scan."""

    scan_id: str
    status: str
    host_id: str
    hostname: str
    framework: Optional[str]
    total_rules: int
    passed: int
    failed: int
    skipped: int
    compliance_score: float
    kensa_version: str
    duration_ms: int
    started_at: str
    completed_at: str


class KensaFramework(BaseModel):
    """Framework information."""

    id: str
    title: str
    description: str
    coverage_percent: float
    controls_implemented: int
    controls_total: int


class KensaFrameworksResponse(BaseModel):
    """List of available frameworks."""

    frameworks: List[KensaFramework]


class ComplianceFinding(BaseModel):
    """Individual compliance finding."""

    rule_id: str
    title: str
    severity: str
    status: str
    detail: Optional[str] = None
    framework_section: Optional[str] = None
    evidence: Optional[List[Dict[str, Any]]] = None
    framework_refs: Optional[Dict[str, str]] = None
    skip_reason: Optional[str] = None


class ComplianceStateResponse(BaseModel):
    """Compliance state for a host based on latest scan."""

    host_id: str
    hostname: str
    scan_id: Optional[str] = None
    scan_date: Optional[str] = None
    total_rules: int
    passed: int
    failed: int
    unknown: int
    compliance_score: float
    findings: List[ComplianceFinding]
    severity_summary: Dict[str, Dict[str, int]]


# =============================================================================
# ENDPOINTS
# =============================================================================


@router.post("/", response_model=KensaScanResponse)
async def execute_kensa_scan(
    request: KensaScanRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> KensaScanResponse:
    """
    Execute a Kensa compliance scan on a target host.

    This endpoint uses the Kensa compliance engine for SSH-based scanning
    with native check handlers (no OVAL transformation).

    Args:
        request: Scan configuration with host_id and optional filters.
        db: SQLAlchemy database session.
        current_user: Authenticated user from JWT token.

    Returns:
        KensaScanResponse with scan results and compliance score.

    Raises:
        HTTPException 404: Host not found.
        HTTPException 500: Scan execution failure.
    """
    start_time = datetime.now(timezone.utc)
    scan_uuid = uuid.uuid4()
    scan_id = str(scan_uuid)

    logger.info(
        "Starting Kensa scan %s for host %s",
        scan_id,
        request.host_id,
        extra={
            "scan_id": scan_id,
            "host_id": request.host_id,
            "framework": request.framework,
            "user_id": current_user.get("id"),
        },
    )

    try:
        # Import Kensa components
        from runner.engine import check_rules_from_path
        from runner.paths import get_rules_path, get_version

        kensa_version = get_version()
        from app.plugins.kensa import KensaSessionFactory

        rules_path = Path(get_rules_path())

        # Verify host exists
        host_query = text("SELECT id, hostname, display_name FROM hosts WHERE id = :id")
        host_result = db.execute(host_query, {"id": request.host_id}).fetchone()

        if not host_result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Host not found: {request.host_id}",
            )

        hostname = host_result.hostname

        # Create scan record in database
        scan_name = request.name or f"Kensa Scan - {hostname} - {start_time.strftime('%Y-%m-%d %H:%M')}"

        # profile_id for Kensa uses the framework name or "kensa_all"
        profile_id = f"kensa_{request.framework}" if request.framework else "kensa_all"

        insert_builder = (
            InsertBuilder("scans")
            .columns(
                "id",
                "name",
                "host_id",
                "content_id",
                "profile_id",
                "status",
                "progress",
                "started_at",
                "started_by",
                "scan_options",
                "remediation_requested",
                "verification_scan",
            )
            .values(
                scan_id,
                scan_name,
                request.host_id,
                1,  # Kensa Compliance Rules content entry
                profile_id,
                "running",
                0,  # progress starts at 0
                start_time,
                current_user.get("id"),
                f'{{"scanner": "kensa", "framework": "{request.framework or "all"}"}}',
                False,  # remediation_requested
                False,  # verification_scan
            )
        )
        insert_query, insert_params = insert_builder.build()
        db.execute(text(insert_query), insert_params)
        db.commit()

        # Execute Kensa scan
        factory = KensaSessionFactory(db)

        async with factory.create_session(request.host_id) as session:
            results = check_rules_from_path(
                session,
                str(rules_path),
                severity=request.severity,
                category=request.category,
            )

        end_time = datetime.now(timezone.utc)
        duration_ms = int((end_time - start_time).total_seconds() * 1000)

        # Calculate totals and severity breakdown
        total = len(results)
        passed = sum(1 for r in results if r.passed and not r.skipped)
        failed = sum(1 for r in results if not r.passed and not r.skipped)
        skipped = sum(1 for r in results if r.skipped)
        score = (passed / (passed + failed) * 100) if (passed + failed) > 0 else 0.0

        # Calculate severity counts (Kensa uses: critical, high, medium, low)
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        severity_passed = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        severity_failed = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for r in results:
            if r.skipped:
                continue
            sev = r.severity.lower() if r.severity else "medium"
            if sev not in severity_counts:
                sev = "medium"  # Default unknown severities to medium
            severity_counts[sev] += 1
            if r.passed:
                severity_passed[sev] += 1
            else:
                severity_failed[sev] += 1

        # Update scan record with results
        update_builder = (
            UpdateBuilder("scans")
            .set("status", "completed")
            .set("completed_at", end_time)
            .set("progress", 100)
            .where("id = :id", scan_id, "id")
        )
        update_query, update_params = update_builder.build()
        db.execute(text(update_query), update_params)

        # Insert scan results with severity breakdown
        results_insert = (
            InsertBuilder("scan_results")
            .columns(
                "scan_id",
                "total_rules",
                "passed_rules",
                "failed_rules",
                "error_rules",
                "unknown_rules",
                "not_applicable_rules",
                "score",
                "severity_high",
                "severity_medium",
                "severity_low",
                "severity_critical",
                "severity_critical_passed",
                "severity_critical_failed",
                "severity_high_passed",
                "severity_high_failed",
                "severity_medium_passed",
                "severity_medium_failed",
                "severity_low_passed",
                "severity_low_failed",
                "created_at",
            )
            .values(
                scan_id,
                total,
                passed,
                failed,
                skipped,
                0,  # unknown_rules
                0,  # not_applicable_rules
                f"{score:.2f}",
                severity_counts["high"],
                severity_counts["medium"],
                severity_counts["low"],
                severity_counts["critical"],
                severity_passed["critical"],
                severity_failed["critical"],
                severity_passed["high"],
                severity_failed["high"],
                severity_passed["medium"],
                severity_failed["medium"],
                severity_passed["low"],
                severity_failed["low"],
                end_time,
            )
        )
        results_query, results_params = results_insert.build()
        db.execute(text(results_query), results_params)

        # Insert individual rule findings into scan_findings table
        for r in results:
            status_str = "pass" if r.passed else "fail"
            if r.skipped:
                status_str = "skipped"

            finding_insert = (
                InsertBuilder("scan_findings")
                .columns(
                    "scan_id",
                    "rule_id",
                    "title",
                    "severity",
                    "status",
                    "detail",
                    "framework_section",
                    "evidence",
                    "framework_refs",
                    "skip_reason",
                    "created_at",
                )
                .values(
                    scan_id,
                    r.rule_id,
                    r.title[:500] if r.title else "Unknown",  # Truncate to fit column
                    r.severity or "medium",
                    status_str,
                    r.detail[:2000] if r.detail else None,  # Truncate long details
                    r.framework_section,
                    serialize_evidence(r),
                    serialize_framework_refs(r),
                    r.skip_reason if r.skipped else None,
                    end_time,
                )
            )
            finding_query, finding_params = finding_insert.build()
            db.execute(text(finding_query), finding_params)

        db.commit()

        logger.info(
            "Kensa scan %s completed: %d/%d passed (%.1f%%)",
            scan_id,
            passed,
            total,
            score,
        )

        return KensaScanResponse(
            scan_id=scan_id,
            status="completed",
            host_id=request.host_id,
            hostname=hostname,
            framework=request.framework,
            total_rules=total,
            passed=passed,
            failed=failed,
            skipped=skipped,
            compliance_score=round(score, 2),
            kensa_version=kensa_version,
            duration_ms=duration_ms,
            started_at=start_time.isoformat(),
            completed_at=end_time.isoformat(),
        )

    except HTTPException:
        raise
    except ImportError as e:
        logger.error("Kensa package not available: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Kensa compliance engine not available. Check installation.",
        )
    except Exception as e:
        logger.exception("Kensa scan failed: %s", e)

        # Update scan status to failed
        try:
            update_builder = (
                UpdateBuilder("scans")
                .set("status", "failed")
                .set("error_message", str(e)[:500])
                .set("completed_at", datetime.now(timezone.utc))
                .where("id = :id", scan_id, "id")
            )
            update_query, update_params = update_builder.build()
            db.execute(text(update_query), update_params)
            db.commit()
        except Exception:
            pass

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan execution failed: {str(e)}",
        )


@router.get("/frameworks", response_model=KensaFrameworksResponse)
async def list_kensa_frameworks(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> KensaFrameworksResponse:
    """
    List available Kensa compliance frameworks.

    Returns framework information including coverage statistics.
    """
    frameworks = [
        KensaFramework(
            id="cis-rhel9-v2.0.0",
            title="CIS RHEL 9 v2.0.0",
            description="Center for Internet Security Benchmark for RHEL 9",
            coverage_percent=95.1,
            controls_implemented=271,
            controls_total=285,
        ),
        KensaFramework(
            id="stig-rhel9-v2r7",
            title="STIG RHEL 9 V2R7",
            description="DISA Security Technical Implementation Guide for RHEL 9",
            coverage_percent=75.8,
            controls_implemented=338,
            controls_total=446,
        ),
        KensaFramework(
            id="nist-800-53",
            title="NIST 800-53",
            description="NIST Special Publication 800-53 Security Controls",
            coverage_percent=100.0,
            controls_implemented=338,
            controls_total=338,
        ),
    ]

    return KensaFrameworksResponse(frameworks=frameworks)


@router.get("/health")
async def kensa_health(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Check Kensa engine health and availability.

    Returns version information and rule count.
    """
    try:
        from runner.paths import get_rules_path, get_version

        kensa_version = get_version()
        rules_path = Path(get_rules_path())

        rule_count = len(list(rules_path.rglob("*.yml"))) if rules_path.exists() else 0

        return {
            "status": "healthy",
            "kensa_version": kensa_version,
            "rules_path": str(rules_path),
            "rules_available": rule_count,
            "frameworks_supported": ["cis-rhel9-v2.0.0", "stig-rhel9-v2r7", "nist-800-53"],
        }

    except ImportError as e:
        return {
            "status": "unavailable",
            "error": f"Kensa package not installed: {e}",
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
        }


# =============================================================================
# FRAMEWORK MAPPING ENDPOINTS
# =============================================================================


class FrameworkMappingRule(BaseModel):
    """Rule with framework mapping information."""

    rule_id: str
    title: str
    description: Optional[str] = None
    severity: str
    category: str
    tags: Optional[Any] = None
    control_id: str
    framework_version: Optional[str] = None
    cis_section: Optional[str] = None
    cis_level: Optional[str] = None
    stig_id: Optional[str] = None
    vuln_id: Optional[str] = None
    control_severity: Optional[str] = None


class FrameworkRulesResponse(BaseModel):
    """Response for framework rules list."""

    framework: str
    version: Optional[str] = None
    rules: List[FrameworkMappingRule]
    total_rules: int


class FrameworkCoverageResponse(BaseModel):
    """Response for framework coverage statistics."""

    framework: str
    version: Optional[str] = None
    framework_name: str
    total_controls: int
    total_rules: int
    severity_breakdown: Dict[str, int]
    category_breakdown: Dict[str, int]


class FrameworkRefResponse(BaseModel):
    """Framework references for a rule."""

    rule_id: str
    cis: Dict[str, Any]
    stig: Dict[str, Any]
    nist_800_53: List[str]
    pci_dss: List[str]
    srg: List[str]


class FrameworkListItem(BaseModel):
    """Framework summary item."""

    framework: str
    version: Optional[str] = None
    name: str
    controls: int
    rules: int


class FrameworkListResponse(BaseModel):
    """Response for list of frameworks."""

    frameworks: List[FrameworkListItem]


class ControlSearchResult(BaseModel):
    """Control search result item."""

    framework: str
    framework_version: Optional[str] = None
    control_id: str
    stig_id: Optional[str] = None
    cis_section: Optional[str] = None
    rule_id: str
    rule_title: str


class ControlSearchResponse(BaseModel):
    """Response for control search."""

    results: List[ControlSearchResult]
    total: int


class ControlRulesResponse(BaseModel):
    """Response for rules implementing a control."""

    framework: str
    control_id: str
    version: Optional[str] = None
    rules: List[Dict[str, Any]]


@router.get("/frameworks/db", response_model=FrameworkListResponse)
async def list_frameworks_from_db(
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> FrameworkListResponse:
    """
    List all compliance frameworks from the database.

    Returns framework information with rule counts from synced Kensa rules.
    This queries the PostgreSQL framework_mappings table.
    """
    try:
        from app.plugins.kensa import FrameworkMapper

        mapper = FrameworkMapper(db)
        frameworks = await mapper.list_frameworks()

        return FrameworkListResponse(
            frameworks=[
                FrameworkListItem(
                    framework=f["framework"],
                    version=f.get("version"),
                    name=f.get("name", f["framework"].upper()),
                    controls=f.get("controls", 0),
                    rules=f.get("rules", 0),
                )
                for f in frameworks
            ]
        )

    except Exception as e:
        logger.exception("Failed to list frameworks: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list frameworks: {str(e)}",
        )


@router.get("/rules/framework/{framework}", response_model=FrameworkRulesResponse)
async def get_rules_for_framework(
    framework: str,
    version: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> FrameworkRulesResponse:
    """
    Get all Kensa rules mapped to a compliance framework.

    Args:
        framework: Framework name (cis, stig, nist_800_53, pci_dss).
        version: Optional framework version (rhel9_v2, v2r7).
        severity: Optional severity filter (high, medium, low).
        category: Optional category filter.

    Returns:
        List of rules with their framework mappings.
    """
    try:
        from app.plugins.kensa import FrameworkMapper

        mapper = FrameworkMapper(db)
        rules = await mapper.get_rules_for_framework(
            framework=framework,
            version=version,
            severity=severity,
            category=category,
        )

        return FrameworkRulesResponse(
            framework=framework,
            version=version,
            rules=[
                FrameworkMappingRule(
                    rule_id=r["rule_id"],
                    title=r["title"],
                    description=r.get("description"),
                    severity=r["severity"],
                    category=r["category"],
                    tags=r.get("tags"),
                    control_id=r["control_id"],
                    framework_version=r.get("framework_version"),
                    cis_section=r.get("cis_section"),
                    cis_level=r.get("cis_level"),
                    stig_id=r.get("stig_id"),
                    vuln_id=r.get("vuln_id"),
                    control_severity=r.get("control_severity"),
                )
                for r in rules
            ],
            total_rules=len(rules),
        )

    except Exception as e:
        logger.exception("Failed to get rules for framework %s: %s", framework, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get rules for framework: {str(e)}",
        )


@router.get("/framework/{framework}/coverage", response_model=FrameworkCoverageResponse)
async def get_framework_coverage(
    framework: str,
    version: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> FrameworkCoverageResponse:
    """
    Get coverage statistics for a compliance framework.

    Returns total controls mapped, rules implementing them, and breakdowns
    by severity and category.

    Args:
        framework: Framework name (cis, stig, nist_800_53).
        version: Optional framework version.

    Returns:
        Coverage statistics for the framework.
    """
    try:
        from app.plugins.kensa import FrameworkMapper

        mapper = FrameworkMapper(db)
        coverage = await mapper.get_framework_coverage(
            framework=framework,
            version=version,
        )

        return FrameworkCoverageResponse(
            framework=coverage["framework"],
            version=coverage.get("version"),
            framework_name=coverage.get("framework_name", framework.upper()),
            total_controls=coverage.get("total_controls", 0),
            total_rules=coverage.get("total_rules", 0),
            severity_breakdown=coverage.get("severity_breakdown", {}),
            category_breakdown=coverage.get("category_breakdown", {}),
        )

    except Exception as e:
        logger.exception("Failed to get framework coverage for %s: %s", framework, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get framework coverage: {str(e)}",
        )


@router.get("/rules/{rule_id}/framework-refs", response_model=FrameworkRefResponse)
async def get_rule_framework_refs(
    rule_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> FrameworkRefResponse:
    """
    Get all framework references for a specific Kensa rule.

    Returns mappings to CIS, STIG, NIST 800-53, PCI-DSS, and SRG.

    Args:
        rule_id: Kensa rule ID.

    Returns:
        Framework references for the rule.
    """
    try:
        from app.plugins.kensa import FrameworkMapper

        mapper = FrameworkMapper(db)
        refs = await mapper.get_rule_framework_refs(rule_id)

        return FrameworkRefResponse(
            rule_id=rule_id,
            cis=refs.get("cis", {}),
            stig=refs.get("stig", {}),
            nist_800_53=refs.get("nist_800_53", []),
            pci_dss=refs.get("pci_dss", []),
            srg=refs.get("srg", []),
        )

    except Exception as e:
        logger.exception("Failed to get framework refs for rule %s: %s", rule_id, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get framework references: {str(e)}",
        )


@router.get("/controls/search", response_model=ControlSearchResponse)
async def search_controls(
    q: str,
    framework: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> ControlSearchResponse:
    """
    Search for controls by ID or description across frameworks.

    Args:
        q: Search term (partial match on control ID, STIG ID, CIS section, or rule title).
        framework: Optional framework filter.

    Returns:
        Matching controls with their rules.
    """
    if len(q) < 2:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Search term must be at least 2 characters",
        )

    try:
        from app.plugins.kensa import FrameworkMapper

        mapper = FrameworkMapper(db)
        results = await mapper.search_controls(
            search_term=q,
            framework=framework,
        )

        return ControlSearchResponse(
            results=[
                ControlSearchResult(
                    framework=r["framework"],
                    framework_version=r.get("framework_version"),
                    control_id=r["control_id"],
                    stig_id=r.get("stig_id"),
                    cis_section=r.get("cis_section"),
                    rule_id=r["rule_id"],
                    rule_title=r["rule_title"],
                )
                for r in results
            ],
            total=len(results),
        )

    except Exception as e:
        logger.exception("Failed to search controls: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to search controls: {str(e)}",
        )


@router.get("/controls/{framework}/{control_id}", response_model=ControlRulesResponse)
async def get_control_rules(
    framework: str,
    control_id: str,
    version: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> ControlRulesResponse:
    """
    Get all Kensa rules that implement a specific control.

    Args:
        framework: Framework name (cis, stig, nist_800_53).
        control_id: Control ID to look up.
        version: Optional framework version.

    Returns:
        List of rules implementing the control.
    """
    try:
        from app.plugins.kensa import FrameworkMapper

        mapper = FrameworkMapper(db)
        rules = await mapper.get_control_rules(
            framework=framework,
            control_id=control_id,
            version=version,
        )

        return ControlRulesResponse(
            framework=framework,
            control_id=control_id,
            version=version,
            rules=rules,
        )

    except Exception as e:
        logger.exception("Failed to get rules for control %s/%s: %s", framework, control_id, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get rules for control: {str(e)}",
        )


@router.get("/sync-stats")
async def get_sync_stats(
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get current Kensa rule sync statistics.

    Returns counts of synced rules and framework mappings.
    """
    try:
        from app.plugins.kensa import KensaRuleSyncService

        sync_service = KensaRuleSyncService(db)
        return sync_service.get_sync_stats()

    except Exception as e:
        logger.exception("Failed to get sync stats: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get sync statistics: {str(e)}",
        )


@router.post("/sync")
async def trigger_rule_sync(
    force: bool = False,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Manually trigger Kensa rule sync to PostgreSQL.

    This reloads all YAML rules from kensa rules/ and upserts them to the
    kensa_rules and framework_mappings tables.

    Args:
        force: If True, sync all rules regardless of hash changes.

    Returns:
        Sync statistics including rules synced and mappings created.
    """
    try:
        from app.plugins.kensa import KensaRuleSyncService

        sync_service = KensaRuleSyncService(db)
        result = sync_service.sync_all_rules(force=force)

        logger.info(
            "Manual Kensa rule sync triggered by user %s: %d rules, %d mappings",
            current_user.get("id"),
            result.get("rules_synced", 0),
            result.get("mappings_created", 0),
        )

        return result

    except Exception as e:
        logger.exception("Failed to sync rules: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to sync rules: {str(e)}",
        )


# =============================================================================
# COMPLIANCE STATE ENDPOINTS
# =============================================================================


@router.get("/compliance-state/{host_id}", response_model=ComplianceStateResponse)
async def get_compliance_state(
    host_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> ComplianceStateResponse:
    """
    Get the current compliance state for a host.

    Returns all rule findings from the most recent completed Kensa scan,
    providing a complete view of the host's compliance posture.

    Args:
        host_id: UUID of the target host.
        db: SQLAlchemy database session.
        current_user: Authenticated user from JWT token.

    Returns:
        ComplianceStateResponse with all findings and summary stats.

    Raises:
        HTTPException 404: Host not found.
    """
    # Verify host exists and get hostname
    host_query = text("SELECT id, hostname, display_name FROM hosts WHERE id = :id")
    host_result = db.execute(host_query, {"id": host_id}).fetchone()

    if not host_result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Host not found: {host_id}",
        )

    hostname = host_result.display_name or host_result.hostname

    # Find the latest completed Kensa scan for this host
    latest_scan_query = text(
        """
        SELECT id, name, completed_at
        FROM scans
        WHERE host_id = :host_id
          AND status = 'completed'
          AND profile_id LIKE 'kensa_%'
        ORDER BY completed_at DESC
        LIMIT 1
    """
    )
    scan_result = db.execute(latest_scan_query, {"host_id": host_id}).fetchone()

    if not scan_result:
        # No Kensa scans yet - return empty state
        return ComplianceStateResponse(
            host_id=host_id,
            hostname=hostname,
            scan_id=None,
            scan_date=None,
            total_rules=0,
            passed=0,
            failed=0,
            unknown=0,
            compliance_score=0.0,
            findings=[],
            severity_summary={
                "critical": {"passed": 0, "failed": 0},
                "high": {"passed": 0, "failed": 0},
                "medium": {"passed": 0, "failed": 0},
                "low": {"passed": 0, "failed": 0},
            },
        )

    scan_id = str(scan_result.id)
    scan_date = scan_result.completed_at.isoformat() if scan_result.completed_at else None

    # Get all findings for this scan
    findings_query = text(
        """
        SELECT rule_id, title, severity, status, detail, framework_section,
               evidence, framework_refs, skip_reason
        FROM scan_findings
        WHERE scan_id = :scan_id
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            status DESC,
            rule_id ASC
    """
    )
    findings_result = db.execute(findings_query, {"scan_id": scan_id}).fetchall()

    # Build findings list and calculate summaries
    findings = []
    passed = 0
    failed = 0
    unknown = 0
    severity_summary = {
        "critical": {"passed": 0, "failed": 0},
        "high": {"passed": 0, "failed": 0},
        "medium": {"passed": 0, "failed": 0},
        "low": {"passed": 0, "failed": 0},
    }

    for row in findings_result:
        finding = ComplianceFinding(
            rule_id=row.rule_id,
            title=row.title,
            severity=row.severity,
            status=row.status,
            detail=row.detail,
            framework_section=row.framework_section,
            evidence=getattr(row, "evidence", None),
            framework_refs=getattr(row, "framework_refs", None),
            skip_reason=getattr(row, "skip_reason", None),
        )
        findings.append(finding)

        # Count by status
        if row.status == "pass":
            passed += 1
        elif row.status == "fail":
            failed += 1
        else:
            unknown += 1

        # Count by severity (only for pass/fail, not skipped)
        if row.status in ("pass", "fail"):
            sev = row.severity.lower() if row.severity else "medium"
            if sev in severity_summary:
                if row.status == "pass":
                    severity_summary[sev]["passed"] += 1
                else:
                    severity_summary[sev]["failed"] += 1

    total_rules = len(findings)
    evaluable = passed + failed
    compliance_score = (passed / evaluable * 100) if evaluable > 0 else 0.0

    return ComplianceStateResponse(
        host_id=host_id,
        hostname=hostname,
        scan_id=scan_id,
        scan_date=scan_date,
        total_rules=total_rules,
        passed=passed,
        failed=failed,
        unknown=unknown,
        compliance_score=round(compliance_score, 2),
        findings=findings,
        severity_summary=severity_summary,
    )
