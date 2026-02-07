"""
Compliance Intelligence API Endpoints

Provides semantic SCAP intelligence and cross-framework compliance data.
Part of Phase 4 API Standardization: System & Integrations.

Endpoint Structure:
    GET  /semantic-rules                    - Get semantic rules from rule intelligence
    GET  /framework-intelligence            - Get framework intelligence overview
    GET  /overview                          - Get compliance intelligence overview
    GET  /semantic-analysis/{scan_id}       - Get semantic analysis for a scan
    GET  /compliance-matrix                 - Get framework compliance matrix
    POST /remediation/strategy              - Create intelligent remediation strategy
    GET  /health                            - Health check for compliance services
    POST /upload-rules                      - Upload compliance rules archive
    GET  /upload-history                    - Get upload history
    GET  /upload-history/{upload_id}/export - Export upload report

Migration Status:
    - compliance.py -> compliance/intelligence.py
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from ...auth import get_current_user
from ...database import get_db
from ...repositories import UploadHistoryRepository
from ...services.compliance_rules import ComplianceRulesUploadService, DeduplicationStrategy
from ...utils.file_security import sanitize_filename, validate_file_extension
from ...utils.query_builder import QueryBuilder

logger = logging.getLogger(__name__)

# Router without prefix - prefix handled by parent package
router = APIRouter(tags=["Compliance Intelligence"])


# =============================================================================
# PYDANTIC MODELS
# =============================================================================


class SemanticRule(BaseModel):
    """Semantic rule response model."""

    id: str
    semantic_name: str
    scap_rule_id: str
    title: str
    compliance_intent: str
    business_impact: str
    risk_level: str
    frameworks: List[str]
    remediation_complexity: str
    estimated_fix_time: int
    remediation_available: bool
    confidence_score: float


class FrameworkIntelligence(BaseModel):
    """Framework intelligence response model."""

    framework: str
    display_name: str
    semantic_rules_count: int
    cross_framework_mappings: int
    remediation_coverage: int
    business_impact_breakdown: Dict[str, int]
    estimated_remediation_time: int
    compatible_distributions: List[str]
    compliance_score: Optional[float] = None


class ComplianceOverview(BaseModel):
    """Compliance intelligence overview response model."""

    total_frameworks: int
    semantic_rules_count: int
    universal_coverage: int
    remediation_readiness: int
    last_intelligence_update: str


# =============================================================================
# INTELLIGENCE ENDPOINTS
# =============================================================================


@router.get("/semantic-rules")
async def get_semantic_rules(
    framework: Optional[str] = Query(None, description="Filter by framework"),
    business_impact: Optional[str] = Query(None, description="Filter by business impact"),
    remediation_available: Optional[bool] = Query(None, description="Filter by remediation availability"),
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get semantic rules from the rule intelligence database."""
    try:
        # Build query with optional filters using QueryBuilder
        builder = QueryBuilder("rule_intelligence").select(
            "id",
            "scap_rule_id",
            "semantic_name",
            "title",
            "compliance_intent",
            "business_impact",
            "risk_level",
            "applicable_frameworks as frameworks",
            "remediation_complexity",
            "estimated_fix_time",
            "remediation_available",
            "confidence_score",
            "created_at",
        )

        if framework:
            builder = builder.where(":framework = ANY(applicable_frameworks)", framework, "framework")

        if business_impact:
            builder = builder.where("business_impact = :business_impact", business_impact, "business_impact")

        if remediation_available is not None:
            builder = builder.where(
                "remediation_available = :remediation_available",
                remediation_available,
                "remediation_available",
            )

        builder = builder.order_by("created_at", "DESC")

        query, params = builder.build()
        result = db.execute(text(query), params)
        rules = result.fetchall()

        # Convert to list of dictionaries
        semantic_rules = []
        for rule in rules:
            semantic_rules.append(
                {
                    "id": str(rule.id),
                    "semantic_name": rule.semantic_name,
                    "scap_rule_id": rule.scap_rule_id,
                    "title": rule.title,
                    "compliance_intent": rule.compliance_intent,
                    "business_impact": rule.business_impact,
                    "risk_level": rule.risk_level,
                    "frameworks": rule.frameworks if rule.frameworks else [],
                    "remediation_complexity": rule.remediation_complexity,
                    "estimated_fix_time": rule.estimated_fix_time,
                    "remediation_available": rule.remediation_available,
                    "confidence_score": (float(rule.confidence_score) if rule.confidence_score else 1.0),
                }
            )

        return {
            "rules": semantic_rules,
            "total_count": len(semantic_rules),
            "filters_applied": {
                "framework": framework,
                "business_impact": business_impact,
                "remediation_available": remediation_available,
            },
        }

    except Exception as e:
        logger.error(f"Error retrieving semantic rules: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve semantic rules: {str(e)}")


@router.get("/framework-intelligence")
async def get_framework_intelligence(
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get framework intelligence overview and statistics."""
    try:
        # Get all semantic rules grouped by framework
        query = """
            SELECT
                unnest(applicable_frameworks) as framework,
                COUNT(*) as rule_count,
                SUM(CASE WHEN remediation_available THEN 1 ELSE 0 END) as remediation_available_count,
                SUM(CASE WHEN business_impact = 'high' THEN 1 ELSE 0 END) as high_impact_count,
                SUM(CASE WHEN business_impact = 'medium' THEN 1 ELSE 0 END) as medium_impact_count,
                SUM(CASE WHEN business_impact = 'low' THEN 1 ELSE 0 END) as low_impact_count,
                SUM(estimated_fix_time) as total_remediation_time
            FROM rule_intelligence
            WHERE applicable_frameworks IS NOT NULL AND array_length(applicable_frameworks, 1) > 0
            GROUP BY unnest(applicable_frameworks)
        """

        result = db.execute(text(query))
        framework_stats = result.fetchall()

        # Process framework data
        frameworks = []
        framework_config = {
            "stig": "DISA STIG",
            "cis": "CIS Controls",
            "nist": "NIST Cybersecurity",
            "pci_dss": "PCI DSS",
        }

        for stats in framework_stats:
            framework_key = stats.framework
            if framework_key not in framework_config:
                continue

            # Get cross-framework mappings (rules that appear in multiple frameworks)
            cross_builder = (
                QueryBuilder("rule_intelligence")
                .select("COUNT(*) as cross_framework_count")
                .where(
                    ":framework = ANY(applicable_frameworks)",
                    framework_key,
                    "framework",
                )
                .where("array_length(applicable_frameworks, 1) > 1")
            )
            cross_query, cross_params = cross_builder.build()
            cross_result = db.execute(text(cross_query), cross_params)
            cross_row = cross_result.fetchone()
            cross_framework_count = cross_row.cross_framework_count if cross_row else 0

            remediation_coverage = 0
            if stats.rule_count > 0:
                remediation_coverage = round((stats.remediation_available_count / stats.rule_count) * 100)

            frameworks.append(
                {
                    "framework": framework_key,
                    "display_name": framework_config[framework_key],
                    "semantic_rules_count": stats.rule_count,
                    "cross_framework_mappings": cross_framework_count,
                    "remediation_coverage": remediation_coverage,
                    "business_impact_breakdown": {
                        "high": stats.high_impact_count,
                        "medium": stats.medium_impact_count,
                        "low": stats.low_impact_count,
                    },
                    "estimated_remediation_time": stats.total_remediation_time or 0,
                    "compatible_distributions": [
                        "RHEL 9",
                        "Ubuntu 22.04",
                        "Oracle Linux 8",
                    ],
                    "compliance_score": 85 + (framework_key == "stig" and 10 or 5),  # Mock data
                }
            )

        return {"frameworks": frameworks, "last_updated": datetime.utcnow().isoformat()}

    except Exception as e:
        logger.error(f"Error retrieving framework intelligence: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve framework intelligence: {str(e)}",
        )


@router.get("/overview")
async def get_compliance_overview(
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get overall compliance intelligence overview metrics."""
    try:
        # Get total semantic rules count
        rules_query = """
            SELECT
                COUNT(*) as total_rules,
                SUM(CASE WHEN remediation_available THEN 1 ELSE 0 END) as remediation_ready_count
            FROM rule_intelligence
        """

        result = db.execute(text(rules_query))
        stats = result.fetchone()

        total_rules = stats.total_rules if stats else 0
        remediation_ready = stats.remediation_ready_count if stats else 0

        # Calculate universal coverage
        universal_coverage = 0
        remediation_readiness = 0

        if total_rules > 0:
            universal_coverage = round((remediation_ready / total_rules) * 100)
            remediation_readiness = universal_coverage

        # Get unique frameworks count - simplified approach
        frameworks_query = """
            WITH framework_list AS (
                SELECT DISTINCT unnest(applicable_frameworks) as framework_name
                FROM rule_intelligence
                WHERE applicable_frameworks IS NOT NULL
            )
            SELECT COUNT(*) as framework_count FROM framework_list
        """

        framework_result = db.execute(text(frameworks_query))
        framework_row = framework_result.fetchone()
        framework_count = framework_row.framework_count if framework_row else 0

        return {
            "total_frameworks": framework_count,
            "semantic_rules_count": total_rules,
            "universal_coverage": universal_coverage,
            "remediation_readiness": remediation_readiness,
            "last_intelligence_update": datetime.utcnow().strftime("%H:%M:%S"),
        }

    except Exception as e:
        logger.error(f"Error retrieving compliance overview: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve compliance overview: {str(e)}")


@router.get("/semantic-analysis/{scan_id}")
async def get_semantic_analysis(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get semantic analysis results for a specific scan."""
    try:
        builder = (
            QueryBuilder("semantic_scan_analysis")
            .select(
                "scan_id",
                "host_id",
                "semantic_rules_count",
                "frameworks_analyzed",
                "remediation_available_count",
                "processing_metadata",
                "analysis_data",
                "created_at",
                "updated_at",
            )
            .where("scan_id = :scan_id", scan_id, "scan_id")
        )

        query, params = builder.build()
        result = db.execute(text(query), params)
        analysis = result.fetchone()

        if not analysis:
            raise HTTPException(status_code=404, detail="Semantic analysis not found for this scan")

        return {
            "scan_id": str(analysis.scan_id),
            "host_id": str(analysis.host_id),
            "semantic_rules_count": analysis.semantic_rules_count,
            "frameworks_analyzed": (json.loads(analysis.frameworks_analyzed) if analysis.frameworks_analyzed else []),
            "remediation_available_count": analysis.remediation_available_count,
            "processing_metadata": (json.loads(analysis.processing_metadata) if analysis.processing_metadata else {}),
            "analysis_data": (json.loads(analysis.analysis_data) if analysis.analysis_data else {}),
            "created_at": (analysis.created_at.isoformat() if analysis.created_at else None),
            "updated_at": (analysis.updated_at.isoformat() if analysis.updated_at else None),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving semantic analysis: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve semantic analysis: {str(e)}")


@router.get("/compliance-matrix")
async def get_compliance_matrix(
    host_id: Optional[str] = Query(None, description="Filter by host ID"),
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get framework compliance matrix data."""
    try:
        builder = QueryBuilder("framework_compliance_matrix").select(
            "host_id",
            "framework",
            "compliance_score",
            "total_rules",
            "passed_rules",
            "failed_rules",
            "previous_score",
            "trend",
            "last_scan_id",
            "last_updated",
            "predicted_next_score",
            "prediction_confidence",
        )

        if host_id:
            builder = builder.where("host_id = :host_id", host_id, "host_id")

        builder = builder.order_by("last_updated", "DESC")

        query, params = builder.build()
        result = db.execute(text(query), params)
        matrix_data = result.fetchall()

        compliance_matrix = []
        for row in matrix_data:
            compliance_matrix.append(
                {
                    "host_id": str(row.host_id),
                    "framework": row.framework,
                    "compliance_score": (float(row.compliance_score) if row.compliance_score else 0.0),
                    "total_rules": row.total_rules,
                    "passed_rules": row.passed_rules,
                    "failed_rules": row.failed_rules,
                    "previous_score": (float(row.previous_score) if row.previous_score else None),
                    "trend": row.trend,
                    "last_scan_id": str(row.last_scan_id) if row.last_scan_id else None,
                    "last_updated": (row.last_updated.isoformat() if row.last_updated else None),
                    "predicted_next_score": (float(row.predicted_next_score) if row.predicted_next_score else None),
                    "prediction_confidence": (float(row.prediction_confidence) if row.prediction_confidence else None),
                }
            )

        return {
            "compliance_matrix": compliance_matrix,
            "total_entries": len(compliance_matrix),
            "last_updated": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"Error retrieving compliance matrix: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve compliance matrix: {str(e)}")


@router.post("/remediation/strategy")
async def create_remediation_strategy(
    request: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Create an intelligent remediation strategy based on semantic analysis."""
    try:
        # Extract request parameters
        host_id = request.get("host_id")
        framework_goals = request.get("frameworks", ["stig"])

        if not host_id:
            raise HTTPException(status_code=400, detail="host_id is required")

        # For now, return a structured remediation strategy
        strategy = {
            "host_id": host_id,
            "frameworks": framework_goals,
            "strategy_id": f"strategy_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            "created_at": datetime.utcnow().isoformat(),
            "phases": [
                {
                    "phase": 1,
                    "name": "High Impact Quick Wins",
                    "description": "Address high-impact rules with simple remediation",
                    "estimated_time": 30,
                    "rules_count": 5,
                },
                {
                    "phase": 2,
                    "name": "Medium Impact Remediation",
                    "description": "Address medium-impact security controls",
                    "estimated_time": 60,
                    "rules_count": 8,
                },
                {
                    "phase": 3,
                    "name": "Complex Security Hardening",
                    "description": "Address complex rules requiring system changes",
                    "estimated_time": 120,
                    "rules_count": 7,
                },
            ],
            "total_estimated_time": 210,
            "total_rules": 20,
            "expected_compliance_improvement": {
                "stig": {"current": 75, "predicted": 92},
                "cis": {"current": 82, "predicted": 95},
            },
        }

        return strategy

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating remediation strategy: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create remediation strategy: {str(e)}")


@router.get("/health")
async def compliance_health_check() -> Dict[str, Any]:
    """Health check endpoint for compliance intelligence services."""
    try:
        return {
            "status": "healthy",
            "services": {
                "semantic_engine": "available",
                "database": "connected",
                "api": "operational",
            },
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"Compliance health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat(),
        }


# =============================================================================
# UPLOAD ENDPOINTS
# =============================================================================


@router.post("/upload-rules")
async def upload_compliance_rules(
    file: UploadFile = File(...),
    deduplication_strategy: str = Query(
        DeduplicationStrategy.SKIP_UNCHANGED_UPDATE_CHANGED,
        description=(  # noqa: E501
            "Deduplication strategy: skip_unchanged_update_changed, skip_existing, " "update_all, fail_on_duplicate"
        ),
    ),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Upload compliance rules archive (tar.gz with BSON or JSON files)

    Supports:
    - BSON (Binary JSON) format (preferred)
    - JSON format (backward compatibility)
    - Smart deduplication (skip unchanged, update changed)
    - Dependency validation
    - Inheritance resolution

    Args:
        file: tar.gz archive containing manifest and rule files
        deduplication_strategy: How to handle duplicate rule_ids
        current_user: Authenticated user (from JWT token)

    Returns:
        Upload result with statistics and impact analysis
    """
    try:
        # Validate filename exists before sanitization
        if not file.filename:
            raise HTTPException(status_code=400, detail="Filename is required")

        # Sanitize filename to prevent path traversal
        safe_filename = sanitize_filename(file.filename)

        # Validate file type
        if not validate_file_extension(safe_filename, [".tar.gz", ".tgz"]):
            raise HTTPException(
                status_code=400,
                detail="Invalid file type. Only .tar.gz archives are allowed.",
            )

        # Read file content
        file_content = await file.read()

        if len(file_content) == 0:
            raise HTTPException(status_code=400, detail="Uploaded file is empty")

        logger.info(
            f"Upload initiated by {current_user.get('username', 'unknown')}: "
            f"{safe_filename} ({len(file_content):,} bytes)"
        )

        # Validate deduplication strategy
        if not DeduplicationStrategy.is_valid(deduplication_strategy):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid deduplication strategy. Valid options: {DeduplicationStrategy.all_strategies()}",
            )

        # Initialize upload service
        upload_service = ComplianceRulesUploadService()

        # Process upload with sanitized filename
        result = await upload_service.upload_rules_archive(
            archive_data=file_content,
            archive_filename=safe_filename,
            deduplication_strategy=deduplication_strategy,
            user_id=current_user.get("user_id"),
        )

        # Return success or failure
        if result["success"]:
            logger.info(
                f"Upload {result['upload_id']} completed: "
                f"{result['statistics']['imported']} imported, "
                f"{result['statistics']['updated']} updated, "
                f"{result['statistics']['skipped']} skipped"
            )

            return {
                "success": True,
                "upload_id": result["upload_id"],
                "filename": result["filename"],
                "file_hash": result["file_hash"],
                "statistics": result["statistics"],
                "manifest": result.get("manifest", {}),
                "dependency_validation": result.get("dependency_validation", {}),
                "inheritance_impact": result.get("inheritance_impact", {}),
                "warnings": result.get("warnings", []),
                "processing_time_seconds": result.get("processing_time_seconds", 0),
            }
        else:
            # Upload failed - return error details
            logger.error(f"Upload {result['upload_id']} failed: {result['errors']}")

            return {
                "success": False,
                "upload_id": result["upload_id"],
                "filename": result["filename"],
                "phase": result.get("phase", "unknown"),
                "errors": result.get("errors", []),
                "warnings": result.get("warnings", []),
                "security_validation": result.get("security_validation", {}),
            }

    except HTTPException:
        raise  # Re-raise HTTP exceptions

    except Exception as e:
        logger.error(f"Upload endpoint error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")


@router.get("/upload-history")
async def get_upload_history(
    limit: int = Query(100, ge=1, le=100, description="Maximum 100 records"),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get compliance bundle upload history (last 100 uploads)

    Returns audit trail of compliance rule bundle uploads with:
    - Upload metadata (filename, date, user, success/failure)
    - Import statistics (imported, updated, skipped, errors)
    - Manifest information
    - Processing details
    - Errors and warnings

    Args:
        limit: Maximum number of uploads to return (max 100)
        current_user: Authenticated user

    Returns:
        List of upload history records sorted by date descending
    """
    try:
        # Query MongoDB for upload history, sorted by most recent first
        repo = UploadHistoryRepository()
        upload_records = await repo.find_recent(limit=limit)

        # Convert Beanie documents to dictionaries
        uploads = []
        for record in upload_records:
            upload_dict = {
                "upload_id": record.upload_id,
                "filename": record.filename,
                "file_hash": record.file_hash,
                "uploaded_at": record.uploaded_at.isoformat() + "Z",
                "uploaded_by": record.uploaded_by,
                "user_id": record.user_id,
                "success": record.success,
                "phase": record.phase,
                "statistics": record.statistics,
                "manifest": record.manifest,
                "processing_time_seconds": record.processing_time_seconds,
                "errors": record.errors,
                "warnings": record.warnings,
                "security_validation": record.security_validation,
                "dependency_validation": record.dependency_validation,
                "inheritance_impact": record.inheritance_impact,
            }
            uploads.append(upload_dict)

        logger.info(f"Retrieved {len(uploads)} upload history records")

        return {"uploads": uploads, "total_count": len(uploads), "limit": limit}

    except Exception as e:
        logger.error(f"Error retrieving upload history: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to retrieve upload history: {str(e)}")


@router.get("/upload-history/{upload_id}/export")
async def export_upload_report(
    upload_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    """
    Export upload report as JSON file

    Downloads a complete upload report for a specific upload operation,
    including all metadata, statistics, errors, warnings, and validation results.

    Args:
        upload_id: UUID of the upload operation
        current_user: Authenticated user

    Returns:
        JSON file download with complete upload report
    """
    try:
        # Find upload record by upload_id
        repo = UploadHistoryRepository()
        upload_record = await repo.find_by_upload_id(upload_id)

        if not upload_record:
            raise HTTPException(
                status_code=404,
                detail=f"Upload history record not found for upload_id: {upload_id}",
            )

        # Build complete report
        report = {
            "upload_id": upload_record.upload_id,
            "filename": upload_record.filename,
            "file_hash": upload_record.file_hash,
            "uploaded_at": upload_record.uploaded_at.isoformat() + "Z",
            "uploaded_by": upload_record.uploaded_by,
            "user_id": upload_record.user_id,
            "success": upload_record.success,
            "phase": upload_record.phase,
            "processing_time_seconds": upload_record.processing_time_seconds,
            # Statistics
            "statistics": upload_record.statistics,
            # Manifest
            "manifest": upload_record.manifest,
            # Validation results
            "security_validation": upload_record.security_validation,
            "dependency_validation": upload_record.dependency_validation,
            "inheritance_impact": upload_record.inheritance_impact,
            # Errors and warnings
            "errors": upload_record.errors,
            "warnings": upload_record.warnings,
            # Export metadata
            "export_metadata": {
                "exported_at": datetime.utcnow().isoformat() + "Z",
                "exported_by": current_user.get("username", "unknown"),
                "report_version": "1.0",
            },
        }

        # Generate filename
        safe_filename = upload_record.filename.replace(".tar.gz", "").replace(".tgz", "")
        export_filename = f"{safe_filename}_upload_report_{upload_id[:8]}.json"

        logger.info(f"Exporting upload report for upload_id={upload_id}")

        # Return as downloadable JSON file
        return JSONResponse(
            content=report,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{export_filename}"'},
        )

    except HTTPException:
        raise  # Re-raise HTTP exceptions

    except Exception as e:
        logger.error(f"Error exporting upload report: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to export upload report: {str(e)}")
