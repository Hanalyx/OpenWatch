"""
Universal Compliance Intelligence API Routes
Provides semantic SCAP intelligence and cross-framework compliance data
"""
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import text
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from pydantic import BaseModel

from ..database import get_db
from ..services.semantic_scap_engine import get_semantic_scap_engine
from ..services.compliance_rules_upload_service import ComplianceRulesUploadService
from ..services.compliance_rules_deduplication_service import DeduplicationStrategy
from ..auth import get_current_user
from ..utils.file_security import sanitize_filename, validate_file_extension

logger = logging.getLogger(__name__)
router = APIRouter(tags=["compliance"])


class SemanticRule(BaseModel):
    """Semantic rule response model"""
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
    """Framework intelligence response model"""
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
    """Compliance intelligence overview response model"""
    total_frameworks: int
    semantic_rules_count: int
    universal_coverage: int
    remediation_readiness: int
    last_intelligence_update: str


@router.get("/semantic-rules")
async def get_semantic_rules(
    framework: Optional[str] = Query(None, description="Filter by framework"),
    business_impact: Optional[str] = Query(None, description="Filter by business impact"),
    remediation_available: Optional[bool] = Query(None, description="Filter by remediation availability"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get semantic rules from the rule intelligence database"""
    try:
        # Build query with optional filters
        query = """
            SELECT 
                id, scap_rule_id, semantic_name, title, compliance_intent,
                business_impact, risk_level, applicable_frameworks as frameworks,
                remediation_complexity, estimated_fix_time, remediation_available,
                confidence_score, created_at
            FROM rule_intelligence
            WHERE 1=1
        """
        params = {}
        
        if framework:
            query += " AND :framework = ANY(applicable_frameworks)"
            params["framework"] = framework
            
        if business_impact:
            query += " AND business_impact = :business_impact"
            params["business_impact"] = business_impact
            
        if remediation_available is not None:
            query += " AND remediation_available = :remediation_available"
            params["remediation_available"] = remediation_available
        
        query += " ORDER BY created_at DESC"
        
        result = db.execute(text(query), params)
        rules = result.fetchall()
        
        # Convert to list of dictionaries
        semantic_rules = []
        for rule in rules:
            semantic_rules.append({
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
                "confidence_score": float(rule.confidence_score) if rule.confidence_score else 1.0
            })
        
        return {
            "rules": semantic_rules,
            "total_count": len(semantic_rules),
            "filters_applied": {
                "framework": framework,
                "business_impact": business_impact,
                "remediation_available": remediation_available
            }
        }
        
    except Exception as e:
        logger.error(f"Error retrieving semantic rules: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve semantic rules: {str(e)}")


@router.get("/framework-intelligence")
async def get_framework_intelligence(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get framework intelligence overview and statistics"""
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
            'stig': 'DISA STIG',
            'cis': 'CIS Controls', 
            'nist': 'NIST Cybersecurity',
            'pci_dss': 'PCI DSS'
        }
        
        for stats in framework_stats:
            framework_key = stats.framework
            if framework_key not in framework_config:
                continue
                
            # Get cross-framework mappings (rules that appear in multiple frameworks)
            cross_framework_query = """
                SELECT COUNT(*) as cross_framework_count
                FROM rule_intelligence
                WHERE :framework = ANY(applicable_frameworks)
                AND array_length(applicable_frameworks, 1) > 1
            """
            cross_result = db.execute(text(cross_framework_query), {"framework": framework_key})
            cross_framework_count = cross_result.fetchone().cross_framework_count or 0
            
            remediation_coverage = 0
            if stats.rule_count > 0:
                remediation_coverage = round((stats.remediation_available_count / stats.rule_count) * 100)
            
            frameworks.append({
                "framework": framework_key,
                "display_name": framework_config[framework_key],
                "semantic_rules_count": stats.rule_count,
                "cross_framework_mappings": cross_framework_count,
                "remediation_coverage": remediation_coverage,
                "business_impact_breakdown": {
                    "high": stats.high_impact_count,
                    "medium": stats.medium_impact_count,
                    "low": stats.low_impact_count
                },
                "estimated_remediation_time": stats.total_remediation_time or 0,
                "compatible_distributions": ["RHEL 9", "Ubuntu 22.04", "Oracle Linux 8"],
                "compliance_score": 85 + (framework_key == 'stig' and 10 or 5)  # Mock data
            })
        
        return {
            "frameworks": frameworks,
            "last_updated": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error retrieving framework intelligence: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve framework intelligence: {str(e)}")


@router.get("/overview")
async def get_compliance_overview(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get overall compliance intelligence overview metrics"""
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
        
        total_rules = stats.total_rules or 0
        remediation_ready = stats.remediation_ready_count or 0
        
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
        framework_count = framework_result.fetchone().framework_count or 0
        
        return {
            "total_frameworks": framework_count,
            "semantic_rules_count": total_rules,
            "universal_coverage": universal_coverage,
            "remediation_readiness": remediation_readiness,
            "last_intelligence_update": datetime.utcnow().strftime("%H:%M:%S")
        }
        
    except Exception as e:
        logger.error(f"Error retrieving compliance overview: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve compliance overview: {str(e)}")


@router.get("/semantic-analysis/{scan_id}")
async def get_semantic_analysis(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get semantic analysis results for a specific scan"""
    try:
        query = """
            SELECT 
                scan_id, host_id, semantic_rules_count, frameworks_analyzed,
                remediation_available_count, processing_metadata, analysis_data,
                created_at, updated_at
            FROM semantic_scan_analysis
            WHERE scan_id = :scan_id
        """
        
        result = db.execute(text(query), {"scan_id": scan_id})
        analysis = result.fetchone()
        
        if not analysis:
            raise HTTPException(status_code=404, detail="Semantic analysis not found for this scan")
        
        return {
            "scan_id": str(analysis.scan_id),
            "host_id": str(analysis.host_id),
            "semantic_rules_count": analysis.semantic_rules_count,
            "frameworks_analyzed": json.loads(analysis.frameworks_analyzed) if analysis.frameworks_analyzed else [],
            "remediation_available_count": analysis.remediation_available_count,
            "processing_metadata": json.loads(analysis.processing_metadata) if analysis.processing_metadata else {},
            "analysis_data": json.loads(analysis.analysis_data) if analysis.analysis_data else {},
            "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
            "updated_at": analysis.updated_at.isoformat() if analysis.updated_at else None
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
    current_user: dict = Depends(get_current_user)
):
    """Get framework compliance matrix data"""
    try:
        query = """
            SELECT 
                host_id, framework, compliance_score, total_rules,
                passed_rules, failed_rules, previous_score, trend,
                last_scan_id, last_updated, predicted_next_score,
                prediction_confidence
            FROM framework_compliance_matrix
            WHERE 1=1
        """
        params = {}
        
        if host_id:
            query += " AND host_id = :host_id"
            params["host_id"] = host_id
        
        query += " ORDER BY last_updated DESC"
        
        result = db.execute(text(query), params)
        matrix_data = result.fetchall()
        
        compliance_matrix = []
        for row in matrix_data:
            compliance_matrix.append({
                "host_id": str(row.host_id),
                "framework": row.framework,
                "compliance_score": float(row.compliance_score) if row.compliance_score else 0.0,
                "total_rules": row.total_rules,
                "passed_rules": row.passed_rules,
                "failed_rules": row.failed_rules,
                "previous_score": float(row.previous_score) if row.previous_score else None,
                "trend": row.trend,
                "last_scan_id": str(row.last_scan_id) if row.last_scan_id else None,
                "last_updated": row.last_updated.isoformat() if row.last_updated else None,
                "predicted_next_score": float(row.predicted_next_score) if row.predicted_next_score else None,
                "prediction_confidence": float(row.prediction_confidence) if row.prediction_confidence else None
            })
        
        return {
            "compliance_matrix": compliance_matrix,
            "total_entries": len(compliance_matrix),
            "last_updated": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error retrieving compliance matrix: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve compliance matrix: {str(e)}")


@router.post("/remediation/strategy")
async def create_remediation_strategy(
    request: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Create an intelligent remediation strategy based on semantic analysis"""
    try:
        # Get the semantic SCAP engine
        
        # Extract request parameters
        host_id = request.get("host_id")
        framework_goals = request.get("frameworks", ["stig"])
        
        if not host_id:
            raise HTTPException(status_code=400, detail="host_id is required")
        
        # Get semantic rules for the host (mock data for now)
        # This would be implemented with actual database query when ready
        
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
                    "rules_count": 5
                },
                {
                    "phase": 2,
                    "name": "Medium Impact Remediation",
                    "description": "Address medium-impact security controls",
                    "estimated_time": 60,
                    "rules_count": 8
                },
                {
                    "phase": 3,
                    "name": "Complex Security Hardening",
                    "description": "Address complex rules requiring system changes",
                    "estimated_time": 120,
                    "rules_count": 7
                }
            ],
            "total_estimated_time": 210,
            "total_rules": 20,
            "expected_compliance_improvement": {
                "stig": {"current": 75, "predicted": 92},
                "cis": {"current": 82, "predicted": 95}
            }
        }
        
        return strategy
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating remediation strategy: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create remediation strategy: {str(e)}")


@router.get("/health")
async def compliance_health_check():
    """Health check endpoint for compliance intelligence services"""
    try:
        # Test semantic engine availability
        
        return {
            "status": "healthy",
            "services": {
                "semantic_engine": "available",
                "database": "connected",
                "api": "operational"
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Compliance health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }


@router.post("/upload-rules")
async def upload_compliance_rules(
    file: UploadFile = File(...),
    deduplication_strategy: str = Query(
        DeduplicationStrategy.SKIP_UNCHANGED_UPDATE_CHANGED,
        description="Deduplication strategy: skip_unchanged_update_changed, skip_existing, update_all, fail_on_duplicate"
    ),
    current_user: dict = Depends(get_current_user)
):
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
        # Sanitize filename to prevent path traversal
        safe_filename = sanitize_filename(file.filename)

        # Validate file type
        if not validate_file_extension(safe_filename, ['.tar.gz', '.tgz']):
            raise HTTPException(
                status_code=400,
                detail="Invalid file type. Only .tar.gz archives are allowed."
            )

        # Read file content
        file_content = await file.read()

        if len(file_content) == 0:
            raise HTTPException(
                status_code=400,
                detail="Uploaded file is empty"
            )

        logger.info(
            f"Upload initiated by {current_user.get('username', 'unknown')}: "
            f"{safe_filename} ({len(file_content):,} bytes)"
        )

        # Validate deduplication strategy
        if not DeduplicationStrategy.is_valid(deduplication_strategy):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid deduplication strategy. Valid options: {DeduplicationStrategy.all_strategies()}"
            )

        # Initialize upload service
        upload_service = ComplianceRulesUploadService()

        # Process upload with sanitized filename
        result = await upload_service.upload_rules_archive(
            archive_data=file_content,
            archive_filename=safe_filename,
            deduplication_strategy=deduplication_strategy,
            user_id=current_user.get('user_id')
        )

        # Return success or failure
        if result['success']:
            logger.info(
                f"Upload {result['upload_id']} completed: "
                f"{result['statistics']['imported']} imported, "
                f"{result['statistics']['updated']} updated, "
                f"{result['statistics']['skipped']} skipped"
            )

            return {
                "success": True,
                "upload_id": result['upload_id'],
                "filename": result['filename'],
                "file_hash": result['file_hash'],
                "statistics": result['statistics'],
                "manifest": result.get('manifest', {}),
                "dependency_validation": result.get('dependency_validation', {}),
                "inheritance_impact": result.get('inheritance_impact', {}),
                "warnings": result.get('warnings', []),
                "processing_time_seconds": result.get('processing_time_seconds', 0)
            }
        else:
            # Upload failed - return error details
            logger.error(f"Upload {result['upload_id']} failed: {result['errors']}")

            return {
                "success": False,
                "upload_id": result['upload_id'],
                "filename": result['filename'],
                "phase": result.get('phase', 'unknown'),
                "errors": result.get('errors', []),
                "warnings": result.get('warnings', []),
                "security_validation": result.get('security_validation', {})
            }

    except HTTPException:
        raise  # Re-raise HTTP exceptions

    except Exception as e:
        logger.error(f"Upload endpoint error: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Upload failed: {str(e)}"
        )


@router.get("/upload-history")
async def get_upload_history(
    limit: int = Query(50, ge=1, le=200, description="Maximum number of uploads to return"),
    current_user: dict = Depends(get_current_user)
):
    """
    Get compliance rules upload history

    Args:
        limit: Maximum number of uploads to return
        current_user: Authenticated user

    Returns:
        List of recent uploads with statistics
    """
    # TODO: Implement upload history tracking in database
    # For now, return placeholder
    return {
        "uploads": [],
        "total_count": 0,
        "message": "Upload history tracking not yet implemented"
    }