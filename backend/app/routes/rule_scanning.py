"""
Rule-Specific Scanning API Routes
Handles targeted scanning of specific SCAP rules

WARNING: This file may contain references to removed scap_content.
Migration: backend/alembic/versions/20250106_remove_scap_content_table.py (applied 2025-01-06)

REFACTORING GUIDE: See docs/MONGODB_SCANNING_ARCHITECTURE.md
All rule scanning should now use MongoDB compliance_rules collection directly.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..services.compliance_framework_mapper import ComplianceFrameworkMapper

# Engine module integration - AegisMapper provides AEGIS remediation system mapping
from ..services.engine import get_aegis_mapper
from ..services.rule_specific_scanner import RuleSpecificScanner

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/rule-scanning", tags=["Rule Scanning"])

# Initialize services
rule_scanner = RuleSpecificScanner()
# AegisMapper handles SCAP-to-AEGIS rule mapping and remediation planning
aegis_mapper = get_aegis_mapper()
framework_mapper: ComplianceFrameworkMapper = ComplianceFrameworkMapper()


class RuleScanRequest(BaseModel):
    """Request model for rule-specific scanning"""

    host_id: str
    content_id: int
    profile_id: str
    rule_ids: List[str]
    connection_params: Optional[Dict[str, Any]] = None


class RemediationVerificationRequest(BaseModel):
    """Request model for remediation verification"""

    host_id: str
    content_id: int
    aegis_remediation_id: str
    remediated_rules: List[str]
    connection_params: Optional[Dict[str, Any]] = None


@router.post("/scan-rules")
async def scan_specific_rules(
    request: RuleScanRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Scan specific SCAP rules on a host"""
    try:
        logger.info(
            f"Rule-specific scan requested by {current_user['username']} for {len(request.rule_ids)} rules"
        )

        # Get SCAP content file path
        content_result = db.execute(
            text(
                """
            SELECT file_path FROM scap_content WHERE id = :id
        """
            ),
            {"id": request.content_id},
        ).fetchone()

        if not content_result:
            raise HTTPException(status_code=404, detail="SCAP content not found")

        # Perform rule-specific scan
        scan_results = await rule_scanner.scan_specific_rules(
            host_id=request.host_id,
            content_path=content_result.file_path,
            profile_id=request.profile_id,
            rule_ids=request.rule_ids,
            connection_params=request.connection_params,
        )

        # Store scan results in database (sync function)
        _store_rule_scan_results(db, scan_results)

        # Generate remediation recommendations
        failed_rules = [
            {"rule_id": rule["rule_id"], "severity": rule["severity"]}
            for rule in scan_results["rule_results"]
            if rule["result"] == "fail"
        ]

        remediation_priorities = framework_mapper.get_remediation_priorities(failed_rules)

        return {
            "scan_results": scan_results,
            "remediation_recommendations": remediation_priorities[:10],  # Top 10 priorities
            "summary": {
                "total_scanned": scan_results["total_rules"],
                "passed": scan_results["passed_rules"],
                "failed": scan_results["failed_rules"],
                "compliance_score": scan_results.get("compliance_score", 0),
                "automated_remediation_available": sum(
                    1 for r in remediation_priorities if r["automated_remediation"]
                ),
            },
        }

    except Exception as e:
        logger.error(f"Error in rule-specific scanning: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/rescan-failed")
async def rescan_failed_rules(
    previous_scan_id: str,
    content_id: int,
    connection_params: Optional[Dict[str, Any]] = None,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Re-scan only failed rules from a previous scan"""
    try:
        # Get SCAP content file path
        content_result = db.execute(
            text(
                """
            SELECT file_path FROM scap_content WHERE id = :id
        """
            ),
            {"id": content_id},
        ).fetchone()

        if not content_result:
            raise HTTPException(status_code=404, detail="SCAP content not found")

        # Perform failed rule re-scan
        scan_results = await rule_scanner.scan_failed_rules_from_previous_scan(
            previous_scan_id=previous_scan_id,
            content_path=content_result.file_path,
            connection_params=connection_params,
        )

        if "message" in scan_results:
            return scan_results  # No failed rules to re-scan

        # Store results (sync function)
        _store_rule_scan_results(db, scan_results)

        return {
            "scan_results": scan_results,
            "improvement_analysis": _analyze_improvement(previous_scan_id, scan_results),
        }

    except Exception as e:
        logger.error(f"Error re-scanning failed rules: {e}")
        raise HTTPException(status_code=500, detail=f"Re-scan failed: {str(e)}")


@router.post("/verify-remediation")
async def verify_remediation(
    request: RemediationVerificationRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Verify specific rules after AEGIS remediation"""
    try:
        # Get SCAP content file path
        content_result = db.execute(
            text(
                """
            SELECT file_path FROM scap_content WHERE id = :id
        """
            ),
            {"id": request.content_id},
        ).fetchone()

        if not content_result:
            raise HTTPException(status_code=404, detail="SCAP content not found")

        # Perform remediation verification
        verification_report = await rule_scanner.verify_remediation(
            host_id=request.host_id,
            content_path=content_result.file_path,
            aegis_remediation_id=request.aegis_remediation_id,
            remediated_rules=request.remediated_rules,
            connection_params=request.connection_params,
        )

        # Update remediation plan status if exists (sync function)
        _update_remediation_plan_status(db, request.aegis_remediation_id, verification_report)

        return verification_report

    except Exception as e:
        logger.error(f"Error verifying remediation: {e}")
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")


@router.get("/rule/{rule_id}/history")
async def get_rule_scan_history(
    rule_id: str,
    host_id: Optional[str] = None,
    limit: int = 10,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get scan history for a specific rule"""
    try:
        # Get from database first
        query = """
            SELECT scan_id, host_id, result, severity, scan_timestamp, duration_ms
            FROM rule_scan_history
            WHERE rule_id = :rule_id
        """
        # Type annotation for mixed value types (str and int)
        params: Dict[str, Any] = {"rule_id": rule_id}

        if host_id:
            query += " AND host_id = :host_id"
            params["host_id"] = host_id

        query += " ORDER BY scan_timestamp DESC LIMIT :limit"
        params["limit"] = limit

        db_results = db.execute(text(query), params).fetchall()

        history = [
            {
                "scan_id": row.scan_id,
                "host_id": str(row.host_id),
                "result": row.result,
                "severity": row.severity,
                "timestamp": row.scan_timestamp.isoformat(),
                "duration_ms": row.duration_ms,
            }
            for row in db_results
        ]

        # Get additional history from files if needed
        if len(history) < limit:
            file_history = await rule_scanner.get_rule_scan_history(
                rule_id, host_id, limit - len(history)
            )
            history.extend(file_history)

        # Get remediation guidance
        guidance = rule_scanner.get_rule_remediation_guidance(rule_id)

        return {
            "rule_id": rule_id,
            "scan_history": history,
            "remediation_guidance": guidance,
        }

    except Exception as e:
        logger.error(f"Error getting rule scan history: {e}")
        raise HTTPException(status_code=500, detail="Failed to get rule history")


@router.get("/rule/{rule_id}/compliance-info")
async def get_rule_compliance_info(
    rule_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get compliance framework information for a specific rule"""
    try:
        # Get unified control information
        control = framework_mapper.get_unified_control(rule_id)

        if not control:
            raise HTTPException(status_code=404, detail="Rule not found in framework mappings")

        # Get AEGIS mapping if available
        aegis_mapping = aegis_mapper.get_aegis_mapping(rule_id)

        return {
            "rule_id": rule_id,
            "title": control.title,
            "description": control.description,
            "frameworks": [
                {
                    "framework": mapping.framework.value,
                    "control_id": mapping.control_id,
                    "control_title": mapping.control_title,
                    "control_family": mapping.control_family,
                    "severity": mapping.severity,
                    "maturity_level": mapping.maturity_level,
                    "implementation_guidance": mapping.implementation_guidance,
                    "assessment_objectives": mapping.assessment_objectives,
                }
                for mapping in control.frameworks
            ],
            "automated_remediation": {
                "available": control.automated_remediation,
                "aegis_rule_id": control.aegis_rule_id,
                "estimated_duration": (aegis_mapping.estimated_duration if aegis_mapping else None),
                "requires_reboot": (aegis_mapping.requires_reboot if aegis_mapping else False),
                "category": aegis_mapping.rule_category if aegis_mapping else None,
            },
            "tags": control.tags,
            "categories": control.categories,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting rule compliance info: {e}")
        raise HTTPException(status_code=500, detail="Failed to get rule information")


@router.post("/create-remediation-plan")
async def create_remediation_plan(
    scan_id: str,
    host_id: str,
    platform: str = "rhel9",
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Create remediation plan for failed rules from a scan"""
    try:
        # Get failed rules from scan
        failed_rules = []

        # First try to get from rule_scan_history
        history_results = db.execute(
            text(
                """
            SELECT rule_id, severity FROM rule_scan_history
            WHERE scan_id = :scan_id AND result = 'fail'
        """
            ),
            {"scan_id": scan_id},
        ).fetchall()

        if history_results:
            failed_rules = [
                {"rule_id": row.rule_id, "severity": row.severity} for row in history_results
            ]
        else:
            # Fallback to getting from scan results table if exists
            scan_result = db.execute(
                text(
                    """
                SELECT sr.rule_details FROM scan_results sr
                JOIN scans s ON sr.scan_id = s.id
                WHERE s.id = :scan_id OR CAST(s.id AS TEXT) = :scan_id
            """
                ),
                {"scan_id": scan_id},
            ).fetchone()

            if scan_result and scan_result.rule_details:
                rule_details = json.loads(scan_result.rule_details)
                failed_rules = [
                    {
                        "rule_id": rule["rule_id"],
                        "severity": rule.get("severity", "medium"),
                    }
                    for rule in rule_details
                    if rule.get("result") == "fail"
                ]

        if not failed_rules:
            raise HTTPException(status_code=404, detail="No failed rules found for scan")

        # Create remediation plan
        plan = aegis_mapper.create_remediation_plan(
            scan_id=scan_id,
            host_id=host_id,
            failed_rules=failed_rules,
            platform=platform,
        )

        # Store plan in database (sync function)
        _store_remediation_plan(db, plan, current_user["id"])

        # Generate AEGIS job request
        aegis_job_request = aegis_mapper.generate_aegis_job_request(plan)

        return {
            "plan": {
                "plan_id": plan.plan_id,
                "total_rules": plan.total_rules,
                "remediable_rules": plan.remediable_rules,
                "estimated_duration": plan.estimated_duration,
                "requires_reboot": plan.requires_reboot,
                "dependencies_resolved": plan.dependencies_resolved,
                "rule_groups": {
                    category: len(rules) for category, rules in plan.rule_groups.items()
                },
            },
            "aegis_job_request": aegis_job_request,
            "execution_ready": plan.dependencies_resolved,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating remediation plan: {e}")
        raise HTTPException(status_code=500, detail="Failed to create remediation plan")


def _store_rule_scan_results(db: Session, scan_results: Dict[str, Any]) -> None:
    """Store rule scan results in database"""
    try:
        for rule_result in scan_results.get("rule_results", []):
            db.execute(
                text(
                    """
                INSERT INTO rule_scan_history (
                    id, scan_id, host_id, rule_id, profile_id, result, severity,
                    scan_output, compliance_frameworks, automated_remediation_available,
                    aegis_rule_id, scan_timestamp, duration_ms
                ) VALUES (
                    gen_random_uuid(), :scan_id, :host_id, :rule_id, :profile_id, :result, :severity,
                    :scan_output, :compliance_frameworks, :automated_remediation_available,
                    :aegis_rule_id, NOW(), :duration_ms
                )
            """
                ),
                {
                    "scan_id": scan_results["scan_id"],
                    "host_id": scan_results["host_id"],
                    "rule_id": rule_result["rule_id"],
                    "profile_id": scan_results.get("profile_id", ""),
                    "result": rule_result["result"],
                    "severity": rule_result.get("severity", "unknown"),
                    "scan_output": rule_result.get("scan_output", ""),
                    "compliance_frameworks": json.dumps(
                        rule_result.get("compliance_frameworks", [])
                    ),
                    "automated_remediation_available": rule_result.get(
                        "automated_remediation_available", False
                    ),
                    "aegis_rule_id": rule_result.get("aegis_rule_id"),
                    "duration_ms": scan_results.get("duration_seconds", 0) * 1000,
                },
            )

        db.commit()
        logger.info(f"Stored {len(scan_results.get('rule_results', []))} rule scan results")

    except Exception as e:
        logger.error(f"Error storing rule scan results: {e}")
        db.rollback()


def _store_remediation_plan(db: Session, plan: Any, created_by: int) -> None:
    """Store remediation plan in database"""
    try:
        db.execute(
            text(
                """
            INSERT INTO remediation_plans (
                id, plan_id, scan_id, host_id, total_rules, remediable_rules, remediated_rules,
                estimated_duration, requires_reboot, status, execution_order, rule_groups,
                created_by, created_at
            ) VALUES (
                gen_random_uuid(), :plan_id, :scan_id, :host_id, :total_rules, :remediable_rules, 0,
                :estimated_duration, :requires_reboot, 'pending', :execution_order, :rule_groups,
                :created_by, NOW()
            )
        """
            ),
            {
                "plan_id": plan.plan_id,
                "scan_id": plan.scan_id,
                "host_id": plan.host_id,
                "total_rules": plan.total_rules,
                "remediable_rules": plan.remediable_rules,
                "estimated_duration": plan.estimated_duration,
                "requires_reboot": plan.requires_reboot,
                "execution_order": json.dumps(plan.execution_order),
                "rule_groups": json.dumps(
                    {
                        category: [mapping.scap_rule_id for mapping in mappings]
                        for category, mappings in plan.rule_groups.items()
                    }
                ),
                "created_by": created_by,
            },
        )

        db.commit()
        logger.info(f"Stored remediation plan: {plan.plan_id}")

    except Exception as e:
        logger.error(f"Error storing remediation plan: {e}")
        db.rollback()


def _update_remediation_plan_status(
    db: Session, aegis_remediation_id: str, verification_report: Dict[str, Any]
) -> None:
    """Update remediation plan status after verification"""
    try:
        # Determine status based on verification results
        success_rate = verification_report.get("remediation_success_rate", 0)

        if success_rate >= 100:
            status = "completed"
        elif success_rate >= 50:
            status = "partial"
        else:
            status = "failed"

        db.execute(
            text(
                """
            UPDATE remediation_plans
            SET status = :status,
                remediated_rules = :remediated_rules,
                completed_at = NOW()
            WHERE aegis_job_id = :aegis_job_id
        """
            ),
            {
                "status": status,
                "remediated_rules": verification_report.get("successfully_remediated", 0),
                "aegis_job_id": aegis_remediation_id,
            },
        )

        db.commit()

    except Exception as e:
        logger.error(f"Error updating remediation plan status: {e}")
        db.rollback()


def _analyze_improvement(previous_scan_id: str, current_results: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze improvement between scans"""
    # This would compare previous and current scan results
    # For now, return basic analysis
    return {
        "scan_comparison": "improvement_analysis",
        "current_compliance_score": current_results.get("compliance_score", 0),
        "rules_improved": 0,  # Would calculate from comparison
        "rules_regressed": 0,
        "net_improvement": True,
    }
