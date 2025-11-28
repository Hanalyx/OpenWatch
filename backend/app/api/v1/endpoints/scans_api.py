#!/usr/bin/env python3
"""
Scan Execution API Endpoints

Provides REST API for executing and managing compliance scans.
"""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from ....auth import get_current_user
from ....models.scan_models import ScanConfiguration, ScanResult, ScanStatus, ScanTargetType
from ....services.mongo_integration_service import get_mongo_service
from ....services.scan_orchestrator_service import ScanOrchestrator

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/execute", response_model=ScanResult)
async def execute_scan(
    config: ScanConfiguration,
    scan_name: Optional[str] = None,
    mongo_service: Any = Depends(get_mongo_service),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> ScanResult:
    """
    Execute compliance scan

    Executes a compliance scan against the specified target using rules
    from the selected framework. Supports multi-scanner execution with
    XCCDF variable customization.

    **Process**:
    1. Query MongoDB for rules matching framework/version
    2. Group rules by scanner_type (oscap, kubernetes, cloud APIs)
    3. Execute scanners in parallel
    4. Aggregate and store results

    **Example Request**:
    ```json
    {
      "target": {
        "type": "ssh_host",
        "identifier": "prod-web-01.example.com",
        "credentials": {"username": "root", "ssh_key": "..."}
      },
      "framework": "nist",
      "framework_version": "800-53r5",
      "variable_overrides": {
        "xccdf_com.hanalyx.openwatch_value_var_accounts_tmout": "300"
      }
    }
    ```
    """
    try:
        db = mongo_service.mongo_manager.database

        logger.info(
            f"User {current_user.get('username')} initiating scan: "
            f"framework={config.framework}, target={config.target.identifier}"
        )

        # Create orchestrator
        orchestrator = ScanOrchestrator(db)

        # Execute scan
        result = await orchestrator.execute_scan(
            config=config,
            started_by=current_user.get("username", "unknown"),
            scan_name=scan_name,
        )

        return result

    except Exception as e:
        logger.error(f"Scan execution failed: {e}")
        raise HTTPException(status_code=500, detail=f"Scan execution failed: {str(e)}")


@router.get("/{scan_id}", response_model=ScanResult)
async def get_scan(
    scan_id: str,
    mongo_service: Any = Depends(get_mongo_service),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> ScanResult:
    """
    Get scan result by ID

    Returns complete scan results including rule-level details,
    summary statistics, and scanner metadata.
    """
    try:
        db = mongo_service.mongo_manager.database

        orchestrator = ScanOrchestrator(db)
        result = await orchestrator.get_scan_result(scan_id)

        if not result:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/", response_model=List[ScanResult])
async def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    status: Optional[ScanStatus] = None,
    mongo_service: Any = Depends(get_mongo_service),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[ScanResult]:
    """
    List scans with optional filters

    Returns list of scans ordered by start time (most recent first).
    Supports filtering by status and pagination.
    """
    try:
        db = mongo_service.mongo_manager.database

        orchestrator = ScanOrchestrator(db)

        # Regular users can only see their own scans
        # Admins can see all scans
        started_by = None if current_user.get("role") == "admin" else current_user.get("username")

        scans = await orchestrator.list_scans(
            skip=skip, limit=limit, status=status, started_by=started_by
        )

        return scans

    except Exception as e:
        logger.error(f"Error listing scans: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{scan_id}")
async def delete_scan(
    scan_id: str,
    mongo_service: Any = Depends(get_mongo_service),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Delete scan result

    Only the user who initiated the scan or admins can delete it.
    """
    try:
        db = mongo_service.mongo_manager.database

        orchestrator = ScanOrchestrator(db)
        scan = await orchestrator.get_scan_result(scan_id)

        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

        # Check permissions
        if scan.started_by != current_user.get("username") and current_user.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Permission denied")

        await scan.delete()

        return {"message": f"Scan {scan_id} deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics/summary")
async def get_scan_statistics(
    framework: Optional[str] = None,
    target_type: Optional[ScanTargetType] = None,
    days: int = Query(30, ge=1, le=365),
    mongo_service: Any = Depends(get_mongo_service),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get scan statistics

    Returns aggregated statistics for scans over the specified time period.
    Supports filtering by framework and target type.
    """
    try:
        db = mongo_service.mongo_manager.database

        from datetime import datetime, timedelta, timezone

        # Build aggregation pipeline
        match_stage = {"started_at": {"$gte": datetime.now(timezone.utc) - timedelta(days=days)}}

        if framework:
            match_stage["config.framework"] = framework

        if target_type:
            match_stage["config.target.type"] = target_type

        # Regular users only see their own stats
        if current_user.get("role") != "admin":
            match_stage["started_by"] = current_user.get("username")

        pipeline = [
            {"$match": match_stage},
            {
                "$group": {
                    "_id": None,
                    "total_scans": {"$sum": 1},
                    "completed_scans": {
                        "$sum": {"$cond": [{"$eq": ["$status", "completed"]}, 1, 0]}
                    },
                    "failed_scans": {"$sum": {"$cond": [{"$eq": ["$status", "failed"]}, 1, 0]}},
                    "avg_compliance": {"$avg": "$summary.compliance_percentage"},
                    "total_rules_checked": {"$sum": "$summary.total_rules"},
                    "total_passed": {"$sum": "$summary.passed"},
                    "total_failed": {"$sum": "$summary.failed"},
                }
            },
        ]

        results = await db.scan_results.aggregate(pipeline).to_list(length=1)

        if not results:
            return {
                "total_scans": 0,
                "completed_scans": 0,
                "failed_scans": 0,
                "avg_compliance": 0.0,
                "total_rules_checked": 0,
                "total_passed": 0,
                "total_failed": 0,
            }

        return results[0]

    except Exception as e:
        logger.error(f"Error getting scan statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))
