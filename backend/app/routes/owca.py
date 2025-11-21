"""
OWCA API Endpoints

REST API for OpenWatch Compliance Algorithm (OWCA) functionality.
"""

import logging
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.auth import get_current_user
from backend.app.database import get_db
from backend.app.services.owca import get_owca_service
from backend.app.services.owca.models import (
    BaselineDrift,
    ComplianceScore,
    DriftSeverity,
    FleetStatistics,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/owca", tags=["OWCA"])


@router.get(
    "/host/{host_id}/score",
    response_model=Optional[ComplianceScore],
    summary="Get host compliance score",
    description="Calculate compliance score for a specific host using OWCA",
)
async def get_host_compliance_score(
    host_id: UUID,
    db: Session = Depends(get_db),
    _current_user: dict = Depends(get_current_user),
):
    """
    Get OWCA-calculated compliance score for a specific host.

    This endpoint returns the canonical compliance score using the
    OpenWatch Compliance Algorithm (OWCA), which is the single source
    of truth for all compliance calculations.

    Args:
        host_id: UUID of the host

    Returns:
        ComplianceScore with full breakdown, or None if no scans exist

    Example Response:
        {
            "entity_id": "550e8400-e29b-41d4-a716-446655440000",
            "entity_type": "host",
            "overall_score": 87.5,
            "tier": "good",
            "passed_rules": 175,
            "failed_rules": 25,
            "total_rules": 200,
            "severity_breakdown": {
                "critical_passed": 45,
                "critical_failed": 2,
                "critical_total": 47,
                ...
            },
            "calculated_at": "2025-11-21T12:34:56.789Z",
            "algorithm_version": "1.0.0",
            "scan_id": "abc12345-..."
        }
    """
    try:
        owca = get_owca_service(db)
        score = await owca.get_host_compliance_score(str(host_id))

        if not score:
            logger.info(f"No compliance score available for host {host_id}")
            return None

        return score

    except Exception as e:
        logger.error(f"Error calculating compliance score for host {host_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to calculate compliance score")


@router.get(
    "/fleet/statistics",
    response_model=FleetStatistics,
    summary="Get fleet statistics",
    description="Get organization-wide fleet compliance statistics",
)
async def get_fleet_statistics(
    db: Session = Depends(get_db),
    _current_user: dict = Depends(get_current_user),
):
    """
    Get comprehensive fleet-wide compliance statistics.

    Provides aggregated metrics across all hosts in the organization,
    including compliance averages, issue counts, and tier distribution.

    Returns:
        FleetStatistics with all aggregated metrics

    Example Response:
        {
            "total_hosts": 150,
            "online_hosts": 142,
            "offline_hosts": 8,
            "scanned_hosts": 145,
            "never_scanned": 5,
            "needs_scan": 12,
            "average_compliance": 85.3,
            "median_compliance": 87.0,
            "hosts_excellent": 45,
            "hosts_good": 67,
            "hosts_fair": 28,
            "hosts_poor": 10,
            "total_critical_issues": 234,
            "total_high_issues": 567,
            "total_medium_issues": 1234,
            "total_low_issues": 2345,
            "hosts_with_critical": 89,
            "calculated_at": "2025-11-21T12:34:56.789Z"
        }
    """
    try:
        owca = get_owca_service(db)
        stats = await owca.get_fleet_statistics()
        return stats

    except Exception as e:
        logger.error(f"Error calculating fleet statistics: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to calculate fleet statistics")


@router.get(
    "/host/{host_id}/drift",
    response_model=Optional[BaselineDrift],
    summary="Detect baseline drift",
    description="Detect compliance drift from active baseline for a host",
)
async def detect_baseline_drift(
    host_id: UUID,
    db: Session = Depends(get_db),
    _current_user: dict = Depends(get_current_user),
):
    """
    Detect compliance drift from active baseline.

    Compares current compliance state against the host's established
    baseline (per NIST SP 800-137 Continuous Monitoring guidelines).

    Args:
        host_id: UUID of the host

    Returns:
        BaselineDrift analysis, or None if no active baseline exists

    Example Response:
        {
            "host_id": "550e8400-e29b-41d4-a716-446655440000",
            "baseline_id": "abc12345-...",
            "current_score": 75.5,
            "baseline_score": 87.0,
            "drift_percentage": -11.5,
            "drift_severity": "critical",
            "rules_changed": 23,
            "newly_failed": 23,
            "newly_passed": 0,
            "critical_regressions": 3,
            "high_regressions": 8,
            "detected_at": "2025-11-21T12:34:56.789Z"
        }
    """
    try:
        owca = get_owca_service(db)
        drift = await owca.detect_baseline_drift(str(host_id))

        if not drift:
            logger.info(f"No active baseline for host {host_id}")
            return None

        return drift

    except Exception as e:
        logger.error(f"Error detecting baseline drift for host {host_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to detect baseline drift")


@router.get(
    "/fleet/drift",
    response_model=List[BaselineDrift],
    summary="Get hosts with drift",
    description="Get all hosts with significant baseline drift",
)
async def get_hosts_with_drift(
    min_severity: DriftSeverity = Query(
        DriftSeverity.MEDIUM,
        description="Minimum drift severity to include (critical, high, medium, low, none)",
    ),
    db: Session = Depends(get_db),
    _current_user: dict = Depends(get_current_user),
):
    """
    Get all hosts with significant baseline drift.

    Returns hosts where compliance has drifted from baseline by
    more than the specified severity threshold.

    Args:
        min_severity: Minimum drift severity (default: medium)

    Returns:
        List of BaselineDrift objects sorted by severity and drift %

    Example Response:
        [
            {
                "host_id": "550e8400-...",
                "drift_percentage": -15.5,
                "drift_severity": "critical",
                ...
            },
            {
                "host_id": "abc12345-...",
                "drift_percentage": -7.2,
                "drift_severity": "high",
                ...
            }
        ]
    """
    try:
        owca = get_owca_service(db)
        # Access drift_detector directly from owca service
        drifted_hosts = await owca.drift_detector.get_hosts_with_drift(min_severity=min_severity)
        return drifted_hosts

    except Exception as e:
        logger.error(f"Error getting hosts with drift: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to get hosts with drift")


@router.get(
    "/fleet/priority-hosts",
    response_model=List[dict],
    summary="Get top priority hosts",
    description="Get hosts prioritized for remediation",
)
async def get_top_priority_hosts(
    limit: int = Query(10, ge=1, le=100, description="Maximum number of hosts to return"),
    db: Session = Depends(get_db),
    _current_user: dict = Depends(get_current_user),
):
    """
    Get top priority hosts for remediation.

    Hosts are prioritized based on:
    - Number of critical issues
    - Number of high issues
    - Overall compliance score

    Args:
        limit: Maximum number of hosts to return (1-100, default: 10)

    Returns:
        List of host dictionaries with priority ranking

    Example Response:
        [
            {
                "rank": 1,
                "host_id": "550e8400-...",
                "hostname": "web-server-01",
                "ip_address": "192.168.1.100",
                "compliance_score": 65.5,
                "critical_issues": 5,
                "high_issues": 12,
                "priority_score": 110,
                "last_scan": "2025-11-21T10:00:00Z"
            },
            ...
        ]
    """
    try:
        owca = get_owca_service(db)
        # Access fleet_aggregator directly from owca service
        priority_hosts = await owca.fleet_aggregator.get_top_priority_hosts(limit=limit)
        return priority_hosts

    except Exception as e:
        logger.error(f"Error getting top priority hosts: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to get top priority hosts")


@router.get(
    "/version",
    response_model=dict,
    summary="Get OWCA version",
    description="Get current OWCA algorithm version",
)
async def get_owca_version(
    db: Session = Depends(get_db),
    _current_user: dict = Depends(get_current_user),
):
    """
    Get OWCA algorithm version information.

    Returns:
        Dictionary with version and algorithm metadata

    Example Response:
        {
            "algorithm": "OpenWatch Compliance Algorithm",
            "version": "1.0.0",
            "description": "Single source of truth for compliance calculations"
        }
    """
    owca = get_owca_service(db)
    return {
        "algorithm": "OpenWatch Compliance Algorithm (OWCA)",
        "version": owca.get_version(),
        "description": "Single source of truth for all compliance calculations",
        "layers": [
            "Core Layer: Canonical score calculations",
            "Framework Layer: Framework-specific intelligence",
            "Aggregation Layer: Multi-entity rollup",
            "Intelligence Layer: Trends, predictions, drift detection",
        ],
    }
