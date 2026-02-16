"""
OWCA API Endpoints

REST API for OpenWatch Compliance Algorithm (OWCA) functionality.
Part of Phase 4 API Standardization: System & Integrations.

Endpoint Structure:
    GET  /owca/host/{host_id}/score              - Get host compliance score
    GET  /owca/fleet/statistics                  - Get fleet statistics
    GET  /owca/fleet/trend                       - Get fleet compliance trend (NEW)
    GET  /owca/host/{host_id}/drift              - Detect baseline drift
    GET  /owca/fleet/drift                       - Get hosts with drift
    GET  /owca/fleet/priority-hosts              - Get top priority hosts
    GET  /owca/host/{host_id}/framework/{fw}     - Get framework intelligence
    GET  /owca/frameworks                        - List available frameworks
    GET  /owca/host/{host_id}/trend              - Analyze compliance trend
    GET  /owca/host/{host_id}/risk               - Calculate host risk score
    GET  /owca/fleet/risk-ranking                - Rank hosts by risk
    GET  /owca/host/{host_id}/forecast           - Forecast compliance
    GET  /owca/host/{host_id}/anomalies          - Detect anomalies
    GET  /owca/version                           - Get OWCA version

Migration Status:
    - owca.py -> compliance/owca.py

Unified Data Source:
    Fleet trend endpoint uses posture_snapshots as single source of truth,
    unifying OWCA with Temporal Compliance for historical fleet data.
"""

import logging
from datetime import date, timedelta
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ...auth import get_current_user
from ...database import get_db
from ...services.owca import get_owca_service
from ...services.owca.models import BaselineDrift, ComplianceScore, DriftSeverity, FleetComplianceTrend, FleetStatistics

logger = logging.getLogger(__name__)

# Router with /owca prefix - parent adds /compliance prefix
router = APIRouter(prefix="/owca", tags=["OWCA"])


@router.get(
    "/host/{host_id}/score",
    response_model=Optional[ComplianceScore],
    summary="Get host compliance score",
    description="Calculate compliance score for a specific host using OWCA",
)
async def get_host_compliance_score(
    host_id: UUID,
    db: Session = Depends(get_db),
    _current_user: Dict[str, Any] = Depends(get_current_user),
) -> Optional[ComplianceScore]:
    """
    Get OWCA-calculated compliance score for a specific host.

    This endpoint returns the canonical compliance score using the
    OpenWatch Compliance Algorithm (OWCA), which is the single source
    of truth for all compliance calculations.

    Args:
        host_id: UUID of the host

    Returns:
        ComplianceScore with full breakdown, or None if no scans exist
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
    _current_user: Dict[str, Any] = Depends(get_current_user),
) -> FleetStatistics:
    """
    Get comprehensive fleet-wide compliance statistics.

    Provides aggregated metrics across all hosts in the organization,
    including compliance averages, issue counts, and tier distribution.

    Returns:
        FleetStatistics with all aggregated metrics
    """
    try:
        owca = get_owca_service(db)
        stats = await owca.get_fleet_statistics()
        return stats

    except Exception as e:
        logger.error(f"Error calculating fleet statistics: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to calculate fleet statistics")


@router.get(
    "/fleet/trend",
    response_model=Optional[FleetComplianceTrend],
    summary="Get fleet compliance trend",
    description="Get fleet-wide compliance trend over time from posture snapshots",
)
async def get_fleet_trend(
    start_date: Optional[date] = Query(None, description="Start date (default: 30 days ago)"),
    end_date: Optional[date] = Query(None, description="End date (default: today)"),
    days: int = Query(30, ge=7, le=365, description="Number of days if start_date not provided"),
    db: Session = Depends(get_db),
    _current_user: Dict[str, Any] = Depends(get_current_user),
) -> Optional[FleetComplianceTrend]:
    """
    Get fleet-wide compliance trend over time.

    Uses posture_snapshots as the single source of truth for historical
    compliance data, unifying OWCA with Temporal Compliance.

    Provides daily fleet statistics including:
    - Average/median compliance scores
    - Host distribution by compliance tier (excellent/good/fair/poor)
    - Total issues by severity
    - Trend direction and improvement rate

    License Note:
        Historical queries (non-current dates) require OpenWatch+ subscription.
        For now, this endpoint is available to all users.

    Args:
        start_date: Start of date range (default: 30 days ago)
        end_date: End of date range (default: today)
        days: Number of days to analyze if start_date not provided

    Returns:
        FleetComplianceTrend with daily statistics and trend analysis
    """
    try:
        # Calculate dates if not provided
        if end_date is None:
            end_date = date.today()
        if start_date is None:
            start_date = end_date - timedelta(days=days)

        # Validate date range
        if start_date > end_date:
            raise HTTPException(status_code=400, detail="start_date must be before end_date")

        # Check if this is a historical query (not just current data)
        # License check would go here for OpenWatch+ gating
        # For now, allow all queries
        # is_historical = start_date < date.today() - timedelta(days=1)
        # if is_historical:
        #     license_service = LicenseService()
        #     if not await license_service.has_feature("temporal_queries"):
        #         raise HTTPException(403, "Fleet trends require OpenWatch+ subscription")

        owca = get_owca_service(db)
        trend = await owca.get_fleet_trend(start_date, end_date)

        if not trend:
            logger.info(f"No fleet trend data available for {start_date} to {end_date}")
            return None

        return trend

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting fleet trend: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to get fleet compliance trend")


@router.get(
    "/host/{host_id}/drift",
    response_model=Optional[BaselineDrift],
    summary="Detect baseline drift",
    description="Detect compliance drift from active baseline for a host",
)
async def detect_baseline_drift(
    host_id: UUID,
    db: Session = Depends(get_db),
    _current_user: Dict[str, Any] = Depends(get_current_user),
) -> Optional[BaselineDrift]:
    """
    Detect compliance drift from active baseline.

    Compares current compliance state against the host's established
    baseline (per NIST SP 800-137 Continuous Monitoring guidelines).

    Args:
        host_id: UUID of the host

    Returns:
        BaselineDrift analysis, or None if no active baseline exists
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
    _current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[BaselineDrift]:
    """
    Get all hosts with significant baseline drift.

    Returns hosts where compliance has drifted from baseline by
    more than the specified severity threshold.

    Args:
        min_severity: Minimum drift severity (default: medium)

    Returns:
        List of BaselineDrift objects sorted by severity and drift %
    """
    try:
        owca = get_owca_service(db)
        # Access drift_detector directly from owca service
        drifted_hosts = await owca.drift_detector.get_hosts_with_drift(min_severity=min_severity)
        # Ensure proper type cast for mypy
        return list(drifted_hosts)

    except Exception as e:
        logger.error(f"Error getting hosts with drift: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to get hosts with drift")


@router.get(
    "/fleet/priority-hosts",
    response_model=List[Dict[str, Any]],
    summary="Get top priority hosts",
    description="Get hosts prioritized for remediation",
)
async def get_top_priority_hosts(
    limit: int = Query(10, ge=1, le=100, description="Maximum number of hosts to return"),
    db: Session = Depends(get_db),
    _current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[Dict[str, Any]]:
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
    """
    try:
        owca = get_owca_service(db)
        # Access fleet_aggregator directly from owca service
        priority_hosts = await owca.fleet_aggregator.get_top_priority_hosts(limit=limit)
        # Ensure proper type for mypy
        result: List[Dict[str, Any]] = list(priority_hosts) if priority_hosts else []
        return result

    except Exception as e:
        logger.error(f"Error getting top priority hosts: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to get top priority hosts")


@router.get(
    "/host/{host_id}/framework/{framework}",
    response_model=Dict[str, Any],
    summary="Get framework-specific intelligence",
    description="Get detailed framework-specific compliance analysis for a host",
)
async def get_host_framework_intelligence(
    host_id: UUID,
    framework: str,
    db: Session = Depends(get_db),
    _current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get framework-specific compliance intelligence for a host.

    This endpoint provides deep framework-specific analysis including:
    - NIST 800-53: Control families, security baselines, enhancements
    - CIS Benchmarks: Level 1/2 compliance, Implementation Groups
    - STIG: CAT I/II/III severity breakdown, finding status

    Args:
        host_id: UUID of the host to analyze
        framework: Framework identifier (NIST_800_53, CIS, STIG)

    Returns:
        Framework-specific intelligence object with complete analysis

    Raises:
        404: Framework not supported or no scan data available
        500: Internal error during analysis
    """
    try:
        owca = get_owca_service(db)
        intelligence = await owca.get_framework_intelligence(framework=framework, host_id=str(host_id))

        if not intelligence:
            raise HTTPException(
                status_code=404,
                detail=f"Framework '{framework}' not supported or no scan data available for host {host_id}",
            )

        # Convert Pydantic model to dict for JSON response
        result: Dict[str, Any]
        if hasattr(intelligence, "dict"):
            result = dict(intelligence.dict())
        else:
            result = dict(intelligence) if isinstance(intelligence, dict) else {"data": intelligence}
        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Error getting framework intelligence for host {host_id}, framework {framework}: {e}",
            exc_info=True,
        )
        raise HTTPException(status_code=500, detail="Failed to get framework-specific intelligence")


@router.get(
    "/frameworks",
    response_model=Dict[str, Any],
    summary="List available frameworks",
    description="Get list of supported compliance frameworks",
)
async def list_available_frameworks(
    db: Session = Depends(get_db),
    _current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get list of all supported compliance frameworks.

    Returns metadata about each framework including identifiers,
    full names, and descriptions.

    Returns:
        Dictionary with framework metadata
    """
    return {
        "frameworks": [
            {
                "id": "NIST_800_53",
                "name": "NIST SP 800-53 Rev 5",
                "description": "Federal security controls with control families, baselines, and enhancements",
                "aliases": ["nist_800_53", "nist"],
                "features": [
                    "Control family analysis (AC, AU, IA, etc.)",
                    "Security baseline assessment (LOW/MODERATE/HIGH)",
                    "Control enhancement coverage tracking",
                ],
            },
            {
                "id": "CIS",
                "name": "CIS Benchmarks",
                "description": "Security configuration standards with levels and implementation groups",
                "aliases": ["cis"],
                "features": [
                    "Level 1/2 compliance tracking",
                    "Implementation Group analysis (IG1/IG2/IG3)",
                    "Best practice recommendations",
                ],
            },
            {
                "id": "STIG",
                "name": "Security Technical Implementation Guides",
                "description": "DoD security requirements with CAT I/II/III severity classifications",
                "aliases": ["stig"],
                "features": [
                    "CAT I/II/III severity analysis",
                    "Finding status distribution",
                    "Automated vs manual check breakdown",
                ],
            },
        ]
    }


@router.get(
    "/host/{host_id}/trend",
    response_model=Optional[Dict[str, Any]],
    summary="Analyze compliance trend",
    description="Analyze historical compliance trend for a host",
)
async def analyze_host_trend(
    host_id: UUID,
    days: int = Query(30, ge=7, le=365, description="Number of days to analyze"),
    db: Session = Depends(get_db),
    _current_user: Dict[str, Any] = Depends(get_current_user),
) -> Optional[Dict[str, Any]]:
    """
    Analyze compliance trend over time for a host.

    Provides historical data points and trend analysis including:
    - Overall trend direction (improving, declining, stable)
    - Rate of improvement or decline (percentage points per day)
    - Historical compliance scores by date

    Args:
        host_id: UUID of the host
        days: Number of days to analyze (7-365, default: 30)

    Returns:
        TrendData with historical analysis
    """
    try:
        owca = get_owca_service(db)
        trend = await owca.analyze_trend(str(host_id), entity_type="host", days=days)

        if not trend:
            return None

        # Convert to dict with proper type annotation
        result: Dict[str, Any] = dict(trend.dict()) if hasattr(trend, "dict") else dict(trend)
        return result

    except Exception as e:
        logger.error(f"Error analyzing trend for host {host_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to analyze compliance trend")


@router.get(
    "/host/{host_id}/risk",
    response_model=Optional[Dict[str, Any]],
    summary="Calculate host risk score",
    description="Calculate composite risk score for remediation prioritization",
)
async def calculate_host_risk(
    host_id: UUID,
    business_criticality: Optional[str] = Query(
        None, description="Business tier (production, staging, development, testing)"
    ),
    db: Session = Depends(get_db),
    _current_user: Dict[str, Any] = Depends(get_current_user),
) -> Optional[Dict[str, Any]]:
    """
    Calculate composite risk score for a host.

    Combines multiple risk factors:
    - Compliance score (40% weight)
    - Critical issues (25% weight)
    - Scan staleness (15% weight)
    - Baseline drift (15% weight)
    - Business criticality (5% weight)

    Args:
        host_id: UUID of the host
        business_criticality: Optional business tier for risk weighting

    Returns:
        RiskScore with composite analysis
    """
    try:
        owca = get_owca_service(db)
        risk = await owca.calculate_risk(str(host_id), business_criticality)

        if not risk:
            raise HTTPException(
                status_code=404,
                detail=f"No compliance data available for host {host_id}",
            )

        # Convert to dict with proper type annotation
        result: Dict[str, Any] = dict(risk.dict()) if hasattr(risk, "dict") else dict(risk)
        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error calculating risk for host {host_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to calculate risk score")


@router.get(
    "/fleet/risk-ranking",
    response_model=List[Dict[str, Any]],
    summary="Rank hosts by risk",
    description="Get all hosts ranked by risk score for prioritization",
)
async def rank_fleet_by_risk(
    limit: Optional[int] = Query(None, ge=1, le=100, description="Maximum number of hosts to return"),
    db: Session = Depends(get_db),
    _current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """
    Rank all hosts by composite risk score.

    Useful for generating prioritized remediation lists and
    identifying highest-risk assets.

    Args:
        limit: Optional maximum number of hosts (default: all)

    Returns:
        List of RiskScore objects sorted by risk (highest first)
    """
    try:
        owca = get_owca_service(db)
        risk_scores = await owca.rank_hosts_by_risk(limit)

        return [risk.dict() if hasattr(risk, "dict") else risk for risk in risk_scores]

    except Exception as e:
        logger.error(f"Error ranking hosts by risk: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to rank hosts by risk")


@router.get(
    "/host/{host_id}/forecast",
    response_model=Optional[Dict[str, Any]],
    summary="Forecast compliance",
    description="Predict future compliance scores using statistical forecasting",
)
async def forecast_host_compliance(
    host_id: UUID,
    days_ahead: int = Query(30, ge=7, le=90, description="Number of days to forecast (7-90)"),
    db: Session = Depends(get_db),
    _current_user: Dict[str, Any] = Depends(get_current_user),
) -> Optional[Dict[str, Any]]:
    """
    Forecast future compliance scores using linear regression.

    Analyzes historical trends and projects future trajectory
    with 95% confidence intervals.

    Args:
        host_id: UUID of the host
        days_ahead: Number of days to forecast (7-90, default: 30)

    Returns:
        ComplianceForecast with predictions
    """
    try:
        owca = get_owca_service(db)
        forecast = await owca.forecast_compliance(str(host_id), entity_type="host", days_ahead=days_ahead)

        if not forecast:
            raise HTTPException(
                status_code=404,
                detail="Insufficient historical data for forecasting (need at least 5 scans)",
            )

        # Convert to dict with proper type annotation
        result: Dict[str, Any] = dict(forecast.dict()) if hasattr(forecast, "dict") else dict(forecast)
        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error forecasting for host {host_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to forecast compliance")


@router.get(
    "/host/{host_id}/anomalies",
    response_model=List[Dict[str, Any]],
    summary="Detect anomalies",
    description="Detect unusual compliance score changes using statistical analysis",
)
async def detect_host_anomalies(
    host_id: UUID,
    lookback_days: int = Query(60, ge=30, le=180, description="Days of history to analyze (30-180)"),
    db: Session = Depends(get_db),
    _current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """
    Detect anomalous compliance scores using z-score method.

    Identifies scans with scores that deviate significantly
    from historical mean (>1 standard deviation).

    Args:
        host_id: UUID of the host
        lookback_days: Days of history to analyze (30-180, default: 60)

    Returns:
        List of detected anomalies
    """
    try:
        owca = get_owca_service(db)
        anomalies = await owca.detect_anomalies(str(host_id), entity_type="host", lookback_days=lookback_days)

        return [anomaly.dict() if hasattr(anomaly, "dict") else anomaly for anomaly in anomalies]

    except Exception as e:
        logger.error(f"Error detecting anomalies for host {host_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to detect anomalies")


@router.get(
    "/version",
    response_model=Dict[str, Any],
    summary="Get OWCA version",
    description="Get current OWCA algorithm version",
)
async def get_owca_version(
    db: Session = Depends(get_db),
    _current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get OWCA algorithm version information.

    Returns:
        Dictionary with version and algorithm metadata
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
        "supported_frameworks": ["NIST_800_53", "CIS", "STIG"],
        "intelligence_features": [
            "Baseline drift detection",
            "Trend analysis",
            "Risk scoring",
            "Compliance forecasting",
            "Anomaly detection",
        ],
    }
