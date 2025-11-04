"""
Integration Metrics API Routes
Provides endpoints for monitoring integration performance and health
"""

import json
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from ..auth import get_current_user
from ..rbac import require_admin
from ..services.integration_metrics import metrics_collector

router = APIRouter()


@router.get("/health")
async def integration_health():
    """Get integration health status - no auth required"""
    try:
        stats = metrics_collector.get_current_stats()
        summaries = metrics_collector.get_metrics_summary(hours=1)

        # Calculate overall health score
        total_operations = sum(summary.total_requests for summary in summaries.values())
        total_errors = sum(summary.failed_requests for summary in summaries.values())

        error_rate = (total_errors / total_operations * 100) if total_operations > 0 else 0

        # Determine health status
        if error_rate < 1:
            health_status = "healthy"
        elif error_rate < 5:
            health_status = "degraded"
        else:
            health_status = "unhealthy"

        return {
            "status": health_status,
            "timestamp": datetime.utcnow().isoformat(),
            "metrics": {
                "total_operations_1h": total_operations,
                "error_rate_1h": round(error_rate, 2),
                "recent_errors": len(stats.get("recent_errors", [])),
                "active_metrics": stats["total_metrics"],
            },
            "top_operations": stats.get("top_operations", {}),
        }
    except Exception as e:
        return {
            "status": "unknown",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e),
        }


@router.get("/stats")
@require_admin()
async def get_integration_stats(
    hours: int = Query(1, ge=1, le=168, description="Hours of data to analyze"),
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Get detailed integration statistics"""
    try:
        stats = metrics_collector.get_current_stats()
        summaries = metrics_collector.get_metrics_summary(hours=hours)

        return {
            "period_hours": hours,
            "timestamp": datetime.utcnow().isoformat(),
            "current_stats": stats,
            "operation_summaries": {
                op: {
                    "total_requests": summary.total_requests,
                    "successful_requests": summary.successful_requests,
                    "failed_requests": summary.failed_requests,
                    "error_rate": round(summary.error_rate, 2),
                    "avg_duration_ms": round(summary.average_duration * 1000, 2),
                    "min_duration_ms": round(summary.min_duration * 1000, 2),
                    "max_duration_ms": round(summary.max_duration * 1000, 2),
                    "p95_duration_ms": round(summary.p95_duration * 1000, 2),
                }
                for op, summary in summaries.items()
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get integration stats: {e}")


@router.get("/metrics")
@require_admin()
async def get_metrics(
    format: str = Query("json", regex="^(json|prometheus)$"),
    operation: Optional[str] = Query(None, description="Filter by specific operation"),
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Export metrics in various formats"""
    try:
        if format == "prometheus":
            metrics_data = metrics_collector.export_metrics("prometheus")
            return Response(
                content=metrics_data,
                media_type="text/plain; version=0.0.4; charset=utf-8",
                headers={"Content-Type": "text/plain; version=0.0.4; charset=utf-8"},
            )
        else:
            # Filter metrics if operation specified
            all_metrics = list(metrics_collector.metrics)
            if operation:
                all_metrics = [m for m in all_metrics if m.operation == operation]

            # Convert to serializable format
            metrics_data = []
            for metric in all_metrics[-1000:]:  # Last 1000 metrics
                metrics_data.append(
                    {
                        "timestamp": datetime.fromtimestamp(metric.timestamp).isoformat(),
                        "metric_type": metric.metric_type,
                        "operation": metric.operation,
                        "value": metric.value,
                        "success": metric.success,
                        "error": metric.error,
                        "labels": metric.labels,
                    }
                )

            return {
                "total_metrics": len(all_metrics),
                "returned_metrics": len(metrics_data),
                "metrics": metrics_data,
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to export metrics: {e}")


@router.get("/performance")
@require_admin()
async def get_performance_overview(
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Get performance overview dashboard data"""
    try:
        # Get metrics for different time periods
        last_hour = metrics_collector.get_metrics_summary(hours=1)
        last_day = metrics_collector.get_metrics_summary(hours=24)

        # Calculate trends
        performance_data = {}

        for operation in set(list(last_hour.keys()) + list(last_day.keys())):
            hour_data = last_hour.get(operation)
            day_data = last_day.get(operation)

            performance_data[operation] = {
                "last_hour": {
                    "requests": hour_data.total_requests if hour_data else 0,
                    "error_rate": round(hour_data.error_rate, 2) if hour_data else 0,
                    "avg_duration_ms": (
                        round(hour_data.average_duration * 1000, 2) if hour_data else 0
                    ),
                    "p95_duration_ms": (
                        round(hour_data.p95_duration * 1000, 2) if hour_data else 0
                    ),
                },
                "last_24h": {
                    "requests": day_data.total_requests if day_data else 0,
                    "error_rate": round(day_data.error_rate, 2) if day_data else 0,
                    "avg_duration_ms": (
                        round(day_data.average_duration * 1000, 2) if day_data else 0
                    ),
                    "p95_duration_ms": (round(day_data.p95_duration * 1000, 2) if day_data else 0),
                },
            }

            # Calculate trends
            if hour_data and day_data:
                performance_data[operation]["trends"] = {
                    "error_rate_trend": (
                        "up"
                        if hour_data.error_rate > day_data.error_rate
                        else ("down" if hour_data.error_rate < day_data.error_rate else "stable")
                    ),
                    "performance_trend": (
                        "better"
                        if hour_data.average_duration < day_data.average_duration
                        else (
                            "worse"
                            if hour_data.average_duration > day_data.average_duration
                            else "stable"
                        )
                    ),
                }

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "performance_data": performance_data,
            "summary": {
                "total_operations_1h": sum(
                    data["last_hour"]["requests"] for data in performance_data.values()
                ),
                "total_operations_24h": sum(
                    data["last_24h"]["requests"] for data in performance_data.values()
                ),
                "avg_error_rate_1h": (
                    sum(data["last_hour"]["error_rate"] for data in performance_data.values())
                    / len(performance_data)
                    if performance_data
                    else 0
                ),
                "avg_error_rate_24h": (
                    sum(data["last_24h"]["error_rate"] for data in performance_data.values())
                    / len(performance_data)
                    if performance_data
                    else 0
                ),
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get performance overview: {e}")


@router.post("/cleanup")
@require_admin()
async def cleanup_old_metrics(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Manually trigger cleanup of old metrics"""
    try:
        initial_count = len(metrics_collector.metrics)
        metrics_collector.cleanup_old_metrics()
        final_count = len(metrics_collector.metrics)

        return {
            "message": "Metrics cleanup completed",
            "metrics_removed": initial_count - final_count,
            "metrics_remaining": final_count,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to cleanup metrics: {e}")
