"""
OS Discovery Settings API Routes

Provides endpoints for configuring and monitoring scheduled OS discovery
for hosts missing platform information (os_family, os_version, platform_identifier).

OS Discovery runs:
1. On host creation (if credentials are provided) - via trigger_os_discovery task
2. Daily at 2 AM UTC (scheduled) - via discover_all_hosts_os task (can be disabled)
3. Just-in-time during scans - via engine/discovery module (always enabled)

This module follows the QueryBuilder pattern per CLAUDE.md for safe SQL queries.
All endpoints require authentication and appropriate RBAC permissions.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..rbac import Permission, require_permission
from ..utils.query_builder import QueryBuilder

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/system/os-discovery", tags=["OS Discovery"])


# Pydantic models
class OSDiscoveryConfigResponse(BaseModel):
    """OS Discovery configuration response"""

    enabled: bool = Field(description="Whether scheduled OS discovery is enabled")
    schedule: str = Field(default="daily at 2 AM UTC", description="Discovery schedule")
    last_run: Optional[str] = Field(None, description="Last scheduled run timestamp")
    next_run: Optional[str] = Field(None, description="Next scheduled run timestamp")


class OSDiscoveryConfigUpdate(BaseModel):
    """OS Discovery configuration update"""

    enabled: Optional[bool] = Field(None, description="Enable or disable scheduled discovery")


class DiscoveryFailure(BaseModel):
    """A single discovery failure record"""

    host_id: str
    error_message: str
    timestamp: str
    retry_count: int = 3  # Always 3 (max retries exhausted)


class OSDiscoveryStatsResponse(BaseModel):
    """OS Discovery statistics"""

    total_hosts: int = Field(description="Total number of hosts")
    hosts_with_platform: int = Field(description="Hosts with platform_identifier set")
    hosts_missing_platform: int = Field(description="Hosts missing platform data")
    pending_failures: int = Field(description="Number of unacknowledged discovery failures")
    failures: List[DiscoveryFailure] = Field(
        default_factory=list, description="Recent discovery failures"
    )


class AcknowledgeFailuresRequest(BaseModel):
    """Request to acknowledge discovery failures"""

    host_ids: Optional[List[str]] = Field(
        None, description="Specific host IDs to acknowledge (None = all)"
    )


@router.get("/config", response_model=OSDiscoveryConfigResponse)
@require_permission(Permission.SYSTEM_MAINTENANCE)
async def get_os_discovery_config(
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> OSDiscoveryConfigResponse:
    """
    Get current OS discovery configuration.

    Returns the enabled/disabled state and schedule information.
    Queries system_settings table for os_discovery_enabled and os_discovery_last_run.

    Args:
        db: Database session from dependency injection
        current_user: Authenticated user context from JWT

    Returns:
        OSDiscoveryConfigResponse with enabled status and schedule info

    Raises:
        HTTPException: 500 if database query fails
    """
    try:
        # Query os_discovery_enabled setting using QueryBuilder for SQL injection safety
        builder = (
            QueryBuilder("system_settings")
            .select("setting_value")
            .where("setting_key = :key", "os_discovery_enabled", "key")
        )
        query, params = builder.build()
        result = db.execute(text(query), params)
        row = result.fetchone()

        # Default to enabled if setting not found (safe default for discovery)
        enabled = True
        if row:
            enabled = row.setting_value.lower() in ("true", "1", "yes", "enabled")

        # Query last run timestamp
        last_run_builder = (
            QueryBuilder("system_settings")
            .select("setting_value")
            .where("setting_key = :key", "os_discovery_last_run", "key")
        )
        last_run_query, last_run_params = last_run_builder.build()
        last_run_result = db.execute(text(last_run_query), last_run_params)
        last_run_row = last_run_result.fetchone()
        last_run = last_run_row.setting_value if last_run_row else None

        return OSDiscoveryConfigResponse(
            enabled=enabled,
            schedule="daily at 2 AM UTC",
            last_run=last_run,
            next_run=None,  # Could calculate based on Celery beat schedule
        )

    except Exception as e:
        logger.error(f"Failed to get OS discovery config: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve OS discovery configuration")


@router.put("/config", response_model=OSDiscoveryConfigResponse)
@require_permission(Permission.SYSTEM_MAINTENANCE)
async def update_os_discovery_config(
    config: OSDiscoveryConfigUpdate,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> OSDiscoveryConfigResponse:
    """
    Update OS discovery configuration.

    Toggle the scheduled daily discovery on/off.
    Note: JIT discovery during scans is always enabled and cannot be disabled.

    Args:
        config: Configuration update with enabled field
        db: Database session from dependency injection
        current_user: Authenticated user context from JWT

    Returns:
        Updated OSDiscoveryConfigResponse

    Raises:
        HTTPException: 500 if database update fails
    """
    try:
        if config.enabled is not None:
            # Use parameterized query for upsert (PostgreSQL ON CONFLICT)
            # Note: QueryBuilder doesn't support ON CONFLICT syntax directly,
            # so we use parameterized raw SQL which is still safe from injection
            db.execute(
                text(
                    """
                    INSERT INTO system_settings (setting_key, setting_value, updated_at)
                    VALUES (:key, :value, CURRENT_TIMESTAMP)
                    ON CONFLICT (setting_key)
                    DO UPDATE SET setting_value = :value, updated_at = CURRENT_TIMESTAMP
                    """
                ),
                {"key": "os_discovery_enabled", "value": str(config.enabled).lower()},
            )
            db.commit()

            logger.info(
                f"OS discovery {'enabled' if config.enabled else 'disabled'} "
                f"by user {current_user.get('username', 'unknown')}"
            )

        # Return updated config
        return await get_os_discovery_config(db, current_user)

    except Exception as e:
        logger.error(f"Failed to update OS discovery config: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to update OS discovery configuration")


@router.get("/stats", response_model=OSDiscoveryStatsResponse)
@require_permission(Permission.HOST_READ)
async def get_os_discovery_stats(
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> OSDiscoveryStatsResponse:
    """
    Get OS discovery statistics.

    Returns counts of hosts with/without platform data and any pending failures.
    Used by frontend to display coverage metrics and failure notifications.

    Args:
        db: Database session from dependency injection
        current_user: Authenticated user context from JWT

    Returns:
        OSDiscoveryStatsResponse with host counts and failure list

    Raises:
        HTTPException: 500 if database query fails
    """
    try:
        # Count total hosts using QueryBuilder
        total_builder = QueryBuilder("hosts")
        total_query, total_params = total_builder.count_query()
        total_result = db.execute(text(total_query), total_params)
        total_hosts = total_result.fetchone().total

        # Count hosts with platform_identifier set
        # Using raw parameterized query for COUNT with WHERE clause
        # (QueryBuilder count_query doesn't support WHERE conditions)
        with_platform_result = db.execute(
            text(
                """
                SELECT COUNT(*) as count FROM hosts
                WHERE platform_identifier IS NOT NULL AND platform_identifier != ''
                """
            )
        )
        hosts_with_platform = with_platform_result.fetchone().count

        # Get discovery failures from system_settings using QueryBuilder
        failures_builder = (
            QueryBuilder("system_settings")
            .select("setting_value")
            .where("setting_key = :key", "os_discovery_failures", "key")
        )
        failures_query, failures_params = failures_builder.build()
        failures_result = db.execute(text(failures_query), failures_params)
        failures_row = failures_result.fetchone()

        # Parse JSON failures data with defensive error handling
        failures: List[DiscoveryFailure] = []
        if failures_row and failures_row.setting_value:
            try:
                failures_data = json.loads(failures_row.setting_value)
                failures = [DiscoveryFailure(**f) for f in failures_data]
            except (json.JSONDecodeError, TypeError) as parse_error:
                # Log but don't fail - return empty failures list
                logger.warning(f"Invalid JSON in os_discovery_failures setting: {parse_error}")

        return OSDiscoveryStatsResponse(
            total_hosts=total_hosts,
            hosts_with_platform=hosts_with_platform,
            hosts_missing_platform=total_hosts - hosts_with_platform,
            pending_failures=len(failures),
            failures=failures,
        )

    except Exception as e:
        logger.error(f"Failed to get OS discovery stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve OS discovery statistics")


@router.post("/run")
@require_permission(Permission.SYSTEM_MAINTENANCE)
async def trigger_os_discovery(
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Manually trigger OS discovery for all hosts missing platform data.

    This bypasses the enabled/disabled setting and runs immediately.
    Queues a Celery task to discover platform information for all hosts
    that are missing os_family, os_version, or platform_identifier.

    Args:
        db: Database session (unused but required for consistency)
        current_user: Authenticated user context for audit logging

    Returns:
        Dict with success message and Celery task ID

    Raises:
        HTTPException: 500 if task queuing fails
    """
    try:
        # Import here to avoid circular dependency
        from ..tasks.os_discovery_tasks import discover_all_hosts_os

        # Trigger the task with force=True to bypass the enabled check
        task = discover_all_hosts_os.delay(force=True)

        logger.info(
            f"Manual OS discovery triggered by user {current_user.get('username', 'unknown')}, "
            f"task_id={task.id}"
        )

        return {
            "message": "OS discovery task queued successfully",
            "task_id": str(task.id),
        }

    except Exception as e:
        logger.error(f"Failed to trigger OS discovery: {e}")
        raise HTTPException(status_code=500, detail="Failed to trigger OS discovery")


@router.post("/acknowledge-failures")
@require_permission(Permission.SYSTEM_MAINTENANCE)
async def acknowledge_discovery_failures(
    request: AcknowledgeFailuresRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Acknowledge (clear) discovery failure notifications.

    Clears failure records from system_settings to dismiss notifications.
    Supports clearing specific hosts or all failures at once.

    Args:
        request: Contains optional host_ids list (None = clear all)
        db: Database session from dependency injection
        current_user: Authenticated user context for audit logging

    Returns:
        Dict with success message and count of cleared failures

    Raises:
        HTTPException: 500 if database operation fails
    """
    try:
        if request.host_ids is None:
            # Clear all failures using parameterized query
            db.execute(
                text("DELETE FROM system_settings WHERE setting_key = :key"),
                {"key": "os_discovery_failures"},
            )
            cleared_count: Any = "all"
        else:
            # Get current failures using QueryBuilder
            failures_builder = (
                QueryBuilder("system_settings")
                .select("setting_value")
                .where("setting_key = :key", "os_discovery_failures", "key")
            )
            failures_query, failures_params = failures_builder.build()
            failures_result = db.execute(text(failures_query), failures_params)
            failures_row = failures_result.fetchone()

            if failures_row and failures_row.setting_value:
                try:
                    failures_data = json.loads(failures_row.setting_value)
                    # Filter out acknowledged failures (keep those not in request.host_ids)
                    remaining = [f for f in failures_data if f["host_id"] not in request.host_ids]
                    cleared_count = len(failures_data) - len(remaining)

                    if remaining:
                        # Update with remaining failures
                        db.execute(
                            text(
                                """
                                UPDATE system_settings
                                SET setting_value = :value, updated_at = CURRENT_TIMESTAMP
                                WHERE setting_key = :key
                                """
                            ),
                            {"value": json.dumps(remaining), "key": "os_discovery_failures"},
                        )
                    else:
                        # No remaining failures, delete the setting
                        db.execute(
                            text("DELETE FROM system_settings WHERE setting_key = :key"),
                            {"key": "os_discovery_failures"},
                        )
                except (json.JSONDecodeError, TypeError) as parse_error:
                    logger.warning(f"Failed to parse failures JSON: {parse_error}")
                    cleared_count = 0
            else:
                cleared_count = 0

        db.commit()

        logger.info(
            f"OS discovery failures acknowledged ({cleared_count}) "
            f"by user {current_user.get('username', 'unknown')}"
        )

        return {
            "message": f"Acknowledged {cleared_count} discovery failure(s)",
            "cleared": cleared_count,
        }

    except Exception as e:
        logger.error(f"Failed to acknowledge discovery failures: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to acknowledge discovery failures")


@router.get("/failures/count")
@require_permission(Permission.HOST_READ)
async def get_failure_count(
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, int]:
    """
    Get count of pending discovery failures for notification badge.

    Lightweight endpoint optimized for frequent polling from frontend.
    Returns only the count, not the full failure details.

    Args:
        db: Database session from dependency injection
        current_user: Authenticated user context from JWT

    Returns:
        Dict with count key containing number of pending failures

    Note:
        Returns {"count": 0} on error to prevent UI issues from failed polls.
        Full failure details available via /stats endpoint.
    """
    try:
        # Use QueryBuilder for safe parameterized query
        failures_builder = (
            QueryBuilder("system_settings")
            .select("setting_value")
            .where("setting_key = :key", "os_discovery_failures", "key")
        )
        failures_query, failures_params = failures_builder.build()
        failures_result = db.execute(text(failures_query), failures_params)
        failures_row = failures_result.fetchone()

        count = 0
        if failures_row and failures_row.setting_value:
            try:
                failures_data = json.loads(failures_row.setting_value)
                count = len(failures_data)
            except (json.JSONDecodeError, TypeError):
                # Silently return 0 on parse error to avoid UI disruption
                pass

        return {"count": count}

    except Exception as e:
        # Return 0 on error to prevent notification badge issues
        logger.error(f"Failed to get failure count: {e}")
        return {"count": 0}
