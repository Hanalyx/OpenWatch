"""
Plugin Update API Routes for Phase 5

Endpoints for checking and installing plugin updates.

Part of Phase 5: Control Plane (Kensa Integration Plan)
"""

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.plugins.kensa.config import get_kensa_config
from app.plugins.kensa.updater import KensaUpdater
from app.schemas.plugin_update_schemas import (
    ChangelogResponse,
    DismissNotificationRequest,
    PluginHealthResponse,
    PluginUpdateStatus,
    UpdateCheckResponse,
    UpdateHistoryItem,
    UpdateHistoryResponse,
    UpdateInstallRequest,
    UpdateInstallResponse,
    UpdateNotification,
    UpdateNotificationListResponse,
    UpdateProgressResponse,
)

from ...auth import get_current_user
from ...rbac import UserRole, require_role

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/kensa", tags=["kensa-updates"])


# =============================================================================
# Update Check Endpoints
# =============================================================================


@router.get(
    "/updates/check",
    response_model=UpdateCheckResponse,
    summary="Check for Kensa updates",
    description="Check the registry for available Kensa updates.",
)
@require_role([UserRole.SECURITY_ADMIN, UserRole.SUPER_ADMIN])
async def check_for_updates(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Check the Kensa update registry for available updates.

    Returns version information, compatibility status, and changelog.
    """
    config = get_kensa_config()
    updater = KensaUpdater(db, config)

    result = await updater.check_for_updates()

    if result.error and not result.current_version:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=result.error,
        )

    return result


@router.get(
    "/version",
    summary="Get current Kensa version",
    description="Get the currently installed Kensa version.",
)
@require_role([UserRole.SECURITY_ANALYST, UserRole.SECURITY_ADMIN, UserRole.SUPER_ADMIN])
async def get_current_version(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get the currently installed Kensa version."""
    config = get_kensa_config()
    updater = KensaUpdater(db, config)

    return {
        "plugin_id": "kensa",
        "version": updater._get_current_version(),
        "rules_path": str(config.rules_path),
    }


# =============================================================================
# Update Install Endpoints
# =============================================================================


@router.post(
    "/updates/install",
    response_model=UpdateInstallResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Install Kensa update",
    description="Download and install a Kensa update. Requires SUPER_ADMIN role.",
)
@require_role([UserRole.SUPER_ADMIN])
async def install_update(
    request: UpdateInstallRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Install a Kensa update.

    This will:
    1. Download the update package
    2. Verify package integrity
    3. Backup current installation
    4. Install the new version
    5. Validate the installation
    6. Sync new rules to database

    If any step fails, automatic rollback is attempted.
    """
    config = get_kensa_config()
    updater = KensaUpdater(db, config)

    result = await updater.perform_update(
        version=request.version,
        user_id=current_user["id"],
        skip_backup=request.skip_backup,
    )

    if not result.success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "update_failed",
                "message": result.error,
                "update_id": str(result.update_id) if result.update_id else None,
                "status": result.status.value,
            },
        )

    logger.info(
        f"User {current_user['username']} installed Kensa update " f"from {result.from_version} to {result.to_version}"
    )

    return result


@router.post(
    "/updates/install-offline",
    response_model=UpdateInstallResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Install offline Kensa update",
    description="Install Kensa update from uploaded package (air-gapped mode).",
)
@require_role([UserRole.SUPER_ADMIN])
async def install_offline_update(
    package: UploadFile = File(..., description="Kensa update package (.tar.gz)"),
    checksum: str = Query(..., description="Expected SHA256 checksum"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Install a Kensa update from an uploaded package.

    For air-gapped environments where the server cannot reach the update registry.

    Upload the package file and provide the expected SHA256 checksum.
    """
    import tempfile
    from pathlib import Path

    # Save uploaded file
    temp_dir = Path(tempfile.mkdtemp())
    package_path = temp_dir / package.filename

    with open(package_path, "wb") as f:
        content = await package.read()
        f.write(content)

    config = get_kensa_config()
    updater = KensaUpdater(db, config)

    result = await updater.install_offline_package(
        package_path=package_path,
        expected_checksum=checksum,
        user_id=current_user["id"],
    )

    # Cleanup temp file
    package_path.unlink(missing_ok=True)
    temp_dir.rmdir()

    if not result.success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "offline_update_failed",
                "message": result.error,
            },
        )

    logger.info(
        f"User {current_user['username']} installed offline Kensa update "
        f"from {result.from_version} to {result.to_version}"
    )

    return result


# =============================================================================
# Update History & Progress
# =============================================================================


@router.get(
    "/updates/history",
    response_model=UpdateHistoryResponse,
    summary="Get update history",
    description="Get history of Kensa updates.",
)
@require_role([UserRole.SECURITY_ADMIN, UserRole.SUPER_ADMIN])
async def get_update_history(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get history of Kensa updates."""
    from sqlalchemy import text

    offset = (page - 1) * per_page

    query = """
        SELECT id, from_version, to_version, status, changes,
               initiated_by, created_at, completed_at, error_message
        FROM plugin_updates
        WHERE plugin_id = 'kensa'
        ORDER BY created_at DESC
        LIMIT :limit OFFSET :offset
    """
    result = db.execute(text(query), {"limit": per_page, "offset": offset})
    rows = result.fetchall()

    count_query = "SELECT COUNT(*) FROM plugin_updates WHERE plugin_id = 'kensa'"
    total = db.execute(text(count_query)).scalar() or 0

    items = [
        UpdateHistoryItem(
            id=row.id,
            from_version=row.from_version,
            to_version=row.to_version,
            status=PluginUpdateStatus(row.status),
            changes=row.changes or [],
            initiated_by=row.initiated_by,
            created_at=row.created_at,
            completed_at=row.completed_at,
            error_message=row.error_message,
        )
        for row in rows
    ]

    return UpdateHistoryResponse(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get(
    "/updates/{update_id}/progress",
    response_model=UpdateProgressResponse,
    summary="Get update progress",
    description="Get progress of a running update.",
)
@require_role([UserRole.SECURITY_ADMIN, UserRole.SUPER_ADMIN])
async def get_update_progress(
    update_id: UUID,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get progress of a running or completed update."""
    from sqlalchemy import text

    query = """
        SELECT id, status, progress, started_at, error_message
        FROM plugin_updates
        WHERE id = :id
    """
    result = db.execute(text(query), {"id": update_id})
    row = result.fetchone()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Update {update_id} not found",
        )

    from datetime import datetime, timezone

    elapsed = 0
    if row.started_at:
        elapsed = int((datetime.now(timezone.utc) - row.started_at).total_seconds())

    # Map status to current step
    step_map = {
        "pending": "Waiting to start",
        "downloading": "Downloading package",
        "verifying": "Verifying package integrity",
        "installing": "Installing update",
        "completed": "Update complete",
        "failed": "Update failed",
        "rolled_back": "Rolled back to previous version",
    }

    return UpdateProgressResponse(
        update_id=row.id,
        status=PluginUpdateStatus(row.status),
        progress=row.progress,
        current_step=step_map.get(row.status, "Unknown"),
        message=row.error_message,
        started_at=row.started_at or datetime.now(timezone.utc),
        elapsed_seconds=elapsed,
    )


# =============================================================================
# Changelog
# =============================================================================


@router.get(
    "/changelog",
    response_model=ChangelogResponse,
    summary="Get Kensa changelog",
    description="Get the changelog for the installed Kensa version.",
)
@require_role([UserRole.SECURITY_ANALYST, UserRole.SECURITY_ADMIN, UserRole.SUPER_ADMIN])
async def get_changelog(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get the Kensa changelog."""
    config = get_kensa_config()
    updater = KensaUpdater(db, config)

    changelog = updater.get_changelog()
    current_version = updater._get_current_version()

    return ChangelogResponse(
        plugin_id="kensa",
        current_version=current_version,
        changelog_markdown=changelog,
    )


# =============================================================================
# Notifications
# =============================================================================


@router.get(
    "/updates/notifications",
    response_model=UpdateNotificationListResponse,
    summary="Get update notifications",
    description="Get pending update notifications.",
)
@require_role([UserRole.SECURITY_ADMIN, UserRole.SUPER_ADMIN])
async def get_update_notifications(
    include_dismissed: bool = Query(False, description="Include dismissed notifications"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get pending update notifications."""
    from sqlalchemy import text

    query = """
        SELECT id, plugin_id, current_version, available_version,
               min_openwatch_version, changes, dismissed, checked_at, created_at
        FROM plugin_update_notifications
        WHERE (:include_dismissed OR dismissed = false)
        ORDER BY created_at DESC
    """
    result = db.execute(text(query), {"include_dismissed": include_dismissed})
    rows = result.fetchall()

    notifications = [
        UpdateNotification(
            id=row.id,
            plugin_id=row.plugin_id,
            plugin_name="Kensa Compliance Engine" if row.plugin_id == "kensa" else row.plugin_id,
            current_version=row.current_version,
            available_version=row.available_version,
            changes=row.changes or [],
            min_openwatch_version=row.min_openwatch_version,
            dismissed=row.dismissed,
            checked_at=row.checked_at,
            created_at=row.created_at,
        )
        for row in rows
    ]

    return UpdateNotificationListResponse(
        notifications=notifications,
        total=len(notifications),
    )


@router.post(
    "/updates/notifications/dismiss",
    summary="Dismiss update notification",
    description="Dismiss an update notification.",
)
@require_role([UserRole.SECURITY_ADMIN, UserRole.SUPER_ADMIN])
async def dismiss_notification(
    request: DismissNotificationRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Dismiss an update notification."""
    from sqlalchemy import text

    query = """
        UPDATE plugin_update_notifications
        SET dismissed = true,
            dismissed_by = :user_id,
            dismissed_at = CURRENT_TIMESTAMP
        WHERE id = :id
    """
    result = db.execute(
        text(query),
        {"id": request.notification_id, "user_id": current_user["id"]},
    )
    db.commit()

    if result.rowcount == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification not found",
        )

    return {"message": "Notification dismissed"}


# =============================================================================
# Plugin Health
# =============================================================================


@router.get(
    "/health",
    response_model=PluginHealthResponse,
    summary="Get Kensa health",
    description="Get health status of the Kensa plugin.",
)
@require_role([UserRole.SECURITY_ANALYST, UserRole.SECURITY_ADMIN, UserRole.SUPER_ADMIN])
async def get_kensa_health(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get health status of the Kensa plugin."""
    from datetime import datetime, timezone

    config = get_kensa_config()
    updater = KensaUpdater(db, config)

    current_version = updater._get_current_version()
    healthy = True
    rules_loaded = 0
    frameworks = []
    error = None
    details = {}

    try:
        # Try to load rules
        from runner.engine import load_rules

        rules = load_rules(str(config.rules_path))
        rules_loaded = len(rules)

        # Get unique frameworks
        framework_set = set()
        for rule in rules:
            if hasattr(rule, "frameworks") and rule.frameworks:
                framework_set.update(rule.frameworks.keys())
        frameworks = sorted(framework_set)

        details = {
            "rules_path": str(config.rules_path),
            "kensa_path": str(config.kensa_path),
            "rules_path_exists": config.rules_path.exists(),
        }

    except Exception as e:
        healthy = False
        error = str(e)

    # Update registry health status
    from sqlalchemy import text

    query = """
        UPDATE plugin_registry
        SET health_status = :status,
            last_health_check = CURRENT_TIMESTAMP
        WHERE plugin_id = 'kensa'
    """
    db.execute(text(query), {"status": "healthy" if healthy else "unhealthy"})
    db.commit()

    return PluginHealthResponse(
        plugin_id="kensa",
        healthy=healthy,
        version=current_version,
        rules_loaded=rules_loaded,
        frameworks_supported=frameworks,
        last_check=datetime.now(timezone.utc),
        details=details,
        error=error,
    )
