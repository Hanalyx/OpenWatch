"""
Admin endpoints for transaction table management.

Provides a backfill trigger to migrate historical scan_findings
into the transactions table.
"""

from typing import Dict

from fastapi import APIRouter, Depends

from app.auth import get_current_user
from app.rbac import UserRole, require_role

router = APIRouter(prefix="/admin/transactions", tags=["admin"])


@router.post("/backfill")
@require_role([UserRole.SUPER_ADMIN])
async def trigger_backfill(
    chunk_size: int = 10000,
    current_user: Dict = Depends(get_current_user),
):
    """Trigger an async backfill of scan_findings into transactions.

    Requires SUPER_ADMIN role. The backfill runs as a Celery task
    and is idempotent -- safe to call multiple times.

    Args:
        chunk_size: Number of rows per processing chunk (default 10000).

    Returns:
        Dict with task_id and queued status.
    """
    from app.services.job_queue.dispatch import enqueue_task

    job_id = enqueue_task("app.tasks.backfill_host_rule_state", chunk_size=chunk_size)
    return {"task_id": job_id, "status": "queued"}
