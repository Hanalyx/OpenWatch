"""PostgreSQL-native job queue using SKIP LOCKED for concurrent dispatch.

Provides enqueue, dequeue, complete, and fail operations backed by the
job_queue table. Dequeue uses SELECT ... FOR UPDATE SKIP LOCKED to
guarantee exactly-once dispatch across concurrent workers.

Spec: specs/system/job-queue.spec.yaml (AC-1, AC-2, AC-3, AC-4)
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.utils.mutation_builders import InsertBuilder, UpdateBuilder

logger = logging.getLogger(__name__)


class JobQueueService:
    """Job queue operations using PostgreSQL SKIP LOCKED."""

    def __init__(self, db: Session):
        self.db = db

    def enqueue(
        self,
        task_name: str,
        args: Optional[Dict[str, Any]] = None,
        queue: str = "default",
        priority: int = 0,
        delay_seconds: int = 0,
        max_retries: int = 0,
        timeout_seconds: int = 3600,
    ) -> str:
        """Insert a pending job. Returns job ID.

        Args:
            task_name: Dotted task name (e.g. 'app.tasks.ping_all_managed_hosts').
            args: Keyword arguments passed to the task handler.
            queue: Queue name for routing (default, scans, maintenance, etc.).
            priority: Higher values are dequeued first.
            delay_seconds: Delay before the job becomes eligible for dequeue.
            max_retries: Maximum retry attempts on failure.
            timeout_seconds: Per-execution timeout enforced by the worker.

        Returns:
            String UUID of the created job.
        """
        scheduled_at = datetime.now(timezone.utc)
        if delay_seconds > 0:
            scheduled_at += timedelta(seconds=delay_seconds)

        builder = (
            InsertBuilder("job_queue")
            .columns(
                "task_name",
                "args",
                "queue",
                "priority",
                "scheduled_at",
                "max_retries",
                "timeout_seconds",
            )
            .values(
                task_name,
                json.dumps(args or {}),
                queue,
                priority,
                scheduled_at,
                max_retries,
                timeout_seconds,
            )
            .returning("id")
        )
        q, p = builder.build()
        row = self.db.execute(text(q), p).fetchone()
        self.db.commit()
        return str(row.id)

    def dequeue(self, queue: str = "default") -> Optional[Dict[str, Any]]:
        """Atomically claim the next pending job via SKIP LOCKED.

        Uses SELECT ... FOR UPDATE SKIP LOCKED inside an UPDATE ... WHERE id = (...)
        subquery to atomically transition a single pending job to running status.

        Args:
            queue: Queue name to poll.

        Returns:
            Dict with job metadata if a job was claimed, None otherwise.
        """
        now = datetime.now(timezone.utc)
        row = self.db.execute(
            text(
                """
                UPDATE job_queue
                SET status = 'running', started_at = :now
                WHERE id = (
                    SELECT id FROM job_queue
                    WHERE status = 'pending'
                      AND scheduled_at <= :now
                      AND queue = :queue
                    ORDER BY priority DESC, created_at ASC
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED
                )
                RETURNING id, task_name, args, priority, retry_count,
                          max_retries, timeout_seconds, created_at
            """
            ),
            {"now": now, "queue": queue},
        ).fetchone()

        if not row:
            return None

        self.db.commit()
        return {
            "id": str(row.id),
            "task_name": row.task_name,
            "args": json.loads(row.args) if isinstance(row.args, str) else (row.args or {}),
            "priority": row.priority,
            "retry_count": row.retry_count,
            "max_retries": row.max_retries,
            "timeout_seconds": row.timeout_seconds,
        }

    def complete(self, job_id: str, result: Optional[Dict] = None) -> None:
        """Mark job completed with optional result.

        Args:
            job_id: UUID string of the job to complete.
            result: Optional dict stored as JSONB in the result column.
        """
        builder = (
            UpdateBuilder("job_queue")
            .set("status", "completed")
            .set("completed_at", datetime.now(timezone.utc))
            .set("result", json.dumps(result) if result else None)
            .where("id = :id", job_id, "id")
        )
        q, p = builder.build()
        self.db.execute(text(q), p)
        self.db.commit()

    def fail(self, job_id: str, error: str, retry: bool = True) -> None:
        """Mark job failed. Re-enqueue with exponential backoff if retries remain.

        Backoff formula: scheduled_at = NOW() + (2^retry_count * 60) seconds.

        Args:
            job_id: UUID string of the failed job.
            error: Error message (truncated to 2000 chars).
            retry: Whether to attempt retry (if retries remain).
        """
        # Get current state to decide retry vs permanent failure
        row = self.db.execute(
            text("SELECT retry_count, max_retries FROM job_queue WHERE id = :id"),
            {"id": job_id},
        ).fetchone()

        if row and retry and row.retry_count < row.max_retries:
            # Re-enqueue with exponential backoff: 60s, 120s, 240s, ...
            backoff = 2**row.retry_count * 60
            scheduled_at = datetime.now(timezone.utc) + timedelta(seconds=backoff)

            builder = (
                UpdateBuilder("job_queue")
                .set("status", "pending")
                .set("retry_count", row.retry_count + 1)
                .set("scheduled_at", scheduled_at)
                .set("started_at", None)
                .set("error", error[:2000])
                .where("id = :id", job_id, "id")
            )
        else:
            builder = (
                UpdateBuilder("job_queue")
                .set("status", "failed")
                .set("completed_at", datetime.now(timezone.utc))
                .set("error", error[:2000])
                .where("id = :id", job_id, "id")
            )

        q, p = builder.build()
        self.db.execute(text(q), p)
        self.db.commit()

    def get_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get job status and result.

        Args:
            job_id: UUID string of the job.

        Returns:
            Dict with id, task_name, status, result, error or None if not found.
        """
        row = self.db.execute(
            text(
                "SELECT id, task_name, status, result, error, "
                "created_at, started_at, completed_at "
                "FROM job_queue WHERE id = :id"
            ),
            {"id": job_id},
        ).fetchone()
        if not row:
            return None
        return {
            "id": str(row.id),
            "task_name": row.task_name,
            "status": row.status,
            "result": row.result,
            "error": row.error,
        }
