"""Job queue worker -- polls PostgreSQL, dispatches tasks, enforces timeouts.

Uses signal.alarm() for per-task timeout enforcement on Unix. Handles
SIGTERM/SIGINT for graceful shutdown (finish current task, stop polling).

Spec: specs/system/job-queue.spec.yaml (AC-5, AC-7)
"""

import logging
import os
import signal
import time
from typing import Any, Callable, Dict, Optional

from app.database import SessionLocal

from .service import JobQueueService

logger = logging.getLogger(__name__)


class Worker:
    """Polls job_queue table and dispatches tasks to registered handlers.

    Attributes:
        queues: List of queue names to poll in round-robin order.
        concurrency: Maximum concurrent tasks (reserved for future use).
        poll_interval: Seconds to sleep when no jobs are available.
    """

    def __init__(
        self,
        queues: Optional[list[str]] = None,
        concurrency: Optional[int] = None,
        poll_interval: float = 1.0,
    ):
        self.queues = queues or ["default"]
        self.concurrency = concurrency or os.cpu_count() or 4
        self.poll_interval = poll_interval
        self._running = True
        self._registry: Dict[str, Callable] = {}

    def register(self, task_name: str, func: Callable) -> None:
        """Register a single task handler.

        Args:
            task_name: Dotted task name matching enqueue calls.
            func: Callable that accepts **kwargs from job args.
        """
        self._registry[task_name] = func

    def register_all(self, registry: Dict[str, Callable]) -> None:
        """Bulk-register task handlers from a dict.

        Args:
            registry: Mapping of task_name to callable.
        """
        self._registry.update(registry)

    def run(self) -> None:
        """Main loop. Handles SIGTERM/SIGINT for graceful shutdown."""
        signal.signal(signal.SIGTERM, self._handle_sigterm)
        signal.signal(signal.SIGINT, self._handle_sigterm)

        logger.info(
            "Worker starting: queues=%s, concurrency=%d",
            self.queues,
            self.concurrency,
        )

        while self._running:
            dispatched = False
            for queue in self.queues:
                db = SessionLocal()
                try:
                    service = JobQueueService(db)
                    job = service.dequeue(queue)
                    if job:
                        dispatched = True
                        self._execute(job, db)
                finally:
                    db.close()

            if not dispatched:
                time.sleep(self.poll_interval)

    def _execute(self, job: Dict[str, Any], db: Any) -> None:
        """Execute a single job with timeout enforcement via signal.alarm().

        Args:
            job: Job metadata dict from dequeue().
            db: SQLAlchemy session for status updates.
        """
        task_name = job["task_name"]
        handler = self._registry.get(task_name)
        service = JobQueueService(db)

        if not handler:
            service.fail(job["id"], f"Unknown task: {task_name}", retry=False)
            logger.error("No handler for task %s", task_name)
            return

        timeout = job.get("timeout_seconds", 3600)
        logger.info("Executing %s (job=%s, timeout=%ds)", task_name, job["id"], timeout)

        try:
            # Enforce timeout via signal.alarm on Unix
            old_handler = signal.signal(signal.SIGALRM, self._alarm_handler)
            signal.alarm(timeout)

            result = handler(**job["args"])

            signal.alarm(0)  # Cancel alarm
            signal.signal(signal.SIGALRM, old_handler)

            service.complete(
                job["id"],
                result if isinstance(result, dict) else {"result": str(result)},
            )
            logger.info("Completed %s (job=%s)", task_name, job["id"])

        except TimeoutError:
            signal.alarm(0)
            service.fail(job["id"], f"Task timed out after {timeout}s", retry=True)
            logger.error(
                "Timeout %s (job=%s) after %ds",
                task_name,
                job["id"],
                timeout,
            )

        except Exception as exc:
            signal.alarm(0)
            service.fail(job["id"], str(exc)[:2000], retry=True)
            logger.exception("Failed %s (job=%s): %s", task_name, job["id"], exc)

    def _alarm_handler(self, signum: int, frame: Any) -> None:
        """Signal handler for SIGALRM -- raises TimeoutError."""
        raise TimeoutError("Task execution timed out")

    def _handle_sigterm(self, signum: int, frame: Any) -> None:
        """Signal handler for SIGTERM/SIGINT -- triggers graceful shutdown."""
        logger.info("Received signal %d, shutting down gracefully...", signum)
        self._running = False
