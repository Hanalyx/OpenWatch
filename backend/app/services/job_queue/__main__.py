"""Entry point: python -m app.services.job_queue

Starts the job queue worker (main thread) and recurring job scheduler
(background daemon thread). The worker polls all configured queues and
dispatches tasks to registered handlers.
"""

import logging
import threading

from .registry import build_registry
from .scheduler import Scheduler
from .worker import Worker

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)


def main() -> None:
    """Start worker and scheduler."""
    registry = build_registry()

    worker = Worker(
        queues=[
            "default",
            "scans",
            "maintenance",
            "monitoring",
            "host_monitoring",
            "compliance_scanning",
        ],
    )
    worker.register_all(registry)

    # Run scheduler in a background daemon thread
    scheduler = Scheduler(check_interval=10.0)
    scheduler_thread = threading.Thread(target=scheduler.run, daemon=True)
    scheduler_thread.start()

    # Run worker in main thread (handles SIGTERM/SIGINT)
    worker.run()


if __name__ == "__main__":
    main()
