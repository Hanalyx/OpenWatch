"""
Exception Management Tasks

Celery tasks for managing compliance exception lifecycle.

Part of Phase 3: Governance Primitives (Aegis Integration Plan)
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict

from celery import shared_task

from app.database import SessionLocal
from app.services.compliance import ExceptionService

logger = logging.getLogger(__name__)


@shared_task(name="expire_compliance_exceptions")
def expire_compliance_exceptions() -> Dict[str, Any]:
    """
    Mark expired exceptions as expired.

    This task should be scheduled to run periodically (e.g., every hour)
    to maintain the exception lifecycle.

    Returns:
        Summary of expiration results
    """
    logger.info("Starting compliance exception expiration check")

    db = SessionLocal()
    try:
        service = ExceptionService(db)
        expired_count = service.expire_exceptions()

        logger.info("Compliance exception expiration complete: %d expired", expired_count)

        return {
            "success": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "expired": expired_count,
        }

    except Exception as e:
        logger.exception("Failed to expire compliance exceptions: %s", e)
        return {
            "success": False,
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    finally:
        db.close()


__all__ = [
    "expire_compliance_exceptions",
]
