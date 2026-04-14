"""Retention policy enforcement tasks.

Provides the ``cleanup_old_transactions`` task that is invoked on
schedule by the PostgreSQL job queue to delete expired rows based
on configured retention policies.

Spec: specs/services/compliance/retention-policy.spec.yaml (AC-3)
"""

import logging
from typing import Any, Dict

from app.database import SessionLocal
from app.services.compliance.retention_policy import RetentionService

logger = logging.getLogger(__name__)


def cleanup_old_transactions() -> Dict[str, Any]:
    """Enforce all enabled retention policies.

    Deletes rows older than the configured retention_days for each
    resource type.  Does NOT delete host_rule_state rows.

    Returns:
        Dict with per-resource deletion counts.
    """
    logger.info("Starting retention enforcement (cleanup_old_transactions)")

    db = SessionLocal()
    try:
        service = RetentionService(db)
        result = service.enforce()
        logger.info("Retention enforcement complete: %s", result)
        return result
    except Exception:
        logger.exception("Retention enforcement failed")
        raise
    finally:
        db.close()
