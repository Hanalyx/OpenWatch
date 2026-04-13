"""
Celery task for dispatching alert notifications to enabled channels.

Runs asynchronously so that AlertService.create_alert() is never blocked
by outbound HTTP/SMTP calls.  Each channel is attempted independently;
one failure does not prevent delivery to other channels.  Results are
recorded in the notification_deliveries table.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict

from sqlalchemy import text

from app.database import SessionLocal
from app.utils.mutation_builders import InsertBuilder

logger = logging.getLogger(__name__)


def dispatch_alert_notifications(alert_data: Dict[str, Any]) -> Dict[str, Any]:
    """Dispatch an alert to notification channels matched by routing rules.

    First checks alert_routing_rules for rules matching the alert's
    severity and type.  If matching rules exist, dispatches only to
    those channels.  If NO matching rules exist, falls back to
    dispatching to ALL enabled channels (AC-6 default behaviour).

    Runs async so AlertService.create_alert() is not blocked.
    Each channel is attempted independently -- one failure doesn't block
    others.  Results are recorded in notification_deliveries table.

    Args:
        alert_data: Dict with alert_id, alert_type, severity, title, and
            optional host_id, rule_id, detail keys.

    Returns:
        Summary dict with dispatched count and per-channel results.
    """
    db = SessionLocal()
    try:
        # Check routing rules for targeted dispatch (AC-2, AC-3)
        routing_query = text("""
            SELECT DISTINCT arr.channel_id
            FROM alert_routing_rules arr
            WHERE arr.enabled = true
            AND (arr.severity = :severity OR arr.severity = 'all')
            AND (arr.alert_type = :alert_type OR arr.alert_type = 'all')
        """)
        rules = db.execute(routing_query, {
            "severity": alert_data.get("severity"),
            "alert_type": alert_data.get("alert_type"),
        }).fetchall()

        if rules:
            # Dispatch to matched channels only
            channel_ids = [str(r.channel_id) for r in rules]
            channels_query = text(
                "SELECT id, channel_type, config_encrypted "
                "FROM notification_channels "
                "WHERE id = ANY(:ids) AND enabled = true"
            )
            channels = db.execute(channels_query, {"ids": channel_ids}).fetchall()
        else:
            # Default: all enabled channels (AC-6 fallback)
            channels_query = text(
                "SELECT id, channel_type, config_encrypted "
                "FROM notification_channels WHERE enabled = true"
            )
            channels = db.execute(channels_query).fetchall()

        if not channels:
            return {"dispatched": 0, "channels": []}

        from app.encryption import decrypt_data
        from app.services.notifications import (
            EmailChannel,
            JiraChannel,
            PagerDutyChannel,
            SlackChannel,
            WebhookChannel,
        )

        channel_map = {
            "slack": SlackChannel,
            "email": EmailChannel,
            "webhook": WebhookChannel,
            "pagerduty": PagerDutyChannel,
            "jira": JiraChannel,
        }

        results = []

        for ch in channels:
            try:
                # Decrypt config (bytes in, bytes out)
                config = json.loads(decrypt_data(ch.config_encrypted))

                channel_cls = channel_map.get(ch.channel_type)
                if not channel_cls:
                    logger.warning(
                        "Unknown channel type %s for channel %s",
                        ch.channel_type,
                        ch.id,
                    )
                    continue

                channel = channel_cls(config)

                # send() is async; run it in a one-shot event loop
                result = asyncio.run(channel.send(alert_data))

                # Record delivery
                delivery_insert = (
                    InsertBuilder("notification_deliveries")
                    .columns(
                        "alert_id",
                        "channel_id",
                        "status",
                        "response_code",
                        "response_body",
                        "attempted_at",
                    )
                    .values(
                        alert_data.get("alert_id"),
                        str(ch.id),
                        "delivered" if result.success else "failed",
                        result.status_code,
                        (result.response_body or result.error or "")[:2000],
                        datetime.now(timezone.utc),
                    )
                )
                q, p = delivery_insert.build()
                db.execute(text(q), p)

                results.append(
                    {
                        "channel_id": str(ch.id),
                        "type": ch.channel_type,
                        "success": result.success,
                    }
                )

            except Exception as e:
                logger.warning("Failed to dispatch to channel %s: %s", ch.id, e)
                results.append(
                    {
                        "channel_id": str(ch.id),
                        "type": ch.channel_type,
                        "success": False,
                        "error": str(e),
                    }
                )

        db.commit()
        return {"dispatched": len(results), "channels": results}
    finally:
        db.close()
