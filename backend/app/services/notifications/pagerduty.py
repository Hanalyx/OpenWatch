"""PagerDuty notification channel using Events API v2.

Creates PagerDuty incidents for OpenWatch compliance alerts.
Severity is mapped from OpenWatch levels to PagerDuty levels.

Spec: specs/services/compliance/alert-routing.spec.yaml (AC-4)
"""

import logging
from typing import Any, Dict

from .base import DeliveryResult, NotificationChannel

logger = logging.getLogger(__name__)

# Map OpenWatch severity -> PagerDuty severity
_SEVERITY_MAP: Dict[str, str] = {
    "critical": "critical",
    "high": "error",
    "medium": "warning",
    "low": "info",
    "info": "info",
}

PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"


class PagerDutyChannel(NotificationChannel):
    """PagerDuty Events API v2 notification channel.

    Config keys:
        routing_key (str): PagerDuty Events API v2 routing/integration key (required).
    """

    async def send(self, alert: Dict[str, Any]) -> DeliveryResult:
        """Send an alert to PagerDuty via Events API v2.

        Creates a trigger event that generates an incident in PagerDuty.
        Never raises -- returns DeliveryResult on all outcomes.

        Args:
            alert: Dict with at least severity and title keys.

        Returns:
            DeliveryResult describing the outcome.
        """
        routing_key = self.config.get("routing_key")
        if not routing_key:
            return DeliveryResult(success=False, error="No routing_key configured")

        severity = str(alert.get("severity", "warning")).lower()
        pd_severity = _SEVERITY_MAP.get(severity, "warning")

        payload = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": alert.get("title", "OpenWatch Alert"),
                "severity": pd_severity,
                "source": "openwatch",
                "custom_details": {
                    "host_id": alert.get("host_id"),
                    "rule_id": alert.get("rule_id"),
                    "alert_type": alert.get("alert_type"),
                },
            },
        }

        try:
            import httpx

            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    PAGERDUTY_EVENTS_URL,
                    json=payload,
                    timeout=10,
                )
                return DeliveryResult(
                    success=resp.status_code == 202,
                    status_code=resp.status_code,
                    response_body=resp.text[:500],
                    error=None if resp.status_code == 202 else f"PagerDuty returned {resp.status_code}",
                )
        except Exception as exc:
            logger.exception("PagerDuty notification delivery failed")
            return DeliveryResult(
                success=False,
                error=f"PagerDutyChannel error: {exc}",
            )
