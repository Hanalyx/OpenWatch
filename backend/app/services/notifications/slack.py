"""
Slack notification channel using slack-sdk incoming webhooks.

Messages are formatted with Block Kit: a header block showing severity
and alert type, a section with host/rule/detail, and a link back to
the OpenWatch dashboard.

Sensitive evidence fields (stdout, credentials) are intentionally
excluded from the payload.
"""

import logging
from typing import Any, Dict

from .base import DeliveryResult, NotificationChannel

logger = logging.getLogger(__name__)

# Fields that must never appear in Slack payloads (security requirement AC-8)
_SENSITIVE_KEYS = frozenset(
    {
        "stdout",
        "stderr",
        "credentials",
        "password",
        "private_key",
        "secret",
        "token",
        "api_key",
        "evidence",
    }
)

# Severity-to-emoji mapping for the header
_SEVERITY_ICON: Dict[str, str] = {
    "critical": "[CRITICAL]",
    "high": "[HIGH]",
    "medium": "[MEDIUM]",
    "low": "[LOW]",
    "info": "[INFO]",
}


def _sanitize_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Strip sensitive keys from alert dict before formatting."""
    return {k: v for k, v in alert.items() if k.lower() not in _SENSITIVE_KEYS}


def _build_blocks(alert: Dict[str, Any], base_url: str) -> list:
    """Build Slack Block Kit blocks for an alert notification."""
    safe = _sanitize_alert(alert)
    severity = str(safe.get("severity", "info")).lower()
    icon = _SEVERITY_ICON.get(severity, "[ALERT]")
    alert_type = safe.get("type", safe.get("alert_type", "alert"))
    title = safe.get("title", "OpenWatch Alert")

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{icon} {alert_type}: {title}"[:150],
            },
        },
    ]

    # Detail section
    fields = []
    if safe.get("host_id"):
        fields.append({"type": "mrkdwn", "text": f"*Host:* `{safe['host_id']}`"})
    if safe.get("rule_id"):
        fields.append({"type": "mrkdwn", "text": f"*Rule:* `{safe['rule_id']}`"})
    if safe.get("severity"):
        fields.append({"type": "mrkdwn", "text": f"*Severity:* {safe['severity']}"})
    if safe.get("detail"):
        detail_text = str(safe["detail"])[:300]
        fields.append({"type": "mrkdwn", "text": f"*Detail:* {detail_text}"})

    if fields:
        blocks.append({"type": "section", "fields": fields})

    # Link back to OpenWatch
    if base_url:
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"<{base_url}|View in OpenWatch>"},
                ],
            }
        )

    return blocks


class SlackChannel(NotificationChannel):
    """Slack incoming-webhook notification channel.

    Config keys:
        webhook_url (str): Slack incoming webhook URL (required).
        base_url (str): OpenWatch dashboard URL for deep-links (optional).
    """

    async def send(self, alert: Dict[str, Any]) -> DeliveryResult:
        """Post an alert to a Slack channel via incoming webhook.

        Uses slack-sdk AsyncWebhookClient with Block Kit formatting.
        Never raises -- returns DeliveryResult on all outcomes.
        """
        webhook_url = self.config.get("webhook_url", "")
        if not webhook_url:
            return DeliveryResult(
                success=False,
                error="Missing webhook_url in channel config",
            )

        base_url = self.config.get("base_url", "")
        blocks = _build_blocks(alert, base_url)

        try:
            from slack_sdk.webhook.async_client import AsyncWebhookClient

            client = AsyncWebhookClient(url=webhook_url)
            response = await client.send(blocks=blocks)
            return DeliveryResult(
                success=response.status_code == 200,
                status_code=response.status_code,
                response_body=response.body if hasattr(response, "body") else None,
                error=None if response.status_code == 200 else f"Slack returned {response.status_code}",
            )
        except Exception as exc:
            logger.exception("Slack notification delivery failed")
            return DeliveryResult(
                success=False,
                error=f"SlackChannel error: {exc}",
            )
