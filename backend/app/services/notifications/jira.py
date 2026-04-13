"""Jira notification channel using REST API v3 (no SDK dependency).

Creates Jira issues via httpx when compliance alerts fire.
Reuses the SSRF protection from the webhook channel to prevent
outbound requests to private IP ranges.

Spec: specs/services/infrastructure/jira-sync.spec.yaml (AC-1, AC-2, AC-3)
"""

import logging
from typing import Any, Dict
from urllib.parse import urlparse

import httpx

from .base import DeliveryResult, NotificationChannel
from .webhook import _is_private_ip

logger = logging.getLogger(__name__)

# Map OpenWatch severity -> Jira priority name
_PRIORITY_MAP: Dict[str, str] = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Lowest",
}


class JiraChannel(NotificationChannel):
    """Creates Jira issues via REST API v3 when alerts fire.

    Config keys:
        base_url (str): Jira instance URL, e.g. https://myorg.atlassian.net (required).
        email (str): Jira user email for basic auth (required).
        api_token (str): Jira API token (required).
        project_key (str): Jira project key, e.g. OPS (required).
        issue_type (str): Issue type name (default: "Bug").
    """

    async def send(self, alert: Dict[str, Any]) -> DeliveryResult:
        """Create a Jira issue from an OpenWatch alert.

        Includes SSRF protection -- rejects URLs that resolve to private
        IP ranges.  Never raises; returns DeliveryResult on all outcomes.

        Args:
            alert: Dict with at least alert_type, severity, title keys.

        Returns:
            DeliveryResult describing the outcome.
        """
        base_url = self.config.get("base_url", "").rstrip("/")
        email = self.config.get("email")
        api_token = self.config.get("api_token")
        project_key = self.config.get("project_key")
        issue_type = self.config.get("issue_type", "Bug")

        if not all([base_url, email, api_token, project_key]):
            return DeliveryResult(
                success=False,
                error="Missing Jira config (base_url, email, api_token, project_key)",
            )

        # SSRF protection: reject private IP destinations
        parsed = urlparse(base_url)
        hostname = parsed.hostname or ""
        if _is_private_ip(hostname):
            return DeliveryResult(
                success=False,
                error=f"Jira base_url resolves to private IP range (SSRF blocked): {hostname}",
            )

        severity = str(alert.get("severity", "medium")).lower()
        priority_name = _PRIORITY_MAP.get(severity, "Medium")

        summary = (
            f"[OpenWatch] {alert.get('alert_type', 'Alert')}: "
            f"{alert.get('title', 'Compliance Alert')}"
        )
        description = self._build_description(alert)

        # Build labels including rule_id for inbound webhook correlation
        labels = ["openwatch", f"severity-{severity}"]
        alert_type = alert.get("alert_type")
        if alert_type:
            labels.append(str(alert_type))
        rule_id = alert.get("rule_id")
        if rule_id:
            labels.append(f"rule-{rule_id}")

        payload: Dict[str, Any] = {
            "fields": {
                "project": {"key": project_key},
                "summary": summary[:255],
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": description}],
                        }
                    ],
                },
                "issuetype": {"name": issue_type},
                "priority": {"name": priority_name},
                "labels": labels,
            }
        }

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{base_url}/rest/api/3/issue",
                    json=payload,
                    auth=(email, api_token),
                    headers={"Accept": "application/json"},
                    timeout=15,
                )
                if resp.status_code in (200, 201):
                    issue_key = resp.json().get("key", "unknown")
                    return DeliveryResult(
                        success=True,
                        status_code=resp.status_code,
                        response_body=f"Created issue {issue_key}",
                    )
                return DeliveryResult(
                    success=False,
                    status_code=resp.status_code,
                    response_body=resp.text[:500],
                )
        except Exception as exc:
            logger.exception("Jira notification delivery failed")
            return DeliveryResult(success=False, error=str(exc)[:500])

    def _build_description(self, alert: Dict[str, Any]) -> str:
        """Build a plain-text description from alert fields.

        Args:
            alert: Alert data dict.

        Returns:
            Multi-line description string.
        """
        parts = [f"Alert Type: {alert.get('alert_type', 'N/A')}"]
        parts.append(f"Severity: {alert.get('severity', 'N/A')}")
        if alert.get("host_id"):
            parts.append(f"Host: {alert.get('host_id')}")
        if alert.get("rule_id"):
            parts.append(f"Rule: {alert.get('rule_id')}")
        if alert.get("detail"):
            parts.append(f"Detail: {str(alert['detail'])[:500]}")
        return "\n".join(parts)
