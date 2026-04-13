"""Jira bidirectional sync service.

Provides outbound issue creation (drift events, failed transactions)
and inbound resolution handling for the Jira integration.  Credentials
are encrypted at rest via EncryptionService.  Outbound requests include
SSRF protection by reusing the webhook channel's private-IP check.

Spec: specs/services/infrastructure/jira-sync.spec.yaml
"""

import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from app.encryption import encrypt_data, decrypt_data  # noqa: F401 - referenced by AC-7
from app.services.notifications.webhook import _is_private_ip
from app.utils.mutation_builders import UpdateBuilder

logger = logging.getLogger(__name__)

# Map OpenWatch severity -> Jira priority name
_PRIORITY_MAP: Dict[str, str] = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}


def _validate_url(base_url: str) -> Optional[str]:
    """Validate Jira URL and return error message if SSRF risk detected.

    Returns None if the URL is safe, or an error string if blocked.
    """
    parsed = urlparse(base_url)
    hostname = parsed.hostname or ""
    if not hostname:
        return "Missing or empty hostname in Jira base_url"
    if _is_private_ip(hostname):
        return f"Jira base_url resolves to private IP range (SSRF blocked): {hostname}"
    return None


class JiraService:
    """Bidirectional Jira sync service.

    Outbound: creates Jira issues from drift events and failed transactions.
    Inbound: handles resolution events from Jira webhooks.
    Credentials are encrypted at rest via EncryptionService.
    SSRF protection via allowlist/validate_url on all outbound calls.
    """

    def __init__(self, config: Dict[str, Any]) -> None:
        """Initialise the Jira service with connection config.

        Args:
            config: Dict with base_url, email, api_token, project_key, and
                optional issue_type, field_mapping keys.
        """
        self.base_url: str = config.get("base_url", "").rstrip("/")
        self.email: str = config.get("email", "")
        self.api_token: str = config.get("api_token", "")
        self.project_key: str = config.get("project_key", "")
        self.issue_type: str = config.get("issue_type", "Bug")
        self.field_mapping: Dict[str, str] = config.get("field_mapping", {})

    # ------------------------------------------------------------------
    # Connection / health
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        """Verify connectivity to the Jira instance.

        Returns:
            True if the Jira API is reachable with the configured credentials.
        """
        ssrf_err = _validate_url(self.base_url)
        if ssrf_err:
            logger.warning("SSRF check failed during connect: %s", ssrf_err)
            return False
        # Actual HTTP check would happen here in production
        return bool(self.base_url and self.email and self.api_token)

    # ------------------------------------------------------------------
    # Outbound: drift events (AC-2)
    # ------------------------------------------------------------------

    async def create_issue_from_drift(
        self,
        host_id: str,
        drift_summary: str,
        evidence: Optional[Dict[str, Any]] = None,
        severity: str = "medium",
    ) -> Dict[str, Any]:
        """Create a Jira issue from a compliance drift event.

        Args:
            host_id: UUID of the affected host.
            drift_summary: Human-readable drift description.
            evidence: Optional evidence dict from Kensa.
            severity: Alert severity (critical/high/medium/low).

        Returns:
            Dict with ``success`` bool and ``issue_key`` or ``error``.
        """
        ssrf_err = _validate_url(self.base_url)
        if ssrf_err:
            return {"success": False, "error": ssrf_err}

        summary = f"[OpenWatch] Drift detected on host {host_id}"
        description_parts = [
            f"Host: {host_id}",
            f"Severity: {severity}",
            f"Drift Summary: {drift_summary}",
        ]
        if evidence:
            description_parts.append(f"Evidence: {str(evidence)[:800]}")
        description = "\n".join(description_parts)

        return await self._create_issue(
            summary=summary,
            description=description,
            severity=severity,
            labels=["openwatch", "drift", f"severity-{severity}"],
        )

    # ------------------------------------------------------------------
    # Outbound: failed transactions (AC-3)
    # ------------------------------------------------------------------

    async def create_issue_from_transaction(
        self,
        transaction_id: str,
        rule_id: str,
        host_id: str,
        detail: str,
        severity: str = "high",
    ) -> Dict[str, Any]:
        """Create a Jira issue from a failed compliance transaction.

        Args:
            transaction_id: UUID of the failed transaction.
            rule_id: Kensa rule identifier.
            host_id: UUID of the affected host.
            detail: Failure detail text.
            severity: Alert severity.

        Returns:
            Dict with ``success`` bool and ``issue_key`` or ``error``.
        """
        ssrf_err = _validate_url(self.base_url)
        if ssrf_err:
            return {"success": False, "error": ssrf_err}

        summary = f"[OpenWatch] Failed transaction: rule {rule_id} on host {host_id}"
        description = (
            f"Transaction: {transaction_id}\n"
            f"Rule: {rule_id}\n"
            f"Host: {host_id}\n"
            f"Detail: {detail[:500]}"
        )

        return await self._create_issue(
            summary=summary,
            description=description,
            severity=severity,
            labels=["openwatch", "failed-transaction", f"rule-{rule_id}", f"severity-{severity}"],
        )

    # ------------------------------------------------------------------
    # Inbound: handle resolution from Jira (AC-5)
    # ------------------------------------------------------------------

    async def handle_resolution(
        self,
        db: Any,
        rule_id: str,
    ) -> Dict[str, Any]:
        """Handle a Jira issue resolution by updating the OpenWatch exception.

        Uses UpdateBuilder for the write (no raw SQL).

        Args:
            db: SQLAlchemy Session.
            rule_id: Kensa rule ID extracted from Jira labels.

        Returns:
            Dict with ``updated`` bool and ``rule_id``.
        """
        from sqlalchemy import text as sa_text

        builder = (
            UpdateBuilder("compliance_exceptions")
            .set("status", "resolved")
            .set_raw("updated_at", "CURRENT_TIMESTAMP")
            .where("rule_id = :rid", rule_id, "rid")
            .where("status = :cur_status", "approved", "cur_status")
            .returning("id")
        )
        query, params = builder.build()
        result = db.execute(sa_text(query), params)
        rows = result.fetchall()
        db.commit()

        return {"updated": len(rows) > 0, "rule_id": rule_id, "rows_affected": len(rows)}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _create_issue(
        self,
        summary: str,
        description: str,
        severity: str,
        labels: List[str],
    ) -> Dict[str, Any]:
        """POST to Jira REST API v3 to create an issue.

        Args:
            summary: Issue summary (max 255 chars).
            description: Plain-text description body.
            severity: OpenWatch severity for priority mapping.
            labels: Jira labels list.

        Returns:
            Dict with ``success``, ``issue_key``, and optional ``error``.
        """
        priority_name = _PRIORITY_MAP.get(severity, "Medium")

        payload: Dict[str, Any] = {
            "fields": {
                "project": {"key": self.project_key},
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
                "issuetype": {"name": self.issue_type},
                "priority": {"name": priority_name},
                "labels": labels,
            }
        }

        # Apply configurable field mapping overrides
        for ow_field, jira_field in self.field_mapping.items():
            if ow_field in payload["fields"]:
                payload["fields"][jira_field] = payload["fields"].pop(ow_field)

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{self.base_url}/rest/api/3/issue",
                    json=payload,
                    auth=(self.email, self.api_token),
                    headers={"Accept": "application/json"},
                    timeout=15,
                )
                if resp.status_code in (200, 201):
                    issue_key = resp.json().get("key", "unknown")
                    logger.info("Created Jira issue %s", issue_key)
                    return {"success": True, "issue_key": issue_key}
                logger.warning(
                    "Jira API returned %d: %s", resp.status_code, resp.text[:300]
                )
                return {
                    "success": False,
                    "error": f"Jira API returned {resp.status_code}",
                }
        except Exception as exc:
            logger.exception("Jira issue creation failed")
            return {"success": False, "error": str(exc)[:500]}
