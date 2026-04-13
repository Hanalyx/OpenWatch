"""
Email notification channel using aiosmtplib for async SMTP delivery.

Supports STARTTLS (port 587) and SMTPS (port 465).  Messages are sent as
multipart HTML + plaintext so that both rich and text-only mail clients
render a readable alert.  Templates use f-strings (no external engine).
"""

import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List

from .base import DeliveryResult, NotificationChannel

logger = logging.getLogger(__name__)


def _plain_body(alert: Dict[str, Any]) -> str:
    """Render plaintext email body."""
    severity = alert.get("severity", "info")
    alert_type = alert.get("type", alert.get("alert_type", "alert"))
    title = alert.get("title", "OpenWatch Alert")
    host = alert.get("host_id", "N/A")
    rule = alert.get("rule_id", "N/A")
    detail = alert.get("detail", "")
    return (
        f"OpenWatch Alert\n"
        f"{'=' * 40}\n\n"
        f"Type:     {alert_type}\n"
        f"Severity: {severity}\n"
        f"Title:    {title}\n"
        f"Host:     {host}\n"
        f"Rule:     {rule}\n\n"
        f"Detail:\n{detail}\n"
    )


def _html_body(alert: Dict[str, Any]) -> str:
    """Render HTML email body."""
    severity = alert.get("severity", "info")
    alert_type = alert.get("type", alert.get("alert_type", "alert"))
    title = alert.get("title", "OpenWatch Alert")
    host = alert.get("host_id", "N/A")
    rule = alert.get("rule_id", "N/A")
    detail = alert.get("detail", "")
    return (
        "<html><body>"
        f"<h2>OpenWatch Alert</h2>"
        f"<table>"
        f"<tr><td><b>Type</b></td><td>{alert_type}</td></tr>"
        f"<tr><td><b>Severity</b></td><td>{severity}</td></tr>"
        f"<tr><td><b>Title</b></td><td>{title}</td></tr>"
        f"<tr><td><b>Host</b></td><td>{host}</td></tr>"
        f"<tr><td><b>Rule</b></td><td>{rule}</td></tr>"
        f"</table>"
        f"<p>{detail}</p>"
        "</body></html>"
    )


def _build_message(
    alert: Dict[str, Any],
    from_addr: str,
    to_addrs: List[str],
    cc_addrs: List[str],
    bcc_addrs: List[str],
) -> MIMEMultipart:
    """Build a multipart email message from an alert dict."""
    severity = alert.get("severity", "info")
    title = alert.get("title", "OpenWatch Alert")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[OpenWatch] [{severity.upper()}] {title}"
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    if cc_addrs:
        msg["Cc"] = ", ".join(cc_addrs)
    # BCC is intentionally omitted from headers (blind copy)

    msg.attach(MIMEText(_plain_body(alert), "plain", "utf-8"))
    msg.attach(MIMEText(_html_body(alert), "html", "utf-8"))
    return msg


class EmailChannel(NotificationChannel):
    """Email notification channel via async SMTP.

    Config keys:
        smtp_host (str): SMTP server hostname (required).
        smtp_port (int): SMTP port -- 587 for STARTTLS, 465 for SMTPS (default 587).
        smtp_user (str): SMTP authentication username (optional).
        smtp_password (str): SMTP authentication password (optional).
        use_tls (bool): True to use SMTPS (port 465). False for STARTTLS (default False).
        from_address (str): Sender address (required).
        to (list[str]): Primary recipients (required).
        cc (list[str]): CC recipients (optional).
        bcc (list[str]): BCC recipients (optional).
    """

    async def send(self, alert: Dict[str, Any]) -> DeliveryResult:
        """Send an alert notification via SMTP.

        Uses aiosmtplib for async delivery with STARTTLS or SMTPS support.
        Never raises -- returns DeliveryResult on all outcomes.
        """
        smtp_host = self.config.get("smtp_host", "")
        if not smtp_host:
            return DeliveryResult(success=False, error="Missing smtp_host in channel config")

        smtp_port = int(self.config.get("smtp_port", 587))
        smtp_user = self.config.get("smtp_user")
        smtp_password = self.config.get("smtp_password")
        use_tls = bool(self.config.get("use_tls", False))
        from_addr = self.config.get("from_address", "openwatch@localhost")
        to_addrs: List[str] = self.config.get("to", [])
        cc_addrs: List[str] = self.config.get("cc", [])
        bcc_addrs: List[str] = self.config.get("bcc", [])

        if not to_addrs:
            return DeliveryResult(success=False, error="No recipients configured (to list empty)")

        all_recipients = list(to_addrs) + list(cc_addrs) + list(bcc_addrs)
        msg = _build_message(alert, from_addr, to_addrs, cc_addrs, bcc_addrs)

        try:
            import aiosmtplib

            kwargs: Dict[str, Any] = {
                "hostname": smtp_host,
                "port": smtp_port,
            }

            if use_tls:
                # SMTPS -- direct TLS on connect (port 465)
                kwargs["use_tls"] = True
            else:
                # STARTTLS -- upgrade after EHLO (port 587)
                kwargs["start_tls"] = True

            if smtp_user and smtp_password:
                kwargs["username"] = smtp_user
                kwargs["password"] = smtp_password

            response = await aiosmtplib.send(
                msg,
                sender=from_addr,
                recipients=all_recipients,
                **kwargs,
            )
            # aiosmtplib.send returns a tuple of (response_dict, message_str)
            # or raises on failure
            return DeliveryResult(
                success=True,
                status_code=250,
                response_body=str(response) if response else None,
            )
        except Exception as exc:
            logger.exception("Email notification delivery failed")
            return DeliveryResult(
                success=False,
                error=f"EmailChannel error: {exc}",
            )
