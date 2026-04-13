"""
Generic webhook notification channel.

POSTs a JSON payload to a configured URL, signing the body with
HMAC-SHA256 using a per-channel secret.  Outbound URLs that resolve
to private IP ranges are rejected to prevent SSRF.
"""

import hashlib
import hmac
import ipaddress
import json
import logging
import socket
from typing import Any, Dict
from urllib.parse import urlparse

from .base import DeliveryResult, NotificationChannel

logger = logging.getLogger(__name__)

# Private/reserved networks that must be blocked (SSRF protection)
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_private_ip(hostname: str) -> bool:
    """Resolve hostname and check if any resulting IP is in a private range.

    Returns True if the destination should be blocked (SSRF protection).
    """
    try:
        addr_infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        # Cannot resolve -- fail open would be dangerous, fail closed instead
        logger.warning("Cannot resolve hostname %s -- blocking as potential SSRF", hostname)
        return True

    for family, _type, _proto, _canonname, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        for network in _BLOCKED_NETWORKS:
            if ip in network:
                logger.warning(
                    "Webhook URL resolves to private IP %s (network %s) -- blocked",
                    ip_str,
                    network,
                )
                return True
    return False


def _compute_hmac_sha256(secret: str, body: bytes) -> str:
    """Compute HMAC-SHA256 hex digest for webhook payload signing."""
    return hmac.new(
        secret.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()


class WebhookChannel(NotificationChannel):
    """Generic HTTPS webhook notification channel.

    Config keys:
        url (str): Destination URL (required).
        secret (str): HMAC-SHA256 signing secret (required).
        headers (dict): Additional HTTP headers to include (optional).
    """

    async def send(self, alert: Dict[str, Any]) -> DeliveryResult:
        """POST alert payload as JSON to the configured webhook URL.

        The request body is signed with HMAC-SHA256 and the signature is
        included in the ``X-OpenWatch-Signature`` header.  URLs that
        resolve to private IP ranges are rejected (SSRF protection).

        Never raises -- returns DeliveryResult on all outcomes.
        """
        url = self.config.get("url", "")
        secret = self.config.get("secret", "")

        if not url:
            return DeliveryResult(success=False, error="Missing url in channel config")
        if not secret:
            return DeliveryResult(success=False, error="Missing secret in channel config")

        # SSRF protection: reject private IP destinations
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        if _is_private_ip(hostname):
            return DeliveryResult(
                success=False,
                error=f"Webhook URL resolves to private IP range (SSRF blocked): {hostname}",
            )

        body = json.dumps(alert, default=str).encode("utf-8")
        signature = _compute_hmac_sha256(secret, body)

        headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "X-OpenWatch-Signature": f"sha256={signature}",
        }
        # Merge any extra headers from config
        extra_headers = self.config.get("headers")
        if isinstance(extra_headers, dict):
            headers.update(extra_headers)

        try:
            import httpx

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(url, content=body, headers=headers)

            return DeliveryResult(
                success=200 <= response.status_code < 300,
                status_code=response.status_code,
                response_body=response.text[:1000] if response.text else None,
                error=None if 200 <= response.status_code < 300 else f"Webhook returned {response.status_code}",
            )
        except Exception as exc:
            logger.exception("Webhook notification delivery failed")
            return DeliveryResult(
                success=False,
                error=f"WebhookChannel error: {exc}",
            )
