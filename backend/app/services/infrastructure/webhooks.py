"""
OpenWatch Webhook Security
HMAC-SHA256 signature generation and verification for webhooks
Compatible with Kensa webhook security implementation
"""

import hashlib
import hmac
import json
import logging
from typing import Any, Dict, Optional, Union

from ...config import get_settings

logger = logging.getLogger(__name__)


class WebhookSecurity:
    """HMAC-SHA256 webhook signature generation and verification"""

    def __init__(self, secret: Optional[str] = None):
        """
        Initialize webhook security with shared secret

        Args:
            secret: Webhook secret key. If None, uses settings
        """
        self.settings = get_settings()
        self.secret = secret or getattr(self.settings, "webhook_secret", None)

        if not self.secret and not self.settings.debug:
            logger.error("Webhook secret not configured")
            raise ValueError("Webhook secret is required for signature generation")

    def generate_signature(self, payload: Union[Dict[str, Any], str, bytes]) -> str:
        """
        Generate HMAC-SHA256 signature for webhook payload

        Args:
            payload: Webhook payload (dict, string, or bytes)

        Returns:
            Signature string in format "sha256=<hex_digest>"

        Raises:
            ValueError: If secret is not configured
        """
        if not self.secret:
            if self.settings.debug:
                logger.warning("Webhook signature generation skipped - no secret in debug mode")
                return "sha256=debug-signature"
            raise ValueError("Webhook secret not configured")

        # Normalize payload to bytes
        if isinstance(payload, dict):
            message = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        elif isinstance(payload, str):
            message = payload.encode("utf-8")
        elif isinstance(payload, bytes):
            message = payload
        else:
            raise ValueError(f"Unsupported payload type: {type(payload)}")

        # Generate HMAC-SHA256 signature
        signature = hmac.new(self.secret.encode("utf-8"), message, hashlib.sha256).hexdigest()

        return f"sha256={signature}"

    def verify_signature(self, payload: Union[Dict[str, Any], str, bytes], received_signature: str) -> bool:
        """
        Verify HMAC-SHA256 signature for webhook payload

        Args:
            payload: Webhook payload (dict, string, or bytes)
            received_signature: Signature from webhook header

        Returns:
            True if signature is valid

        Raises:
            ValueError: If secret is not configured
        """
        if not self.secret:
            if self.settings.debug:
                logger.warning("Webhook signature verification skipped - no secret in debug mode")
                return True
            raise ValueError("Webhook secret not configured")

        try:
            # Generate expected signature
            expected_signature = self.generate_signature(payload)

            # Normalize received signature format
            if not received_signature.startswith("sha256="):
                received_signature = f"sha256={received_signature}"

            # Use constant-time comparison to prevent timing attacks
            is_valid = hmac.compare_digest(expected_signature, received_signature)

            if is_valid:
                logger.debug("Webhook signature verified successfully")
            else:
                logger.warning(
                    f"Webhook signature verification failed: expected={expected_signature[:16]}..., "
                    f"received={received_signature[:16]}..."
                )

            return is_valid

        except Exception as e:
            logger.error(
                f"Error during webhook signature verification: error={e}",
                exc_info=True,
            )
            return False

    def create_webhook_headers(
        self,
        payload: Union[Dict[str, Any], str, bytes],
        event_type: Optional[str] = None,
        delivery_id: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Create HTTP headers for webhook delivery

        Args:
            payload: Webhook payload
            event_type: Type of event (e.g., 'scan.completed')
            delivery_id: Unique delivery ID for tracking

        Returns:
            Dictionary of headers to include in HTTP request
        """
        signature = self.generate_signature(payload)

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "OpenWatch-Webhook/1.0",
            "X-OpenWatch-Signature": signature,
            "X-Hub-Signature-256": signature,  # GitHub compatible
        }

        if event_type:
            headers["X-OpenWatch-Event"] = event_type

        if delivery_id:
            headers["X-OpenWatch-Delivery"] = delivery_id

        return headers

    def extract_signature_from_headers(self, headers: Dict[str, str]) -> Optional[str]:
        """
        Extract webhook signature from HTTP headers

        Args:
            headers: HTTP headers dictionary (case-insensitive)

        Returns:
            Signature string if found, None otherwise
        """
        # Convert headers to lowercase for case-insensitive lookup
        lower_headers = {k.lower(): v for k, v in headers.items()}

        # Try common webhook signature header names
        possible_headers = [
            "x-openwatch-signature",
            "x-hub-signature-256",
            "x-webhook-signature",
            "x-signature-256",
        ]

        for header_name in possible_headers:
            signature = lower_headers.get(header_name)
            if signature:
                logger.debug(f"Found webhook signature in header: {header_name}")
                return signature

        logger.debug("No webhook signature found in headers")
        return None

    def create_event_payload(
        self, event_type: str, data: Dict[str, Any], timestamp: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create standardized webhook event payload

        Args:
            event_type: Type of event (e.g., 'scan.completed')
            data: Event-specific data
            timestamp: Event timestamp (ISO format)

        Returns:
            Standardized event payload
        """
        from datetime import datetime

        if not timestamp:
            timestamp = datetime.utcnow().isoformat()

        return {"event": event_type, "timestamp": timestamp, "data": data}

    def sign_api_request(
        self,
        method: str,
        url: str,
        payload: Optional[Union[Dict[str, Any], str, bytes]] = None,
    ) -> Dict[str, str]:
        """
        Create signature headers for API requests to external services

        Args:
            method: HTTP method
            url: Request URL
            payload: Request payload

        Returns:
            Headers with signature information
        """
        # For API requests, we might need different signing logic
        # This is a placeholder for future API request signing
        headers = {"User-Agent": "OpenWatch-API/1.0"}

        if payload:
            signature = self.generate_signature(payload)
            headers.update({"X-OpenWatch-Signature": signature, "Content-Type": "application/json"})

        return headers


# Global webhook security instance
_webhook_security: Optional[WebhookSecurity] = None


def get_webhook_security() -> WebhookSecurity:
    """Get the global webhook security instance"""
    global _webhook_security
    if _webhook_security is None:
        _webhook_security = WebhookSecurity()
    return _webhook_security


# Convenience functions for common operations
def generate_webhook_signature(payload: Union[Dict[str, Any], str, bytes]) -> str:
    """
    Generate signature for webhook payload

    Args:
        payload: Webhook payload

    Returns:
        Signature string in format "sha256=<hex_digest>"
    """
    return get_webhook_security().generate_signature(payload)


def verify_webhook_signature(payload: Union[Dict[str, Any], str, bytes], signature: str) -> bool:
    """
    Verify webhook signature

    Args:
        payload: Webhook payload
        signature: Signature from webhook header

    Returns:
        True if signature is valid
    """
    return get_webhook_security().verify_signature(payload, signature)


def create_webhook_headers(
    payload: Union[Dict[str, Any], str, bytes],
    event_type: str,
    delivery_id: Optional[str] = None,
) -> Dict[str, str]:
    """
    Create headers for webhook delivery

    Args:
        payload: Webhook payload
        event_type: Type of event
        delivery_id: Unique delivery ID

    Returns:
        Dictionary of headers
    """
    return get_webhook_security().create_webhook_headers(payload, event_type, delivery_id)


def create_scan_completed_payload(scan_id: str, scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create scan.completed webhook payload

    Args:
        scan_id: Scan identifier
        scan_data: Scan result data

    Returns:
        Standardized webhook payload
    """
    return get_webhook_security().create_event_payload("scan.completed", {"scan_id": scan_id, **scan_data})


def create_scan_failed_payload(scan_id: str, scan_data: Dict[str, Any], error_message: str) -> Dict[str, Any]:
    """
    Create scan.failed webhook payload

    Args:
        scan_id: Scan identifier
        scan_data: Scan data
        error_message: Failure reason

    Returns:
        Standardized webhook payload
    """
    return get_webhook_security().create_event_payload(
        "scan.failed", {"scan_id": scan_id, "error_message": error_message, **scan_data}
    )
