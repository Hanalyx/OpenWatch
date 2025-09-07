"""
Webhook Delivery Tasks
Background tasks for delivering webhooks to AEGIS and other integrations
"""

import json
import uuid
import hashlib
import hmac
import time
from datetime import datetime
from typing import Dict, Any, Optional

import httpx
import logging
from sqlalchemy import text
from ..database import get_db
from ..services.http_client import get_webhook_client
from ..services.webhook_security import (
    create_webhook_headers,
    create_scan_completed_payload,
    create_scan_failed_payload,
)
from ..services.integration_metrics import record_webhook_delivery, time_webhook_delivery

logger = logging.getLogger(__name__)


async def deliver_webhook(
    url: str, secret_hash: str, event_data: Dict[str, Any], webhook_id: str, max_retries: int = 3
) -> bool:
    """
    Deliver webhook to endpoint with signature verification

    Args:
        url: Target webhook URL
        secret_hash: Hashed webhook secret for signature generation
        event_data: Event payload to send
        webhook_id: Webhook endpoint ID for tracking
        max_retries: Maximum retry attempts

    Returns:
        bool: True if delivery successful, False otherwise
    """
    # Create delivery record
    delivery_id = str(uuid.uuid4())

    try:
        db = next(get_db())
        try:
            db.execute(
                text(
                    """
                INSERT INTO webhook_deliveries 
                (id, webhook_id, event_type, event_data, delivery_status, created_at)
                VALUES (:id, :webhook_id, :event_type, :event_data, :delivery_status, :created_at)
            """
                ),
                {
                    "id": delivery_id,
                    "webhook_id": webhook_id,
                    "event_type": event_data.get("event_type", "unknown"),
                    "event_data": json.dumps(event_data),
                    "delivery_status": "pending",
                    "created_at": datetime.utcnow(),
                },
            )
            db.commit()
        finally:
            db.close()
    except Exception as e:
        logger.error(
            "Failed to create webhook delivery record", error=str(e), webhook_id=webhook_id
        )
        return False

    # Create webhook headers with signature
    headers = create_webhook_headers(
        event_data, event_data.get("event_type", "unknown"), delivery_id
    )

    # Get webhook client
    webhook_client = await get_webhook_client()

    # Time the webhook delivery operation
    start_time = time.time()
    success = False
    error_msg = None

    # Attempt delivery using enhanced HTTP client (it has built-in retries)
    try:
        response = await webhook_client.deliver_webhook(url, event_data, headers)

        success = True
        duration = time.time() - start_time

        # Record successful delivery metrics
        record_webhook_delivery(
            success=True,
            duration=duration,
            target_service=url.split("/")[2],  # Extract domain from URL
            error=None,
        )

        # Update delivery record with success
        db = next(get_db())
        try:
            db.execute(
                text(
                    """
                UPDATE webhook_deliveries SET
                delivery_status = 'delivered',
                http_status_code = :status_code,
                response_body = :response_body,
                delivered_at = :delivered_at
                WHERE id = :id
            """
                ),
                {
                    "id": delivery_id,
                    "status_code": response.status_code,
                    "response_body": response.text[:1000],  # Truncate long responses
                    "delivered_at": datetime.utcnow(),
                },
            )
            db.commit()
        finally:
            db.close()

        logger.info(
            "Webhook delivered successfully",
            webhook_id=webhook_id,
            delivery_id=delivery_id,
            status_code=response.status_code,
            duration_ms=round(duration * 1000, 2),
        )
        return True

    except Exception as e:
        # Record failed delivery metrics
        error_msg = str(e)
        duration = time.time() - start_time

        record_webhook_delivery(
            success=False,
            duration=duration,
            target_service=url.split("/")[2],  # Extract domain from URL
            error=error_msg,
        )

        # Update delivery record with failure
        db = next(get_db())
        try:
            db.execute(
                text(
                    """
                UPDATE webhook_deliveries SET
                delivery_status = 'failed',
                error_message = :error_message
                WHERE id = :id
            """
                ),
                {"id": delivery_id, "error_message": error_msg},
            )
            db.commit()
        finally:
            db.close()

        logger.error(
            "Webhook delivery failed",
            webhook_id=webhook_id,
            delivery_id=delivery_id,
            error=error_msg,
            duration_ms=round(duration * 1000, 2),
        )

    return False


async def send_scan_completed_webhook(scan_id: str, scan_data: Dict[str, Any]):
    """Send scan.completed webhook to all registered endpoints"""
    try:
        # Get active webhook endpoints that listen for scan.completed events
        db = next(get_db())
        try:
            result = db.execute(
                text(
                    """
                SELECT id, url, secret_hash FROM webhook_endpoints
                WHERE is_active = true 
                AND event_types::jsonb ? 'scan.completed'
            """
                )
            )

            webhooks = result.fetchall()
        finally:
            db.close()

        if not webhooks:
            logger.info("No active webhooks configured for scan.completed events")
            return

        # Create standardized event payload
        event_data = create_scan_completed_payload(scan_id, scan_data)

        # Send to all registered endpoints
        for webhook in webhooks:
            try:
                await deliver_webhook(webhook.url, webhook.secret_hash, event_data, str(webhook.id))
            except Exception as e:
                logger.error(
                    "Failed to deliver scan.completed webhook",
                    webhook_id=str(webhook.id),
                    error=str(e),
                )

    except Exception as e:
        logger.error("Failed to process scan.completed webhooks", scan_id=scan_id, error=str(e))


async def send_scan_failed_webhook(scan_id: str, scan_data: Dict[str, Any], error_message: str):
    """Send scan.failed webhook to all registered endpoints"""
    try:
        # Get active webhook endpoints that listen for scan.failed events
        db = next(get_db())
        try:
            result = db.execute(
                text(
                    """
                SELECT id, url, secret_hash FROM webhook_endpoints
                WHERE is_active = true 
                AND event_types::jsonb ? 'scan.failed'
            """
                )
            )

            webhooks = result.fetchall()
        finally:
            db.close()

        if not webhooks:
            logger.info("No active webhooks configured for scan.failed events")
            return

        # Create standardized event payload
        event_data = create_scan_failed_payload(scan_id, scan_data, error_message)

        # Send to all registered endpoints
        for webhook in webhooks:
            try:
                await deliver_webhook(webhook.url, webhook.secret_hash, event_data, str(webhook.id))
            except Exception as e:
                logger.error(
                    "Failed to deliver scan.failed webhook",
                    webhook_id=str(webhook.id),
                    error=str(e),
                )

    except Exception as e:
        logger.error("Failed to process scan.failed webhooks", scan_id=scan_id, error=str(e))
