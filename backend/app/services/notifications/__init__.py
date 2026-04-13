"""
Outbound notification dispatch for OpenWatch alerts.

Provides a NotificationChannel abstraction with concrete Slack, email (SMTP),
and webhook implementations.  AlertService.create_alert dispatches to all
enabled channels after inserting the alert row.

Usage:
    from app.services.notifications import (
        NotificationChannel, DeliveryResult,
        SlackChannel, EmailChannel, WebhookChannel,
    )
"""

from .base import DeliveryResult, NotificationChannel
from .email import EmailChannel
from .pagerduty import PagerDutyChannel
from .slack import SlackChannel
from .webhook import WebhookChannel

__all__ = [
    "NotificationChannel",
    "DeliveryResult",
    "SlackChannel",
    "EmailChannel",
    "WebhookChannel",
    "PagerDutyChannel",
]
