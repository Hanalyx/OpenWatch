"""
Abstract base class for outbound notification channels.

Each concrete channel (Slack, Email, Webhook) inherits from
NotificationChannel and implements the async send() method.
Channels MUST NOT raise on failure; they return a DeliveryResult
that the dispatch loop records in notification_deliveries.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class DeliveryResult:
    """Outcome of a single notification delivery attempt."""

    success: bool
    status_code: Optional[int] = None
    response_body: Optional[str] = None
    error: Optional[str] = None


class NotificationChannel(ABC):
    """Abstract base for outbound notification channels.

    Subclasses receive a decrypted config dict at construction time and
    must implement ``send()`` which returns a DeliveryResult without raising.
    """

    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config

    @abstractmethod
    async def send(self, alert: Dict[str, Any]) -> DeliveryResult:
        """Send an alert notification.

        Must not raise on failure -- return a DeliveryResult with
        ``success=False`` and an ``error`` message instead.

        Args:
            alert: Dict with at least ``type``, ``severity``, ``title``,
                   and optionally ``host_id``, ``rule_id``, ``detail``.

        Returns:
            DeliveryResult describing the outcome.
        """
        ...
