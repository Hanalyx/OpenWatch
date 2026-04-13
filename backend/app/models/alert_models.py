"""
Alert-related SQLAlchemy models.

Contains the AlertRoutingRule model for per-severity alert dispatch routing.
"""

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, text
from sqlalchemy.dialects.postgresql import UUID

from ..database import Base


class AlertRoutingRule(Base):  # type: ignore[valid-type, misc]
    """Maps alert severity/type combinations to notification channels.

    When an alert is created, the routing engine queries this table to
    determine which notification channels should receive it.  If no
    matching rules exist, the system falls back to dispatching to ALL
    enabled channels (AC-6 default behaviour).
    """

    __tablename__ = "alert_routing_rules"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    severity = Column(
        String(16),
        nullable=False,
        comment="Alert severity filter: critical, high, medium, low, or all",
    )
    alert_type = Column(
        String(64),
        nullable=False,
        comment="Alert type filter or 'all' for any type",
    )
    channel_id = Column(
        UUID(as_uuid=True),
        ForeignKey("notification_channels.id", ondelete="CASCADE"),
        nullable=False,
    )
    enabled = Column(
        Boolean,
        nullable=False,
        server_default=text("true"),
    )
    created_at = Column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
    )
