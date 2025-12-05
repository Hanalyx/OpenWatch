"""
Shared Enums

Common enumeration types used across multiple modules.
These are kept separate to avoid circular imports between
routes, services, and models.

Usage:
    from backend.app.models.enums import ScanPriority, ScanSessionStatus
"""

from enum import Enum


class ScanPriority(str, Enum):
    """
    Priority levels for scan execution.

    Used by scan intelligence services and host group scanning
    to determine execution order and resource allocation.
    """

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class ScanSessionStatus(str, Enum):
    """
    Status values for group scan sessions.

    Tracks the lifecycle of bulk/group scan operations.
    """

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
