"""
SQLAlchemy model for retention_policies table.

Used for source-inspection tests (AC-1) and schema introspection.
The actual data access uses QueryBuilder / InsertBuilder / UpdateBuilder
rather than ORM queries.
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


class RetentionPolicy(Base):
    """Retention policy for a given resource type and optional tenant.

    Attributes:
        id: Primary key UUID.
        tenant_id: Optional tenant scope (NULL = global default).
        resource_type: The resource governed by this policy
            (e.g. 'transactions', 'audit_exports', 'posture_snapshots').
        retention_days: Number of days to retain rows before cleanup.
        enabled: Whether enforcement is active for this policy.
        created_at: Row creation timestamp.
        updated_at: Row last-modified timestamp.
    """

    __tablename__ = "retention_policies"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), nullable=True)
    resource_type = Column(String(64), nullable=False)
    retention_days = Column(Integer, nullable=False, default=365)
    enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (UniqueConstraint("tenant_id", "resource_type", name="uq_retention_tenant_resource"),)

    def __repr__(self) -> str:
        return (
            f"<RetentionPolicy(id={self.id}, resource_type={self.resource_type!r}, "
            f"retention_days={self.retention_days}, enabled={self.enabled})>"
        )
