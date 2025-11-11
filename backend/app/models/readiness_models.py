"""
Host Readiness Check Models

Stores historical host readiness validation results for:
- Compliance audit trails (FedRAMP, CMMC, ISO 27001)
- Trend analysis (detect systemic issues)
- Smart caching (skip redundant checks)
- Remediation tracking

Database: PostgreSQL (relational data requiring ACID guarantees)
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field
from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.database import Base


class ReadinessCheckType(str, Enum):
    """Types of readiness validation checks"""

    OSCAP_INSTALLATION = "oscap_installation"
    DISK_SPACE = "disk_space"
    SUDO_ACCESS = "sudo_access"
    OPERATING_SYSTEM = "operating_system"
    NETWORK_CONNECTIVITY = "network_connectivity"
    MEMORY_AVAILABILITY = "memory_availability"
    SELINUX_STATUS = "selinux_status"
    DEPENDENCIES = "dependencies"


class ReadinessCheckSeverity(str, Enum):
    """Severity levels for readiness check failures"""

    ERROR = "error"  # Critical failure, scan cannot proceed
    WARNING = "warning"  # Non-critical issue, scan may have issues
    INFO = "info"  # Informational, no impact on scan


class ReadinessStatus(str, Enum):
    """Overall readiness status for a host"""

    READY = "ready"  # All checks passed
    NOT_READY = "not_ready"  # Critical checks failed
    DEGRADED = "degraded"  # Some non-critical checks failed


# SQLAlchemy ORM Models (PostgreSQL)


class HostReadinessCheck(Base):
    """
    Individual readiness check result.

    One record per check type per host per validation run.
    Enables historical tracking and trend analysis.
    """

    __tablename__ = "host_readiness_checks"

    # Primary key
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4, index=True
    )

    # Foreign keys
    host_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("hosts.id"), index=True)
    validation_run_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("host_readiness_validations.id"), index=True
    )

    # Check identification
    check_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    check_name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Check result
    passed: Mapped[bool] = mapped_column(Boolean, nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Check details (JSON for flexibility)
    details: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    # Timing
    check_duration_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Audit trail
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False, index=True
    )
    created_by: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), nullable=True)

    # Relationships
    validation_run = relationship("HostReadinessValidation", back_populates="checks")

    __table_args__ = (
        # Composite index for querying recent checks by host and type
        Index("idx_host_check_type_created", "host_id", "check_type", "created_at"),
        # Composite index for failed checks
        Index("idx_host_failed_checks", "host_id", "passed", "created_at"),
    )


class HostReadinessValidation(Base):
    """
    Complete validation run for a host.

    One record per host per validation attempt.
    Aggregates all individual check results.
    """

    __tablename__ = "host_readiness_validations"

    # Primary key
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4, index=True
    )

    # Foreign key
    host_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("hosts.id"), index=True)

    # Validation result
    status: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    overall_passed: Mapped[bool] = mapped_column(Boolean, nullable=False, index=True)

    # Check summary
    total_checks: Mapped[int] = mapped_column(nullable=False)
    passed_checks: Mapped[int] = mapped_column(nullable=False)
    failed_checks: Mapped[int] = mapped_column(nullable=False)
    warnings_count: Mapped[int] = mapped_column(nullable=False, default=0)

    # Summary details (JSON for flexibility)
    summary: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    # Timing
    validation_duration_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    completed_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)

    # Audit trail
    created_by: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), nullable=True)

    # Relationships
    checks = relationship(
        "HostReadinessCheck", back_populates="validation_run", cascade="all, delete-orphan"
    )

    __table_args__ = (
        # Composite index for querying recent validations by host
        Index("idx_host_completed", "host_id", "completed_at"),
        # Composite index for querying failed validations
        Index("idx_host_status_completed", "host_id", "status", "completed_at"),
    )


# Pydantic Models (API Request/Response)


class ReadinessCheckResult(BaseModel):
    """
    Result of a single readiness check.

    Used for API responses and service layer communication.
    """

    check_type: ReadinessCheckType
    check_name: str
    passed: bool
    severity: ReadinessCheckSeverity
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)
    check_duration_ms: Optional[float] = None

    class Config:
        use_enum_values = True


class HostReadiness(BaseModel):
    """
    Complete readiness report for a single host.

    Aggregates all check results with overall status.
    """

    host_id: UUID
    hostname: str
    ip_address: str
    status: ReadinessStatus
    overall_passed: bool

    # Check results
    checks: List[ReadinessCheckResult]
    total_checks: int
    passed_checks: int
    failed_checks: int
    warnings_count: int

    # Timing
    validation_duration_ms: float
    completed_at: datetime

    # Summary
    summary: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        use_enum_values = True


class BulkReadinessRequest(BaseModel):
    """
    Request to validate multiple hosts.

    Empty host_ids list = validate ALL hosts.
    """

    host_ids: List[UUID] = Field(default_factory=list, description="Empty = validate all hosts")
    check_types: Optional[List[ReadinessCheckType]] = Field(
        default=None, description="Specific checks to run (None = all checks)"
    )
    parallel: bool = Field(default=True, description="Run validations in parallel")
    use_cache: bool = Field(default=True, description="Use cached results if available (24h)")
    cache_ttl_hours: int = Field(default=24, description="Cache TTL in hours")

    class Config:
        use_enum_values = True


class BulkReadinessReport(BaseModel):
    """
    Aggregated results for multiple hosts.

    Provides summary statistics and per-host details.
    """

    total_hosts: int
    ready_hosts: int
    not_ready_hosts: int
    degraded_hosts: int

    # Per-host results
    hosts: List[HostReadiness]

    # Timing
    total_duration_ms: float
    completed_at: datetime

    # Aggregated insights
    common_failures: Dict[str, int] = Field(
        default_factory=dict, description="Map of check_type -> failure count"
    )
    remediation_priorities: List[Dict[str, Any]] = Field(
        default_factory=list, description="Prioritized list of issues to fix"
    )


class ReadinessHistoryRequest(BaseModel):
    """Request for historical readiness data"""

    host_id: UUID
    check_types: Optional[List[ReadinessCheckType]] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    limit: int = Field(default=100, ge=1, le=1000)

    class Config:
        use_enum_values = True


class ReadinessTrendPoint(BaseModel):
    """Single data point for trend analysis"""

    timestamp: datetime
    status: ReadinessStatus
    passed_checks: int
    failed_checks: int
    warnings_count: int

    class Config:
        use_enum_values = True


class ReadinessHistory(BaseModel):
    """Historical readiness data for a host"""

    host_id: UUID
    hostname: str
    trend_data: List[ReadinessTrendPoint]
    first_validation: Optional[datetime] = None
    last_validation: Optional[datetime] = None
    total_validations: int

    # Trend insights
    improving: bool = Field(description="Is readiness improving over time?")
    consistent_failures: List[str] = Field(
        default_factory=list, description="Checks that consistently fail"
    )


class QuickCheckRequest(BaseModel):
    """
    Request for quick pre-flight check before scan.

    Only runs critical checks (OSCAP, disk, network).
    """

    host_id: UUID
    use_cache: bool = Field(default=True, description="Use cached results if available (1h)")
    cache_ttl_hours: int = Field(default=1, description="Cache TTL in hours for quick checks")
