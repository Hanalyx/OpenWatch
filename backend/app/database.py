"""
FIPS-compliant database configuration with encryption support
PostgreSQL with TLS and encrypted connections
"""

import logging
from datetime import datetime
from typing import Any, Callable, Generator, Optional
from uuid import uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    create_engine,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import QueuePool

from .config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Database connection with SSL/TLS
DATABASE_URL = settings.database_url

# SSL parameters for FIPS compliance
ssl_params = {}
if settings.database_ssl_mode and not settings.debug:
    # Only use SSL in production with certificates
    ssl_params.update(
        {
            "sslmode": settings.database_ssl_mode,
            "sslcert": settings.database_ssl_cert,
            "sslkey": settings.database_ssl_key,
            "sslrootcert": settings.database_ssl_ca,
        }
    )
elif settings.debug:
    # Development mode - disable SSL
    ssl_params.update({"sslmode": "disable"})

# Create engine with security configuration
engine = create_engine(
    DATABASE_URL,
    poolclass=QueuePool,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    pool_recycle=3600,  # Recycle connections every hour
    connect_args={
        **ssl_params,
        "connect_timeout": 10,
        "options": "-c application_name=openwatch",
    },
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# Database Models
class User(Base):  # type: ignore[valid-type, misc]
    """User model with secure password storage"""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)  # Argon2id hash
    role: Column[str] = Column(
        Enum(
            "super_admin",
            "security_admin",
            "security_analyst",
            "compliance_officer",
            "auditor",
            "guest",
            name="user_roles",
        ),
        default="guest",
        nullable=False,
    )
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)

    # MFA Support
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    mfa_secret = Column(Text, nullable=True)  # Encrypted TOTP secret
    backup_codes = Column(JSON, nullable=True)  # Hashed backup codes
    mfa_enrolled_at = Column(DateTime, nullable=True)
    last_mfa_use = Column(DateTime, nullable=True)
    mfa_recovery_codes_generated_at = Column(DateTime, nullable=True)


class MFAAuditLog(Base):  # type: ignore[valid-type, misc]
    """MFA audit log for security monitoring"""

    __tablename__ = "mfa_audit_log"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    action = Column(String(50), nullable=False)  # enroll, validate, disable, etc.
    method = Column(String(20), nullable=True)  # totp, backup_code
    success = Column(Boolean, nullable=False)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    details = Column(JSON, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)


class MFAUsedCodes(Base):  # type: ignore[valid-type, misc]
    """TOTP replay protection"""

    __tablename__ = "mfa_used_codes"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    code_hash = Column(String(64), nullable=False)  # SHA-256 hash
    used_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Host(Base):  # type: ignore[valid-type, misc]
    """Host model with encrypted credential storage

    Status values (aligned with frontend monitoring states):
    - online: Can ping AND ssh to host (fully operational)
    - down: No ping, no ssh (completely unavailable)
    - unknown: Host added but not yet checked
    - critical: Can ping but can't ssh (partial connectivity)
    - maintenance: Planned/manual maintenance mode
    - degraded: Can ping and ssh, but no elevated privilege (permission issues)

    Monitoring fields track consecutive check results:
    - ping_consecutive_failures: Failed ping attempts in a row
    - ping_consecutive_successes: Successful ping attempts in a row
    - ssh_consecutive_failures: Failed SSH attempts in a row (when ping succeeds)
    - ssh_consecutive_successes: Successful SSH attempts in a row
    - privilege_consecutive_failures: Failed privilege escalation attempts in a row (when SSH succeeds)
    - privilege_consecutive_successes: Successful privilege checks in a row
    """

    __tablename__ = "hosts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)  # Native UUID
    hostname = Column(String(255), nullable=False)
    ip_address = Column(String(45), nullable=False)  # IPv4 or IPv6
    display_name = Column(String(255), nullable=True)
    operating_system = Column(String(255), nullable=True)
    os_family = Column(String(50), nullable=True)  # Added for compatibility validation
    os_version = Column(String(100), nullable=True)  # Added for compatibility validation
    architecture = Column(String(50), nullable=True)  # Added for compatibility validation
    last_os_detection = Column(DateTime, nullable=True)  # Added for OS detection tracking
    status = Column(
        String(50), default="unknown", nullable=False
    )  # Current status: online, down, unknown, critical, maintenance, degraded
    port = Column(Integer, default=22, nullable=False)
    username = Column(String(50), nullable=True)  # Made optional
    auth_method = Column(String(20), default="ssh_key", nullable=True)  # Made optional
    encrypted_credentials = Column(LargeBinary, nullable=True)  # Made optional for basic hosts
    description = Column(Text, nullable=True)
    environment = Column(String(50), nullable=True, default="production")  # Added for bulk import
    tags = Column(String(500), nullable=True)  # Added for bulk import (comma-separated)
    owner = Column(String(100), nullable=True)  # Added for bulk import
    is_active = Column(Boolean, default=True, nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)  # Made optional for development
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Host monitoring fields
    last_check = Column(DateTime, nullable=True)  # Last monitoring check timestamp
    next_check_time = Column(DateTime, nullable=True)  # When next check is scheduled
    check_priority = Column(Integer, default=5, nullable=False)  # Priority 1-10 (higher = more urgent)
    response_time_ms = Column(Integer, nullable=True)  # Response time in milliseconds
    last_state_change = Column(DateTime, nullable=True)  # When status last changed

    # Consecutive check counters for multi-level monitoring (ping -> ssh -> privilege)
    ping_consecutive_failures = Column(Integer, default=0, nullable=False)
    ping_consecutive_successes = Column(Integer, default=0, nullable=False)
    ssh_consecutive_failures = Column(Integer, default=0, nullable=False)
    ssh_consecutive_successes = Column(Integer, default=0, nullable=False)
    privilege_consecutive_failures = Column(Integer, default=0, nullable=False)
    privilege_consecutive_successes = Column(Integer, default=0, nullable=False)


class ScapContent(Base):  # type: ignore[valid-type, misc]
    """SCAP content metadata"""

    __tablename__ = "scap_content"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    filename = Column(String(255), nullable=False)
    file_path = Column(String(500), nullable=False)
    content_type = Column(String(50), nullable=False)  # datastream, xccdf, oval
    profiles = Column(Text, nullable=True)  # JSON array of available profiles
    description = Column(Text, nullable=True)
    version = Column(String(50), nullable=True)
    os_family = Column(String(50), nullable=True)  # Added for compatibility validation
    os_version = Column(String(100), nullable=True)  # Added for OS version compatibility validation
    compliance_framework = Column(String(100), nullable=True)  # Added for compliance tracking
    uploaded_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    uploaded_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    file_hash = Column(String(64), nullable=False)  # SHA-256 hash for integrity


class Scan(Base):  # type: ignore[valid-type, misc]
    """Scan job tracking"""

    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)  # Native UUID
    name = Column(String(100), nullable=False)
    host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id"), nullable=False)  # Updated to match Host.id
    content_id = Column(Integer, ForeignKey("scap_content.id"), nullable=False)
    profile_id = Column(String(100), nullable=False)
    status = Column(String(20), default="pending", nullable=False)  # pending, running, completed, failed
    progress = Column(Integer, default=0, nullable=False)  # 0-100
    result_file = Column(String(500), nullable=True)
    report_file = Column(String(500), nullable=True)
    error_message = Column(Text, nullable=True)
    scan_options = Column(Text, nullable=True)  # JSON options
    started_by = Column(Integer, ForeignKey("users.id"), nullable=True)  # Made optional for development
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    celery_task_id = Column(String(100), nullable=True)

    # AEGIS Integration Fields
    remediation_requested = Column(Boolean, default=False, nullable=False)
    aegis_remediation_id = Column(UUID(as_uuid=True), nullable=True)  # Link to AEGIS remediation job
    verification_scan = Column(Boolean, default=False, nullable=False)  # True if this is a verification scan
    remediation_status = Column(String(20), nullable=True)  # completed, failed, partial
    remediation_completed_at = Column(DateTime, nullable=True)
    scan_metadata = Column(JSON, nullable=True)  # Additional metadata including remediation results


class ScanResult(Base):  # type: ignore[valid-type, misc]
    """Scan results summary"""

    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    total_rules = Column(Integer, nullable=False)
    passed_rules = Column(Integer, nullable=False)
    failed_rules = Column(Integer, nullable=False)
    error_rules = Column(Integer, nullable=False)
    unknown_rules = Column(Integer, nullable=False)
    not_applicable_rules = Column(Integer, nullable=False)
    score = Column(String(10), nullable=True)  # Overall compliance score

    # NIST SP 800-30 Risk Management Guide requires separate tracking
    # of critical severity findings (CVSS >= 9.0) for risk scoring
    # Total failed rule counts by severity
    severity_critical = Column(Integer, default=0, nullable=False)
    severity_high = Column(Integer, default=0, nullable=False)
    severity_medium = Column(Integer, default=0, nullable=False)
    severity_low = Column(Integer, default=0, nullable=False)

    # Per-severity pass/fail breakdown for accurate risk visualization
    # NIST SP 800-137 Continuous Monitoring requires granular severity tracking
    # to enable accurate compliance ring visualization and drift detection
    #
    # Critical severity (CVSS >= 9.0)
    severity_critical_passed = Column(
        Integer,
        default=0,
        nullable=False,
        comment="Count of passed critical severity rules (CVSS >= 9.0)",
    )
    severity_critical_failed = Column(
        Integer,
        default=0,
        nullable=False,
        comment="Count of failed critical severity rules (CVSS >= 9.0)",
    )

    # High severity (CVSS 7.0-8.9)
    severity_high_passed = Column(
        Integer,
        default=0,
        nullable=False,
        comment="Count of passed high severity rules (CVSS 7.0-8.9)",
    )
    severity_high_failed = Column(
        Integer,
        default=0,
        nullable=False,
        comment="Count of failed high severity rules (CVSS 7.0-8.9)",
    )

    # Medium severity (CVSS 4.0-6.9)
    severity_medium_passed = Column(
        Integer,
        default=0,
        nullable=False,
        comment="Count of passed medium severity rules (CVSS 4.0-6.9)",
    )
    severity_medium_failed = Column(
        Integer,
        default=0,
        nullable=False,
        comment="Count of failed medium severity rules (CVSS 4.0-6.9)",
    )

    # Low severity (CVSS 0.1-3.9)
    severity_low_passed = Column(
        Integer,
        default=0,
        nullable=False,
        comment="Count of passed low severity rules (CVSS 0.1-3.9)",
    )
    severity_low_failed = Column(
        Integer,
        default=0,
        nullable=False,
        comment="Count of failed low severity rules (CVSS 0.1-3.9)",
    )

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class ScanBaseline(Base):  # type: ignore[valid-type, misc]
    """
    Compliance baseline tracking for drift detection.

    Baselines establish known-good compliance state per NIST SP 800-137
    Continuous Monitoring requirements. Each host can have one active baseline.
    """

    __tablename__ = "scan_baselines"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)
    host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    baseline_type = Column(String(20), nullable=False, comment="Baseline type: initial, manual, or rolling_avg")
    established_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    established_by = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=True,
        comment="User who established baseline (NULL for automated)",
    )

    # Baseline compliance scores
    baseline_score = Column(Float, nullable=False)
    baseline_passed_rules = Column(Integer, nullable=False)
    baseline_failed_rules = Column(Integer, nullable=False)
    baseline_total_rules = Column(Integer, nullable=False)

    # Per-severity baseline metrics for drift detection
    baseline_critical_passed = Column(Integer, default=0, nullable=False)
    baseline_critical_failed = Column(Integer, default=0, nullable=False)
    baseline_high_passed = Column(Integer, default=0, nullable=False)
    baseline_high_failed = Column(Integer, default=0, nullable=False)
    baseline_medium_passed = Column(Integer, default=0, nullable=False)
    baseline_medium_failed = Column(Integer, default=0, nullable=False)
    baseline_low_passed = Column(Integer, default=0, nullable=False)
    baseline_low_failed = Column(Integer, default=0, nullable=False)

    # Drift thresholds (percentage points)
    drift_threshold_major = Column(Float, default=10.0, nullable=False)
    drift_threshold_minor = Column(Float, default=5.0, nullable=False)

    # Baseline status
    is_active = Column(Boolean, default=True, nullable=False)
    superseded_at = Column(DateTime, nullable=True)
    superseded_by = Column(UUID(as_uuid=True), ForeignKey("scan_baselines.id"), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class SystemCredentials(Base):  # type: ignore[valid-type, misc]
    """System-wide SSH credentials for enterprise environments"""

    __tablename__ = "system_credentials"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)  # e.g., "Default Admin Account"
    description = Column(Text, nullable=True)
    username = Column(String(100), nullable=False)
    auth_method = Column(String(20), nullable=False)  # ssh_key, password, both
    encrypted_password = Column(LargeBinary, nullable=True)  # AES-256-GCM encrypted
    encrypted_private_key = Column(LargeBinary, nullable=True)  # AES-256-GCM encrypted
    private_key_passphrase = Column(LargeBinary, nullable=True)  # AES-256-GCM encrypted
    # SSH key metadata for fingerprint display
    ssh_key_fingerprint = Column(String(128), nullable=True, index=True)  # SHA256:base64hash
    ssh_key_type = Column(String(20), nullable=True)  # rsa, ed25519, ecdsa, dsa
    ssh_key_bits = Column(Integer, nullable=True)  # Key size in bits
    ssh_key_comment = Column(String(255), nullable=True)  # Key comment/label
    is_default = Column(Boolean, default=False, nullable=False)  # Only one can be default
    is_active = Column(Boolean, default=True, nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class Role(Base):  # type: ignore[valid-type, misc]
    """Role definitions with permissions"""

    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False)  # super_admin, security_admin, etc.
    display_name = Column(String(100), nullable=False)  # "Super Administrator"
    description = Column(Text, nullable=True)
    permissions = Column(JSON, nullable=False)  # JSON array of permission strings
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class UserGroup(Base):  # type: ignore[valid-type, misc]
    """User groups for organizing access to hosts and resources"""

    __tablename__ = "user_groups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class UserGroupMembership(Base):  # type: ignore[valid-type, misc]
    """Many-to-many relationship between users and groups"""

    __tablename__ = "user_group_memberships"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    group_id = Column(Integer, ForeignKey("user_groups.id"), nullable=False)
    assigned_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    assigned_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class HostAccess(Base):  # type: ignore[valid-type, misc]
    """Host access control for users and groups"""

    __tablename__ = "host_access"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # Direct user access
    group_id = Column(Integer, ForeignKey("user_groups.id"), nullable=True)  # Group access
    access_level: Column[str] = Column(
        Enum("read", "write", "admin", name="access_levels"),
        default="read",
        nullable=False,
    )
    granted_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    granted_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)  # Optional expiration


class HostGroup(Base):  # type: ignore[valid-type, misc]
    """Host groups for organizing hosts"""

    __tablename__ = "host_groups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    color = Column(String(7), nullable=True)  # Hex color code
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    # Smart group validation fields
    os_family = Column(String(50), nullable=True)
    os_version_pattern = Column(String(100), nullable=True)
    architecture = Column(String(20), nullable=True)
    # SCAP configuration fields
    scap_content_id = Column(Integer, ForeignKey("scap_content.id"), nullable=True)
    default_profile_id = Column(String(100), nullable=True)
    compliance_framework = Column(String(50), nullable=True)
    auto_scan_enabled = Column(Boolean, default=False, nullable=False)
    scan_schedule = Column(String(100), nullable=True)
    validation_rules = Column(Text, nullable=True)  # JSON-encoded rules


class HostGroupMembership(Base):  # type: ignore[valid-type, misc]
    """Host group membership mapping"""

    __tablename__ = "host_group_memberships"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id"), nullable=False)
    group_id = Column(Integer, ForeignKey("host_groups.id"), nullable=False)
    assigned_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    assigned_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class AuditLog(Base):  # type: ignore[valid-type, misc]
    """Security audit log"""

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True)  # User ID if authenticated
    action = Column(String(50), nullable=False)
    resource_type = Column(String(50), nullable=False)
    resource_id = Column(String(100), nullable=True)
    ip_address = Column(String(45), nullable=False)  # IPv4 or IPv6
    user_agent = Column(String(500), nullable=True)
    details = Column(Text, nullable=True)  # JSON details
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)


class WebhookEndpoint(Base):  # type: ignore[valid-type, misc]
    """Webhook endpoint management for AEGIS integration"""

    __tablename__ = "webhook_endpoints"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)
    name = Column(String(100), nullable=False)
    url = Column(String(500), nullable=False)
    event_types = Column(JSON, nullable=False)  # List of event types
    secret_hash = Column(String(128), nullable=False)  # Hashed webhook secret
    is_active = Column(Boolean, default=True, nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class WebhookDelivery(Base):  # type: ignore[valid-type, misc]
    """Webhook delivery tracking"""

    __tablename__ = "webhook_deliveries"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)
    webhook_id = Column(UUID(as_uuid=True), ForeignKey("webhook_endpoints.id"), nullable=False)
    event_type = Column(String(50), nullable=False)
    event_data = Column(JSON, nullable=False)
    delivery_status = Column(String(20), default="pending", nullable=False)  # pending, delivered, failed
    http_status_code = Column(Integer, nullable=True)
    response_body = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    retry_count = Column(Integer, default=0, nullable=False)
    max_retries = Column(Integer, default=3, nullable=False)
    next_retry_at = Column(DateTime, nullable=True)
    delivered_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class ApiKey(Base):  # type: ignore[valid-type, misc]
    """API keys for service-to-service authentication"""

    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)
    name = Column(String(100), nullable=False)
    key_hash = Column(String(128), nullable=False)  # Hashed API key
    permissions = Column(JSON, nullable=False)  # List of permissions
    is_active = Column(Boolean, default=True, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class IntegrationAuditLog(Base):  # type: ignore[valid-type, misc]
    """Audit log for cross-service operations"""

    __tablename__ = "integration_audit_log"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)
    event_type = Column(String(50), nullable=False)  # scan.completed, remediation.requested, etc.
    source_service = Column(String(20), nullable=False)  # openwatch, aegis
    target_service = Column(String(20), nullable=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=True)
    host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id"), nullable=True)
    event_data = Column(JSON, nullable=True)
    success = Column(Boolean, nullable=False)
    error_message = Column(Text, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class AlertSettings(Base):  # type: ignore[valid-type, misc]
    """Alert settings for monitoring notifications"""

    __tablename__ = "alert_settings"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    alert_type = Column(String(50), nullable=False)  # host_offline, host_online, scan_failed, etc.
    enabled = Column(Boolean, default=True, nullable=False)
    email_enabled = Column(Boolean, default=False, nullable=False)
    email_addresses = Column(JSON, nullable=True)  # List of email addresses
    webhook_url = Column(String(500), nullable=True)
    webhook_enabled = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    __table_args__ = (UniqueConstraint("user_id", "alert_type", name="uq_user_alert_type"),)


# Database dependency for FastAPI
def get_db() -> Generator[Session, None, None]:
    """
    Database session dependency for FastAPI endpoints.

    Yields:
        SQLAlchemy Session instance.

    Note:
        Session is automatically closed when the request completes.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_db_session() -> Session:
    """Get database session for Celery tasks"""
    return SessionLocal()


def get_encryption_service() -> Callable[..., Any]:
    """
    Dependency for getting encryption service from FastAPI app state.

    This allows routes to receive the encryption service via dependency injection:

    Example:
        @router.post("/credentials")
        async def create_credential(
            db: Session = Depends(get_db),
            encryption_service = Depends(get_encryption_service)
        ):
            # Use encryption_service here
            encrypted = encryption_service.encrypt(plaintext)

    Note:
        The encryption service is initialized in main.py lifespan and stored
        in app.state.encryption_service. This function retrieves it.

    Returns:
        A callable that accepts a Request and returns an EncryptionService.
    """
    from fastapi import Request

    # This will be called with request context by FastAPI
    # We need to use a callable that accepts the request
    def _get_encryption_service(request: Request) -> Any:
        """Inner function that receives the request from FastAPI."""
        if not hasattr(request.app.state, "encryption_service"):
            # Fallback for testing or if lifespan hasn't run yet
            logger.warning(
                "Encryption service not found in app.state - "
                "creating temporary instance. This should only happen in tests."
            )
            from .config import get_settings
            from .encryption import create_encryption_service

            settings = get_settings()
            return create_encryption_service(settings.master_key)

        return request.app.state.encryption_service

    return _get_encryption_service


def create_tables() -> None:
    """Create database tables if they don't exist."""
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
        raise


def check_database_health() -> bool:
    """Check database connectivity for health checks"""
    try:
        from sqlalchemy import text

        db = SessionLocal()
        # Simple query to test connection
        db.execute(text("SELECT 1"))
        db.close()
        return True
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False


class DatabaseManager:
    """Database operations with security logging"""

    def __init__(self, db: Session):
        self.db = db

    def create_user(self, username: str, email: str, hashed_password: str, role: str = "user") -> User:
        """Create new user with audit logging"""
        user = User(username=username, email=email, hashed_password=hashed_password, role=role)
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)

        # Audit log
        self.log_audit("CREATE", "USER", str(user.id), f"Created user: {username}")

        return user

    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username"""
        return self.db.query(User).filter(User.username == username).first()

    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email"""
        return self.db.query(User).filter(User.email == email).first()

    def create_host(
        self,
        name: str,
        hostname: str,
        port: int,
        username: str,
        auth_method: str,
        encrypted_credentials: bytes,
        created_by: int,
        description: Optional[str] = None,
    ) -> Host:
        """Create new host with encrypted credentials"""
        host = Host(
            name=name,
            hostname=hostname,
            port=port,
            username=username,
            auth_method=auth_method,
            encrypted_credentials=encrypted_credentials,
            description=description,
            created_by=created_by,
        )
        self.db.add(host)
        self.db.commit()
        self.db.refresh(host)

        # Audit log
        self.log_audit("CREATE", "HOST", str(host.id), f"Created host: {name}")

        return host

    def log_audit(
        self,
        action: str,
        resource_type: str,
        resource_id: str,
        details: str,
        user_id: Optional[int] = None,
        ip_address: str = "unknown",
    ) -> None:
        """
        Log audit event to the database.

        Args:
            action: The action performed (CREATE, UPDATE, DELETE, etc.).
            resource_type: The type of resource affected.
            resource_id: The identifier of the resource.
            details: Human-readable description of the action.
            user_id: ID of the user who performed the action, if known.
            ip_address: IP address of the request origin.
        """
        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            details=details,
        )
        self.db.add(audit_log)
        self.db.commit()


# Initialize database connection test
async def init_database() -> None:
    """
    Initialize database connection and verify FIPS compliance.

    Performs connectivity test and creates tables if they don't exist.
    Raises an exception if initialization fails.
    """
    try:
        # Test connection
        healthy = check_database_health()
        if not healthy:
            raise Exception("Database connection failed")

        # Create tables
        create_tables()

        logger.info("Database initialized successfully with FIPS-compliant configuration")

    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise
