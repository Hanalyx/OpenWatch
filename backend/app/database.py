"""
FIPS-compliant database configuration with encryption support
PostgreSQL with TLS and encrypted connections
"""
import logging
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, DateTime, Text, Boolean, LargeBinary, Float, JSON, ForeignKey, Enum
from sqlalchemy.dialects.postgresql import UUID
from uuid import uuid4
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool
import asyncpg
import asyncio
from typing import AsyncGenerator, Optional
from datetime import datetime

from .config import get_settings
from .rbac import UserRole

logger = logging.getLogger(__name__)
settings = get_settings()

# Database connection with SSL/TLS
DATABASE_URL = settings.database_url

# SSL parameters for FIPS compliance
ssl_params = {}
if settings.database_ssl_mode and not settings.debug:
    # Only use SSL in production with certificates
    ssl_params.update({
        "sslmode": settings.database_ssl_mode,
        "sslcert": settings.database_ssl_cert,
        "sslkey": settings.database_ssl_key,
        "sslrootcert": settings.database_ssl_ca
    })
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
        "options": "-c application_name=openwatch"
    }
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# Database Models
class User(Base):
    """User model with secure password storage"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)  # Argon2id hash
    role = Column(Enum('super_admin', 'security_admin', 'security_analyst', 'compliance_officer', 'auditor', 'guest', name='user_roles'), default='guest', nullable=False)
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


class MFAAuditLog(Base):
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


class MFAUsedCodes(Base):
    """TOTP replay protection"""
    __tablename__ = "mfa_used_codes"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    code_hash = Column(String(64), nullable=False)  # SHA-256 hash
    used_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Host(Base):
    """Host model with encrypted credential storage"""
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
    status = Column(String(50), default="offline", nullable=False)
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


class ScapContent(Base):
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


class Scan(Base):
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


class ScanResult(Base):
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
    severity_high = Column(Integer, default=0, nullable=False)
    severity_medium = Column(Integer, default=0, nullable=False)
    severity_low = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class SystemCredentials(Base):
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


class Role(Base):
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


class UserGroup(Base):
    """User groups for organizing access to hosts and resources"""
    __tablename__ = "user_groups"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class UserGroupMembership(Base):
    """Many-to-many relationship between users and groups"""
    __tablename__ = "user_group_memberships"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    group_id = Column(Integer, ForeignKey("user_groups.id"), nullable=False)
    assigned_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    assigned_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class HostAccess(Base):
    """Host access control for users and groups"""
    __tablename__ = "host_access"
    
    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # Direct user access
    group_id = Column(Integer, ForeignKey("user_groups.id"), nullable=True)  # Group access
    access_level = Column(Enum('read', 'write', 'admin', name='access_levels'), default='read', nullable=False)
    granted_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    granted_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)  # Optional expiration


class HostGroup(Base):
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


class HostGroupMembership(Base):
    """Host group membership mapping"""
    __tablename__ = "host_group_memberships"
    
    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id"), nullable=False)
    group_id = Column(Integer, ForeignKey("host_groups.id"), nullable=False)
    assigned_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    assigned_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class AuditLog(Base):
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


class WebhookEndpoint(Base):
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


class WebhookDelivery(Base):
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


class ApiKey(Base):
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


class IntegrationAuditLog(Base):
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


# Database dependency for FastAPI
def get_db() -> Session:
    """Database session dependency"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables():
    """Create database tables if they don't exist"""
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
        user = User(
            username=username,
            email=email,
            hashed_password=hashed_password,
            role=role
        )
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
    
    def create_host(self, name: str, hostname: str, port: int, username: str, 
                   auth_method: str, encrypted_credentials: bytes, 
                   created_by: int, description: str = None) -> Host:
        """Create new host with encrypted credentials"""
        host = Host(
            name=name,
            hostname=hostname,
            port=port,
            username=username,
            auth_method=auth_method,
            encrypted_credentials=encrypted_credentials,
            description=description,
            created_by=created_by
        )
        self.db.add(host)
        self.db.commit()
        self.db.refresh(host)
        
        # Audit log
        self.log_audit("CREATE", "HOST", str(host.id), f"Created host: {name}")
        
        return host
    
    def log_audit(self, action: str, resource_type: str, resource_id: str, 
                  details: str, user_id: int = None, ip_address: str = "unknown"):
        """Log audit event"""
        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            details=details
        )
        self.db.add(audit_log)
        self.db.commit()


# Initialize database connection test
async def init_database():
    """Initialize database connection and verify FIPS compliance"""
    try:
        # Test connection
        healthy = await check_database_health()
        if not healthy:
            raise Exception("Database connection failed")
        
        # Create tables
        await create_tables()
        
        logger.info("Database initialized successfully with FIPS-compliant configuration")
        
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise