"""
Host Management Routes
"""
from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer
from pydantic import BaseModel, Field
from typing import List, Optional
import logging
from datetime import datetime
import uuid
import json

from ..database import get_db
from ..utils.logging_security import sanitize_id_for_log
from ..utils.query_builder import QueryBuilder
from ..config import get_settings
from sqlalchemy.orm import Session
from sqlalchemy import text
# NOTE: json and base64 imports removed - using centralized auth service
from ..services.unified_ssh_service import validate_ssh_key, format_validation_message
from ..services.unified_ssh_service import extract_ssh_key_metadata
from ..auth import get_current_user

logger = logging.getLogger(__name__)
security = HTTPBearer(auto_error=False)

router = APIRouter()


# NOTE: Old encrypt_credentials function removed - now using centralized auth service


class Host(BaseModel):
    id: Optional[str] = None
    hostname: str
    ip_address: str
    display_name: Optional[str] = None
    operating_system: str
    status: str = "offline"
    port: Optional[int] = 22
    username: Optional[str] = None
    auth_method: Optional[str] = None
    last_scan: Optional[str] = None
    last_check: Optional[str] = None
    compliance_score: Optional[float] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    ssh_key_fingerprint: Optional[str] = None
    ssh_key_type: Optional[str] = None
    ssh_key_bits: Optional[int] = None
    ssh_key_comment: Optional[str] = None

    # Host monitoring fields
    response_time_ms: Optional[int] = None
    check_priority: Optional[int] = None
    ping_consecutive_failures: Optional[int] = None
    ssh_consecutive_failures: Optional[int] = None
    privilege_consecutive_failures: Optional[int] = None
    ping_consecutive_successes: Optional[int] = None
    ssh_consecutive_successes: Optional[int] = None
    privilege_consecutive_successes: Optional[int] = None

    # Latest scan information
    latest_scan_id: Optional[str] = None
    latest_scan_name: Optional[str] = None
    scan_status: Optional[str] = None
    scan_progress: Optional[int] = None
    failed_rules: Optional[int] = None
    passed_rules: Optional[int] = None
    critical_issues: Optional[int] = None
    high_issues: Optional[int] = None
    medium_issues: Optional[int] = None
    low_issues: Optional[int] = None
    total_rules: Optional[int] = None
    
    # Group information
    group_id: Optional[int] = None
    group_name: Optional[str] = None
    group_description: Optional[str] = None
    group_color: Optional[str] = None


class HostCreate(BaseModel):
    hostname: str
    ip_address: str
    display_name: Optional[str] = None
    operating_system: str
    port: Optional[int] = 22
    username: Optional[str] = None
    auth_method: Optional[str] = Field("ssh_key", pattern="^(password|ssh_key|system_default)$")
    ssh_key: Optional[str] = None
    password: Optional[str] = None
    environment: Optional[str] = "production"
    tags: Optional[List[str]] = []
    owner: Optional[str] = None


class HostUpdate(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    display_name: Optional[str] = None
    operating_system: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    auth_method: Optional[str] = Field(None, pattern="^(password|ssh_key|system_default)$")
    ssh_key: Optional[str] = None
    password: Optional[str] = None
    environment: Optional[str] = None
    tags: Optional[List[str]] = None
    owner: Optional[str] = None
    description: Optional[str] = None  # Allow description updates


@router.post("/validate-credentials")
async def validate_credentials(
    validation_data: dict,
    current_user: dict = Depends(get_current_user)
):
    """
    Validate SSH credentials without creating a host.

    This endpoint allows the Add Host frontend to validate SSH keys
    before submission, providing immediate feedback to users.

    Request body:
    {
        "auth_method": "ssh_key" | "password",
        "ssh_key": "string (optional)",
        "password": "string (optional)"
    }

    Returns:
    {
        "is_valid": boolean,
        "auth_method": string,
        "key_type": string (for SSH keys),
        "key_bits": integer (for SSH keys),
        "security_level": string (for SSH keys),
        "error_message": string (if invalid),
        "warnings": list (if any),
        "recommendations": list (if any)
    }
    """
    try:
        auth_method = validation_data.get('auth_method')
        ssh_key = validation_data.get('ssh_key')
        password = validation_data.get('password')

        # Validate SSH key
        if auth_method == 'ssh_key' and ssh_key:
            logger.info("Validating SSH key credentials via validate-credentials endpoint")
            validation_result = validate_ssh_key(ssh_key)

            return {
                "is_valid": validation_result.is_valid,
                "auth_method": "ssh_key",
                "key_type": validation_result.key_type.value if validation_result.key_type else None,
                "key_bits": validation_result.key_size,
                "security_level": validation_result.security_level.value if validation_result.security_level else None,
                "error_message": validation_result.error_message,
                "warnings": validation_result.warnings,
                "recommendations": validation_result.recommendations
            }

        # Password validation (basic check)
        elif auth_method == 'password' and password:
            # Basic password validation - just check it's not empty
            if len(password.strip()) == 0:
                return {
                    "is_valid": False,
                    "auth_method": "password",
                    "error_message": "Password cannot be empty",
                    "warnings": [],
                    "recommendations": ["Use a strong password with at least 12 characters"]
                }

            return {
                "is_valid": True,
                "auth_method": "password",
                "error_message": None,
                "warnings": [] if len(password) >= 12 else ["Password should be at least 12 characters for security"],
                "recommendations": ["Use a password manager", "Consider using SSH key authentication instead"]
            }

        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing credentials: provide either ssh_key or password based on auth_method"
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Credential validation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Validation failed: {str(e)}"
        )


@router.get("/", response_model=List[Host])
async def list_hosts(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """List all managed hosts"""
    try:
        # Try to get hosts from database with latest scan information and group details
        # NOTE: This query uses LATERAL JOIN which is PostgreSQL-specific and complex
        # OW-REFACTOR-001B: Keeping original SQL due to LATERAL JOIN complexity
        result = db.execute(text("""
            SELECT h.id, h.hostname, h.ip_address, h.display_name, h.operating_system,
                   h.status, h.port, h.username, h.auth_method, h.created_at, h.updated_at, h.description,
                   h.last_check, h.response_time_ms, h.check_priority,
                   h.ping_consecutive_failures, h.ssh_consecutive_failures, h.privilege_consecutive_failures,
                   h.ping_consecutive_successes, h.ssh_consecutive_successes, h.privilege_consecutive_successes,
                   s.id as latest_scan_id, s.name as latest_scan_name, s.status as scan_status,
                   s.progress as scan_progress, s.started_at as scan_started_at, s.completed_at as scan_completed_at,
                   sr.score as compliance_score, sr.failed_rules as failed_rules, sr.passed_rules as passed_rules,
                   sr.severity_high as high_issues, sr.severity_medium as medium_issues,
                   sr.severity_low as low_issues, sr.total_rules,
                   hg.id as group_id, hg.name as group_name, hg.description as group_description, hg.color as group_color
            FROM hosts h
            LEFT JOIN LATERAL (
                SELECT s2.id, s2.name, s2.status, s2.progress, s2.started_at, s2.completed_at
                FROM scans s2
                WHERE s2.host_id = h.id
                ORDER BY s2.started_at DESC
                LIMIT 1
            ) s ON true
            LEFT JOIN scan_results sr ON sr.scan_id = s.id
            LEFT JOIN host_group_memberships hgm ON hgm.host_id = h.id
            LEFT JOIN host_groups hg ON hg.id = hgm.group_id
            ORDER BY h.created_at DESC
        """))
        
        hosts = []
        for row in result:
            # Calculate critical issues (high severity issues)
            critical_issues = row.high_issues or 0
            
            # Parse compliance score
            compliance_score = None
            if row.compliance_score:
                try:
                    # Remove % sign if present and convert to float
                    score_str = str(row.compliance_score).replace('%', '')
                    compliance_score = float(score_str)
                except (ValueError, TypeError):
                    pass
            
            host_data = Host(
                id=str(row.id),
                hostname=row.hostname,
                ip_address=str(row.ip_address),
                display_name=row.display_name,
                operating_system=row.operating_system,
                status=row.status,
                port=row.port,
                username=row.username,
                auth_method=row.auth_method,
                created_at=row.created_at.isoformat() + 'Z' if row.created_at else None,
                updated_at=row.updated_at.isoformat() + 'Z' if row.updated_at else None,
                last_check=row.last_check.isoformat() + 'Z' if row.last_check else None,
                response_time_ms=row.response_time_ms,
                check_priority=row.check_priority,
                ping_consecutive_failures=row.ping_consecutive_failures,
                ssh_consecutive_failures=row.ssh_consecutive_failures,
                privilege_consecutive_failures=row.privilege_consecutive_failures,
                ping_consecutive_successes=row.ping_consecutive_successes,
                ssh_consecutive_successes=row.ssh_consecutive_successes,
                privilege_consecutive_successes=row.privilege_consecutive_successes,
                ssh_key_fingerprint=None,  # Not in database schema
                ssh_key_type=None,         # Not in database schema
                ssh_key_bits=None,         # Not in database schema
                ssh_key_comment=None,      # Not in database schema
                group_id=row.group_id,
                group_name=row.group_name,
                group_description=row.group_description,
                group_color=row.group_color
            )
            
            # Add scan information as additional fields
            if row.latest_scan_id:
                host_data.latest_scan_id = str(row.latest_scan_id)
                host_data.latest_scan_name = row.latest_scan_name
                host_data.scan_status = row.scan_status
                host_data.scan_progress = row.scan_progress
                host_data.last_scan = row.scan_completed_at.isoformat() + 'Z' if row.scan_completed_at else (
                    row.scan_started_at.isoformat() + 'Z' if row.scan_started_at else None
                )
                host_data.compliance_score = compliance_score
                host_data.failed_rules = row.failed_rules or 0
                host_data.passed_rules = row.passed_rules or 0
                host_data.critical_issues = critical_issues
                host_data.high_issues = row.high_issues or 0
                host_data.medium_issues = row.medium_issues or 0
                host_data.low_issues = row.low_issues or 0
                host_data.total_rules = row.total_rules or 0
            
            hosts.append(host_data)
        
        return hosts
        
    except Exception as e:
        logger.error(f"Database error in host listing: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve hosts from database"
        )


@router.post("/", response_model=Host)
async def create_host(host: HostCreate, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """Add a new host to management"""
    try:
        # Insert into database
        host_id = str(uuid.uuid4())
        current_time = datetime.utcnow()
        
        # Use display_name if provided, otherwise use hostname
        display_name = host.display_name or host.hostname
        
        # NEW: Handle credentials using unified_credentials system (Phase 5)
        encrypted_creds = None  # Keep NULL for unified system
        if host.auth_method and host.auth_method != "system_default":
            if host.password or host.ssh_key:
                from ..services.auth_service import (
                    get_auth_service,
                    CredentialData,
                    CredentialMetadata,
                    CredentialScope,
                    AuthMethod
                )

                # Validate SSH key if provided
                if host.ssh_key:
                    logger.info(f"Validating SSH key for host '{host.hostname}'")
                    validation_result = validate_ssh_key(host.ssh_key)

                    if not validation_result.is_valid:
                        logger.error(f"SSH key validation failed for host '{host.hostname}': {validation_result.error_message}")
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Invalid SSH key: {validation_result.error_message}"
                        )

                    if validation_result.warnings:
                        logger.warning(f"SSH key warnings for host '{host.hostname}': {'; '.join(validation_result.warnings)}")

                # Create credential data for unified system
                credential_data = CredentialData(
                    username=host.username,
                    auth_method=AuthMethod(host.auth_method),
                    password=host.password if host.auth_method in ['password', 'both'] else None,
                    private_key=host.ssh_key if host.auth_method in ['ssh_key', 'both'] else None,
                    private_key_passphrase=None
                )

                # Create metadata
                metadata = CredentialMetadata(
                    name=f"{host.hostname} credential",
                    description=f"Host-specific credential for {host.hostname}",
                    scope=CredentialScope.HOST,
                    target_id=host_id,  # Link to host we're creating
                    is_default=False
                )

                # Store in unified_credentials after host is created
                # (will be done after the INSERT below)
                logger.info(f"Preparing host-specific credential for {host.hostname} in unified_credentials")
        
        db.execute(text("""
            INSERT INTO hosts (id, hostname, ip_address, display_name, operating_system, status, port, 
                             username, auth_method, encrypted_credentials, is_active, created_at, updated_at)
            VALUES (:id, :hostname, :ip_address, :display_name, :operating_system, :status, :port, 
                    :username, :auth_method, :encrypted_credentials, :is_active, :created_at, :updated_at)
        """), {
            "id": host_id,
            "hostname": host.hostname,
            "ip_address": host.ip_address,
            "display_name": display_name,
            "operating_system": host.operating_system,
            "status": "offline",
            "port": int(host.port) if host.port else 22,
            "username": host.username,
            "auth_method": host.auth_method or "ssh_key",
            "encrypted_credentials": encrypted_creds,
            "is_active": True,
            "created_at": current_time,
            "updated_at": current_time
        })
        
        db.commit()

        # NEW: Store host-specific credential in unified_credentials if provided (Phase 5)
        if host.auth_method and host.auth_method != "system_default":
            if host.password or host.ssh_key:
                try:
                    auth_service = get_auth_service(db)

                    # Get user UUID for created_by field
                    user_id_result = db.execute(text("SELECT id FROM users WHERE id = :user_id"), {"user_id": current_user.get('id')})
                    user_row = user_id_result.fetchone()
                    user_uuid = str(user_row[0]) if user_row else None

                    # Store credential in unified_credentials
                    cred_id = auth_service.store_credential(
                        credential_data=credential_data,
                        metadata=metadata,
                        created_by=user_uuid
                    )
                    logger.info(f"Stored host-specific credential for {host.hostname} in unified_credentials (id: {cred_id})")

                except Exception as e:
                    logger.error(f"Failed to store host-specific credential for {host.hostname}: {e}")
                    # Don't fail the host creation, just log the error
                    # Host will fall back to system default

        new_host = Host(
            id=host_id,
            hostname=host.hostname,
            ip_address=host.ip_address,
            display_name=display_name,
            operating_system=host.operating_system,
            status="offline",
            created_at=current_time.isoformat() + 'Z',
            updated_at=current_time.isoformat() + 'Z'
        )

        logger.info(f"Created new host in database: {host.hostname}")
        return new_host
        
    except Exception as e:
        logger.error(f"Failed to create host in database: {e}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create host"
        )


@router.get("/{host_id}", response_model=Host)
async def get_host(host_id: str, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """Get host details by ID"""
    settings = get_settings()

    try:
        # Validate and convert host_id to UUID
        try:
            host_uuid = uuid.UUID(host_id)
        except (ValueError, TypeError) as e:
            logger.error(f"Invalid host ID format: {sanitize_id_for_log(host_id)} - {type(e).__name__}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid host ID format"
            )

        # OW-REFACTOR-001B: Feature flag for QueryBuilder
        if settings.use_query_builder:
            logger.info(f"Using QueryBuilder for get_host endpoint (host_id: {sanitize_id_for_log(host_id)})")
            # Build query using QueryBuilder
            builder = (QueryBuilder("hosts h")
                .select(
                    "h.id", "h.hostname", "h.ip_address", "h.display_name", "h.operating_system",
                    "h.status", "h.port", "h.username", "h.auth_method", "h.created_at", "h.updated_at", "h.description",
                    "hg.id as group_id", "hg.name as group_name", "hg.description as group_description", "hg.color as group_color"
                )
                .join("host_group_memberships hgm", "hgm.host_id = h.id", "LEFT")
                .join("host_groups hg", "hg.id = hgm.group_id", "LEFT")
                .where("h.id = :id", host_uuid, "id")
            )
            query, params = builder.build()
            result = db.execute(text(query), params)
        else:
            # Original SQL implementation (default)
            logger.info(f"Using original SQL for get_host endpoint (host_id: {sanitize_id_for_log(host_id)})")
            result = db.execute(text("""
                SELECT h.id, h.hostname, h.ip_address, h.display_name, h.operating_system,
                       h.status, h.port, h.username, h.auth_method, h.created_at, h.updated_at, h.description,
                       hg.id as group_id, hg.name as group_name, hg.description as group_description, hg.color as group_color
                FROM hosts h
                LEFT JOIN host_group_memberships hgm ON hgm.host_id = h.id
                LEFT JOIN host_groups hg ON hg.id = hgm.group_id
                WHERE h.id = :id
            """), {"id": host_uuid})
        
        row = result.fetchone()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Host not found"
            )
        
        return Host(
            id=str(row.id),
            hostname=row.hostname,
            ip_address=str(row.ip_address),
            display_name=row.display_name,
            operating_system=row.operating_system,
            status=row.status,
            port=row.port,
            username=row.username,
            auth_method=row.auth_method,
            created_at=row.created_at.isoformat() + 'Z' if row.created_at else None,
            updated_at=row.updated_at.isoformat() + 'Z' if row.updated_at else None,
            ssh_key_fingerprint=None,  # Not in database schema
            ssh_key_type=None,         # Not in database schema
            ssh_key_bits=None,         # Not in database schema 
            ssh_key_comment=None,      # Not in database schema
            group_id=row.group_id,
            group_name=row.group_name,
            group_description=row.group_description,
            group_color=row.group_color
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get host: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve host"
        )


@router.put("/{host_id}", response_model=Host)
async def update_host(host_id: str, host_update: HostUpdate, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """Update host information"""
    try:
        # Validate and convert host_id to UUID
        try:
            host_uuid = uuid.UUID(host_id)
        except (ValueError, TypeError) as e:
            logger.error(f"Invalid host ID format: {sanitize_id_for_log(host_id)} - {type(e).__name__}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid host ID format"
            )
        
        # Check if host exists
        result = db.execute(text("""
            SELECT id FROM hosts WHERE id = :id
        """), {"id": host_uuid})
        
        if not result.fetchone():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Host not found"
            )
        
        # Get current host data for partial updates
        current_host_result = db.execute(text("""
            SELECT hostname, ip_address, display_name, operating_system, port, 
                   username, auth_method, description
            FROM hosts WHERE id = :id
        """), {"id": host_uuid})
        
        current_host = current_host_result.fetchone()
        if not current_host:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Host not found"
            )
        
        # Update host - use existing values if new ones not provided
        current_time = datetime.utcnow()
        
        # Handle display_name logic properly
        new_hostname = host_update.hostname if host_update.hostname is not None else current_host.hostname
        new_display_name = (host_update.display_name if host_update.display_name is not None 
                          else current_host.display_name or new_hostname)
        
        # NEW: Handle credential updates using unified_credentials system (Phase 5)
        encrypted_creds = None  # Always NULL for unified system
        if host_update.auth_method:
            from ..services.auth_service import (
                get_auth_service,
                CredentialData,
                CredentialMetadata,
                CredentialScope,
                AuthMethod
            )

            auth_service = get_auth_service(db)

            if host_update.auth_method == "system_default":
                # Delete host-specific credentials when switching to system default
                try:
                    existing_creds = auth_service.list_credentials(
                        scope=CredentialScope.HOST,
                        target_id=str(host_uuid)
                    )
                    for cred in existing_creds:
                        auth_service.delete_credential(cred['id'])
                    logger.info(f"Deleted host-specific credentials for system default on host {host_id}")
                except Exception as e:
                    logger.error(f"Failed to delete host-specific credentials: {e}")

            elif host_update.password or host_update.ssh_key:
                # Validate SSH key if provided
                if host_update.ssh_key:
                    logger.info(f"Validating SSH key for host update '{host_id}'")
                    validation_result = validate_ssh_key(host_update.ssh_key)

                    if not validation_result.is_valid:
                        logger.error(f"SSH key validation failed for host update '{host_id}': {validation_result.error_message}")
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Invalid SSH key: {validation_result.error_message}"
                        )

                    if validation_result.warnings:
                        logger.warning(f"SSH key warnings for host update '{host_id}': {'; '.join(validation_result.warnings)}")

                # Create credential data
                credential_data = CredentialData(
                    username=host_update.username or current_host.username,
                    auth_method=AuthMethod(host_update.auth_method),
                    password=host_update.password if host_update.auth_method in ['password', 'both'] else None,
                    private_key=host_update.ssh_key if host_update.auth_method in ['ssh_key', 'both'] else None,
                    private_key_passphrase=None
                )

                # Create metadata
                metadata = CredentialMetadata(
                    name=f"{current_host.hostname} credential",
                    description=f"Host-specific credential for {current_host.hostname}",
                    scope=CredentialScope.HOST,
                    target_id=str(host_uuid),
                    is_default=False
                )

                # Check if host-specific credential already exists
                try:
                    existing_creds = auth_service.list_credentials(
                        scope=CredentialScope.HOST,
                        target_id=str(host_uuid)
                    )

                    # Get user UUID for created_by field
                    user_id_result = db.execute(text("SELECT id FROM users WHERE id = :user_id"), {"user_id": current_user.get('id')})
                    user_row = user_id_result.fetchone()
                    user_uuid = str(user_row[0]) if user_row else None

                    if existing_creds:
                        # Delete old credential and create new one (simpler than update)
                        for cred in existing_creds:
                            auth_service.delete_credential(cred['id'])
                        logger.info(f"Deleted old host-specific credential for {current_host.hostname}")

                    # Store new credential
                    cred_id = auth_service.store_credential(
                        credential_data=credential_data,
                        metadata=metadata,
                        created_by=user_uuid
                    )
                    logger.info(f"Stored updated host-specific credential for {current_host.hostname} (id: {cred_id})")

                except Exception as e:
                    logger.error(f"Failed to update host-specific credential: {e}")
                    # Continue with host update even if credential storage fails
        
        # Update all fields including encrypted credentials
        update_params = {
            "id": host_uuid,
            "hostname": new_hostname,
            "ip_address": host_update.ip_address if host_update.ip_address is not None else current_host.ip_address,
            "display_name": new_display_name,
            "operating_system": host_update.operating_system if host_update.operating_system is not None else current_host.operating_system,
            "port": host_update.port if host_update.port is not None else current_host.port,
            "username": host_update.username if host_update.username is not None else current_host.username,
            "auth_method": host_update.auth_method if host_update.auth_method is not None else current_host.auth_method,
            "description": host_update.description if host_update.description is not None else current_host.description,
            "updated_at": current_time
        }
        
        # Build SQL query with optional encrypted_credentials
        if encrypted_creds is not None or (host_update.auth_method == "system_default"):
            update_query = """
                UPDATE hosts 
                SET hostname = :hostname,
                    ip_address = :ip_address,
                    display_name = :display_name,
                    operating_system = :operating_system,
                    port = :port,
                    username = :username,
                    auth_method = :auth_method,
                    description = :description,
                    encrypted_credentials = :encrypted_credentials,
                    updated_at = :updated_at
                WHERE id = :id
            """
            update_params["encrypted_credentials"] = encrypted_creds
        else:
            update_query = """
                UPDATE hosts 
                SET hostname = :hostname,
                    ip_address = :ip_address,
                    display_name = :display_name,
                    operating_system = :operating_system,
                    port = :port,
                    username = :username,
                    auth_method = :auth_method,
                    description = :description,
                    updated_at = :updated_at
                WHERE id = :id
            """
        
        db.execute(text(update_query), update_params)
        
        db.commit()
        
        # Get updated host with group information
        result = db.execute(text("""
            SELECT h.id, h.hostname, h.ip_address, h.display_name, h.operating_system, 
                   h.status, h.port, h.username, h.auth_method, h.created_at, h.updated_at, h.description,
                   hg.id as group_id, hg.name as group_name, hg.description as group_description, hg.color as group_color
            FROM hosts h
            LEFT JOIN host_group_memberships hgm ON hgm.host_id = h.id
            LEFT JOIN host_groups hg ON hg.id = hgm.group_id
            WHERE h.id = :id
        """), {"id": host_uuid})
        
        row = result.fetchone()
        updated_host = Host(
            id=str(row.id),
            hostname=row.hostname,
            ip_address=str(row.ip_address),
            display_name=row.display_name,
            operating_system=row.operating_system,
            status=row.status,
            port=row.port,
            username=row.username,
            auth_method=row.auth_method,
            created_at=row.created_at.isoformat() + 'Z' if row.created_at else None,
            updated_at=row.updated_at.isoformat() + 'Z' if row.updated_at else None,
            ssh_key_fingerprint=None,  # Not in database schema
            ssh_key_type=None,         # Not in database schema
            ssh_key_bits=None,         # Not in database schema 
            ssh_key_comment=None,      # Not in database schema
            group_id=row.group_id,
            group_name=row.group_name,
            group_description=row.group_description,
            group_color=row.group_color
        )
        
        logger.info(f"Updated host {host_id}")
        return updated_host
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update host: {e}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update host"
        )


@router.delete("/{host_id}")
async def delete_host(host_id: str, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """Remove host from management"""
    try:
        # Validate and convert host_id to UUID
        try:
            host_uuid = uuid.UUID(host_id)
        except (ValueError, TypeError) as e:
            logger.error(f"Invalid host ID format: {sanitize_id_for_log(host_id)} - {type(e).__name__}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid host ID format"
            )
        
        # Check if host exists
        result = db.execute(text("""
            SELECT id FROM hosts WHERE id = :id
        """), {"id": host_uuid})
        
        if not result.fetchone():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Host not found"
            )
        
        # Check if host has any scans (optional - you might want to prevent deletion)
        scan_result = db.execute(text("""
            SELECT COUNT(*) as count FROM scans WHERE host_id = :host_id
        """), {"host_id": host_uuid})
        
        scan_count = scan_result.fetchone().count
        if scan_count > 0:
            # You can either delete the scans or prevent deletion
            # For now, we'll delete the scans too
            db.execute(text("""
                DELETE FROM scan_results WHERE scan_id IN (
                    SELECT id FROM scans WHERE host_id = :host_id
                )
            """), {"host_id": host_uuid})
            
            db.execute(text("""
                DELETE FROM scans WHERE host_id = :host_id
            """), {"host_id": host_uuid})
            
            logger.info(f"Deleted {scan_count} scans for host {host_id}")
        
        # Delete the host
        db.execute(text("""
            DELETE FROM hosts WHERE id = :id
        """), {"id": host_uuid})
        
        db.commit()
        
        logger.info(f"Deleted host {host_id}")
        return {"message": "Host deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete host: {e}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete host"
        )


@router.delete("/{host_id}/ssh-key")
async def delete_host_ssh_key(host_id: str, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """Delete SSH key from host"""
    try:
        # Validate and convert host_id to UUID
        try:
            host_uuid = uuid.UUID(host_id)
        except (ValueError, TypeError) as e:
            logger.error(f"Invalid host ID format: {sanitize_id_for_log(host_id)} - {type(e).__name__}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid host ID format"
            )
        
        # Check if host exists and has SSH key
        result = db.execute(text("""
            SELECT id, auth_method, ssh_key_fingerprint FROM hosts 
            WHERE id = :id
        """), {"id": host_uuid})
        
        row = result.fetchone()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Host not found"
            )
        
        if not row.ssh_key_fingerprint:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No SSH key found to delete"
            )
        
        # Update host to remove SSH key
        db.execute(text("""
            UPDATE hosts SET 
                ssh_key_fingerprint = NULL,
                ssh_key_type = NULL,
                ssh_key_bits = NULL,
                ssh_key_comment = NULL,
                updated_at = :updated_at
            WHERE id = :id
        """), {
            "id": host_uuid,
            "updated_at": datetime.utcnow()
        })
        
        db.commit()
        
        logger.info(f"Deleted SSH key from host {host_id}")
        return {"message": "SSH key deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete SSH key from host: {e}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete SSH key"
        )