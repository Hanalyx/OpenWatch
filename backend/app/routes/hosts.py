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


@router.get("/", response_model=List[Host])
async def list_hosts(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """List all managed hosts"""
    try:
        # Try to get hosts from database with latest scan information and group details
        result = db.execute(text("""
            SELECT h.id, h.hostname, h.ip_address, h.display_name, h.operating_system, 
                   h.status, h.port, h.username, h.auth_method, h.created_at, h.updated_at, h.description,
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
                created_at=row.created_at.isoformat() if row.created_at else None,
                updated_at=row.updated_at.isoformat() if row.updated_at else None,
                last_check=None,  # Column doesn't exist in database
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
                host_data.last_scan = row.scan_completed_at.isoformat() if row.scan_completed_at else (
                    row.scan_started_at.isoformat() if row.scan_started_at else None
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
        
        # Handle credential encryption if provided
        encrypted_creds = None
        if host.auth_method == "password" and host.password:
            from ..services.crypto import encrypt_credentials
            cred_data = {
                "username": host.username,
                "password": host.password,
                "auth_method": "password"
            }
            encrypted_creds = encrypt_credentials(json.dumps(cred_data))
            logger.info(f"Encrypting password credentials for new host {host.hostname}")
        elif host.auth_method == "ssh_key" and host.ssh_key:
            from ..services.crypto import encrypt_credentials
            cred_data = {
                "username": host.username,
                "ssh_key": host.ssh_key,
                "auth_method": "ssh_key"
            }
            encrypted_creds = encrypt_credentials(json.dumps(cred_data))
            logger.info(f"Encrypting SSH key credentials for new host {host.hostname}")
        
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
        
        new_host = Host(
            id=host_id,
            hostname=host.hostname,
            ip_address=host.ip_address,
            display_name=display_name,
            operating_system=host.operating_system,
            status="offline",
            created_at=current_time.isoformat(),
            updated_at=current_time.isoformat()
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
            created_at=row.created_at.isoformat() if row.created_at else None,
            updated_at=row.updated_at.isoformat() if row.updated_at else None,
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
        
        # Handle credential updates if provided
        encrypted_creds = None
        if host_update.auth_method:
            if host_update.auth_method == "password" and host_update.password:
                # Encrypt password credentials
                from ..services.crypto import encrypt_credentials
                cred_data = {
                    "username": host_update.username or current_host.username,
                    "password": host_update.password,
                    "auth_method": "password"
                }
                encrypted_creds = encrypt_credentials(json.dumps(cred_data))
                logger.info(f"Encrypting password credentials for host {host_id}")
            elif host_update.auth_method == "ssh_key" and host_update.ssh_key:
                # Encrypt SSH key credentials
                from ..services.crypto import encrypt_credentials
                cred_data = {
                    "username": host_update.username or current_host.username,
                    "ssh_key": host_update.ssh_key,
                    "auth_method": "ssh_key"
                }
                encrypted_creds = encrypt_credentials(json.dumps(cred_data))
                logger.info(f"Encrypting SSH key credentials for host {host_id}")
            elif host_update.auth_method == "system_default":
                # Clear host-specific credentials when using system default
                encrypted_creds = None
                logger.info(f"Clearing host credentials for system default auth on host {host_id}")
        
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
            created_at=row.created_at.isoformat() if row.created_at else None,
            updated_at=row.updated_at.isoformat() if row.updated_at else None,
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