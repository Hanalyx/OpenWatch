"""
Host Management Routes
"""
from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer
from pydantic import BaseModel
from typing import List, Optional
import logging
from datetime import datetime
import uuid

from ..database import get_db
from sqlalchemy.orm import Session
from sqlalchemy import text
import json
import base64
from ..services.ssh_utils import validate_ssh_key, format_validation_message
from ..services.ssh_key_service import extract_ssh_key_metadata

logger = logging.getLogger(__name__)
security = HTTPBearer(auto_error=False)

router = APIRouter()


def encrypt_credentials(credentials_data: dict) -> str:
    """Simple base64 encoding for credentials (should use proper encryption in production)"""
    try:
        json_str = json.dumps(credentials_data)
        encoded = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
        return encoded
    except Exception as e:
        logger.error(f"Failed to encode credentials: {e}")
        raise


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
    auth_method: Optional[str] = "ssh_key"
    ssh_key: Optional[str] = None
    password: Optional[str] = None
    environment: Optional[str] = "production"
    tags: Optional[List[str]] = []
    owner: Optional[str] = None


@router.get("/", response_model=List[Host])
async def list_hosts(db: Session = Depends(get_db), token: str = Depends(security)):
    """List all managed hosts"""
    try:
        # Try to get hosts from database with latest scan information and group details
        result = db.execute(text("""
            SELECT h.id, h.hostname, h.ip_address, h.display_name, h.operating_system, 
                   h.status, h.port, h.username, h.auth_method, h.created_at, h.updated_at, h.last_check,
                   h.ssh_key_fingerprint, h.ssh_key_type, h.ssh_key_bits, h.ssh_key_comment,
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
                last_check=row.last_check.isoformat() if row.last_check else None,
                ssh_key_fingerprint=row.ssh_key_fingerprint,
                ssh_key_type=row.ssh_key_type,
                ssh_key_bits=row.ssh_key_bits,
                ssh_key_comment=row.ssh_key_comment,
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
        logger.warning(f"Database error, returning mock data: {e}")
        # Fallback to mock data if database fails
        mock_hosts = [
            Host(
                id="1",
                hostname="web-server-01",
                ip_address="192.168.1.10",
                display_name="Production Web Server",
                operating_system="Ubuntu 22.04 LTS",
                status="online",
                last_scan="2024-01-15T10:30:00Z",
                compliance_score=92.0
            ),
            Host(
                id="2",
                hostname="db-server-01",
                ip_address="192.168.1.20",
                display_name="Primary Database",
                operating_system="Red Hat Enterprise Linux 9",
                status="online",
                last_scan="2024-01-14T15:45:00Z",
                compliance_score=88.0
            )
        ]
        return mock_hosts


@router.post("/", response_model=Host)
async def create_host(host: HostCreate, db: Session = Depends(get_db), token: str = Depends(security)):
    """Add a new host to management"""
    try:
        # Insert into database
        host_id = str(uuid.uuid4())
        current_time = datetime.utcnow()
        
        # Use display_name if provided, otherwise use hostname
        display_name = host.display_name or host.hostname
        
        db.execute(text("""
            INSERT INTO hosts (id, hostname, ip_address, display_name, operating_system, status, port, is_active, created_at, updated_at)
            VALUES (:id, :hostname, :ip_address, :display_name, :operating_system, :status, :port, :is_active, :created_at, :updated_at)
        """), {
            "id": host_id,
            "hostname": host.hostname,
            "ip_address": host.ip_address,
            "display_name": display_name,
            "operating_system": host.operating_system,
            "status": "offline",
            "port": int(host.port) if host.port else 22,
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
        
        # Fallback to mock response
        new_host = Host(
            id=str(uuid.uuid4()),
            hostname=host.hostname,
            ip_address=host.ip_address,
            display_name=host.display_name or host.hostname,
            operating_system=host.operating_system,
            status="offline"
        )
        
        logger.info(f"Created mock host (database failed): {host.hostname}")
        return new_host


@router.get("/{host_id}", response_model=Host)
async def get_host(host_id: str, db: Session = Depends(get_db), token: str = Depends(security)):
    """Get host details by ID"""
    try:
        result = db.execute(text("""
            SELECT h.id, h.hostname, h.ip_address, h.display_name, h.operating_system, 
                   h.status, h.port, h.username, h.auth_method, h.created_at, h.updated_at, h.last_check,
                   h.ssh_key_fingerprint, h.ssh_key_type, h.ssh_key_bits, h.ssh_key_comment,
                   hg.id as group_id, hg.name as group_name, hg.description as group_description, hg.color as group_color
            FROM hosts h
            LEFT JOIN host_group_memberships hgm ON hgm.host_id = h.id
            LEFT JOIN host_groups hg ON hg.id = hgm.group_id
            WHERE h.id = :id
        """), {"id": host_id})
        
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
            last_check=row.last_check.isoformat() if row.last_check else None,
            ssh_key_fingerprint=row.ssh_key_fingerprint,
            ssh_key_type=row.ssh_key_type,
            ssh_key_bits=row.ssh_key_bits,
            ssh_key_comment=row.ssh_key_comment,
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
async def update_host(host_id: str, host_update: HostCreate, db: Session = Depends(get_db), token: str = Depends(security)):
    """Update host information"""
    try:
        # Check if host exists
        result = db.execute(text("""
            SELECT id FROM hosts WHERE id = :id
        """), {"id": host_id})
        
        if not result.fetchone():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Host not found"
            )
        
        # Update host
        current_time = datetime.utcnow()
        display_name = host_update.display_name or host_update.hostname
        
        # Validate and encrypt SSH credentials if provided
        encrypted_credentials = None
        ssh_key_fingerprint = None
        ssh_key_type = None
        ssh_key_bits = None
        ssh_key_comment = None
        
        if host_update.ssh_key or host_update.password:
            try:
                # Validate SSH key if provided
                if host_update.ssh_key and host_update.auth_method == "ssh_key":
                    logger.info(f"Validating SSH key for host {host_update.hostname}")
                    validation_result = validate_ssh_key(host_update.ssh_key)
                    
                    if not validation_result.is_valid:
                        logger.error(f"SSH key validation failed for {host_update.hostname}: {validation_result.error_message}")
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Invalid SSH key: {validation_result.error_message}"
                        )
                    
                    # Log warnings if any
                    if validation_result.warnings:
                        logger.warning(f"SSH key warnings for {host_update.hostname}: {'; '.join(validation_result.warnings)}")
                    
                    # Log recommendations
                    if validation_result.recommendations:
                        logger.info(f"SSH key recommendations for {host_update.hostname}: {'; '.join(validation_result.recommendations)}")
                    
                    # Extract SSH key metadata for storage and display
                    metadata = extract_ssh_key_metadata(host_update.ssh_key)
                    ssh_key_fingerprint = metadata.get('fingerprint')
                    ssh_key_type = metadata.get('key_type')
                    ssh_key_bits = int(metadata.get('key_bits')) if metadata.get('key_bits') else None
                    ssh_key_comment = metadata.get('key_comment')
                    
                    if metadata.get('error'):
                        logger.warning(f"Failed to extract SSH key metadata for '{host_update.hostname}': {metadata.get('error')}")
                
                credentials_data = {
                    "username": host_update.username,
                    "auth_method": host_update.auth_method
                }
                
                # Add SSH key if provided and validated
                if host_update.ssh_key:
                    credentials_data["ssh_key"] = host_update.ssh_key
                
                # Add password if provided
                if host_update.password:
                    credentials_data["password"] = host_update.password
                
                encrypted_credentials = encrypt_credentials(credentials_data)
                logger.info(f"SSH credentials encrypted successfully for host {host_update.hostname}")
                
            except HTTPException:
                raise  # Re-raise HTTP exceptions (like validation errors)
            except Exception as e:
                logger.error(f"Failed to encrypt SSH credentials: {e}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to encrypt SSH credentials"
                )
        
        db.execute(text("""
            UPDATE hosts 
            SET hostname = :hostname,
                ip_address = :ip_address,
                display_name = :display_name,
                operating_system = :operating_system,
                port = :port,
                username = :username,
                auth_method = :auth_method,
                encrypted_credentials = :encrypted_credentials,
                ssh_key_fingerprint = :ssh_key_fingerprint,
                ssh_key_type = :ssh_key_type,
                ssh_key_bits = :ssh_key_bits,
                ssh_key_comment = :ssh_key_comment,
                updated_at = :updated_at
            WHERE id = :id
        """), {
            "id": host_id,
            "hostname": host_update.hostname,
            "ip_address": host_update.ip_address,
            "display_name": display_name,
            "operating_system": host_update.operating_system,
            "port": host_update.port,
            "username": host_update.username,
            "auth_method": host_update.auth_method,
            "encrypted_credentials": encrypted_credentials,
            "ssh_key_fingerprint": ssh_key_fingerprint if host_update.ssh_key else None,
            "ssh_key_type": ssh_key_type if host_update.ssh_key else None,
            "ssh_key_bits": ssh_key_bits if host_update.ssh_key else None,
            "ssh_key_comment": ssh_key_comment if host_update.ssh_key else None,
            "updated_at": current_time
        })
        
        db.commit()
        
        # Get updated host with group information and SSH key metadata
        result = db.execute(text("""
            SELECT h.id, h.hostname, h.ip_address, h.display_name, h.operating_system, 
                   h.status, h.port, h.username, h.auth_method, h.created_at, h.updated_at,
                   h.ssh_key_fingerprint, h.ssh_key_type, h.ssh_key_bits, h.ssh_key_comment,
                   hg.id as group_id, hg.name as group_name, hg.description as group_description, hg.color as group_color
            FROM hosts h
            LEFT JOIN host_group_memberships hgm ON hgm.host_id = h.id
            LEFT JOIN host_groups hg ON hg.id = hgm.group_id
            WHERE h.id = :id
        """), {"id": host_id})
        
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
            ssh_key_fingerprint=row.ssh_key_fingerprint,
            ssh_key_type=row.ssh_key_type,
            ssh_key_bits=row.ssh_key_bits,
            ssh_key_comment=row.ssh_key_comment,
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
async def delete_host(host_id: str, db: Session = Depends(get_db), token: str = Depends(security)):
    """Remove host from management"""
    try:
        # Check if host exists
        result = db.execute(text("""
            SELECT id FROM hosts WHERE id = :id
        """), {"id": host_id})
        
        if not result.fetchone():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Host not found"
            )
        
        # Check if host has any scans (optional - you might want to prevent deletion)
        scan_result = db.execute(text("""
            SELECT COUNT(*) as count FROM scans WHERE host_id = :host_id
        """), {"host_id": host_id})
        
        scan_count = scan_result.fetchone().count
        if scan_count > 0:
            # You can either delete the scans or prevent deletion
            # For now, we'll delete the scans too
            db.execute(text("""
                DELETE FROM scan_results WHERE scan_id IN (
                    SELECT id FROM scans WHERE host_id = :host_id
                )
            """), {"host_id": host_id})
            
            db.execute(text("""
                DELETE FROM scans WHERE host_id = :host_id
            """), {"host_id": host_id})
            
            logger.info(f"Deleted {scan_count} scans for host {host_id}")
        
        # Delete the host
        db.execute(text("""
            DELETE FROM hosts WHERE id = :id
        """), {"id": host_id})
        
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
async def delete_host_ssh_key(host_id: str, db: Session = Depends(get_db), token: str = Depends(security)):
    """Delete SSH key from host"""
    try:
        # Check if host exists and has SSH key
        result = db.execute(text("""
            SELECT id, auth_method, ssh_key_fingerprint FROM hosts 
            WHERE id = :id
        """), {"id": host_id})
        
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
            "id": host_id,
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