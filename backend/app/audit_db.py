"""
Database Audit Logging Module
Provides functions to write audit events directly to the database
"""
from sqlalchemy.orm import Session
from sqlalchemy import text
from datetime import datetime
from typing import Optional
import logging

logger = logging.getLogger(__name__)


def log_audit_event(
    db: Session,
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    user_id: Optional[int] = None,
    ip_address: str = "0.0.0.0",
    user_agent: Optional[str] = None,
    details: Optional[str] = None
) -> bool:
    """
    Log an audit event to the database
    
    Args:
        db: Database session
        action: Action performed (e.g., LOGIN_SUCCESS, SCAN_CREATED)
        resource_type: Type of resource (e.g., auth, scan, host)
        resource_id: ID of the resource (optional)
        user_id: ID of the user performing the action (optional)
        ip_address: IP address of the client
        user_agent: User agent string (optional)
        details: Additional details about the event (optional)
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        query = text("""
            INSERT INTO audit_logs (
                user_id, action, resource_type, resource_id, 
                ip_address, user_agent, details, timestamp
            ) VALUES (
                :user_id, :action, :resource_type, :resource_id,
                :ip_address, :user_agent, :details, :timestamp
            )
        """)
        
        db.execute(query, {
            "user_id": user_id,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "details": details,
            "timestamp": datetime.utcnow()
        })
        
        db.commit()
        return True
        
    except Exception as e:
        logger.error(f"Failed to log audit event: {e}")
        db.rollback()
        return False


def log_login_event(
    db: Session,
    username: str,
    user_id: Optional[int],
    success: bool,
    ip_address: str,
    user_agent: Optional[str] = None,
    failure_reason: Optional[str] = None
) -> bool:
    """Log login attempt to database"""
    action = "LOGIN_SUCCESS" if success else "LOGIN_FAILED"
    details = f"User {username} logged in successfully" if success else f"Failed login attempt for {username}"
    if failure_reason and not success:
        details += f" - Reason: {failure_reason}"
    
    return log_audit_event(
        db=db,
        action=action,
        resource_type="auth",
        user_id=user_id if success else None,
        ip_address=ip_address,
        user_agent=user_agent,
        details=details
    )


def log_scan_event(
    db: Session,
    action: str,
    scan_id: Optional[str],
    user_id: int,
    ip_address: str,
    host_name: Optional[str] = None,
    details: Optional[str] = None
) -> bool:
    """Log scan-related events to database"""
    scan_details = details or f"Scan operation: {action}"
    if host_name:
        scan_details += f" on host {host_name}"
    
    return log_audit_event(
        db=db,
        action=f"SCAN_{action.upper()}",
        resource_type="scan",
        resource_id=scan_id,
        user_id=user_id,
        ip_address=ip_address,
        details=scan_details
    )


def log_host_event(
    db: Session,
    action: str,
    host_id: Optional[str],
    host_name: str,
    user_id: int,
    ip_address: str,
    details: Optional[str] = None
) -> bool:
    """Log host-related events to database"""
    host_details = details or f"{action.title()} host: {host_name}"
    
    return log_audit_event(
        db=db,
        action=f"HOST_{action.upper()}",
        resource_type="host",
        resource_id=host_id,
        user_id=user_id,
        ip_address=ip_address,
        details=host_details
    )


def log_user_event(
    db: Session,
    action: str,
    target_user_id: Optional[str],
    target_username: str,
    user_id: int,
    ip_address: str,
    details: Optional[str] = None
) -> bool:
    """Log user management events to database"""
    user_details = details or f"{action.title()} user: {target_username}"
    
    return log_audit_event(
        db=db,
        action=f"USER_{action.upper()}",
        resource_type="user",
        resource_id=target_user_id,
        user_id=user_id,
        ip_address=ip_address,
        details=user_details
    )


def log_security_event(
    db: Session,
    event_type: str,
    ip_address: str,
    user_id: Optional[int] = None,
    details: Optional[str] = None
) -> bool:
    """Log security-related events to database"""
    return log_audit_event(
        db=db,
        action=f"SECURITY_{event_type.upper()}",
        resource_type="security",
        user_id=user_id,
        ip_address=ip_address,
        details=details
    )


def log_admin_event(
    db: Session,
    action: str,
    user_id: int,
    ip_address: str,
    resource_type: str = "system",
    details: Optional[str] = None
) -> bool:
    """Log administrative actions to database"""
    return log_audit_event(
        db=db,
        action=f"ADMIN_{action.upper()}",
        resource_type=resource_type,
        user_id=user_id,
        ip_address=ip_address,
        details=details
    )