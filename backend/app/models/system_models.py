"""
System Information Models for Security Fix 5: System Information Sanitization

Provides safe models for exposing only necessary system information while 
preventing reconnaissance attacks through detailed technical information exposure.
"""

from pydantic import BaseModel, Field
from typing import Dict, Any, Optional, List
from datetime import datetime
from enum import Enum
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class SystemInfoLevel(str, Enum):
    """Levels of system information exposure"""
    BASIC = "basic"         # Minimal info for compliance only
    COMPLIANCE = "compliance"  # Info needed for compliance reporting
    OPERATIONAL = "operational"  # Info for system operations 
    ADMIN = "admin"         # Full technical details (admin only)


class ComplianceSystemInfo(BaseModel):
    """Safe system information for compliance reporting"""
    os_family: Optional[str] = None  # e.g., "linux", "windows" (generic)
    compliance_relevant_info: Dict[str, Any] = Field(default_factory=dict)
    last_updated: datetime = Field(default_factory=datetime.utcnow)
    info_level: SystemInfoLevel = SystemInfoLevel.COMPLIANCE
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class OperationalSystemInfo(ComplianceSystemInfo):
    """System information for operational purposes"""
    kernel_family: Optional[str] = None  # e.g., "Linux", "NT" (generic)
    service_status: Dict[str, str] = Field(default_factory=dict)  # sanitized service info
    resource_availability: Dict[str, Any] = Field(default_factory=dict)
    info_level: SystemInfoLevel = SystemInfoLevel.OPERATIONAL


class AdminSystemInfo(ComplianceSystemInfo):
    """Full system information for administrators only"""
    detailed_os_info: Optional[str] = None  # Full os-release content
    kernel_version: Optional[str] = None
    installed_packages: List[str] = Field(default_factory=list) 
    network_configuration: Dict[str, Any] = Field(default_factory=dict)
    running_services: List[Dict[str, Any]] = Field(default_factory=list)
    system_details: Optional[str] = None  # Full uname output
    info_level: SystemInfoLevel = SystemInfoLevel.ADMIN


class SystemInfoSanitizationContext(BaseModel):
    """Context for system information sanitization"""
    user_id: Optional[str] = None
    user_role: Optional[str] = None
    source_ip: Optional[str] = None
    access_level: SystemInfoLevel = SystemInfoLevel.BASIC
    is_admin: bool = False
    compliance_only: bool = True
    
    
class SystemInfoFilter(BaseModel):
    """Configuration for filtering system information"""
    allow_os_version: bool = False
    allow_kernel_info: bool = False 
    allow_package_info: bool = False
    allow_network_config: bool = False
    allow_service_info: bool = False
    allow_detailed_errors: bool = False
    sanitization_level: SystemInfoLevel = SystemInfoLevel.BASIC


class SystemInfoMetadata(BaseModel):
    """Metadata about system information collection"""
    collection_timestamp: datetime = Field(default_factory=datetime.utcnow)
    collection_method: str = "ssh_command"
    sanitization_applied: bool = True
    sanitization_level: SystemInfoLevel = SystemInfoLevel.BASIC
    admin_access_used: bool = False
    reconnaissance_filtered: bool = True


class SanitizedSystemValidation(BaseModel):
    """Sanitized validation result containing safe system information"""
    can_proceed: bool
    system_compatible: bool = True
    compliance_info: ComplianceSystemInfo
    validation_timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: SystemInfoMetadata
    # No technical_details field - removed for security


class SystemReconnaissancePattern(BaseModel):
    """Pattern for detecting reconnaissance attempts"""
    pattern_id: str
    description: str
    regex_pattern: str
    severity: str = "high"  # high, medium, low
    block_exposure: bool = True


class SystemInfoAuditEvent(BaseModel):
    """Audit event for system information access"""
    event_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    user_id: Optional[str] = None
    source_ip: Optional[str] = None
    requested_level: SystemInfoLevel
    granted_level: SystemInfoLevel
    admin_access: bool = False
    reconnaissance_detected: bool = False
    patterns_triggered: List[str] = Field(default_factory=list)
    sanitization_applied: bool = True


class SystemSettings(Base):
    """System configuration settings for SSH and other services"""
    __tablename__ = "system_settings"
    
    id = Column(Integer, primary_key=True, index=True)
    setting_key = Column(String(100), unique=True, nullable=False, index=True)
    setting_value = Column(Text, nullable=True)
    setting_type = Column(String(20), default="string", nullable=False)  # string, json, boolean, integer
    description = Column(Text, nullable=True)
    created_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    modified_by = Column(Integer, nullable=True)
    modified_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    is_secure = Column(Boolean, default=False, nullable=False)  # Encrypt sensitive values