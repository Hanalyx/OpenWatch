"""
Group scan session models and data structures
"""

from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class ScanSessionStatus(str, Enum):
    """Status values for group scan sessions"""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class HostScanStatus(str, Enum):
    """Status values for individual host scans within a group scan"""

    PENDING = "pending"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class GroupScanConfig(BaseModel):
    """Configuration for group scan initiation"""

    content_id: Optional[int] = None
    profile_id: Optional[str] = None
    scan_options: Optional[Dict[str, Any]] = {}
    priority: Optional[str] = "normal"
    stagger_delay: int = 30  # seconds between scan starts
    max_concurrent: int = 5  # maximum concurrent scans
    email_notify: bool = False


class HostScanDetail(BaseModel):
    """Detailed status of a host within a group scan"""

    host_id: str
    host_name: str
    hostname: str
    ip_address: str
    status: HostScanStatus
    scan_id: Optional[str] = None
    scan_start_time: Optional[datetime] = None
    scan_end_time: Optional[datetime] = None
    progress: int = 0
    error_message: Optional[str] = None
    scan_results: Optional[Dict[str, Any]] = None


class GroupScanSession(BaseModel):
    """Group scan session tracking information"""

    session_id: str
    group_id: int
    group_name: str
    total_hosts: int
    initiated_by: int
    start_time: datetime
    estimated_completion: Optional[datetime] = None
    actual_completion: Optional[datetime] = None
    status: ScanSessionStatus
    hosts_scanning: List[str] = []  # Host IDs currently being scanned
    hosts_pending: List[str] = []  # Host IDs waiting to be scanned
    hosts_completed: List[str] = []  # Host IDs with completed scans
    hosts_failed: List[str] = []  # Host IDs with failed scans
    scan_config: Optional[GroupScanConfig] = None
    metadata: Optional[Dict[str, Any]] = {}


class GroupScanProgress(BaseModel):
    """Real-time progress information for a group scan"""

    session_id: str
    group_id: int
    group_name: str
    status: ScanSessionStatus
    total_hosts: int
    hosts_completed: int
    hosts_failed: int
    hosts_scanning: int
    hosts_pending: int
    progress_percentage: float
    estimated_completion: Optional[datetime] = None
    average_scan_duration: Optional[float] = None  # seconds
    started_at: datetime
    last_updated: datetime


class GroupScanSummary(BaseModel):
    """Summary results for a completed group scan"""

    session_id: str
    group_id: int
    group_name: str
    total_hosts: int
    successful_scans: int
    failed_scans: int
    total_rules_checked: int
    total_passed_rules: int
    total_failed_rules: int
    average_compliance_score: float
    scan_duration_minutes: int
    completed_at: datetime
    host_results: List[Dict[str, Any]] = []


class ActiveScanSession(BaseModel):
    """Active scan session information for listing"""

    session_id: str
    group_id: int
    group_name: str
    status: ScanSessionStatus
    progress_percentage: float
    hosts_completed: int
    total_hosts: int
    started_at: datetime
    estimated_completion: Optional[datetime] = None
    initiated_by: int
