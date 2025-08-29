"""
Group Scan Service - Manages group scan sessions and progress tracking
"""
import uuid
import json
import logging
import asyncio
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import text

from ..models.scan_models import (
    GroupScanSession, GroupScanProgress, GroupScanConfig, 
    HostScanDetail, HostScanStatus, ScanSessionStatus, 
    GroupScanSummary, ActiveScanSession
)
from ..tasks.scan_tasks import execute_scan_task


logger = logging.getLogger(__name__)


class GroupScanProgressTracker:
    """Real-time progress tracking for group scans"""
    
    def __init__(self, db: Session):
        self.db = db
    
    async def update_host_status(
        self, 
        session_id: str, 
        host_id: str, 
        status: str, 
        scan_id: Optional[str] = None,
        scan_result_id: Optional[str] = None,
        error_message: Optional[str] = None,
        progress: int = 0
    ):
        """Update individual host scan status within a group scan"""
        try:
            # Update host progress in group_scan_host_progress table
            self.db.execute(text("""
                UPDATE group_scan_host_progress 
                SET status = :status, 
                    scan_result_id = :scan_result_id,
                    error_message = :error_message,
                    updated_at = :updated_at,
                    scan_end_time = CASE WHEN :status IN ('completed', 'failed', 'cancelled') 
                                        THEN :updated_at ELSE scan_end_time END,
                    scan_start_time = CASE WHEN :status = 'scanning' AND scan_start_time IS NULL
                                          THEN :updated_at ELSE scan_start_time END
                WHERE session_id = :session_id AND host_id = :host_id
            """), {
                "session_id": session_id,
                "host_id": host_id,
                "status": status,
                "scan_result_id": scan_result_id,
                "error_message": error_message,
                "updated_at": datetime.utcnow()
            })
            
            # Update the main scan record if scan_id provided
            if scan_id:
                self.db.execute(text("""
                    UPDATE group_scan_host_progress 
                    SET scan_id = :scan_id
                    WHERE session_id = :session_id AND host_id = :host_id
                """), {
                    "session_id": session_id,
                    "host_id": host_id,
                    "scan_id": scan_id
                })
            
            # Update overall session progress
            await self._update_session_progress(session_id)
            
            self.db.commit()
            
            logger.debug(f"Updated host {host_id} status to {status} in session {session_id}")
            
        except Exception as e:
            logger.error(f"Failed to update host status: {e}")
            self.db.rollback()
            raise
    
    async def _update_session_progress(self, session_id: str):
        """Update overall session progress based on host statuses"""
        try:
            # Get host status counts
            result = self.db.execute(text("""
                SELECT 
                    status,
                    COUNT(*) as count
                FROM group_scan_host_progress 
                WHERE session_id = :session_id
                GROUP BY status
            """), {"session_id": session_id})
            
            status_counts = {row.status: row.count for row in result}
            
            total_hosts = sum(status_counts.values())
            completed = status_counts.get('completed', 0)
            failed = status_counts.get('failed', 0)
            scanning = status_counts.get('scanning', 0)
            pending = status_counts.get('pending', 0)
            cancelled = status_counts.get('cancelled', 0)
            
            # Determine overall session status
            session_status = ScanSessionStatus.IN_PROGRESS
            if completed + failed + cancelled == total_hosts:
                if failed == 0 and cancelled == 0:
                    session_status = ScanSessionStatus.COMPLETED
                elif failed > 0:
                    session_status = ScanSessionStatus.FAILED
                else:
                    session_status = ScanSessionStatus.CANCELLED
            elif pending == total_hosts:
                session_status = ScanSessionStatus.PENDING
            
            # Calculate progress percentage
            progress_percentage = ((completed + failed + cancelled) / total_hosts) * 100 if total_hosts > 0 else 0
            
            # Update session record
            update_data = {
                "session_id": session_id,
                "status": session_status.value,
                "updated_at": datetime.utcnow(),
                "progress_percentage": progress_percentage
            }
            
            # Set completion time if finished
            if session_status in [ScanSessionStatus.COMPLETED, ScanSessionStatus.FAILED, ScanSessionStatus.CANCELLED]:
                update_data["completed_at"] = datetime.utcnow()
            
            self.db.execute(text("""
                UPDATE group_scan_sessions 
                SET status = :status, 
                    updated_at = :updated_at,
                    completed_at = COALESCE(:completed_at, completed_at)
                WHERE session_id = :session_id
            """), update_data)
            
            logger.debug(f"Updated session {session_id} progress: {progress_percentage:.1f}% complete")
            
        except Exception as e:
            logger.error(f"Failed to update session progress: {e}")
            raise
    
    async def calculate_progress(self, session_id: str) -> GroupScanProgress:
        """Calculate overall progress for a group scan session"""
        try:
            # Get session details
            session_result = self.db.execute(text("""
                SELECT session_id, group_id, group_name, total_hosts, status, 
                       start_time, estimated_completion, updated_at
                FROM group_scan_sessions 
                WHERE session_id = :session_id
            """), {"session_id": session_id}).fetchone()
            
            if not session_result:
                raise ValueError(f"Session {session_id} not found")
            
            # Get host status counts
            status_result = self.db.execute(text("""
                SELECT 
                    status,
                    COUNT(*) as count
                FROM group_scan_host_progress 
                WHERE session_id = :session_id
                GROUP BY status
            """), {"session_id": session_id})
            
            status_counts = {row.status: row.count for row in status_result}
            
            hosts_completed = status_counts.get('completed', 0)
            hosts_failed = status_counts.get('failed', 0)
            hosts_scanning = status_counts.get('scanning', 0)
            hosts_pending = status_counts.get('pending', 0)
            
            progress_percentage = ((hosts_completed + hosts_failed) / session_result.total_hosts) * 100 \
                                if session_result.total_hosts > 0 else 0
            
            # Calculate average scan duration if we have completed scans
            avg_duration = None
            if hosts_completed > 0:
                duration_result = self.db.execute(text("""
                    SELECT AVG(EXTRACT(EPOCH FROM (scan_end_time - scan_start_time))) as avg_duration
                    FROM group_scan_host_progress 
                    WHERE session_id = :session_id 
                    AND status = 'completed' 
                    AND scan_start_time IS NOT NULL 
                    AND scan_end_time IS NOT NULL
                """), {"session_id": session_id}).fetchone()
                
                if duration_result and duration_result.avg_duration:
                    avg_duration = float(duration_result.avg_duration)
            
            return GroupScanProgress(
                session_id=session_result.session_id,
                group_id=session_result.group_id,
                group_name=session_result.group_name,
                status=ScanSessionStatus(session_result.status),
                total_hosts=session_result.total_hosts,
                hosts_completed=hosts_completed,
                hosts_failed=hosts_failed,
                hosts_scanning=hosts_scanning,
                hosts_pending=hosts_pending,
                progress_percentage=progress_percentage,
                estimated_completion=session_result.estimated_completion,
                average_scan_duration=avg_duration,
                started_at=session_result.start_time,
                last_updated=session_result.updated_at or session_result.start_time
            )
            
        except Exception as e:
            logger.error(f"Failed to calculate progress for session {session_id}: {e}")
            raise
    
    async def estimate_completion(self, session_id: str) -> Optional[datetime]:
        """Estimate completion time based on current progress"""
        try:
            progress = await self.calculate_progress(session_id)
            
            if progress.status in [ScanSessionStatus.COMPLETED, ScanSessionStatus.FAILED, ScanSessionStatus.CANCELLED]:
                return None
            
            if progress.average_scan_duration and progress.hosts_scanning + progress.hosts_pending > 0:
                remaining_hosts = progress.hosts_scanning + progress.hosts_pending
                estimated_seconds = remaining_hosts * progress.average_scan_duration
                return datetime.utcnow() + timedelta(seconds=estimated_seconds)
            
            # Fallback estimate based on typical scan duration (10 minutes per host)
            if progress.hosts_scanning + progress.hosts_pending > 0:
                remaining_hosts = progress.hosts_scanning + progress.hosts_pending
                estimated_minutes = remaining_hosts * 10  # 10 minutes per host average
                return datetime.utcnow() + timedelta(minutes=estimated_minutes)
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to estimate completion for session {session_id}: {e}")
            return None


class GroupScanService:
    """Service for managing group scan operations"""
    
    def __init__(self, db: Session):
        self.db = db
        self.progress_tracker = GroupScanProgressTracker(db)
    
    async def initiate_group_scan(
        self, 
        group_id: int, 
        user_id: int,
        scan_config: Optional[GroupScanConfig] = None
    ) -> GroupScanSession:
        """Initiate a group scan for all hosts in a group"""
        try:
            # Get group details
            group_result = self.db.execute(text("""
                SELECT id, name, description, scap_content_id, default_profile_id
                FROM host_groups 
                WHERE id = :group_id
            """), {"group_id": group_id}).fetchone()
            
            if not group_result:
                raise ValueError(f"Group {group_id} not found")
            
            # Get hosts in the group
            hosts_result = self.db.execute(text("""
                SELECT h.id, h.hostname, h.display_name, h.ip_address, 
                       h.username, h.auth_method, h.port
                FROM hosts h
                JOIN host_group_memberships hgm ON h.id = hgm.host_id
                WHERE hgm.group_id = :group_id AND h.is_active = true
                ORDER BY h.hostname
            """), {"group_id": group_id})
            
            hosts = hosts_result.fetchall()
            if not hosts:
                raise ValueError(f"No active hosts found in group {group_id}")
            
            # Use group defaults or provided config
            if not scan_config:
                scan_config = GroupScanConfig()
            
            # Use group's default SCAP content if not specified
            if not scan_config.content_id and group_result.scap_content_id:
                scan_config.content_id = group_result.scap_content_id
            
            if not scan_config.profile_id and group_result.default_profile_id:
                scan_config.profile_id = group_result.default_profile_id
            
            # Validate SCAP content exists
            if scan_config.content_id:
                content_result = self.db.execute(text("""
                    SELECT id, name, file_path, profiles FROM scap_content 
                    WHERE id = :content_id
                """), {"content_id": scan_config.content_id}).fetchone()
                
                if not content_result:
                    raise ValueError(f"SCAP content {scan_config.content_id} not found")
                
                # Validate profile exists if specified
                if scan_config.profile_id and content_result.profiles:
                    profiles = json.loads(content_result.profiles)
                    profile_ids = [p.get("id") for p in profiles if p.get("id")]
                    if scan_config.profile_id not in profile_ids:
                        raise ValueError(f"Profile {scan_config.profile_id} not found in SCAP content")
            else:
                # Use default SCAP content
                default_content = self.db.execute(text("""
                    SELECT id, name, file_path, profiles FROM scap_content 
                    ORDER BY uploaded_at DESC LIMIT 1
                """)).fetchone()
                
                if not default_content:
                    raise ValueError("No SCAP content available")
                
                scan_config.content_id = default_content.id
                if not scan_config.profile_id and default_content.profiles:
                    profiles = json.loads(default_content.profiles)
                    if profiles:
                        scan_config.profile_id = profiles[0].get("id")
            
            # Create group scan session
            session_id = str(uuid.uuid4())
            session_data = {
                "session_id": session_id,
                "group_id": group_id,
                "group_name": group_result.name,
                "total_hosts": len(hosts),
                "initiated_by": user_id,
                "start_time": datetime.utcnow(),
                "status": ScanSessionStatus.PENDING.value,
                "scan_config": json.dumps(scan_config.dict()) if scan_config else None
            }
            
            # Estimate completion time (10 minutes per host average, with stagger delay)
            estimated_minutes = len(hosts) * 10 + (len(hosts) * scan_config.stagger_delay / 60)
            session_data["estimated_completion"] = datetime.utcnow() + timedelta(minutes=estimated_minutes)
            
            self.db.execute(text("""
                INSERT INTO group_scan_sessions 
                (session_id, group_id, group_name, total_hosts, initiated_by, 
                 start_time, estimated_completion, status, scan_config, created_at, updated_at)
                VALUES (:session_id, :group_id, :group_name, :total_hosts, :initiated_by,
                        :start_time, :estimated_completion, :status, :scan_config, 
                        :start_time, :start_time)
            """), session_data)
            
            # Create host progress tracking records
            for host in hosts:
                self.db.execute(text("""
                    INSERT INTO group_scan_host_progress 
                    (session_id, host_id, host_name, host_ip, status, created_at, updated_at)
                    VALUES (:session_id, :host_id, :host_name, :host_ip, :status, 
                            :created_at, :updated_at)
                """), {
                    "session_id": session_id,
                    "host_id": str(host.id),
                    "host_name": host.display_name or host.hostname,
                    "host_ip": host.ip_address or host.hostname,
                    "status": HostScanStatus.PENDING.value,
                    "created_at": datetime.utcnow(),
                    "updated_at": datetime.utcnow()
                })
            
            self.db.commit()
            
            # Create session object
            session = GroupScanSession(
                session_id=session_id,
                group_id=group_id,
                group_name=group_result.name,
                total_hosts=len(hosts),
                initiated_by=user_id,
                start_time=session_data["start_time"],
                estimated_completion=session_data["estimated_completion"],
                status=ScanSessionStatus.PENDING,
                hosts_pending=[str(host.id) for host in hosts],
                scan_config=scan_config
            )
            
            logger.info(f"Created group scan session {session_id} for group {group_id} with {len(hosts)} hosts")
            return session
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Failed to initiate group scan: {e}")
            raise
    
    async def start_group_scan_execution(self, session_id: str) -> bool:
        """Start executing scans for all hosts in a group scan session"""
        try:
            # Get session details
            session_result = self.db.execute(text("""
                SELECT session_id, group_id, group_name, scan_config, status
                FROM group_scan_sessions 
                WHERE session_id = :session_id
            """), {"session_id": session_id}).fetchone()
            
            if not session_result:
                raise ValueError(f"Session {session_id} not found")
            
            if session_result.status != ScanSessionStatus.PENDING.value:
                raise ValueError(f"Session {session_id} is not in pending status")
            
            # Parse scan config
            scan_config = GroupScanConfig()
            if session_result.scan_config:
                config_data = json.loads(session_result.scan_config)
                scan_config = GroupScanConfig(**config_data)
            
            # Get SCAP content details
            content_result = self.db.execute(text("""
                SELECT id, name, file_path FROM scap_content 
                WHERE id = :content_id
            """), {"content_id": scan_config.content_id}).fetchone()
            
            if not content_result:
                raise ValueError(f"SCAP content {scan_config.content_id} not found")
            
            # Get pending hosts
            hosts_result = self.db.execute(text("""
                SELECT p.host_id, p.host_name, p.host_ip,
                       h.hostname, h.port, h.username, h.auth_method, h.encrypted_credentials
                FROM group_scan_host_progress p
                JOIN hosts h ON p.host_id = h.id
                WHERE p.session_id = :session_id AND p.status = 'pending'
                ORDER BY p.host_name
            """), {"session_id": session_id})
            
            hosts = hosts_result.fetchall()
            if not hosts:
                logger.warning(f"No pending hosts found for session {session_id}")
                return False
            
            # Update session status to in progress
            self.db.execute(text("""
                UPDATE group_scan_sessions 
                SET status = :status, updated_at = :updated_at
                WHERE session_id = :session_id
            """), {
                "session_id": session_id,
                "status": ScanSessionStatus.IN_PROGRESS.value,
                "updated_at": datetime.utcnow()
            })
            self.db.commit()
            
            # Start scans with stagger delay
            asyncio.create_task(self._execute_staggered_scans(
                session_id, hosts, content_result, scan_config
            ))
            
            logger.info(f"Started group scan execution for session {session_id} with {len(hosts)} hosts")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start group scan execution: {e}")
            self.db.rollback()
            raise
    
    async def _execute_staggered_scans(
        self, 
        session_id: str, 
        hosts: List[Any], 
        content_result: Any, 
        scan_config: GroupScanConfig
    ):
        """Execute scans with staggered start times"""
        try:
            concurrent_scans = 0
            max_concurrent = scan_config.max_concurrent or 5
            
            for i, host in enumerate(hosts):
                # Wait for available slot
                while concurrent_scans >= max_concurrent:
                    await asyncio.sleep(5)  # Check every 5 seconds
                    # Update concurrent count by checking active scans
                    active_result = self.db.execute(text("""
                        SELECT COUNT(*) as active_count 
                        FROM group_scan_host_progress 
                        WHERE session_id = :session_id AND status = 'scanning'
                    """), {"session_id": session_id})
                    concurrent_scans = active_result.fetchone().active_count
                
                # Create individual scan
                scan_id = await self._create_individual_scan(
                    session_id, host, content_result, scan_config
                )
                
                if scan_id:
                    # Start the scan task
                    asyncio.create_task(self._execute_host_scan(
                        session_id, scan_id, host, content_result, scan_config
                    ))
                    concurrent_scans += 1
                
                # Stagger delay between scans (except for last scan)
                if i < len(hosts) - 1:
                    await asyncio.sleep(scan_config.stagger_delay)
            
            logger.info(f"Initiated all scans for session {session_id}")
            
        except Exception as e:
            logger.error(f"Error in staggered scan execution: {e}")
    
    async def _create_individual_scan(
        self, 
        session_id: str, 
        host: Any, 
        content_result: Any, 
        scan_config: GroupScanConfig
    ) -> Optional[str]:
        """Create an individual scan record for a host in the group scan"""
        try:
            scan_id = str(uuid.uuid4())
            scan_name = f"Group Scan - {host.host_name}"
            
            # Create scan record
            self.db.execute(text("""
                INSERT INTO scans 
                (id, name, host_id, content_id, profile_id, status, progress, 
                 scan_options, started_by, started_at, remediation_requested, verification_scan)
                VALUES (:id, :name, :host_id, :content_id, :profile_id, :status, 
                        :progress, :scan_options, :started_by, :started_at, :remediation_requested, :verification_scan)
            """), {
                "id": scan_id,
                "name": scan_name,
                "host_id": host.host_id,
                "content_id": scan_config.content_id,
                "profile_id": scan_config.profile_id,
                "status": "pending",
                "progress": 0,
                "scan_options": json.dumps({
                    "group_scan": True,
                    "session_id": session_id,
                    **scan_config.scan_options
                }),
                "started_by": 1,  # System user for group scans
                "started_at": datetime.utcnow(),
                "remediation_requested": False,
                "verification_scan": False
            })
            
            # Update host progress with scan ID
            await self.progress_tracker.update_host_status(
                session_id, host.host_id, HostScanStatus.SCANNING.value, scan_id
            )
            
            self.db.commit()
            return scan_id
            
        except Exception as e:
            logger.error(f"Failed to create individual scan for host {host.host_id}: {e}")
            self.db.rollback()
            return None
    
    async def _execute_host_scan(
        self, 
        session_id: str, 
        scan_id: str, 
        host: Any, 
        content_result: Any, 
        scan_config: GroupScanConfig
    ):
        """Execute scan for a single host within a group scan"""
        try:
            logger.info(f"Starting host scan {scan_id} for {host.host_name} in session {session_id}")
            
            # Prepare host data
            host_data = {
                "id": host.host_id,
                "hostname": host.hostname,
                "port": host.port,
                "username": host.username,
                "auth_method": host.auth_method,
                "encrypted_credentials": host.encrypted_credentials
            }
            
            # Execute the scan task
            # This will run in the background and update progress via the scan task
            execute_scan_task(
                scan_id=scan_id,
                host_data=host_data,
                content_path=content_result.file_path,
                profile_id=scan_config.profile_id,
                scan_options={
                    "group_scan": True,
                    "session_id": session_id,
                    **scan_config.scan_options
                }
            )
            
            # The scan task will handle updating the host status when complete
            
        except Exception as e:
            logger.error(f"Failed to execute host scan {scan_id}: {e}")
            # Update host status to failed
            await self.progress_tracker.update_host_status(
                session_id, host.host_id, HostScanStatus.FAILED.value, 
                scan_id, error_message=str(e)
            )
    
    async def get_scan_progress(self, session_id: str) -> GroupScanProgress:
        """Get real-time progress of a group scan"""
        return await self.progress_tracker.calculate_progress(session_id)
    
    async def get_host_scan_details(self, session_id: str) -> List[HostScanDetail]:
        """Get detailed status of each host in a group scan"""
        try:
            result = self.db.execute(text("""
                SELECT p.host_id, p.host_name, p.host_ip, p.status, p.scan_id,
                       p.scan_start_time, p.scan_end_time, p.error_message,
                       h.hostname, s.progress,
                       sr.total_rules, sr.passed_rules, sr.failed_rules, sr.score
                FROM group_scan_host_progress p
                JOIN hosts h ON p.host_id = h.id
                LEFT JOIN scans s ON p.scan_id = s.id
                LEFT JOIN scan_results sr ON s.id = sr.scan_id
                WHERE p.session_id = :session_id
                ORDER BY p.host_name
            """), {"session_id": session_id})
            
            host_details = []
            for row in result:
                scan_results = None
                if row.total_rules is not None:
                    scan_results = {
                        "total_rules": row.total_rules,
                        "passed_rules": row.passed_rules,
                        "failed_rules": row.failed_rules,
                        "score": row.score
                    }
                
                host_details.append(HostScanDetail(
                    host_id=row.host_id,
                    host_name=row.host_name,
                    hostname=row.hostname,
                    ip_address=row.host_ip,
                    status=HostScanStatus(row.status),
                    scan_id=row.scan_id,
                    scan_start_time=row.scan_start_time,
                    scan_end_time=row.scan_end_time,
                    progress=row.progress or 0,
                    error_message=row.error_message,
                    scan_results=scan_results
                ))
            
            return host_details
            
        except Exception as e:
            logger.error(f"Failed to get host scan details: {e}")
            raise
    
    async def cancel_group_scan(self, session_id: str) -> bool:
        """Cancel an ongoing group scan"""
        try:
            # Update session status
            self.db.execute(text("""
                UPDATE group_scan_sessions 
                SET status = :status, updated_at = :updated_at, completed_at = :completed_at
                WHERE session_id = :session_id AND status IN ('pending', 'in_progress')
            """), {
                "session_id": session_id,
                "status": ScanSessionStatus.CANCELLED.value,
                "updated_at": datetime.utcnow(),
                "completed_at": datetime.utcnow()
            })
            
            # Cancel pending and running scans
            self.db.execute(text("""
                UPDATE scans 
                SET status = 'cancelled', error_message = 'Group scan cancelled by user'
                WHERE id IN (
                    SELECT scan_id FROM group_scan_host_progress 
                    WHERE session_id = :session_id AND scan_id IS NOT NULL
                ) AND status IN ('pending', 'running')
            """), {"session_id": session_id})
            
            # Update host progress statuses
            self.db.execute(text("""
                UPDATE group_scan_host_progress 
                SET status = 'cancelled', updated_at = :updated_at
                WHERE session_id = :session_id AND status IN ('pending', 'scanning')
            """), {
                "session_id": session_id,
                "updated_at": datetime.utcnow()
            })
            
            self.db.commit()
            
            logger.info(f"Cancelled group scan session {session_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to cancel group scan: {e}")
            self.db.rollback()
            return False
    
    async def get_active_scans(self, user_id: Optional[int] = None) -> List[ActiveScanSession]:
        """Get all active scan sessions"""
        try:
            where_clause = ""
            params = {}
            
            if user_id:
                where_clause = "WHERE s.initiated_by = :user_id"
                params["user_id"] = user_id
            
            result = self.db.execute(text(f"""
                SELECT s.session_id, s.group_id, s.group_name, s.status, s.total_hosts,
                       s.start_time, s.estimated_completion, s.initiated_by,
                       COUNT(CASE WHEN p.status = 'completed' THEN 1 END) as hosts_completed
                FROM group_scan_sessions s
                LEFT JOIN group_scan_host_progress p ON s.session_id = p.session_id
                {where_clause}
                GROUP BY s.session_id, s.group_id, s.group_name, s.status, s.total_hosts,
                         s.start_time, s.estimated_completion, s.initiated_by
                HAVING s.status IN ('pending', 'in_progress')
                ORDER BY s.start_time DESC
            """), params)
            
            active_sessions = []
            for row in result:
                progress_percentage = (row.hosts_completed / row.total_hosts) * 100 if row.total_hosts > 0 else 0
                
                active_sessions.append(ActiveScanSession(
                    session_id=row.session_id,
                    group_id=row.group_id,
                    group_name=row.group_name,
                    status=ScanSessionStatus(row.status),
                    progress_percentage=progress_percentage,
                    hosts_completed=row.hosts_completed,
                    total_hosts=row.total_hosts,
                    started_at=row.start_time,
                    estimated_completion=row.estimated_completion,
                    initiated_by=row.initiated_by
                ))
            
            return active_sessions
            
        except Exception as e:
            logger.error(f"Failed to get active scans: {e}")
            return []