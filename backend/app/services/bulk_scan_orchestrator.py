"""
Bulk Scan Orchestrator Service with Authorization Framework
Manages multi-host scanning operations with intelligent batching and progress tracking

CRITICAL SECURITY FIX:
This service now includes per-host authorization validation to prevent the
vulnerability where users could initiate bulk scans without proper permission
checks for each individual host.

ZERO TRUST IMPLEMENTATION:
- Authorization check for every host before scan creation
- Detailed audit trail of authorization decisions
- Fail-secure behavior on permission failures
- Separation of authorized and unauthorized hosts

Design by Emily (Security Engineer) & Implementation by Daniel (Backend Engineer)
"""

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session

from ..models.authorization_models import (
    ActionType,
    AuthorizationContext,
    AuthorizationDecision,
    BulkAuthorizationRequest,
    ResourceIdentifier,
    ResourceType,
)
from .authorization_service import get_authorization_service
from .scan_intelligence import HostInfo, ScanIntelligenceService

logger = logging.getLogger(__name__)


class ScanSessionStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ScanBatch:
    """A batch of scans to execute together"""

    id: str
    hosts: List[HostInfo]
    content_id: int
    profile_id: str
    priority: int  # Lower number = higher priority
    estimated_time: float  # minutes
    max_parallel: int = 3


@dataclass
class ScanSession:
    """Tracks a bulk scanning session with authorization metadata"""

    id: str
    name: str
    total_hosts: int
    completed_hosts: int
    failed_hosts: int
    running_hosts: int
    status: ScanSessionStatus
    created_by: str
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    estimated_completion: Optional[datetime] = None
    scan_ids: Optional[List[str]] = None
    error_message: Optional[str] = None
    # Authorization metadata
    authorized_hosts: int = 0
    unauthorized_hosts: int = 0
    authorization_failures: Optional[List[Dict[str, Any]]] = None

    def __post_init__(self) -> None:
        if self.authorization_failures is None:
            self.authorization_failures = []
        if self.scan_ids is None:
            self.scan_ids = []


@dataclass
class AuthorizationFailure:
    """Represents an authorization failure for a specific host"""

    host_id: str
    hostname: str
    reason: str
    user_id: str
    timestamp: Optional[datetime] = None

    def __post_init__(self) -> None:
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


class BulkScanOrchestrator:
    """
    Orchestrates bulk scanning operations across multiple hosts with authorization validation

    SECURITY ENHANCEMENTS:
    - Per-host authorization validation before scan creation
    - Comprehensive audit logging of authorization decisions
    - Separation of authorized and unauthorized hosts
    - Zero Trust implementation preventing privilege escalation
    """

    def __init__(self, db: Session):
        self.db = db
        self.intelligence_service = ScanIntelligenceService(db)
        self.authorization_service = get_authorization_service(db)

    async def create_bulk_scan_session(
        self,
        host_ids: List[str],
        template_id: str = "auto",
        name_prefix: str = "Bulk Scan",
        priority: str = "normal",
        user_id: Optional[str] = None,
        stagger_delay: int = 30,
        auth_context: Optional[AuthorizationContext] = None,
    ) -> ScanSession:
        """
        Create a bulk scan session with intelligent batching and per-host authorization validation

        CRITICAL SECURITY FIX:
        This method now validates user permissions for each host individually before
        creating any scans, preventing unauthorized access to systems outside the
        user's permission scope.

        Args:
            host_ids: List of host IDs to scan
            template_id: Scan template/profile to use
            name_prefix: Prefix for scan names
            priority: Scan priority level
            user_id: User creating the bulk scan
            stagger_delay: Delay between scan starts in seconds
            auth_context: Authorization context (will be built if not provided)

        Returns:
            ScanSession: Session with authorization results and only authorized scans

        Raises:
            ValueError: If no hosts are authorized for scanning
            PermissionError: If user lacks bulk scan permissions
        """
        try:
            session_id = str(uuid.uuid4())
            logger.info(
                f"Creating bulk scan session {session_id} for {len(host_ids)} hosts by user {user_id}"
            )

            # SECURITY CHECK 1: Validate user exists and is active
            if not user_id:
                raise ValueError("User ID is required for bulk scan operations")

            # SECURITY CHECK 2: Per-host authorization validation
            logger.info(f"Performing authorization checks for {len(host_ids)} hosts")
            authorized_hosts, authorization_failures = await self._validate_bulk_scan_authorization(
                user_id, host_ids, auth_context
            )

            if not authorized_hosts:
                logger.warning(
                    f"User {user_id} has no authorized hosts for bulk scan. {len(authorization_failures)} failures."
                )
                raise PermissionError(
                    f"No hosts authorized for scanning. Access denied to all {len(host_ids)} requested hosts."
                )

            # Log authorization summary
            logger.info(
                f"Authorization complete: {len(authorized_hosts)} authorized, {len(authorization_failures)} denied"
            )

            # Filter host_ids to only include authorized hosts
            authorized_host_ids = [host.host_id for host in authorized_hosts]

            # Analyze bulk scan feasibility for authorized hosts only
            feasibility = await self.intelligence_service.analyze_bulk_scan_feasibility(
                authorized_host_ids
            )
            if not feasibility["feasible"]:
                logger.warning(
                    f"Bulk scan not feasible for authorized hosts: {feasibility['reason']}"
                )
                raise ValueError(f"Bulk scan not feasible: {feasibility['reason']}")

            # Create scan session record with authorization metadata
            session = ScanSession(
                id=session_id,
                name=f"{name_prefix} - {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}",
                total_hosts=len(host_ids),  # Original request count
                completed_hosts=0,
                failed_hosts=0,
                running_hosts=0,
                status=ScanSessionStatus.PENDING,
                created_by=user_id,
                created_at=datetime.utcnow(),
                scan_ids=[],
                estimated_completion=datetime.utcnow()
                + timedelta(minutes=feasibility.get("estimated_time_minutes", 60)),
                authorized_hosts=len(authorized_hosts),
                unauthorized_hosts=len(authorization_failures),
                authorization_failures=[
                    {
                        "host_id": failure.host_id,
                        "hostname": failure.hostname,
                        "reason": failure.reason,
                        "timestamp": failure.timestamp.isoformat() if failure.timestamp else None,
                    }
                    for failure in authorization_failures
                ],
            )

            # Store session in database with authorization metadata
            await self._store_scan_session(session)

            # Plan scan execution for authorized hosts only
            scan_plan = await self._plan_bulk_scan(
                authorized_host_ids, template_id, session_id, priority
            )

            # Store individual scans for authorized hosts
            scan_ids = []
            for batch in scan_plan:
                # Additional authorization check before batch creation
                batch_scan_ids = await self._create_batch_scans_with_authorization(
                    batch,
                    session_id,
                    name_prefix,
                    user_id,
                    stagger_delay,
                    authorized_hosts,
                )
                scan_ids.extend(batch_scan_ids)

            # Update session with scan IDs
            session.scan_ids = scan_ids
            await self._update_scan_session(session)

            # Log final results
            if authorization_failures:
                logger.warning(
                    f"Bulk scan session {session_id} created with {len(scan_ids)} scans. "
                    f"Authorization denied for {len(authorization_failures)} hosts."
                )
            else:
                logger.info(
                    f"Bulk scan session {session_id} created successfully with {len(scan_ids)} scans. "
                    f"All {len(authorized_hosts)} hosts authorized."
                )

            return session

        except Exception as e:
            logger.error(f"Error creating bulk scan session: {e}")
            raise

    async def start_bulk_scan_session(self, session_id: str) -> Dict:
        """Start executing a bulk scan session"""
        try:
            # Get session details
            session = await self._get_scan_session(session_id)
            if not session:
                raise ValueError(f"Session {session_id} not found")

            if session.status != ScanSessionStatus.PENDING:
                raise ValueError(f"Session {session_id} is not in pending status")

            # Update session status
            session.status = ScanSessionStatus.RUNNING
            session.started_at = datetime.utcnow()
            await self._update_scan_session(session)

            # Start scans with staggered execution
            started_scans = await self._execute_staggered_scans(session.scan_ids)

            logger.info(f"Started bulk scan session {session_id} with {len(started_scans)} scans")
            return {
                "session_id": session_id,
                "status": "started",
                "started_scans": len(started_scans),
                "total_scans": len(session.scan_ids),
            }

        except Exception as e:
            logger.error(f"Error starting bulk scan session {session_id}: {e}")
            raise

    async def get_bulk_scan_progress(self, session_id: str) -> Dict:
        """Get real-time progress of a bulk scan session"""
        try:
            # Get session
            session = await self._get_scan_session(session_id)
            if not session:
                raise ValueError(f"Session {session_id} not found")

            # Get individual scan statuses
            scan_statuses = await self._get_scans_status(session.scan_ids)

            # Calculate progress metrics
            total_scans = len(session.scan_ids)
            completed = sum(1 for s in scan_statuses if s["status"] == "completed")
            failed = sum(1 for s in scan_statuses if s["status"] == "failed")
            running = sum(1 for s in scan_statuses if s["status"] in ["pending", "running"])

            # Update session stats
            session.completed_hosts = completed
            session.failed_hosts = failed
            session.running_hosts = running

            # Determine overall session status
            if completed + failed == total_scans:
                session.status = ScanSessionStatus.COMPLETED
                session.completed_at = datetime.utcnow()
            elif failed > 0 and running == 0:
                session.status = ScanSessionStatus.FAILED

            await self._update_scan_session(session)

            # Calculate progress percentage
            progress_percent = int((completed / total_scans) * 100) if total_scans > 0 else 0

            return {
                "session_id": session_id,
                "session_name": session.name,
                "status": session.status.value,
                "progress_percent": progress_percent,
                "total_hosts": total_scans,
                "completed_hosts": completed,
                "failed_hosts": failed,
                "running_hosts": running,
                "started_at": (session.started_at.isoformat() if session.started_at else None),
                "estimated_completion": (
                    session.estimated_completion.isoformat()
                    if session.estimated_completion
                    else None
                ),
                "individual_scans": scan_statuses,
            }

        except Exception as e:
            logger.error(f"Error getting bulk scan progress for {session_id}: {e}")
            raise

    async def _plan_bulk_scan(
        self, host_ids: List[str], template_id: str, session_id: str, priority: str
    ) -> List[ScanBatch]:
        """Plan the execution of bulk scans with intelligent batching"""
        try:
            # Get host information
            host_infos = []
            for host_id in host_ids:
                host_info = await self.intelligence_service._get_host_info(host_id)
                if host_info:
                    host_infos.append(host_info)

            if not host_infos:
                raise ValueError("No valid hosts found for bulk scan")

            # Group hosts by OS family for content optimization
            os_groups: Dict[str, List[Any]] = {}
            for host in host_infos:
                os_family = self._extract_os_family(host.operating_system)
                if os_family not in os_groups:
                    os_groups[os_family] = []
                os_groups[os_family].append(host)

            # Create scan batches
            batches = []
            batch_priority = 1

            for os_family, hosts in os_groups.items():
                # Find best content and profile for this OS group
                content_id, profile_id = await self._find_optimal_content_profile(
                    hosts, template_id
                )

                # Split large groups into smaller batches (max 10 hosts per batch)
                max_batch_size = 10
                for i in range(0, len(hosts), max_batch_size):
                    batch_hosts = hosts[i : i + max_batch_size]

                    # Calculate estimated time based on host count and profile complexity
                    estimated_time: float = len(batch_hosts) * 10  # Base 10 minutes per host

                    # Adjust for profile complexity
                    if "stig" in profile_id.lower():
                        estimated_time *= 1.5  # STIG scans take longer
                    elif "cis" in profile_id.lower():
                        estimated_time *= 1.2  # CIS scans slightly longer

                    batch = ScanBatch(
                        id=str(uuid.uuid4()),
                        hosts=batch_hosts,
                        content_id=content_id,
                        profile_id=profile_id,
                        priority=batch_priority,
                        estimated_time=estimated_time,
                        max_parallel=min(3, len(batch_hosts)),
                    )
                    batches.append(batch)

                batch_priority += 1

            # Sort batches by priority (production hosts first, then by estimated time)
            batches.sort(key=lambda b: (b.priority, b.estimated_time))

            logger.info(f"Created {len(batches)} scan batches for session {session_id}")
            return batches

        except Exception as e:
            logger.error(f"Error planning bulk scan: {e}")
            raise

    def _extract_os_family(self, operating_system: str) -> str:
        """Extract OS family from operating system string"""
        os_lower = operating_system.lower()
        if any(rhel in os_lower for rhel in ["rhel", "red hat", "centos", "fedora"]):
            return "rhel"
        elif any(ubuntu in os_lower for ubuntu in ["ubuntu", "debian"]):
            return "debian"
        elif "sles" in os_lower or "suse" in os_lower:
            return "suse"
        elif "windows" in os_lower:
            return "windows"
        else:
            return "unknown"

    async def _find_optimal_content_profile(
        self, hosts: List[HostInfo], template_id: str
    ) -> Tuple[int, str]:
        """Find the optimal SCAP content and profile for a group of hosts"""
        # For now, use the intelligence service to suggest for the first host
        # In a more sophisticated implementation, this would analyze all hosts
        if hosts and template_id == "auto":
            suggestion = await self.intelligence_service.suggest_scan_profile(hosts[0].id)
            return suggestion.content_id, suggestion.profile_id
        else:
            # Use default content and specified template
            return 1, (
                template_id if template_id != "auto" else "xccdf_org.ssgproject.content_profile_cui"
            )

    def _create_batch_scans(
        self,
        batch: ScanBatch,
        session_id: str,
        name_prefix: str,
        user_id: str,
        stagger_delay: int,
    ) -> List[str]:
        """Create individual scan records for a batch"""
        try:
            scan_ids = []

            for i, host in enumerate(batch.hosts):
                scan_id = str(uuid.uuid4())
                scan_name = f"{name_prefix} - {host.hostname}"

                # Calculate staggered start time
                start_delay = i * stagger_delay  # seconds

                # Create scan record
                self.db.execute(
                    text(
                        """
                    INSERT INTO scans
                    (id, name, host_id, content_id, profile_id, status, progress,
                     scan_options, started_by, started_at, remediation_requested, verification_scan)
                    VALUES (:id, :name, :host_id, :content_id, :profile_id, :status,
                            :progress, :scan_options, :started_by, :started_at, :remediation_requested, :verification_scan)
                """
                    ),
                    {
                        "id": scan_id,
                        "name": scan_name,
                        "host_id": host.id,
                        "content_id": batch.content_id,
                        "profile_id": batch.profile_id,
                        "status": "pending",
                        "progress": 0,
                        "scan_options": json.dumps(
                            {
                                "bulk_scan": True,
                                "session_id": session_id,
                                "batch_id": batch.id,
                                "start_delay": start_delay,
                            }
                        ),
                        "started_by": user_id,
                        "started_at": datetime.utcnow(),
                        "remediation_requested": False,
                        "verification_scan": False,
                    },
                )

                scan_ids.append(scan_id)

            self.db.commit()
            return scan_ids

        except Exception as e:
            logger.error(f"Error creating batch scans: {e}")
            raise

    def _store_scan_session(self, session: ScanSession):
        """Store scan session in database"""
        try:
            # Create a scan sessions table record (you'll need to create this table)
            self.db.execute(
                text(
                    """
                INSERT INTO scan_sessions
                (id, name, total_hosts, completed_hosts, failed_hosts, running_hosts,
                 status, created_by, created_at, started_at, completed_at, estimated_completion, scan_ids, error_message)
                VALUES (:id, :name, :total_hosts, :completed_hosts, :failed_hosts, :running_hosts,
                        :status, :created_by, :created_at, :started_at, :completed_at, :estimated_completion, :scan_ids, :error_message)
            """
                ),
                {
                    "id": session.id,
                    "name": session.name,
                    "total_hosts": session.total_hosts,
                    "completed_hosts": session.completed_hosts,
                    "failed_hosts": session.failed_hosts,
                    "running_hosts": session.running_hosts,
                    "status": session.status.value,
                    "created_by": session.created_by,
                    "created_at": session.created_at,
                    "started_at": session.started_at,
                    "completed_at": session.completed_at,
                    "estimated_completion": session.estimated_completion,
                    "scan_ids": json.dumps(session.scan_ids or []),
                    "error_message": session.error_message,
                },
            )
            self.db.commit()
        except Exception as e:
            logger.error(f"Error storing scan session: {e}")
            raise

    def _update_scan_session(self, session: ScanSession):
        """Update scan session in database"""
        try:
            self.db.execute(
                text(
                    """
                UPDATE scan_sessions SET
                    completed_hosts = :completed_hosts,
                    failed_hosts = :failed_hosts,
                    running_hosts = :running_hosts,
                    status = :status,
                    started_at = :started_at,
                    completed_at = :completed_at,
                    scan_ids = :scan_ids,
                    error_message = :error_message
                WHERE id = :id
            """
                ),
                {
                    "id": session.id,
                    "completed_hosts": session.completed_hosts,
                    "failed_hosts": session.failed_hosts,
                    "running_hosts": session.running_hosts,
                    "status": session.status.value,
                    "started_at": session.started_at,
                    "completed_at": session.completed_at,
                    "scan_ids": json.dumps(session.scan_ids or []),
                    "error_message": session.error_message,
                },
            )
            self.db.commit()
        except Exception as e:
            logger.error(f"Error updating scan session: {e}")
            raise

    def _get_scan_session(self, session_id: str) -> Optional[ScanSession]:
        """Retrieve scan session from database"""
        try:
            result = self.db.execute(
                text(
                    """
                SELECT id, name, total_hosts, completed_hosts, failed_hosts, running_hosts,
                       status, created_by, created_at, started_at, completed_at, estimated_completion, scan_ids, error_message
                FROM scan_sessions WHERE id = :id
            """
                ),
                {"id": session_id},
            ).fetchone()

            if not result:
                return None

            return ScanSession(
                id=result.id,
                name=result.name,
                total_hosts=result.total_hosts,
                completed_hosts=result.completed_hosts,
                failed_hosts=result.failed_hosts,
                running_hosts=result.running_hosts,
                status=ScanSessionStatus(result.status),
                created_by=result.created_by,
                created_at=result.created_at,
                started_at=result.started_at,
                completed_at=result.completed_at,
                estimated_completion=result.estimated_completion,
                scan_ids=json.loads(result.scan_ids or "[]"),
                error_message=result.error_message,
            )
        except Exception as e:
            logger.error(f"Error getting scan session: {e}")
            return None

    def _get_scans_status(self, scan_ids: List[str]) -> List[Dict]:
        """Get status of multiple scans"""
        if not scan_ids:
            return []

        try:
            # Create placeholders for the IN clause
            placeholders = ",".join([f"'{scan_id}'" for scan_id in scan_ids])

            result = self.db.execute(
                text(
                    f"""
                SELECT s.id, s.name, s.status, s.progress, s.started_at, s.completed_at,
                       h.hostname, h.display_name,
                       sr.score, sr.failed_rules, sr.total_rules
                FROM scans s
                JOIN hosts h ON s.host_id = h.id
                LEFT JOIN scan_results sr ON sr.scan_id = s.id
                WHERE s.id IN ({placeholders})
                ORDER BY s.started_at
            """
                )
            ).fetchall()

            scan_statuses = []
            for row in result:
                scan_statuses.append(
                    {
                        "scan_id": row.id,
                        "scan_name": row.name,
                        "hostname": row.hostname,
                        "display_name": row.display_name,
                        "status": row.status,
                        "progress": row.progress,
                        "started_at": (row.started_at.isoformat() if row.started_at else None),
                        "completed_at": (
                            row.completed_at.isoformat() if row.completed_at else None
                        ),
                        "compliance_score": row.score,
                        "failed_rules": row.failed_rules or 0,
                        "total_rules": row.total_rules or 0,
                    }
                )

            return scan_statuses

        except Exception as e:
            logger.error(f"Error getting scans status: {e}")
            return []

    def _execute_staggered_scans(self, scan_ids: List[str]) -> List[str]:
        """Execute scans with staggered start times"""
        # For now, just update all scans to running status
        # In a production system, this would integrate with Celery or similar
        try:
            if not scan_ids:
                return []

            placeholders = ",".join([f"'{scan_id}'" for scan_id in scan_ids])

            # Update scan status to running
            self.db.execute(
                text(
                    f"""
                UPDATE scans SET status = 'running', started_at = :started_at
                WHERE id IN ({placeholders}) AND status = 'pending'
            """
                ),
                {"started_at": datetime.utcnow()},
            )

            self.db.commit()

            # In a real implementation, you would start the actual scan tasks here
            # For now, return the scan IDs that were updated
            return scan_ids

        except Exception as e:
            logger.error(f"Error executing staggered scans: {e}")
            return []

    # AUTHORIZATION METHODS - CRITICAL SECURITY IMPLEMENTATION

    async def _validate_bulk_scan_authorization(
        self,
        user_id: str,
        host_ids: List[str],
        auth_context: Optional[AuthorizationContext] = None,
    ) -> Tuple[List["AuthorizedHost"], List[AuthorizationFailure]]:
        """
        Validate user authorization for each host in bulk scan request

        ZERO TRUST IMPLEMENTATION:
        - Individual validation for each host
        - No implicit permissions or inheritance
        - Comprehensive audit trail
        - Fail-secure behavior

        Args:
            user_id: User requesting bulk scan
            host_ids: List of host IDs to validate
            auth_context: Optional authorization context

        Returns:
            Tuple of (authorized_hosts, authorization_failures)
        """
        try:
            # Build authorization context if not provided
            if auth_context is None:
                auth_context = await self._build_user_authorization_context(user_id)

            # Create resource identifiers for all hosts
            resources = [
                ResourceIdentifier(resource_type=ResourceType.HOST, resource_id=host_id)
                for host_id in host_ids
            ]

            # Perform bulk authorization check
            bulk_request = BulkAuthorizationRequest(
                user_id=user_id,
                resources=resources,
                action=ActionType.SCAN,
                context=auth_context,
                fail_fast=False,  # Check all hosts to provide complete results
                parallel_evaluation=True,  # Enable parallel processing
            )

            logger.debug(f"Performing bulk authorization check for {len(resources)} hosts")
            auth_result = await self.authorization_service.check_bulk_permissions(bulk_request)

            # Get host details for results
            host_details = await self._get_host_details(host_ids)
            host_lookup = {h["id"]: h for h in host_details}

            # Process authorization results
            authorized_hosts = []
            authorization_failures = []

            for result in auth_result.individual_results:
                host_id = result.resource.resource_id
                host_detail = host_lookup.get(
                    host_id, {"hostname": "unknown", "display_name": "unknown"}
                )

                if result.decision == AuthorizationDecision.ALLOW:
                    authorized_hosts.append(
                        AuthorizedHost(
                            host_id=host_id,
                            hostname=host_detail.get("hostname", "unknown"),
                            display_name=host_detail.get("display_name", "unknown"),
                            authorization_reason=result.reason,
                        )
                    )
                else:
                    authorization_failures.append(
                        AuthorizationFailure(
                            host_id=host_id,
                            hostname=host_detail.get("hostname", "unknown"),
                            reason=result.reason,
                            user_id=user_id,
                        )
                    )

            # Log authorization summary for security monitoring
            logger.info(
                f"Bulk authorization results for user {user_id}: "
                f"{len(authorized_hosts)} authorized, {len(authorization_failures)} denied, "
                f"evaluation time: {auth_result.total_evaluation_time_ms}ms"
            )

            # Log denied hosts for security audit
            if authorization_failures:
                denied_host_ids = [f.host_id for f in authorization_failures]
                logger.warning(
                    f"Authorization denied for user {user_id} on hosts: {denied_host_ids}"
                )

            return authorized_hosts, authorization_failures

        except Exception as e:
            logger.error(f"Bulk authorization validation failed: {e}")

            # Fail securely - treat all hosts as unauthorized
            host_details = await self._get_host_details(host_ids)
            authorization_failures = [
                AuthorizationFailure(
                    host_id=host_detail["id"],
                    hostname=host_detail.get("hostname", "unknown"),
                    reason=f"Authorization system error: {str(e)}",
                    user_id=user_id,
                )
                for host_detail in host_details
            ]

            return [], authorization_failures

    def _build_user_authorization_context(self, user_id: str) -> AuthorizationContext:
        """
        Build authorization context for a user including roles and groups
        """
        try:
            result = self.db.execute(
                text(
                    """
                SELECT u.id, u.username, u.role,
                       COALESCE(
                           JSON_AGG(DISTINCT ug.name) FILTER (WHERE ug.name IS NOT NULL),
                           '[]'::json
                       ) as user_groups
                FROM users u
                LEFT JOIN user_group_memberships ugm ON u.id = ugm.user_id
                LEFT JOIN user_groups ug ON ugm.group_id = ug.id
                WHERE u.id = :user_id AND u.is_active = true
                GROUP BY u.id, u.username, u.role
            """
                ),
                {"user_id": user_id},
            )

            row = result.fetchone()
            if not row:
                logger.warning(f"User {user_id} not found or inactive")
                return AuthorizationContext(user_id=user_id, user_roles=[], user_groups=[])

            user_groups = json.loads(row.user_groups) if row.user_groups else []

            return AuthorizationContext(
                user_id=user_id,
                user_roles=[row.role] if row.role else [],
                user_groups=user_groups,
            )

        except Exception as e:
            logger.error(f"Error building authorization context for user {user_id}: {e}")
            return AuthorizationContext(user_id=user_id, user_roles=[], user_groups=[])

    def _get_host_details(self, host_ids: List[str]) -> List[Dict]:
        """
        Get host details for authorization results
        """
        try:
            if not host_ids:
                return []

            # Create placeholders for the IN clause
            placeholders = ",".join([f"'{host_id}'" for host_id in host_ids])

            result = self.db.execute(
                text(
                    f"""
                SELECT id, hostname, display_name, ip_address, status
                FROM hosts
                WHERE id IN ({placeholders})
            """
                )
            )

            return [
                {
                    "id": str(row.id),
                    "hostname": row.hostname,
                    "display_name": row.display_name or row.hostname,
                    "ip_address": row.ip_address,
                    "status": row.status,
                }
                for row in result
            ]

        except Exception as e:
            logger.error(f"Error getting host details: {e}")
            return [
                {"id": host_id, "hostname": "unknown", "display_name": "unknown"}
                for host_id in host_ids
            ]

    def _create_batch_scans_with_authorization(
        self,
        batch: ScanBatch,
        session_id: str,
        name_prefix: str,
        user_id: str,
        stagger_delay: int,
        authorized_hosts: List["AuthorizedHost"],
    ) -> List[str]:
        """
        Create batch scans with additional authorization validation

        This method provides a final authorization check before scan creation
        to ensure only authorized hosts have scans created.
        """
        try:
            # Create lookup of authorized host IDs
            authorized_host_ids = {host.host_id for host in authorized_hosts}

            scan_ids = []

            for i, host in enumerate(batch.hosts):
                # Additional authorization check
                if host.id not in authorized_host_ids:
                    logger.warning(f"Skipping scan creation for unauthorized host {host.id}")
                    continue

                scan_id = str(uuid.uuid4())
                scan_name = f"{name_prefix} - {host.hostname}"

                # Calculate staggered start time
                start_delay = i * stagger_delay  # seconds

                # Create scan record with authorization metadata
                self.db.execute(
                    text(
                        """
                    INSERT INTO scans
                    (id, name, host_id, content_id, profile_id, status, progress,
                     scan_options, started_by, started_at, remediation_requested, verification_scan)
                    VALUES (:id, :name, :host_id, :content_id, :profile_id, :status,
                            :progress, :scan_options, :started_by, :started_at, :remediation_requested, :verification_scan)
                """
                    ),
                    {
                        "id": scan_id,
                        "name": scan_name,
                        "host_id": host.id,
                        "content_id": batch.content_id,
                        "profile_id": batch.profile_id,
                        "status": "pending",
                        "progress": 0,
                        "scan_options": json.dumps(
                            {
                                "bulk_scan": True,
                                "session_id": session_id,
                                "batch_id": batch.id,
                                "start_delay": start_delay,
                                "authorized": True,  # Mark as explicitly authorized
                                "authorization_timestamp": datetime.utcnow().isoformat(),
                            }
                        ),
                        "started_by": user_id,
                        "started_at": datetime.utcnow(),
                        "remediation_requested": False,
                        "verification_scan": False,
                    },
                )

                scan_ids.append(scan_id)

            self.db.commit()

            logger.info(
                f"Created {len(scan_ids)} authorized scans out of {len(batch.hosts)} hosts in batch"
            )
            return scan_ids

        except Exception as e:
            logger.error(f"Error creating authorized batch scans: {e}")
            raise


@dataclass
class AuthorizedHost:
    """Represents a host that has been authorized for scanning"""

    host_id: str
    hostname: str
    display_name: str
    authorization_reason: str
    timestamp: Optional[datetime] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()
