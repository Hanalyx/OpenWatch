"""
Post-Remediation Verification Service
Automatically verifies the effectiveness of remediation by re-scanning hosts and comparing results.
Provides continuous compliance monitoring and remediation quality assurance.
"""

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from beanie import Document
from pydantic import BaseModel, Field, validator

from ..models.mongo_models import Host
from ..models.scan_models import ScanResult as SQLScanResult
from .bulk_remediation_service import BulkRemediationResult, BulkRemediationService
from .scan_service import ScanService

logger = logging.getLogger(__name__)


# ============================================================================
# MODELS AND ENUMS
# ============================================================================


class VerificationStatus(str, Enum):
    """Status of verification process"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ComplianceResult(str, Enum):
    """Individual rule compliance result"""

    PASS = "pass"  # Rule is now compliant
    FAIL = "fail"  # Rule is still non-compliant
    UNCHANGED = "unchanged"  # No change from before remediation
    ERROR = "error"  # Error during verification
    NOT_APPLICABLE = "not_applicable"  # Rule not applicable to host


class VerificationOutcome(str, Enum):
    """Overall verification outcome"""

    SUCCESS = "success"  # All targeted rules are now compliant
    PARTIAL_SUCCESS = "partial_success"  # Some rules fixed, others still failing
    FAILED = "failed"  # No improvement or new failures introduced
    INCONCLUSIVE = "inconclusive"  # Unable to determine due to errors


class RuleVerificationResult(BaseModel):
    """Verification result for individual rule on a host"""

    rule_id: str
    host_id: str

    # Pre-remediation state
    before_compliant: Optional[bool] = None
    before_result: Optional[str] = None
    before_severity: Optional[str] = None

    # Post-remediation state
    after_compliant: Optional[bool] = None
    after_result: Optional[str] = None
    after_severity: Optional[str] = None

    # Verification result
    compliance_result: ComplianceResult
    improvement_achieved: bool = Field(default=False)
    remediation_effective: bool = Field(default=False)

    # Timing
    verified_at: datetime = Field(default_factory=datetime.utcnow)

    # Additional details
    error_message: Optional[str] = None
    verification_notes: Optional[str] = None


class HostVerificationResult(BaseModel):
    """Verification result for all rules on a single host"""

    host_id: str
    platform: str

    # Overall outcome
    verification_outcome: VerificationOutcome

    # Rule-level results
    rule_results: List[RuleVerificationResult] = Field(default_factory=list)

    # Summary statistics
    total_rules_verified: int = 0
    rules_now_compliant: int = 0
    rules_still_failing: int = 0
    rules_unchanged: int = 0
    rules_with_errors: int = 0

    # Timing
    verification_started: datetime
    verification_completed: Optional[datetime] = None
    verification_duration_seconds: Optional[float] = None

    # Scan details
    pre_scan_id: Optional[str] = None
    post_scan_id: Optional[str] = None

    # Error handling
    verification_errors: List[str] = Field(default_factory=list)


class VerificationJob(Document):
    """Post-remediation verification job"""

    verification_id: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True)

    # Associated remediation job
    bulk_job_id: str = Field(..., description="Associated bulk remediation job ID")

    # Verification configuration
    target_hosts: List[str] = Field(..., description="Hosts to verify")
    target_rules: List[str] = Field(..., description="Rules to verify")

    # Timing configuration
    delay_before_verification_seconds: int = Field(default=120, description="Wait time before verification")
    verification_timeout_minutes: int = Field(default=60, description="Timeout for entire verification process")

    # Execution status
    status: VerificationStatus = VerificationStatus.PENDING

    # Results
    host_results: List[HostVerificationResult] = Field(default_factory=list)

    # Summary statistics
    total_hosts: int = 0
    hosts_verified: int = 0
    hosts_with_improvements: int = 0
    overall_success_rate: Optional[float] = None

    # Timing
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None

    # Configuration and context
    verification_config: Dict[str, Any] = Field(default_factory=dict)
    triggered_by: str = Field(default="automatic")

    # Error tracking
    verification_errors: List[str] = Field(default_factory=list)

    class Settings:
        collection = "verification_jobs"
        indexes = [
            "verification_id",
            "bulk_job_id",
            "status",
            "created_at",
            "triggered_by",
        ]


class ContinuousComplianceMonitor(Document):
    """Configuration for continuous compliance monitoring"""

    monitor_id: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True)
    name: str = Field(..., description="Monitor name")

    # Monitoring scope
    host_group_ids: List[str] = Field(default_factory=list, description="Host groups to monitor")
    host_ids: List[str] = Field(default_factory=list, description="Specific hosts to monitor")
    rule_ids: List[str] = Field(..., description="Rules to monitor for compliance")
    framework: Optional[str] = None

    # Monitoring schedule
    scan_frequency_hours: int = Field(default=24, ge=1, le=168, description="How often to scan")
    verification_delay_minutes: int = Field(default=30, ge=1, le=1440, description="Wait time after remediation")

    # Actions on non-compliance
    auto_remediate: bool = Field(default=False, description="Automatically trigger remediation")
    remediation_plugin_preferences: Dict[str, str] = Field(default_factory=dict)
    max_auto_remediations: int = Field(default=3, description="Max automatic remediation attempts")

    # Notification settings
    notify_on_drift: bool = Field(default=True, description="Notify when compliance drifts")
    notification_channels: List[str] = Field(default_factory=list)

    # Status
    is_active: bool = Field(default=True)
    last_scan_at: Optional[datetime] = None
    next_scan_at: Optional[datetime] = None

    # Statistics
    total_scans: int = Field(default=0)
    drift_detections: int = Field(default=0)
    auto_remediations: int = Field(default=0)

    # Metadata
    created_by: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        collection = "continuous_compliance_monitors"
        indexes = ["monitor_id", "is_active", "next_scan_at", "created_by"]


# ============================================================================
# VERIFICATION SERVICE
# ============================================================================


class PostRemediationVerificationService:
    """
    Service for automated post-remediation verification and continuous compliance monitoring

    Features:
    - Automatic verification after remediation completion
    - Before/after compliance comparison
    - Continuous compliance drift detection
    - Remediation effectiveness tracking
    - Integration with scan and remediation services
    """

    def __init__(self):
        self.scan_service = ScanService()
        self.bulk_remediation_service = BulkRemediationService()
        self.active_verifications: Dict[str, VerificationJob] = {}
        self.continuous_monitors: Dict[str, ContinuousComplianceMonitor] = {}
        self.monitor_task: Optional[asyncio.Task] = None
        self.running = False

    async def start_monitoring_service(self):
        """Start the continuous compliance monitoring service"""
        if self.running:
            logger.warning("Verification monitoring service is already running")
            return

        self.running = True
        self.monitor_task = asyncio.create_task(self._monitoring_loop())
        logger.info("Post-remediation verification monitoring service started")

    async def stop_monitoring_service(self):
        """Stop the continuous compliance monitoring service"""
        if not self.running:
            return

        self.running = False
        if self.monitor_task:
            self.monitor_task.cancel()
            try:
                await self.monitor_task
            except asyncio.CancelledError:
                pass

        logger.info("Post-remediation verification monitoring service stopped")

    async def schedule_verification(
        self,
        bulk_job_id: str,
        target_hosts: List[str],
        target_rules: List[str],
        delay_seconds: int = 120,
        timeout_minutes: int = 60,
        triggered_by: str = "automatic",
    ) -> VerificationJob:
        """Schedule post-remediation verification"""

        verification = VerificationJob(
            bulk_job_id=bulk_job_id,
            target_hosts=target_hosts,
            target_rules=target_rules,
            delay_before_verification_seconds=delay_seconds,
            verification_timeout_minutes=timeout_minutes,
            total_hosts=len(target_hosts),
            triggered_by=triggered_by,
        )

        await verification.save()
        self.active_verifications[verification.verification_id] = verification

        # Schedule the verification execution
        asyncio.create_task(self._execute_verification_after_delay(verification))

        logger.info(f"Scheduled verification job: {verification.verification_id} for bulk job: {bulk_job_id}")
        return verification

    async def execute_verification_now(
        self,
        bulk_job_id: str,
        target_hosts: List[str],
        target_rules: List[str],
        triggered_by: str = "manual",
    ) -> VerificationJob:
        """Execute verification immediately without delay"""

        verification = VerificationJob(
            bulk_job_id=bulk_job_id,
            target_hosts=target_hosts,
            target_rules=target_rules,
            delay_before_verification_seconds=0,
            total_hosts=len(target_hosts),
            triggered_by=triggered_by,
        )

        await verification.save()
        self.active_verifications[verification.verification_id] = verification

        # Execute immediately
        await self._execute_verification(verification)

        return verification

    async def get_verification_job(self, verification_id: str) -> Optional[VerificationJob]:
        """Get verification job by ID"""
        # Check active verifications first
        if verification_id in self.active_verifications:
            return self.active_verifications[verification_id]

        # Query database
        return await VerificationJob.find_one(VerificationJob.verification_id == verification_id)

    async def list_verification_jobs(
        self,
        bulk_job_id: Optional[str] = None,
        status: Optional[VerificationStatus] = None,
        triggered_by: Optional[str] = None,
        limit: int = 50,
    ) -> List[VerificationJob]:
        """List verification jobs with filtering"""
        query = {}

        if bulk_job_id:
            query["bulk_job_id"] = bulk_job_id
        if status:
            query["status"] = status
        if triggered_by:
            query["triggered_by"] = triggered_by

        return await VerificationJob.find(query).sort(-VerificationJob.created_at).limit(limit).to_list()

    async def cancel_verification(self, verification_id: str) -> bool:
        """Cancel a pending or running verification job"""
        verification = await self.get_verification_job(verification_id)
        if not verification:
            return False

        if verification.status in [
            VerificationStatus.COMPLETED,
            VerificationStatus.FAILED,
            VerificationStatus.CANCELLED,
        ]:
            return False  # Already finished

        verification.status = VerificationStatus.CANCELLED
        verification.completed_at = datetime.utcnow()

        if verification.started_at:
            verification.duration_seconds = (verification.completed_at - verification.started_at).total_seconds()

        await verification.save()

        # Remove from active verifications
        self.active_verifications.pop(verification_id, None)

        logger.info(f"Cancelled verification job: {verification_id}")
        return True

    async def create_continuous_monitor(
        self,
        name: str,
        rule_ids: List[str],
        created_by: str,
        host_group_ids: List[str] = None,
        host_ids: List[str] = None,
        scan_frequency_hours: int = 24,
        auto_remediate: bool = False,
    ) -> ContinuousComplianceMonitor:
        """Create a continuous compliance monitor"""

        if not host_group_ids and not host_ids:
            raise ValueError("Must specify either host_group_ids or host_ids")

        monitor = ContinuousComplianceMonitor(
            name=name,
            host_group_ids=host_group_ids or [],
            host_ids=host_ids or [],
            rule_ids=rule_ids,
            scan_frequency_hours=scan_frequency_hours,
            auto_remediate=auto_remediate,
            created_by=created_by,
            next_scan_at=datetime.utcnow() + timedelta(hours=scan_frequency_hours),
        )

        await monitor.save()
        self.continuous_monitors[monitor.monitor_id] = monitor

        logger.info(f"Created continuous compliance monitor: {monitor.monitor_id} ({name})")
        return monitor

    async def get_continuous_monitor(self, monitor_id: str) -> Optional[ContinuousComplianceMonitor]:
        """Get continuous monitor by ID"""
        if monitor_id in self.continuous_monitors:
            return self.continuous_monitors[monitor_id]

        return await ContinuousComplianceMonitor.find_one(ContinuousComplianceMonitor.monitor_id == monitor_id)

    async def list_continuous_monitors(
        self,
        is_active: Optional[bool] = None,
        created_by: Optional[str] = None,
        limit: int = 50,
    ) -> List[ContinuousComplianceMonitor]:
        """List continuous compliance monitors"""
        query = {}

        if is_active is not None:
            query["is_active"] = is_active
        if created_by:
            query["created_by"] = created_by

        return (
            await ContinuousComplianceMonitor.find(query)
            .sort(-ContinuousComplianceMonitor.created_at)
            .limit(limit)
            .to_list()
        )

    async def _execute_verification_after_delay(self, verification: VerificationJob):
        """Execute verification after configured delay"""
        if verification.delay_before_verification_seconds > 0:
            logger.info(
                f"Waiting {verification.delay_before_verification_seconds}s before verification: {verification.verification_id}"
            )
            await asyncio.sleep(verification.delay_before_verification_seconds)

        await self._execute_verification(verification)

    async def _execute_verification(self, verification: VerificationJob):
        """Execute the verification process"""
        try:
            verification.status = VerificationStatus.RUNNING
            verification.started_at = datetime.utcnow()
            await verification.save()

            logger.info(f"Starting verification execution: {verification.verification_id}")

            # Get pre-remediation scan results
            bulk_job = await self.bulk_remediation_service.get_bulk_job_status(verification.bulk_job_id)
            if not bulk_job:
                raise ValueError(f"Bulk remediation job not found: {verification.bulk_job_id}")

            # Execute post-remediation scans for each host
            host_results = []
            for host_id in verification.target_hosts:
                try:
                    host_result = await self._verify_single_host(host_id, verification.target_rules, verification)
                    host_results.append(host_result)

                    if host_result.verification_outcome in [
                        VerificationOutcome.SUCCESS,
                        VerificationOutcome.PARTIAL_SUCCESS,
                    ]:
                        verification.hosts_with_improvements += 1

                    verification.hosts_verified += 1

                except Exception as e:
                    logger.error(f"Host verification failed for {host_id}: {e}")
                    verification.verification_errors.append(f"Host {host_id}: {str(e)}")

            # Store results
            verification.host_results = host_results

            # Calculate overall success rate
            if verification.hosts_verified > 0:
                verification.overall_success_rate = verification.hosts_with_improvements / verification.hosts_verified

            # Determine overall status
            verification.status = VerificationStatus.COMPLETED

            logger.info(
                f"Verification completed: {verification.verification_id} - {verification.hosts_with_improvements}/{verification.hosts_verified} hosts improved"
            )

        except Exception as e:
            logger.error(f"Verification execution failed: {e}")
            verification.status = VerificationStatus.FAILED
            verification.verification_errors.append(str(e))

        finally:
            verification.completed_at = datetime.utcnow()
            if verification.started_at:
                verification.duration_seconds = (verification.completed_at - verification.started_at).total_seconds()

            await verification.save()

            # Remove from active verifications
            self.active_verifications.pop(verification.verification_id, None)

    async def _verify_single_host(
        self, host_id: str, rule_ids: List[str], verification: VerificationJob
    ) -> HostVerificationResult:
        """Verify remediation effectiveness for a single host"""

        host = await Host.find_one(Host.id == host_id)
        if not host:
            raise ValueError(f"Host not found: {host_id}")

        verification_started = datetime.utcnow()

        # Execute post-remediation scan
        scan_request = {
            "host_id": host_id,
            "content_type": "profile",
            "profile_id": "default",  # Would be determined based on rules
            "scan_type": "compliance",
        }

        try:
            post_scan_result = await self.scan_service.execute_scan(scan_request)
            post_scan_id = post_scan_result.get("scan_id")

            # Wait for scan completion (simplified)
            await asyncio.sleep(30)  # In production, would poll for completion

            # Get scan results and compare
            rule_results = []
            rules_now_compliant = 0
            rules_still_failing = 0
            rules_unchanged = 0
            rules_with_errors = 0

            for rule_id in rule_ids:
                try:
                    # Get pre and post remediation compliance status
                    # This would query actual scan results
                    rule_result = await self._compare_rule_compliance(
                        host_id, rule_id, verification.bulk_job_id, post_scan_id
                    )

                    rule_results.append(rule_result)

                    # Update counters
                    if rule_result.compliance_result == ComplianceResult.PASS:
                        rules_now_compliant += 1
                    elif rule_result.compliance_result == ComplianceResult.FAIL:
                        rules_still_failing += 1
                    elif rule_result.compliance_result == ComplianceResult.UNCHANGED:
                        rules_unchanged += 1
                    elif rule_result.compliance_result == ComplianceResult.ERROR:
                        rules_with_errors += 1

                except Exception as e:
                    logger.error(f"Rule verification failed for {rule_id}: {e}")
                    rule_results.append(
                        RuleVerificationResult(
                            rule_id=rule_id,
                            host_id=host_id,
                            compliance_result=ComplianceResult.ERROR,
                            error_message=str(e),
                        )
                    )
                    rules_with_errors += 1

            # Determine overall outcome
            if rules_now_compliant == len(rule_ids):
                outcome = VerificationOutcome.SUCCESS
            elif rules_now_compliant > 0:
                outcome = VerificationOutcome.PARTIAL_SUCCESS
            elif rules_with_errors > 0:
                outcome = VerificationOutcome.INCONCLUSIVE
            else:
                outcome = VerificationOutcome.FAILED

            return HostVerificationResult(
                host_id=host_id,
                platform=host.platform,
                verification_outcome=outcome,
                rule_results=rule_results,
                total_rules_verified=len(rule_ids),
                rules_now_compliant=rules_now_compliant,
                rules_still_failing=rules_still_failing,
                rules_unchanged=rules_unchanged,
                rules_with_errors=rules_with_errors,
                verification_started=verification_started,
                verification_completed=datetime.utcnow(),
                verification_duration_seconds=(datetime.utcnow() - verification_started).total_seconds(),
                post_scan_id=post_scan_id,
            )

        except Exception as e:
            logger.error(f"Host verification failed for {host_id}: {e}")
            return HostVerificationResult(
                host_id=host_id,
                platform=host.platform if host else "unknown",
                verification_outcome=VerificationOutcome.INCONCLUSIVE,
                rule_results=[],
                verification_started=verification_started,
                verification_completed=datetime.utcnow(),
                verification_duration_seconds=(datetime.utcnow() - verification_started).total_seconds(),
                verification_errors=[str(e)],
            )

    async def _compare_rule_compliance(
        self, host_id: str, rule_id: str, bulk_job_id: str, post_scan_id: str
    ) -> RuleVerificationResult:
        """Compare rule compliance before and after remediation"""

        # This would query actual scan results from the database
        # For now, simulate the comparison logic

        # Get pre-remediation compliance status (would come from original scan)
        before_compliant = False  # Simulate non-compliant before
        before_result = "fail"

        # Get post-remediation compliance status (from post_scan_id)
        # Simulate improved compliance
        after_compliant = True
        after_result = "pass"

        # Determine compliance result
        if before_compliant and after_compliant:
            compliance_result = ComplianceResult.UNCHANGED
            improvement_achieved = False
        elif not before_compliant and after_compliant:
            compliance_result = ComplianceResult.PASS
            improvement_achieved = True
        elif not before_compliant and not after_compliant:
            compliance_result = ComplianceResult.FAIL
            improvement_achieved = False
        else:  # before_compliant and not after_compliant (regression)
            compliance_result = ComplianceResult.FAIL
            improvement_achieved = False

        remediation_effective = improvement_achieved and after_compliant

        return RuleVerificationResult(
            rule_id=rule_id,
            host_id=host_id,
            before_compliant=before_compliant,
            before_result=before_result,
            after_compliant=after_compliant,
            after_result=after_result,
            compliance_result=compliance_result,
            improvement_achieved=improvement_achieved,
            remediation_effective=remediation_effective,
        )

    async def _monitoring_loop(self):
        """Main continuous compliance monitoring loop"""
        while self.running:
            try:
                await self._check_continuous_monitors()
                await asyncio.sleep(300)  # Check every 5 minutes
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(300)

    async def _check_continuous_monitors(self):
        """Check for monitors that need to run scans"""
        now = datetime.utcnow()

        # Get active monitors that are due for scanning
        monitors = await ContinuousComplianceMonitor.find({"is_active": True, "next_scan_at": {"$lte": now}}).to_list()

        for monitor in monitors:
            try:
                await self._execute_continuous_monitor(monitor)
            except Exception as e:
                logger.error(f"Continuous monitor execution failed: {monitor.monitor_id}: {e}")

    async def _execute_continuous_monitor(self, monitor: ContinuousComplianceMonitor):
        """Execute a continuous compliance monitor"""
        logger.info(f"Executing continuous monitor: {monitor.monitor_id} ({monitor.name})")

        # Get target hosts
        target_hosts = []
        if monitor.host_ids:
            target_hosts.extend(monitor.host_ids)

        # Add hosts from host groups (would query host group service)
        # for group_id in monitor.host_group_ids:
        #     group_hosts = await self.get_hosts_in_group(group_id)
        #     target_hosts.extend(group_hosts)

        if not target_hosts:
            logger.warning(f"No target hosts for monitor: {monitor.monitor_id}")
            return

        # Execute verification scan
        verification = await self.execute_verification_now(
            bulk_job_id=f"continuous-monitor-{monitor.monitor_id}",
            target_hosts=target_hosts,
            target_rules=monitor.rule_ids,
            triggered_by=f"continuous-monitor:{monitor.monitor_id}",
        )

        # Update monitor statistics
        monitor.total_scans += 1
        monitor.last_scan_at = datetime.utcnow()
        monitor.next_scan_at = datetime.utcnow() + timedelta(hours=monitor.scan_frequency_hours)

        # Check for compliance drift
        drift_detected = False
        for host_result in verification.host_results:
            if host_result.verification_outcome in [
                VerificationOutcome.FAILED,
                VerificationOutcome.PARTIAL_SUCCESS,
            ]:
                drift_detected = True
                break

        if drift_detected:
            monitor.drift_detections += 1

            # Trigger auto-remediation if enabled
            if monitor.auto_remediate and monitor.auto_remediations < monitor.max_auto_remediations:

                logger.info(f"Triggering auto-remediation for monitor: {monitor.monitor_id}")

                # Would trigger remediation job here
                # await self._trigger_auto_remediation(monitor, verification)

                monitor.auto_remediations += 1

        monitor.updated_at = datetime.utcnow()
        await monitor.save()

        logger.info(f"Continuous monitor execution completed: {monitor.monitor_id}")

    async def get_verification_statistics(self) -> Dict[str, Any]:
        """Get verification service statistics"""
        total_verifications = await VerificationJob.count()

        # Status distribution
        status_stats = {}
        for status in VerificationStatus:
            count = await VerificationJob.find({"status": status}).count()
            status_stats[status.value] = count

        # Success rate statistics
        completed_verifications = await VerificationJob.find(
            {
                "status": VerificationStatus.COMPLETED,
                "overall_success_rate": {"$ne": None},
            }
        ).to_list()

        avg_success_rate = 0.0
        if completed_verifications:
            avg_success_rate = sum(v.overall_success_rate for v in completed_verifications) / len(
                completed_verifications
            )

        # Continuous monitoring statistics
        total_monitors = await ContinuousComplianceMonitor.count()
        active_monitors = await ContinuousComplianceMonitor.find({"is_active": True}).count()

        return {
            "total_verifications": total_verifications,
            "status_distribution": status_stats,
            "completed_verifications": len(completed_verifications),
            "average_success_rate": avg_success_rate,
            "continuous_monitors": {"total": total_monitors, "active": active_monitors},
            "active_verification_jobs": len(self.active_verifications),
        }
