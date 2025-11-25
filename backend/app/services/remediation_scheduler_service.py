"""
Remediation Scheduler Service
Handles scheduling of remediation jobs for maintenance windows with comprehensive support
for recurring schedules, maintenance window management, and execution coordination.
"""

import asyncio
import logging
import uuid
from datetime import datetime
from datetime import time as dt_time
from datetime import timedelta
from enum import Enum
from typing import Any, Dict, List, Optional
from zoneinfo import ZoneInfo

import croniter
from beanie import Document
from pydantic import BaseModel, Field, validator

from .bulk_remediation_service import BulkExecutionStrategy, BulkRemediationRequest, BulkRemediationService

logger = logging.getLogger(__name__)


# ============================================================================
# MODELS AND ENUMS
# ============================================================================


class ScheduleType(str, Enum):
    """Types of remediation schedules"""

    ONE_TIME = "one_time"  # Execute once at specified time
    RECURRING = "recurring"  # Execute on recurring schedule
    MAINTENANCE_WINDOW = "maintenance_window"  # Execute during maintenance windows


class ScheduleStatus(str, Enum):
    """Schedule execution status"""

    ACTIVE = "active"  # Schedule is active and will execute
    PAUSED = "paused"  # Schedule is temporarily paused
    COMPLETED = "completed"  # One-time schedule completed
    FAILED = "failed"  # Schedule failed to execute
    CANCELLED = "cancelled"  # Schedule was cancelled


class MaintenanceWindowType(str, Enum):
    """Types of maintenance windows"""

    WEEKLY = "weekly"  # Weekly recurring window
    MONTHLY = "monthly"  # Monthly recurring window
    QUARTERLY = "quarterly"  # Quarterly recurring window
    CUSTOM = "custom"  # Custom cron-based schedule


class MaintenanceWindow(BaseModel):
    """Maintenance window definition"""

    window_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(..., description="Human-readable name for the window")
    description: Optional[str] = None

    # Window timing
    window_type: MaintenanceWindowType
    start_time: dt_time = Field(..., description="Start time (HH:MM)")
    duration_minutes: int = Field(..., ge=1, le=1440, description="Duration in minutes")
    timezone: str = Field(default="UTC", description="Timezone for the window")

    # Recurrence settings
    cron_expression: Optional[str] = None  # For custom schedules
    day_of_week: Optional[int] = Field(None, ge=0, le=6)  # 0=Monday for weekly
    day_of_month: Optional[int] = Field(None, ge=1, le=31)  # For monthly

    # Execution settings
    max_parallel_jobs: int = Field(default=3, ge=1, le=10)
    allowed_execution_strategies: List[BulkExecutionStrategy] = Field(
        default=[BulkExecutionStrategy.BATCHED, BulkExecutionStrategy.ROLLING]
    )

    # Approval settings
    requires_approval: bool = Field(default=True, description="Require approval before execution")
    approval_window_hours: int = Field(default=24, ge=1, le=168, description="Hours before window to require approval")

    # Notification settings
    notify_before_minutes: List[int] = Field(default=[60, 15], description="Notification times before window")
    notification_channels: List[str] = Field(default_factory=list, description="Notification channels")

    # Status
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    @validator("timezone")
    def validate_timezone(cls, v):
        try:
            ZoneInfo(v)
            return v
        except Exception:
            raise ValueError(f"Invalid timezone: {v}")

    def get_next_window_start(self, after: datetime = None) -> Optional[datetime]:
        """Calculate the next window start time"""
        if not self.is_active:
            return None

        if after is None:
            after = datetime.utcnow()

        tz = ZoneInfo(self.timezone)
        after_tz = after.replace(tzinfo=ZoneInfo("UTC")).astimezone(tz)

        if self.window_type == MaintenanceWindowType.WEEKLY:
            # Calculate next weekly occurrence
            days_ahead = self.day_of_week - after_tz.weekday()
            if days_ahead <= 0:  # Target day already happened this week
                days_ahead += 7

            next_date = after_tz.date() + timedelta(days=days_ahead)
            next_datetime = datetime.combine(next_date, self.start_time, tz)

        elif self.window_type == MaintenanceWindowType.MONTHLY:
            # Calculate next monthly occurrence
            next_month = after_tz.replace(day=1) + timedelta(days=32)
            next_month = next_month.replace(day=1)  # First day of next month

            # Handle edge case where day_of_month doesn't exist in target month
            import calendar

            max_day = calendar.monthrange(next_month.year, next_month.month)[1]
            target_day = min(self.day_of_month, max_day)

            next_datetime = next_month.replace(day=target_day, hour=self.start_time.hour, minute=self.start_time.minute)

        elif self.window_type == MaintenanceWindowType.CUSTOM and self.cron_expression:
            # Use cron expression
            cron = croniter.croniter(self.cron_expression, after_tz)
            next_datetime = cron.get_next(datetime)

        else:
            return None

        # Convert back to UTC
        return next_datetime.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)

    def get_window_end(self, window_start: datetime) -> datetime:
        """Calculate window end time"""
        return window_start + timedelta(minutes=self.duration_minutes)


class RemediationSchedule(Document):
    """Scheduled remediation job"""

    schedule_id: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True)
    name: str = Field(..., description="Human-readable schedule name")
    description: Optional[str] = None

    # Schedule configuration
    schedule_type: ScheduleType
    status: ScheduleStatus = ScheduleStatus.ACTIVE

    # Remediation configuration
    remediation_request: BulkRemediationRequest

    # Timing configuration
    scheduled_at: Optional[datetime] = None  # For one-time schedules
    cron_expression: Optional[str] = None  # For recurring schedules
    maintenance_window_id: Optional[str] = None  # For maintenance window schedules
    timezone: str = Field(default="UTC")

    # Execution configuration
    max_retries: int = Field(default=3, ge=0, le=10)
    retry_delay_minutes: int = Field(default=30, ge=1, le=1440)
    timeout_minutes: int = Field(default=180, ge=10, le=1440)

    # Approval workflow
    requires_approval: bool = Field(default=False)
    approval_required_by: Optional[datetime] = None
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    approval_notes: Optional[str] = None

    # Execution tracking
    last_execution_at: Optional[datetime] = None
    last_execution_job_id: Optional[str] = None
    last_execution_status: Optional[str] = None
    next_execution_at: Optional[datetime] = None
    execution_count: int = Field(default=0)
    failure_count: int = Field(default=0)

    # Metadata
    created_by: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    # Notification settings
    notify_on_success: bool = Field(default=False)
    notify_on_failure: bool = Field(default=True)
    notification_channels: List[str] = Field(default_factory=list)

    class Settings:
        collection = "remediation_schedules"
        indexes = [
            "schedule_id",
            "status",
            "schedule_type",
            "next_execution_at",
            "maintenance_window_id",
            "created_by",
        ]


class ScheduleExecution(Document):
    """Record of schedule execution"""

    execution_id: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True)
    schedule_id: str = Field(..., description="Associated schedule ID")

    # Execution details
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None

    # Results
    bulk_job_id: Optional[str] = None
    execution_status: str = Field(..., description="pending, running, success, failed, cancelled")
    error_message: Optional[str] = None

    # Context
    triggered_by: str = Field(default="scheduler", description="scheduler, manual, api")
    execution_context: Dict[str, Any] = Field(default_factory=dict)

    class Settings:
        collection = "schedule_executions"
        indexes = ["execution_id", "schedule_id", "started_at", "execution_status"]


# ============================================================================
# SCHEDULER SERVICE
# ============================================================================


class RemediationSchedulerService:
    """
    Service for scheduling and executing remediation jobs

    Provides comprehensive scheduling capabilities including:
    - One-time and recurring schedules
    - Maintenance window management
    - Approval workflows
    - Retry logic and failure handling
    - Notification integration
    """

    def __init__(self):
        self.bulk_remediation_service = BulkRemediationService()
        self.maintenance_windows: Dict[str, MaintenanceWindow] = {}
        self.scheduler_task: Optional[asyncio.Task] = None
        self.running = False

    async def start_scheduler(self):
        """Start the background scheduler task"""
        if self.running:
            logger.warning("Scheduler is already running")
            return

        self.running = True
        self.scheduler_task = asyncio.create_task(self._scheduler_loop())
        logger.info("Remediation scheduler started")

    async def stop_scheduler(self):
        """Stop the background scheduler task"""
        if not self.running:
            return

        self.running = False
        if self.scheduler_task:
            self.scheduler_task.cancel()
            try:
                await self.scheduler_task
            except asyncio.CancelledError:
                pass

        logger.info("Remediation scheduler stopped")

    async def create_schedule(self, schedule: RemediationSchedule) -> RemediationSchedule:
        """Create a new remediation schedule"""
        try:
            # Calculate next execution time
            if schedule.schedule_type == ScheduleType.ONE_TIME:
                schedule.next_execution_at = schedule.scheduled_at
            elif schedule.schedule_type == ScheduleType.RECURRING:
                schedule.next_execution_at = self._calculate_next_cron_execution(
                    schedule.cron_expression, schedule.timezone
                )
            elif schedule.schedule_type == ScheduleType.MAINTENANCE_WINDOW:
                window = self.maintenance_windows.get(schedule.maintenance_window_id)
                if window:
                    schedule.next_execution_at = window.get_next_window_start()

            # Set approval deadline if required
            if schedule.requires_approval and schedule.next_execution_at:
                window = self.maintenance_windows.get(schedule.maintenance_window_id)
                approval_hours = window.approval_window_hours if window else 24
                schedule.approval_required_by = schedule.next_execution_at - timedelta(hours=approval_hours)

            # Save schedule
            await schedule.save()

            logger.info(f"Created remediation schedule: {schedule.schedule_id} ({schedule.name})")
            return schedule

        except Exception as e:
            logger.error(f"Failed to create schedule: {e}")
            raise

    async def get_schedule(self, schedule_id: str) -> Optional[RemediationSchedule]:
        """Get a remediation schedule by ID"""
        return await RemediationSchedule.find_one(RemediationSchedule.schedule_id == schedule_id)

    async def list_schedules(
        self,
        status: Optional[ScheduleStatus] = None,
        schedule_type: Optional[ScheduleType] = None,
        created_by: Optional[str] = None,
        limit: int = 50,
    ) -> List[RemediationSchedule]:
        """List remediation schedules with filtering"""
        query = {}

        if status:
            query["status"] = status
        if schedule_type:
            query["schedule_type"] = schedule_type
        if created_by:
            query["created_by"] = created_by

        return await RemediationSchedule.find(query).limit(limit).to_list()

    async def update_schedule(self, schedule_id: str, updates: Dict[str, Any]) -> Optional[RemediationSchedule]:
        """Update a remediation schedule"""
        schedule = await self.get_schedule(schedule_id)
        if not schedule:
            return None

        # Update fields
        for field, value in updates.items():
            if hasattr(schedule, field):
                setattr(schedule, field, value)

        schedule.updated_at = datetime.utcnow()

        # Recalculate next execution if timing changed
        if any(field in updates for field in ["scheduled_at", "cron_expression", "maintenance_window_id"]):
            if schedule.schedule_type == ScheduleType.ONE_TIME:
                schedule.next_execution_at = schedule.scheduled_at
            elif schedule.schedule_type == ScheduleType.RECURRING:
                schedule.next_execution_at = self._calculate_next_cron_execution(
                    schedule.cron_expression, schedule.timezone
                )
            elif schedule.schedule_type == ScheduleType.MAINTENANCE_WINDOW:
                window = self.maintenance_windows.get(schedule.maintenance_window_id)
                if window:
                    schedule.next_execution_at = window.get_next_window_start()

        await schedule.save()
        return schedule

    async def delete_schedule(self, schedule_id: str) -> bool:
        """Delete a remediation schedule"""
        schedule = await self.get_schedule(schedule_id)
        if not schedule:
            return False

        await schedule.delete()
        logger.info(f"Deleted remediation schedule: {schedule_id}")
        return True

    async def approve_schedule(self, schedule_id: str, approver: str, notes: str = None) -> bool:
        """Approve a schedule for execution"""
        schedule = await self.get_schedule(schedule_id)
        if not schedule:
            return False

        if not schedule.requires_approval:
            return True  # No approval needed

        if schedule.approved_at:
            return True  # Already approved

        # Check if approval deadline has passed
        if schedule.approval_required_by and datetime.utcnow() > schedule.approval_required_by:
            logger.warning(f"Approval deadline passed for schedule {schedule_id}")
            return False

        schedule.approved_by = approver
        schedule.approved_at = datetime.utcnow()
        schedule.approval_notes = notes
        await schedule.save()

        logger.info(f"Schedule {schedule_id} approved by {approver}")
        return True

    async def execute_schedule_now(self, schedule_id: str, triggered_by: str = "manual") -> Optional[str]:
        """Execute a schedule immediately"""
        schedule = await self.get_schedule(schedule_id)
        if not schedule:
            return None

        return await self._execute_schedule(schedule, triggered_by)

    async def add_maintenance_window(self, window: MaintenanceWindow) -> MaintenanceWindow:
        """Add a maintenance window"""
        self.maintenance_windows[window.window_id] = window
        logger.info(f"Added maintenance window: {window.window_id} ({window.name})")
        return window

    async def get_maintenance_window(self, window_id: str) -> Optional[MaintenanceWindow]:
        """Get a maintenance window by ID"""
        return self.maintenance_windows.get(window_id)

    async def list_maintenance_windows(self) -> List[MaintenanceWindow]:
        """List all maintenance windows"""
        return list(self.maintenance_windows.values())

    async def get_schedule_executions(self, schedule_id: str, limit: int = 20) -> List[ScheduleExecution]:
        """Get execution history for a schedule"""
        return (
            await ScheduleExecution.find(ScheduleExecution.schedule_id == schedule_id)
            .sort(-ScheduleExecution.started_at)
            .limit(limit)
            .to_list()
        )

    async def get_upcoming_schedules(self, hours_ahead: int = 24) -> List[RemediationSchedule]:
        """Get schedules that will execute in the next N hours"""
        cutoff = datetime.utcnow() + timedelta(hours=hours_ahead)

        return (
            await RemediationSchedule.find(
                {
                    "status": ScheduleStatus.ACTIVE,
                    "next_execution_at": {"$lte": cutoff, "$gte": datetime.utcnow()},
                }
            )
            .sort(RemediationSchedule.next_execution_at)
            .to_list()
        )

    async def _scheduler_loop(self):
        """Main scheduler loop - runs in background"""
        while self.running:
            try:
                await self._process_pending_schedules()
                await asyncio.sleep(60)  # Check every minute
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in scheduler loop: {e}")
                await asyncio.sleep(60)

    async def _process_pending_schedules(self):
        """Process schedules that are due for execution"""
        now = datetime.utcnow()

        # Find schedules due for execution
        due_schedules = await RemediationSchedule.find(
            {"status": ScheduleStatus.ACTIVE, "next_execution_at": {"$lte": now}}
        ).to_list()

        for schedule in due_schedules:
            try:
                # Check if approval is required and not given
                if schedule.requires_approval:
                    if not schedule.approved_at:
                        # Check if approval deadline passed
                        if schedule.approval_required_by and now > schedule.approval_required_by:
                            logger.warning(
                                f"Schedule {schedule.schedule_id} missed approval deadline, skipping execution"
                            )
                            await self._advance_schedule(schedule)
                            continue
                        else:
                            logger.info(f"Schedule {schedule.schedule_id} waiting for approval")
                            continue

                # Execute the schedule
                await self._execute_schedule(schedule, "scheduler")

                # Advance to next execution time
                await self._advance_schedule(schedule)

            except Exception as e:
                logger.error(f"Error processing schedule {schedule.schedule_id}: {e}")
                schedule.failure_count += 1

                # Disable schedule after too many failures
                if schedule.failure_count >= schedule.max_retries:
                    schedule.status = ScheduleStatus.FAILED
                    logger.error(f"Schedule {schedule.schedule_id} disabled after {schedule.failure_count} failures")

                await schedule.save()

    async def _execute_schedule(self, schedule: RemediationSchedule, triggered_by: str) -> str:
        """Execute a specific schedule"""
        execution = ScheduleExecution(
            schedule_id=schedule.schedule_id,
            triggered_by=triggered_by,
            execution_status="pending",
        )
        await execution.save()

        try:
            # Update execution status
            execution.execution_status = "running"
            await execution.save()

            # Submit bulk remediation job
            bulk_job_result = await self.bulk_remediation_service.submit_bulk_remediation(schedule.remediation_request)

            execution.bulk_job_id = bulk_job_result.job_id
            execution.execution_status = "success"
            execution.completed_at = datetime.utcnow()
            execution.duration_seconds = (execution.completed_at - execution.started_at).total_seconds()

            # Update schedule tracking
            schedule.last_execution_at = execution.started_at
            schedule.last_execution_job_id = bulk_job_result.job_id
            schedule.last_execution_status = "success"
            schedule.execution_count += 1

            logger.info(f"Schedule {schedule.schedule_id} executed successfully, job ID: {bulk_job_result.job_id}")

        except Exception as e:
            execution.execution_status = "failed"
            execution.error_message = str(e)
            execution.completed_at = datetime.utcnow()
            execution.duration_seconds = (execution.completed_at - execution.started_at).total_seconds()

            schedule.last_execution_at = execution.started_at
            schedule.last_execution_status = "failed"
            schedule.failure_count += 1

            logger.error(f"Schedule {schedule.schedule_id} execution failed: {e}")
            raise

        finally:
            await execution.save()
            await schedule.save()

        return execution.bulk_job_id

    async def _advance_schedule(self, schedule: RemediationSchedule):
        """Calculate and set the next execution time for a schedule"""
        if schedule.schedule_type == ScheduleType.ONE_TIME:
            # One-time schedules are completed after execution
            schedule.status = ScheduleStatus.COMPLETED
            schedule.next_execution_at = None

        elif schedule.schedule_type == ScheduleType.RECURRING:
            # Calculate next cron execution
            schedule.next_execution_at = self._calculate_next_cron_execution(
                schedule.cron_expression, schedule.timezone
            )

            # Reset approval status for next execution
            if schedule.requires_approval:
                schedule.approved_at = None
                schedule.approved_by = None
                schedule.approval_notes = None

        elif schedule.schedule_type == ScheduleType.MAINTENANCE_WINDOW:
            # Calculate next maintenance window
            window = self.maintenance_windows.get(schedule.maintenance_window_id)
            if window:
                schedule.next_execution_at = window.get_next_window_start()

                # Reset approval status for next execution
                if schedule.requires_approval:
                    schedule.approved_at = None
                    schedule.approved_by = None
                    schedule.approval_notes = None

                    # Set new approval deadline
                    if schedule.next_execution_at:
                        schedule.approval_required_by = schedule.next_execution_at - timedelta(
                            hours=window.approval_window_hours
                        )

        await schedule.save()

    def _calculate_next_cron_execution(self, cron_expression: str, timezone: str) -> Optional[datetime]:
        """Calculate next execution time from cron expression"""
        try:
            tz = ZoneInfo(timezone)
            now_tz = datetime.utcnow().replace(tzinfo=ZoneInfo("UTC")).astimezone(tz)

            cron = croniter.croniter(cron_expression, now_tz)
            next_time_tz = cron.get_next(datetime)

            # Convert back to UTC
            return next_time_tz.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)

        except Exception as e:
            logger.error(f"Error calculating next cron execution: {e}")
            return None


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def create_weekly_maintenance_window(
    name: str,
    day_of_week: int,
    start_hour: int,
    start_minute: int = 0,
    duration_hours: int = 2,
    timezone: str = "UTC",
) -> MaintenanceWindow:
    """Create a weekly maintenance window"""
    return MaintenanceWindow(
        name=name,
        window_type=MaintenanceWindowType.WEEKLY,
        start_time=dt_time(start_hour, start_minute),
        duration_minutes=duration_hours * 60,
        timezone=timezone,
        day_of_week=day_of_week,
    )


def create_monthly_maintenance_window(
    name: str,
    day_of_month: int,
    start_hour: int,
    start_minute: int = 0,
    duration_hours: int = 4,
    timezone: str = "UTC",
) -> MaintenanceWindow:
    """Create a monthly maintenance window"""
    return MaintenanceWindow(
        name=name,
        window_type=MaintenanceWindowType.MONTHLY,
        start_time=dt_time(start_hour, start_minute),
        duration_minutes=duration_hours * 60,
        timezone=timezone,
        day_of_month=day_of_month,
    )
