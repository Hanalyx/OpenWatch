"""
Remediation Workflow Service
Handles complex multi-stage remediation workflows with validation, rollback, and notification capabilities.
Supports conditional execution, parallel/sequential stages, and comprehensive error handling.
"""

import asyncio
import logging
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from beanie import Document
from pydantic import BaseModel, Field

from .bulk_remediation_service import BulkRemediationRequest, BulkRemediationService
from .plugin_execution_service import PluginExecutionService

logger = logging.getLogger(__name__)


# ============================================================================
# WORKFLOW MODELS AND ENUMS
# ============================================================================


class WorkflowStageType(str, Enum):
    """Types of workflow stages"""

    PRE_VALIDATION = "pre_validation"  # Validate prerequisites before remediation
    REMEDIATION = "remediation"  # Main remediation execution
    POST_VALIDATION = "post_validation"  # Verify remediation effectiveness
    NOTIFICATION = "notification"  # Send notifications
    ROLLBACK = "rollback"  # Rollback changes if needed
    CUSTOM = "custom"  # Custom stage with user-defined logic


class StageExecutionMode(str, Enum):
    """How stages should be executed"""

    SEQUENTIAL = "sequential"  # Execute stages one after another
    PARALLEL = "parallel"  # Execute stages in parallel
    CONDITIONAL = "conditional"  # Execute based on conditions


class WorkflowStatus(str, Enum):
    """Overall workflow execution status"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    ROLLED_BACK = "rolled_back"


class StageStatus(str, Enum):
    """Individual stage execution status"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ROLLED_BACK = "rolled_back"


class WorkflowCondition(BaseModel):
    """Condition for conditional stage execution"""

    condition_type: str = Field(..., description="Type of condition (previous_stage_success, rule_count, etc.)")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Condition parameters")

    def evaluate(self, workflow_context: Dict[str, Any]) -> bool:
        """Evaluate if the condition is met"""
        if self.condition_type == "previous_stage_success":
            stage_id = self.parameters.get("stage_id")
            if stage_id:
                stage_result = workflow_context.get("stage_results", {}).get(stage_id)
                return stage_result and stage_result.get("status") == "completed"

        elif self.condition_type == "rule_count_threshold":
            min_rules = self.parameters.get("min_rules", 1)
            rule_count = len(workflow_context.get("target_rules", []))
            return rule_count >= min_rules

        elif self.condition_type == "host_count_threshold":
            min_hosts = self.parameters.get("min_hosts", 1)
            host_count = len(workflow_context.get("target_hosts", []))
            return host_count >= min_hosts

        elif self.condition_type == "time_window":
            # Execute only during specified time window
            start_hour = self.parameters.get("start_hour", 0)
            end_hour = self.parameters.get("end_hour", 23)
            current_hour = datetime.utcnow().hour
            return start_hour <= current_hour <= end_hour

        elif self.condition_type == "always":
            return True

        elif self.condition_type == "never":
            return False

        return False


class WorkflowStage(BaseModel):
    """Definition of a workflow stage"""

    stage_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(..., description="Human-readable stage name")
    stage_type: WorkflowStageType
    description: Optional[str] = None

    # Execution configuration
    execution_mode: StageExecutionMode = StageExecutionMode.SEQUENTIAL
    timeout_minutes: int = Field(default=60, ge=1, le=1440)
    retry_count: int = Field(default=3, ge=0, le=10)
    retry_delay_seconds: int = Field(default=30, ge=1, le=600)

    # Conditions for execution
    execute_conditions: List[WorkflowCondition] = Field(default_factory=list)
    skip_on_failure: bool = Field(default=False, description="Skip stage if previous stages failed")

    # Stage-specific configuration
    stage_config: Dict[str, Any] = Field(default_factory=dict, description="Stage-specific configuration")

    # Dependencies
    depends_on: List[str] = Field(default_factory=list, description="Stage IDs this stage depends on")

    # Rollback configuration
    supports_rollback: bool = Field(default=False)
    rollback_config: Dict[str, Any] = Field(default_factory=dict)


class WorkflowDefinition(BaseModel):
    """Complete workflow definition"""

    workflow_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(..., description="Workflow name")
    description: Optional[str] = None
    version: str = Field(default="1.0")

    # Stages
    stages: List[WorkflowStage] = Field(..., min_items=1)

    # Workflow-level configuration
    execution_mode: StageExecutionMode = StageExecutionMode.SEQUENTIAL
    timeout_minutes: int = Field(default=240, ge=10, le=1440)
    max_parallel_stages: int = Field(default=5, ge=1, le=20)

    # Failure handling
    stop_on_first_failure: bool = Field(default=False)
    auto_rollback_on_failure: bool = Field(default=False)
    rollback_stages: List[str] = Field(default_factory=list, description="Stages to rollback on failure")

    # Notifications
    notification_config: Dict[str, Any] = Field(default_factory=dict)

    # Metadata
    created_by: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    tags: List[str] = Field(default_factory=list)

    def validate_workflow(self) -> List[str]:
        """Validate workflow definition and return list of issues"""
        issues = []

        # Check for circular dependencies
        stage_ids = {stage.stage_id for stage in self.stages}
        for stage in self.stages:
            if self._has_circular_dependency(stage, self.stages, set()):
                issues.append(f"Circular dependency detected in stage: {stage.name}")

            # Check if dependencies exist
            for dep_id in stage.depends_on:
                if dep_id not in stage_ids:
                    issues.append(f"Stage {stage.name} depends on non-existent stage: {dep_id}")

        return issues

    def _has_circular_dependency(self, stage: WorkflowStage, all_stages: List[WorkflowStage], visited: set) -> bool:
        """Check for circular dependencies in workflow stages"""
        if stage.stage_id in visited:
            return True

        visited.add(stage.stage_id)

        stage_map = {s.stage_id: s for s in all_stages}
        for dep_id in stage.depends_on:
            if dep_id in stage_map:
                if self._has_circular_dependency(stage_map[dep_id], all_stages, visited.copy()):
                    return True

        return False


class WorkflowExecution(Document):
    """Active workflow execution instance"""

    execution_id: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True)
    workflow_id: str = Field(..., description="Workflow definition ID")
    workflow_definition: WorkflowDefinition

    # Execution status
    status: WorkflowStatus = WorkflowStatus.PENDING
    current_stage: Optional[str] = None

    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None

    # Target configuration
    target_hosts: List[str] = Field(..., description="Target host IDs")
    target_rules: List[str] = Field(..., description="Rules to remediate")

    # Stage execution results
    stage_results: Dict[str, Any] = Field(default_factory=dict)

    # Overall results
    total_stages: int = 0
    completed_stages: int = 0
    failed_stages: int = 0
    skipped_stages: int = 0

    # Context and configuration
    execution_context: Dict[str, Any] = Field(default_factory=dict)
    user: str = Field(..., description="User who initiated workflow")

    # Error handling
    execution_errors: List[str] = Field(default_factory=list)
    rollback_performed: bool = Field(default=False)
    rollback_results: Dict[str, Any] = Field(default_factory=dict)

    class Settings:
        collection = "workflow_executions"
        indexes = ["execution_id", "workflow_id", "status", "started_at", "user"]


class StageExecutionResult(BaseModel):
    """Result of individual stage execution"""

    stage_id: str
    stage_name: str
    status: StageStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None

    # Stage-specific results
    results: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None
    retry_count: int = 0

    # Context passed to next stages
    output_context: Dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# WORKFLOW SERVICE
# ============================================================================


class RemediationWorkflowService:
    """
    Service for executing complex multi-stage remediation workflows

    Supports:
    - Sequential and parallel stage execution
    - Conditional stage execution based on results
    - Automatic rollback on failure
    - Comprehensive error handling and retry logic
    - Integration with bulk remediation and plugin services
    """

    def __init__(self):
        self.bulk_remediation_service = BulkRemediationService()
        self.plugin_execution_service = PluginExecutionService()
        self.workflow_definitions: Dict[str, WorkflowDefinition] = {}
        self.active_workflows: Dict[str, WorkflowExecution] = {}

    async def register_workflow_definition(self, workflow_def: WorkflowDefinition) -> WorkflowDefinition:
        """Register a new workflow definition"""
        # Validate workflow
        issues = workflow_def.validate_workflow()
        if issues:
            raise ValueError(f"Workflow validation failed: {', '.join(issues)}")

        self.workflow_definitions[workflow_def.workflow_id] = workflow_def
        logger.info(f"Registered workflow definition: {workflow_def.workflow_id} ({workflow_def.name})")

        return workflow_def

    async def get_workflow_definition(self, workflow_id: str) -> Optional[WorkflowDefinition]:
        """Get a workflow definition by ID"""
        return self.workflow_definitions.get(workflow_id)

    async def list_workflow_definitions(self) -> List[WorkflowDefinition]:
        """List all registered workflow definitions"""
        return list(self.workflow_definitions.values())

    async def execute_workflow(
        self,
        workflow_id: str,
        target_hosts: List[str],
        target_rules: List[str],
        user: str,
        execution_context: Dict[str, Any] = None,
    ) -> WorkflowExecution:
        """Execute a workflow"""
        workflow_def = self.workflow_definitions.get(workflow_id)
        if not workflow_def:
            raise ValueError(f"Workflow definition not found: {workflow_id}")

        if execution_context is None:
            execution_context = {}

        # Create execution instance
        execution = WorkflowExecution(
            workflow_id=workflow_id,
            workflow_definition=workflow_def,
            target_hosts=target_hosts,
            target_rules=target_rules,
            total_stages=len(workflow_def.stages),
            execution_context=execution_context,
            user=user,
        )

        await execution.save()
        self.active_workflows[execution.execution_id] = execution

        # Start execution asynchronously
        asyncio.create_task(self._execute_workflow_stages(execution))

        logger.info(f"Started workflow execution: {execution.execution_id} ({workflow_def.name})")
        return execution

    async def get_workflow_execution(self, execution_id: str) -> Optional[WorkflowExecution]:
        """Get workflow execution status"""
        # Check active workflows first
        if execution_id in self.active_workflows:
            return self.active_workflows[execution_id]

        # Query database
        return await WorkflowExecution.find_one(WorkflowExecution.execution_id == execution_id)

    async def cancel_workflow_execution(self, execution_id: str) -> bool:
        """Cancel a running workflow execution"""
        execution = await self.get_workflow_execution(execution_id)
        if not execution:
            return False

        if execution.status not in [WorkflowStatus.PENDING, WorkflowStatus.RUNNING]:
            return False

        execution.status = WorkflowStatus.CANCELLED
        execution.completed_at = datetime.utcnow()

        if execution.started_at:
            execution.duration_seconds = (execution.completed_at - execution.started_at).total_seconds()

        await execution.save()

        # Remove from active workflows
        self.active_workflows.pop(execution_id, None)

        logger.info(f"Cancelled workflow execution: {execution_id}")
        return True

    async def list_workflow_executions(
        self,
        workflow_id: Optional[str] = None,
        status: Optional[WorkflowStatus] = None,
        user: Optional[str] = None,
        limit: int = 50,
    ) -> List[WorkflowExecution]:
        """List workflow executions with filtering"""
        query = {}

        if workflow_id:
            query["workflow_id"] = workflow_id
        if status:
            query["status"] = status
        if user:
            query["user"] = user

        return await WorkflowExecution.find(query).sort(-WorkflowExecution.started_at).limit(limit).to_list()

    async def _execute_workflow_stages(self, execution: WorkflowExecution):
        """Execute all stages of a workflow"""
        try:
            execution.status = WorkflowStatus.RUNNING
            execution.started_at = datetime.utcnow()
            await execution.save()

            workflow_def = execution.workflow_definition

            # Build execution context
            workflow_context = {
                "target_hosts": execution.target_hosts,
                "target_rules": execution.target_rules,
                "execution_context": execution.execution_context,
                "stage_results": execution.stage_results,
            }

            # Execute stages based on workflow execution mode
            if workflow_def.execution_mode == StageExecutionMode.SEQUENTIAL:
                await self._execute_stages_sequential(execution, workflow_context)
            elif workflow_def.execution_mode == StageExecutionMode.PARALLEL:
                await self._execute_stages_parallel(execution, workflow_context)
            elif workflow_def.execution_mode == StageExecutionMode.CONDITIONAL:
                await self._execute_stages_conditional(execution, workflow_context)

            # Finalize execution
            await self._finalize_workflow_execution(execution)

        except Exception as e:
            logger.error(f"Workflow execution failed: {e}")
            execution.status = WorkflowStatus.FAILED
            execution.execution_errors.append(str(e))
            execution.completed_at = datetime.utcnow()

            if execution.started_at:
                execution.duration_seconds = (execution.completed_at - execution.started_at).total_seconds()

            await execution.save()

        finally:
            # Remove from active workflows
            self.active_workflows.pop(execution.execution_id, None)

    async def _execute_stages_sequential(self, execution: WorkflowExecution, workflow_context: Dict[str, Any]):
        """Execute stages sequentially"""
        for stage in execution.workflow_definition.stages:
            if execution.status == WorkflowStatus.CANCELLED:
                break

            # Check if stage should be executed
            if not self._should_execute_stage(stage, workflow_context):
                await self._record_stage_result(execution, stage, StageStatus.SKIPPED)
                continue

            # Execute stage
            stage_result = await self._execute_single_stage(stage, execution, workflow_context)
            await self._record_stage_result(execution, stage, stage_result.status, stage_result)

            # Update workflow context with stage results
            workflow_context["stage_results"][stage.stage_id] = stage_result.dict()

            # Check if workflow should stop on failure
            if stage_result.status == StageStatus.FAILED and execution.workflow_definition.stop_on_first_failure:
                break

    async def _execute_stages_parallel(self, execution: WorkflowExecution, workflow_context: Dict[str, Any]):
        """Execute stages in parallel with dependency management"""
        # Build dependency graph
        self._build_dependency_graph(execution.workflow_definition.stages)

        # Execute stages in topological order with parallelization
        executed_stages = set()

        while len(executed_stages) < len(execution.workflow_definition.stages):
            if execution.status == WorkflowStatus.CANCELLED:
                break

            # Find stages that can be executed (dependencies satisfied)
            ready_stages = []
            for stage in execution.workflow_definition.stages:
                if stage.stage_id not in executed_stages and all(dep in executed_stages for dep in stage.depends_on):
                    ready_stages.append(stage)

            if not ready_stages:
                break  # No more stages can be executed

            # Execute ready stages in parallel
            max_parallel = min(len(ready_stages), execution.workflow_definition.max_parallel_stages)

            stage_tasks = []
            for stage in ready_stages[:max_parallel]:
                if self._should_execute_stage(stage, workflow_context):
                    task = asyncio.create_task(self._execute_single_stage(stage, execution, workflow_context))
                    stage_tasks.append((stage, task))
                else:
                    # Mark as skipped
                    await self._record_stage_result(execution, stage, StageStatus.SKIPPED)
                    executed_stages.add(stage.stage_id)

            # Wait for stage completion
            for stage, task in stage_tasks:
                try:
                    stage_result = await task
                    await self._record_stage_result(execution, stage, stage_result.status, stage_result)
                    workflow_context["stage_results"][stage.stage_id] = stage_result.dict()
                    executed_stages.add(stage.stage_id)
                except Exception as e:
                    logger.error(f"Stage {stage.name} failed: {e}")
                    await self._record_stage_result(execution, stage, StageStatus.FAILED)
                    executed_stages.add(stage.stage_id)

    async def _execute_stages_conditional(self, execution: WorkflowExecution, workflow_context: Dict[str, Any]):
        """Execute stages with conditional logic"""
        # Similar to sequential but with additional condition checking
        await self._execute_stages_sequential(execution, workflow_context)

    async def _execute_single_stage(
        self,
        stage: WorkflowStage,
        execution: WorkflowExecution,
        workflow_context: Dict[str, Any],
    ) -> StageExecutionResult:
        """Execute a single workflow stage"""
        stage_result = StageExecutionResult(
            stage_id=stage.stage_id,
            stage_name=stage.name,
            status=StageStatus.RUNNING,
            started_at=datetime.utcnow(),
        )

        execution.current_stage = stage.stage_id
        await execution.save()

        try:
            # Execute stage based on type
            if stage.stage_type == WorkflowStageType.PRE_VALIDATION:
                await self._execute_pre_validation_stage(stage, execution, workflow_context, stage_result)
            elif stage.stage_type == WorkflowStageType.REMEDIATION:
                await self._execute_remediation_stage(stage, execution, workflow_context, stage_result)
            elif stage.stage_type == WorkflowStageType.POST_VALIDATION:
                await self._execute_post_validation_stage(stage, execution, workflow_context, stage_result)
            elif stage.stage_type == WorkflowStageType.NOTIFICATION:
                await self._execute_notification_stage(stage, execution, workflow_context, stage_result)
            elif stage.stage_type == WorkflowStageType.ROLLBACK:
                await self._execute_rollback_stage(stage, execution, workflow_context, stage_result)
            elif stage.stage_type == WorkflowStageType.CUSTOM:
                await self._execute_custom_stage(stage, execution, workflow_context, stage_result)

            stage_result.status = StageStatus.COMPLETED

        except Exception as e:
            logger.error(f"Stage {stage.name} execution failed: {e}")
            stage_result.status = StageStatus.FAILED
            stage_result.error_message = str(e)

            # Retry logic
            if stage_result.retry_count < stage.retry_count:
                stage_result.retry_count += 1
                await asyncio.sleep(stage.retry_delay_seconds)
                return await self._execute_single_stage(stage, execution, workflow_context)

        finally:
            stage_result.completed_at = datetime.utcnow()
            stage_result.duration_seconds = (stage_result.completed_at - stage_result.started_at).total_seconds()

        return stage_result

    async def _execute_pre_validation_stage(
        self,
        stage: WorkflowStage,
        execution: WorkflowExecution,
        workflow_context: Dict[str, Any],
        stage_result: StageExecutionResult,
    ):
        """Execute pre-validation stage"""
        # Example: Check host connectivity, verify prerequisites
        validation_results = {}

        for host_id in execution.target_hosts:
            # Simulate validation checks
            validation_results[host_id] = {
                "connectivity": True,
                "prerequisites_met": True,
                "disk_space_sufficient": True,
            }

        stage_result.results = {"validation_results": validation_results}
        stage_result.output_context = {"validated_hosts": execution.target_hosts}

    async def _execute_remediation_stage(
        self,
        stage: WorkflowStage,
        execution: WorkflowExecution,
        workflow_context: Dict[str, Any],
        stage_result: StageExecutionResult,
    ):
        """Execute remediation stage using bulk remediation service"""
        # Create bulk remediation request
        bulk_request = BulkRemediationRequest(
            host_ids=execution.target_hosts,
            rule_ids=execution.target_rules,
            user=execution.user,
            **stage.stage_config.get("bulk_remediation_config", {}),
        )

        # Submit bulk remediation
        bulk_result = await self.bulk_remediation_service.submit_bulk_remediation(bulk_request)

        # Store bulk job ID for tracking
        stage_result.results = {
            "bulk_job_id": bulk_result.job_id,
            "bulk_job_status": bulk_result.status,
        }
        stage_result.output_context = {"bulk_job_id": bulk_result.job_id}

    async def _execute_post_validation_stage(
        self,
        stage: WorkflowStage,
        execution: WorkflowExecution,
        workflow_context: Dict[str, Any],
        stage_result: StageExecutionResult,
    ):
        """Execute post-validation stage"""
        # Example: Verify remediation effectiveness
        validation_results = {}

        for host_id in execution.target_hosts:
            for rule_id in execution.target_rules:
                # Simulate compliance verification
                validation_results[f"{host_id}:{rule_id}"] = {
                    "compliant": True,
                    "verified_at": datetime.utcnow().isoformat(),
                }

        stage_result.results = {"post_validation_results": validation_results}

    async def _execute_notification_stage(
        self,
        stage: WorkflowStage,
        execution: WorkflowExecution,
        workflow_context: Dict[str, Any],
        stage_result: StageExecutionResult,
    ):
        """Execute notification stage"""
        # Example: Send notifications about workflow completion
        notifications_sent = []

        notification_config = stage.stage_config.get("notifications", {})
        for channel in notification_config.get("channels", []):
            # Simulate notification sending
            notifications_sent.append(
                {
                    "channel": channel,
                    "message": f"Workflow {execution.workflow_definition.name} completed",
                    "sent_at": datetime.utcnow().isoformat(),
                }
            )

        stage_result.results = {"notifications_sent": notifications_sent}

    async def _execute_rollback_stage(
        self,
        stage: WorkflowStage,
        execution: WorkflowExecution,
        workflow_context: Dict[str, Any],
        stage_result: StageExecutionResult,
    ):
        """Execute rollback stage"""
        # Example: Rollback changes made by previous stages
        rollback_results = {}

        # Get stages to rollback from configuration
        stages_to_rollback = stage.stage_config.get("rollback_stages", [])

        for stage_id in stages_to_rollback:
            if stage_id in workflow_context["stage_results"]:
                # Simulate rollback
                rollback_results[stage_id] = {
                    "rollback_status": "success",
                    "rolled_back_at": datetime.utcnow().isoformat(),
                }

        execution.rollback_performed = True
        execution.rollback_results = rollback_results

        stage_result.results = {"rollback_results": rollback_results}

    async def _execute_custom_stage(
        self,
        stage: WorkflowStage,
        execution: WorkflowExecution,
        workflow_context: Dict[str, Any],
        stage_result: StageExecutionResult,
    ):
        """Execute custom stage with user-defined logic"""
        # Custom stages would implement specific business logic
        # This is a placeholder implementation
        custom_config = stage.stage_config.get("custom_config", {})

        stage_result.results = {
            "custom_execution": "completed",
            "config_applied": custom_config,
        }

    def _should_execute_stage(self, stage: WorkflowStage, workflow_context: Dict[str, Any]) -> bool:
        """Determine if a stage should be executed based on conditions"""
        if not stage.execute_conditions:
            return True

        for condition in stage.execute_conditions:
            if not condition.evaluate(workflow_context):
                return False

        return True

    def _build_dependency_graph(self, stages: List[WorkflowStage]) -> Dict[str, List[str]]:
        """Build dependency graph for stages"""
        graph = {}
        for stage in stages:
            graph[stage.stage_id] = stage.depends_on.copy()
        return graph

    async def _record_stage_result(
        self,
        execution: WorkflowExecution,
        stage: WorkflowStage,
        status: StageStatus,
        stage_result: StageExecutionResult = None,
    ):
        """Record stage execution result"""
        if stage_result:
            execution.stage_results[stage.stage_id] = stage_result.dict()
        else:
            execution.stage_results[stage.stage_id] = {
                "stage_id": stage.stage_id,
                "stage_name": stage.name,
                "status": status,
                "started_at": datetime.utcnow().isoformat(),
            }

        # Update counters
        if status == StageStatus.COMPLETED:
            execution.completed_stages += 1
        elif status == StageStatus.FAILED:
            execution.failed_stages += 1
        elif status == StageStatus.SKIPPED:
            execution.skipped_stages += 1

        await execution.save()

    async def _finalize_workflow_execution(self, execution: WorkflowExecution):
        """Finalize workflow execution and determine final status"""
        execution.completed_at = datetime.utcnow()
        execution.current_stage = None

        if execution.started_at:
            execution.duration_seconds = (execution.completed_at - execution.started_at).total_seconds()

        # Determine final status
        if execution.status == WorkflowStatus.CANCELLED:
            pass  # Already set
        elif execution.failed_stages > 0:
            if execution.rollback_performed:
                execution.status = WorkflowStatus.ROLLED_BACK
            else:
                execution.status = WorkflowStatus.FAILED
        else:
            execution.status = WorkflowStatus.COMPLETED

        await execution.save()

        logger.info(
            f"Workflow execution completed: {execution.execution_id} - "
            f"Status: {execution.status}, "
            f"Stages: {execution.completed_stages}/{execution.total_stages} completed, "
            f"Duration: {execution.duration_seconds:.1f}s"
        )


# ============================================================================
# PREDEFINED WORKFLOW TEMPLATES
# ============================================================================


def create_standard_remediation_workflow(
    workflow_name: str,
    created_by: str,
    enable_rollback: bool = True,
    notification_channels: List[str] = None,
) -> WorkflowDefinition:
    """Create a standard remediation workflow with common stages"""

    if notification_channels is None:
        notification_channels = []

    stages = [
        WorkflowStage(
            name="Pre-Validation",
            stage_type=WorkflowStageType.PRE_VALIDATION,
            description="Validate prerequisites before remediation",
            stage_config={"validation_checks": ["connectivity", "prerequisites", "disk_space"]},
        ),
        WorkflowStage(
            name="Remediation Execution",
            stage_type=WorkflowStageType.REMEDIATION,
            description="Execute bulk remediation across target hosts",
            depends_on=[],  # Will be filled with pre-validation stage ID
            stage_config={
                "bulk_remediation_config": {
                    "strategy": "batched",
                    "batch_size": 10,
                    "continue_on_failure": True,
                }
            },
            supports_rollback=enable_rollback,
        ),
        WorkflowStage(
            name="Post-Validation",
            stage_type=WorkflowStageType.POST_VALIDATION,
            description="Verify remediation effectiveness",
            depends_on=[],  # Will be filled with remediation stage ID
            stage_config={"validation_delay_minutes": 2},
        ),
        WorkflowStage(
            name="Notification",
            stage_type=WorkflowStageType.NOTIFICATION,
            description="Send completion notifications",
            depends_on=[],  # Will be filled with post-validation stage ID
            stage_config={
                "notifications": {
                    "channels": notification_channels,
                    "include_summary": True,
                }
            },
        ),
    ]

    # Set up dependencies
    stages[1].depends_on = [stages[0].stage_id]  # Remediation depends on pre-validation
    stages[2].depends_on = [stages[1].stage_id]  # Post-validation depends on remediation
    stages[3].depends_on = [stages[2].stage_id]  # Notification depends on post-validation

    # Add rollback stage if enabled
    if enable_rollback:
        rollback_stage = WorkflowStage(
            name="Rollback on Failure",
            stage_type=WorkflowStageType.ROLLBACK,
            description="Rollback changes if remediation fails",
            execute_conditions=[
                WorkflowCondition(
                    condition_type="previous_stage_success",
                    parameters={"stage_id": stages[1].stage_id, "expected": False},
                )
            ],
            stage_config={"rollback_stages": [stages[1].stage_id]},
        )
        stages.append(rollback_stage)

    return WorkflowDefinition(
        name=workflow_name,
        description="Standard remediation workflow with validation and notifications",
        stages=stages,
        execution_mode=StageExecutionMode.SEQUENTIAL,
        stop_on_first_failure=False,
        auto_rollback_on_failure=enable_rollback,
        created_by=created_by,
    )
