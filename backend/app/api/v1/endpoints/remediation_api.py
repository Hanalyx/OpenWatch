"""
Remediation API endpoints for ORSA architecture.

Provides REST API for:
- Executing single remediations
- Bulk remediation (from scan results)
- Querying remediation status
- Rolling back remediations
- Statistics and reporting
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from ....auth import get_current_user
from ....models.remediation_models import (
    BulkRemediationJob,
    BulkRemediationRequest,
    RemediationRequest,
    RemediationResult,
    RemediationStatus,
    RemediationSummary,
)
from ....services.mongo_integration_service import get_mongo_service
from ....services.remediation_orchestrator_service import RemediationOrchestrator
from ....services.remediators import RemediationExecutorFactory
from ....services.remediators.base_executor import (
    ExecutorExecutionError,
    ExecutorNotAvailableError,
    ExecutorValidationError,
)

router = APIRouter()


@router.post("/execute", response_model=RemediationResult)
async def execute_remediation(
    request: RemediationRequest,
    mongo_service=Depends(get_mongo_service),
    current_user: dict = Depends(get_current_user),
):
    """
    Execute remediation for a single rule.

    Executes the remediation content associated with a compliance rule against
    the specified target system.

    **Parameters:**
    - `rule_id`: XCCDF rule ID to remediate
    - `target`: Target system (SSH host, Kubernetes cluster, etc.)
    - `variable_overrides`: Optional variable values to override defaults
    - `dry_run`: If true, preview changes without applying (default: false)
    - `scan_id`: Optional scan ID if remediating from scan results

    **Returns:**
    - RemediationResult with execution status and details

    **Example:**
    ```json
    {
      "rule_id": "xccdf_com.hanalyx.openwatch_rule_accounts_tmout",
      "target": {
        "type": "ssh_host",
        "identifier": "192.168.1.100",
        "credentials": {
          "username": "root",
          "ssh_key": "-----BEGIN OPENSSH PRIVATE KEY-----\\n..."
        }
      },
      "variable_overrides": {
        "var_accounts_tmout": "300"
      },
      "dry_run": false
    }
    ```
    """
    try:
        db = mongo_service.mongo_manager.database

        orchestrator = RemediationOrchestrator(db)

        result = await orchestrator.execute_remediation(
            rule_id=request.rule_id,
            target=request.target,
            variable_overrides=request.variable_overrides,
            dry_run=request.dry_run,
            executed_by=current_user.get("username"),
            scan_id=request.scan_id,
        )

        return result

    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ExecutorNotAvailableError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except ExecutorValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ExecutorExecutionError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Remediation failed: {e}")


@router.post("/execute-bulk", response_model=BulkRemediationJob)
async def execute_bulk_remediation(
    request: BulkRemediationRequest,
    mongo_service=Depends(get_mongo_service),
    current_user: dict = Depends(get_current_user),
):
    """
    Execute remediation for multiple rules.

    Remediates multiple rules in a single operation. Rules can be specified by:
    1. Scan ID (remediate all failed rules from a scan)
    2. Explicit rule IDs
    3. Filter criteria (e.g., all high-severity failed rules)

    **Parameters:**
    - `scan_id`: Source scan ID to remediate failed rules
    - `rule_ids`: Specific rule IDs to remediate
    - `rule_filter`: Filter criteria (e.g., `{"severity": ["high", "critical"]}`)
    - `target`: Target system
    - `variable_overrides`: Variable overrides applied to all rules
    - `dry_run`: Preview mode

    **Returns:**
    - BulkRemediationJob with overall job status

    **Example (remediate from scan):**
    ```json
    {
      "scan_id": "550e8400-e29b-41d4-a716-446655440000",
      "rule_filter": {
        "severity": ["high", "critical"]
      },
      "target": {
        "type": "ssh_host",
        "identifier": "prod-web-01.example.com",
        "credentials": {...}
      },
      "dry_run": true
    }
    ```

    **Example (explicit rules):**
    ```json
    {
      "rule_ids": [
        "xccdf_com.hanalyx.openwatch_rule_accounts_tmout",
        "xccdf_com.hanalyx.openwatch_rule_firewall_enabled"
      ],
      "target": {...}
    }
    ```
    """
    try:
        db = mongo_service.mongo_manager.database

        orchestrator = RemediationOrchestrator(db)

        job = await orchestrator.execute_bulk_remediation(
            target=request.target,
            scan_id=request.scan_id,
            rule_ids=request.rule_ids,
            rule_filter=request.rule_filter,
            variable_overrides=request.variable_overrides,
            dry_run=request.dry_run,
            executed_by=current_user.get("username"),
        )

        return job

    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Bulk remediation failed: {e}")


@router.get("/{remediation_id}", response_model=RemediationResult)
async def get_remediation(
    remediation_id: str,
    mongo_service=Depends(get_mongo_service),
    current_user: dict = Depends(get_current_user),
):
    """
    Get remediation result by ID.

    Returns complete remediation execution details including stdout/stderr,
    changes made, and rollback information.

    **Parameters:**
    - `remediation_id`: Remediation UUID

    **Returns:**
    - RemediationResult document
    """
    db = mongo_service.mongo_manager.database

    orchestrator = RemediationOrchestrator(db)
    result = await orchestrator.get_remediation_result(remediation_id)

    if not result:
        raise HTTPException(status_code=404, detail="Remediation not found")

    # Authorization: users can only see their own remediations unless admin
    if current_user.get("role") != "admin":
        if result.executed_by != current_user.get("username"):
            raise HTTPException(status_code=403, detail="Access denied")

    return result


@router.get("/", response_model=List[RemediationResult])
async def list_remediations(
    skip: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(50, ge=1, le=100, description="Max results"),
    status: Optional[RemediationStatus] = Query(None, description="Filter by status"),
    scan_id: Optional[str] = Query(None, description="Filter by scan ID"),
    mongo_service=Depends(get_mongo_service),
    current_user: dict = Depends(get_current_user),
):
    """
    List remediations with filters and pagination.

    **Query Parameters:**
    - `skip`: Pagination offset (default: 0)
    - `limit`: Max results (default: 50, max: 100)
    - `status`: Filter by status (pending, running, completed, failed, rolled_back)
    - `scan_id`: Filter by scan ID

    **Returns:**
    - List of RemediationResult documents

    **Example:**
    ```
    GET /api/remediation-engine/jobs?status=completed&limit=10
    ```
    """
    db = mongo_service.mongo_manager.database

    orchestrator = RemediationOrchestrator(db)

    # Non-admin users can only see their own remediations
    executed_by = None
    if current_user.get("role") != "admin":
        executed_by = current_user.get("username")

    results = await orchestrator.list_remediations(
        skip=skip, limit=limit, status=status, executed_by=executed_by, scan_id=scan_id
    )

    return results


@router.post("/{remediation_id}/rollback", response_model=RemediationResult)
async def rollback_remediation(
    remediation_id: str,
    mongo_service=Depends(get_mongo_service),
    current_user: dict = Depends(get_current_user),
):
    """
    Rollback a remediation.

    Executes the rollback content to undo changes made by the original remediation.
    Only available if rollback content was generated during execution.

    **Parameters:**
    - `remediation_id`: Remediation UUID to rollback

    **Returns:**
    - Updated RemediationResult with rollback execution details

    **Errors:**
    - 404: Remediation not found
    - 400: Rollback not available or already executed
    - 500: Rollback execution failed
    """
    try:
        db = mongo_service.mongo_manager.database

        orchestrator = RemediationOrchestrator(db)

        # Get original remediation for authorization check
        original = await orchestrator.get_remediation_result(remediation_id)
        if not original:
            raise HTTPException(status_code=404, detail="Remediation not found")

        # Authorization
        if current_user.get("role") != "admin":
            if original.executed_by != current_user.get("username"):
                raise HTTPException(status_code=403, detail="Access denied")

        # Execute rollback
        result = await orchestrator.rollback_remediation(
            remediation_id=remediation_id, executed_by=current_user.get("username")
        )

        return result

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ExecutorExecutionError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Rollback failed: {e}")


@router.delete("/{remediation_id}")
async def delete_remediation(
    remediation_id: str,
    mongo_service=Depends(get_mongo_service),
    current_user: dict = Depends(get_current_user),
):
    """
    Delete remediation result.

    Removes remediation execution record from database. Does not undo changes
    made by the remediation (use rollback endpoint for that).

    **Parameters:**
    - `remediation_id`: Remediation UUID

    **Returns:**
    - Success message

    **Authorization:**
    - Admins can delete any remediation
    - Users can only delete their own remediations
    """
    db = mongo_service.mongo_manager.database

    orchestrator = RemediationOrchestrator(db)

    # Get remediation for authorization check
    result = await orchestrator.get_remediation_result(remediation_id)
    if not result:
        raise HTTPException(status_code=404, detail="Remediation not found")

    # Authorization
    if current_user.get("role") != "admin":
        if result.executed_by != current_user.get("username"):
            raise HTTPException(status_code=403, detail="Access denied")

    # Delete
    await result.delete()

    return {"message": f"Remediation {remediation_id} deleted"}


@router.get("/statistics/summary", response_model=RemediationSummary)
async def get_remediation_statistics(
    days: int = Query(30, ge=1, le=365, description="Days to include"),
    mongo_service=Depends(get_mongo_service),
    current_user: dict = Depends(get_current_user),
):
    """
    Get remediation statistics.

    Returns aggregated statistics about remediation executions.

    **Query Parameters:**
    - `days`: Number of days to include (default: 30)

    **Returns:**
    - RemediationSummary with counts by status, executor, severity

    **Example Response:**
    ```json
    {
      "total": 150,
      "pending": 5,
      "running": 2,
      "completed": 120,
      "failed": 20,
      "rolled_back": 3,
      "success_rate": 80.0,
      "by_executor": {
        "ansible": 100,
        "bash": 50
      },
      "by_severity": {
        "high": 80,
        "medium": 50,
        "low": 20
      }
    }
    ```
    """
    db = mongo_service.mongo_manager.database

    orchestrator = RemediationOrchestrator(db)

    # Non-admin users see only their own stats
    executed_by = None
    if current_user.get("role") != "admin":
        executed_by = current_user.get("username")

    summary = await orchestrator.get_remediation_statistics(days=days, executed_by=executed_by)

    return summary


@router.get("/executors/available")
async def list_available_executors(current_user: dict = Depends(get_current_user)):
    """
    List available remediation executors.

    Returns metadata about available executor types (Ansible, Bash, etc.)
    including version, capabilities, and supported target types.

    **Returns:**
    - List of executor metadata

    **Example Response:**
    ```json
    [
      {
        "name": "ansible",
        "display_name": "Ansible",
        "description": "Ansible playbook executor",
        "capabilities": ["dry_run", "rollback", "idempotent", "variable_substitution", "remote_execution"],
        "supported_targets": ["ssh_host", "local"],
        "version": "2.14.3",
        "available": true
      },
      {
        "name": "bash",
        "display_name": "Bash",
        "description": "Bash script executor",
        "capabilities": ["variable_substitution", "remote_execution"],
        "supported_targets": ["ssh_host", "local"],
        "version": "5.1.16",
        "available": true
      }
    ]
    ```
    """
    metadata_list = RemediationExecutorFactory.get_all_executor_metadata()
    return [m.to_dict() for m in metadata_list]


@router.get("/jobs/{job_id}", response_model=BulkRemediationJob)
async def get_bulk_job(
    job_id: str,
    mongo_service=Depends(get_mongo_service),
    current_user: dict = Depends(get_current_user),
):
    """
    Get bulk remediation job status.

    Returns status and progress of a bulk remediation job.

    **Parameters:**
    - `job_id`: Bulk job UUID

    **Returns:**
    - BulkRemediationJob document
    """
    job = await BulkRemediationJob.find_one(BulkRemediationJob.job_id == job_id)

    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    # Authorization
    if current_user.get("role") != "admin":
        if job.executed_by != current_user.get("username"):
            raise HTTPException(status_code=403, detail="Access denied")

    return job
