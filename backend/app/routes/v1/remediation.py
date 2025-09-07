"""
OpenWatch API v1 - Remediation Provider Interface
Enhanced remediation interface for AEGIS integration and other remediation providers
"""

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Query
from pydantic import BaseModel, Field, UUID4
from typing import List, Optional, Dict, Any
from datetime import datetime
import logging
import asyncio
import uuid
from sqlalchemy.orm import Session

from ...auth import get_current_user
from ...database import get_db, Scan, Host
from ...audit_db import log_audit_event
from ...config import get_settings

logger = logging.getLogger(__name__)

router = APIRouter()


class RemediationRequest(BaseModel):
    """Request to start remediation for scan results"""

    scan_id: UUID4
    host_id: UUID4
    failed_rules: List[str] = Field(..., min_items=1)
    provider: str = Field(default="aegis", pattern="^(aegis|ansible|manual)$")
    priority: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    schedule: Optional[datetime] = None
    options: Dict[str, Any] = Field(default_factory=dict)


class RemediationJob(BaseModel):
    """Remediation job status and information"""

    job_id: UUID4
    scan_id: UUID4
    host_id: UUID4
    provider: str
    status: str
    priority: str
    failed_rules: List[str]
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    progress_percentage: int = 0
    estimated_completion: Optional[datetime] = None
    results: List[Dict] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RemediationProvider(BaseModel):
    """Information about a remediation provider"""

    name: str
    version: str
    status: str  # 'available', 'unavailable', 'degraded'
    capabilities: List[str]
    supported_os: List[str]
    supported_frameworks: List[str]
    configuration: Dict[str, Any]


class RemediationSummary(BaseModel):
    """Summary of remediation activities"""

    total_jobs: int
    active_jobs: int
    completed_jobs: int
    failed_jobs: int
    pending_jobs: int
    success_rate: float
    average_duration_minutes: Optional[float]
    last_24h: Dict[str, int]


@router.post("/start", response_model=RemediationJob)
async def start_remediation(
    request: RemediationRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> RemediationJob:
    """
    Start remediation for failed scan rules

    Initiates a remediation job for the specified failed rules using
    the configured remediation provider (AEGIS, Ansible, etc.).
    """
    try:
        # Verify scan exists and user has access
        scan = db.query(Scan).filter(Scan.id == str(request.scan_id)).first()
        if not scan:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

        # Verify host exists
        host = db.query(Host).filter(Host.id == str(request.host_id)).first()
        if not host:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Host not found")

        # Check if remediation is already in progress
        if scan.remediation_status in ["pending", "running"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Remediation already in progress for this scan",
            )

        # Generate job ID
        job_id = uuid.uuid4()

        # Create remediation job
        job = RemediationJob(
            job_id=job_id,
            scan_id=request.scan_id,
            host_id=request.host_id,
            provider=request.provider,
            status="pending",
            priority=request.priority,
            failed_rules=request.failed_rules,
            created_at=datetime.utcnow(),
            metadata={
                "user_id": current_user.get("user_id"),
                "options": request.options,
                "rule_count": len(request.failed_rules),
            },
        )

        # Update scan status
        scan.remediation_requested = True
        scan.remediation_status = "pending"
        scan.aegis_remediation_id = str(job_id)

        # Store job information in scan metadata
        if not scan.metadata:
            scan.metadata = {}

        scan.metadata["remediation_job"] = job.dict()

        db.commit()

        # Log audit event
        await log_audit_event(
            db=db,
            user_id=current_user.get("user_id"),
            action="REMEDIATION_REQUESTED",
            resource_type="scan",
            resource_id=str(scan.id),
            details={
                "job_id": str(job_id),
                "provider": request.provider,
                "rule_count": len(request.failed_rules),
                "priority": request.priority,
            },
            ip_address="127.0.0.1",
        )

        # Start remediation in background
        background_tasks.add_task(
            _execute_remediation_job,
            job_id=job_id,
            provider=request.provider,
            scan_id=request.scan_id,
            host_id=request.host_id,
            failed_rules=request.failed_rules,
            options=request.options,
        )

        logger.info(f"Remediation job {job_id} started for scan {scan.id}")

        return job

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting remediation: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to start remediation"
        )


@router.get("/job/{job_id}", response_model=RemediationJob)
async def get_remediation_job(
    job_id: UUID4, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)
) -> RemediationJob:
    """
    Get remediation job status and details

    Returns detailed information about a specific remediation job
    including progress, results, and current status.
    """
    try:
        # Find scan with this remediation job ID
        scan = db.query(Scan).filter(Scan.aegis_remediation_id == str(job_id)).first()

        if not scan or not scan.metadata or "remediation_job" not in scan.metadata:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Remediation job not found"
            )

        job_data = scan.metadata["remediation_job"]
        job = RemediationJob(**job_data)

        # Update with latest status from scan
        job.status = scan.remediation_status or "unknown"
        if scan.remediation_completed_at:
            job.completed_at = scan.remediation_completed_at

        return job

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting remediation job: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve remediation job",
        )


@router.delete("/job/{job_id}")
async def cancel_remediation_job(
    job_id: UUID4, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    """
    Cancel a running remediation job

    Attempts to cancel a remediation job that is currently pending or running.
    """
    try:
        # Find scan with this remediation job ID
        scan = db.query(Scan).filter(Scan.aegis_remediation_id == str(job_id)).first()

        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Remediation job not found"
            )

        if scan.remediation_status not in ["pending", "running"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot cancel job in current status",
            )

        # Update status
        scan.remediation_status = "cancelled"

        # TODO: Send cancellation request to remediation provider

        db.commit()

        # Log audit event
        await log_audit_event(
            db=db,
            user_id=current_user.get("user_id"),
            action="REMEDIATION_CANCELLED",
            resource_type="scan",
            resource_id=str(scan.id),
            details={"job_id": str(job_id)},
            ip_address="127.0.0.1",
        )

        logger.info(f"Remediation job {job_id} cancelled")

        return {"status": "cancelled", "job_id": str(job_id)}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error cancelling remediation job: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to cancel remediation job",
        )


@router.post("/job/{job_id}/retry")
async def retry_remediation_job(
    job_id: UUID4,
    failed_rules_only: bool = Query(True, description="Retry only failed rules"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Retry a failed remediation job

    Creates a new remediation job based on a previously failed job,
    optionally retrying only the rules that failed.
    """
    try:
        # Find original scan
        scan = db.query(Scan).filter(Scan.aegis_remediation_id == str(job_id)).first()

        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Original remediation job not found"
            )

        if scan.remediation_status not in ["failed", "partial"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Can only retry failed or partial remediation jobs",
            )

        # Get failed rules from original job
        original_job = scan.metadata.get("remediation_job", {})
        if failed_rules_only and "results" in scan.metadata.get("remediation", {}):
            # Extract rules that failed
            failed_rules = [
                r["rule_id"]
                for r in scan.metadata["remediation"]["results"]
                if r["status"] == "failed"
            ]
        else:
            # Retry all original rules
            failed_rules = original_job.get("failed_rules", [])

        if not failed_rules:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="No failed rules to retry"
            )

        # Create new retry request
        retry_request = RemediationRequest(
            scan_id=UUID4(str(scan.id)),
            host_id=UUID4(str(scan.host_id)),
            failed_rules=failed_rules,
            provider=original_job.get("provider", "aegis"),
            priority=original_job.get("priority", "medium"),
        )

        # Start new remediation job
        new_job = await start_remediation(retry_request, BackgroundTasks(), current_user, db)

        logger.info(f"Retry remediation job {new_job.job_id} created for original job {job_id}")

        return {
            "status": "retry_started",
            "original_job_id": str(job_id),
            "new_job_id": str(new_job.job_id),
            "rules_to_retry": len(failed_rules),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrying remediation job: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retry remediation job",
        )


@router.get("/providers", response_model=List[RemediationProvider])
async def get_remediation_providers(
    current_user: dict = Depends(get_current_user),
) -> List[RemediationProvider]:
    """
    Get available remediation providers

    Returns information about all configured remediation providers
    including their status, capabilities, and configuration.
    """
    try:
        providers = []

        # AEGIS Provider
        aegis_status = await _check_aegis_status()
        providers.append(
            RemediationProvider(
                name="aegis",
                version="1.0.0",
                status=aegis_status["status"],
                capabilities=[
                    "automated_remediation",
                    "rule_based_fixes",
                    "rollback_support",
                    "verification_scans",
                ],
                supported_os=[
                    "rhel8",
                    "rhel9",
                    "ubuntu20.04",
                    "ubuntu22.04",
                    "centos8",
                    "debian11",
                ],
                supported_frameworks=["STIG", "CIS", "PCI-DSS"],
                configuration=aegis_status["config"],
            )
        )

        # Ansible Provider (if configured)
        ansible_status = await _check_ansible_status()
        if ansible_status["available"]:
            providers.append(
                RemediationProvider(
                    name="ansible",
                    version=ansible_status.get("version", "unknown"),
                    status="available",
                    capabilities=[
                        "playbook_execution",
                        "idempotent_operations",
                        "multi_host_support",
                    ],
                    supported_os=["linux", "unix"],
                    supported_frameworks=["custom"],
                    configuration=ansible_status["config"],
                )
            )

        # Manual Provider (always available)
        providers.append(
            RemediationProvider(
                name="manual",
                version="1.0.0",
                status="available",
                capabilities=[
                    "guided_remediation",
                    "documentation_generation",
                    "compliance_tracking",
                ],
                supported_os=["all"],
                supported_frameworks=["all"],
                configuration={"type": "manual"},
            )
        )

        return providers

    except Exception as e:
        logger.error(f"Error getting remediation providers: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve remediation providers",
        )


@router.get("/summary", response_model=RemediationSummary)
async def get_remediation_summary(
    current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)
) -> RemediationSummary:
    """
    Get remediation activity summary

    Returns aggregate statistics about remediation jobs and activities.
    """
    try:
        # Query remediation jobs from scan metadata
        # This is a simplified implementation - in production you'd have a dedicated table

        # Count scans with remediation data
        total_jobs = db.query(Scan).filter(Scan.remediation_requested == True).count()

        active_jobs = (
            db.query(Scan).filter(Scan.remediation_status.in_(["pending", "running"])).count()
        )

        completed_jobs = db.query(Scan).filter(Scan.remediation_status == "completed").count()

        failed_jobs = db.query(Scan).filter(Scan.remediation_status == "failed").count()

        pending_jobs = db.query(Scan).filter(Scan.remediation_status == "pending").count()

        # Calculate success rate
        success_rate = 0.0
        if total_jobs > 0:
            success_rate = (completed_jobs / total_jobs) * 100

        return RemediationSummary(
            total_jobs=total_jobs,
            active_jobs=active_jobs,
            completed_jobs=completed_jobs,
            failed_jobs=failed_jobs,
            pending_jobs=pending_jobs,
            success_rate=success_rate,
            average_duration_minutes=None,  # Would calculate from actual data
            last_24h={"jobs_started": 0, "jobs_completed": 0, "rules_fixed": 0},
        )

    except Exception as e:
        logger.error(f"Error getting remediation summary: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve remediation summary",
        )


# Helper functions
async def _execute_remediation_job(
    job_id: UUID4,
    provider: str,
    scan_id: UUID4,
    host_id: UUID4,
    failed_rules: List[str],
    options: Dict[str, Any],
):
    """Execute remediation job in background"""
    try:
        logger.info(f"Starting remediation job {job_id} with provider {provider}")

        if provider == "aegis":
            await _execute_aegis_remediation(job_id, scan_id, host_id, failed_rules, options)
        elif provider == "ansible":
            await _execute_ansible_remediation(job_id, scan_id, host_id, failed_rules, options)
        elif provider == "manual":
            await _execute_manual_remediation(job_id, scan_id, host_id, failed_rules, options)
        else:
            logger.error(f"Unknown remediation provider: {provider}")

    except Exception as e:
        logger.error(f"Error executing remediation job {job_id}: {e}")


async def _execute_aegis_remediation(job_id, scan_id, host_id, failed_rules, options):
    """Execute AEGIS-based remediation"""
    # This would make actual calls to AEGIS API
    logger.info(f"AEGIS remediation job {job_id} - would call AEGIS API")
    # For now, just simulate
    await asyncio.sleep(2)
    logger.info(f"AEGIS remediation job {job_id} completed (simulated)")


async def _execute_ansible_remediation(job_id, scan_id, host_id, failed_rules, options):
    """Execute Ansible-based remediation"""
    logger.info(f"Ansible remediation job {job_id} - would execute playbooks")
    await asyncio.sleep(2)
    logger.info(f"Ansible remediation job {job_id} completed (simulated)")


async def _execute_manual_remediation(job_id, scan_id, host_id, failed_rules, options):
    """Generate manual remediation documentation"""
    logger.info(f"Manual remediation job {job_id} - generating documentation")
    await asyncio.sleep(1)
    logger.info(f"Manual remediation job {job_id} completed (simulated)")


def _check_aegis_status():
    """Check AEGIS provider status"""
    settings = get_settings()
    aegis_url = getattr(settings, "aegis_url", None)

    if not aegis_url:
        return {"status": "unavailable", "config": {"error": "AEGIS_URL not configured"}}

    # Would check actual AEGIS connectivity here
    return {
        "status": "available",
        "config": {"url": aegis_url, "webhook_configured": True, "api_version": "v1"},
    }


async def _check_ansible_status():
    """Check Ansible provider status"""
    try:
        # Check if ansible is installed
        process = await asyncio.create_subprocess_exec(
            "ansible", "--version", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()

        if process.returncode == 0:
            version = stdout.decode().split("\n")[0]
            return {"available": True, "version": version, "config": {"type": "ansible"}}
    except:
        pass

    return {"available": False}
