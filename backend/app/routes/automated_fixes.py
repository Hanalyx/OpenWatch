"""
OpenWatch Secure Automated Fixes API Routes

This module provides REST API endpoints for secure automated fix management,
including request submission, approval workflows, execution, and rollback operations.

Security Features:
- Role-based access control (RBAC)
- Request validation and sanitization
- Comprehensive audit logging
- Multi-factor approval workflow
- Secure execution status monitoring
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..rbac import Permission, check_permission_async
from ..services.error_classification import AutomatedFix
from ..services.secure_automated_fixes import SecureAutomatedFixExecutor

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/automated-fixes", tags=["Automated Fixes"])

# Initialize the secure fix executor
secure_fix_executor: SecureAutomatedFixExecutor = SecureAutomatedFixExecutor()


def sanitize_for_log(value: Any) -> str:
    """Sanitize user input for safe logging."""
    if value is None:
        return "None"
    str_value = str(value)
    # Remove newlines and control characters to prevent log injection
    return str_value.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")[:1000]


class FixEvaluationRequest(BaseModel):
    """Request to evaluate automated fix options"""

    legacy_fixes: List[Dict[str, Any]]
    target_host: str
    context: Optional[Dict[str, Any]] = Field(default_factory=dict)


class FixExecutionRequest(BaseModel):
    """Request to execute an automated fix"""

    fix_id: str
    secure_command_id: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    target_host: str
    justification: str = Field(min_length=10, max_length=500)


class FixApprovalRequest(BaseModel):
    """Request to approve a pending fix"""

    approval_reason: str = Field(min_length=10, max_length=500)


class FixRollbackRequest(BaseModel):
    """Request to rollback a fix"""

    rollback_reason: str = Field(min_length=10, max_length=500)


@router.post("/evaluate-options")
async def evaluate_fix_options(
    request: FixEvaluationRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Evaluate legacy automated fixes and convert to secure options

    Requires: scan:read permission
    """
    try:
        # Check permissions (sync function, no await needed)
        check_permission_async(current_user, Permission.SCAN_READ, db)

        # Convert legacy fixes to AutomatedFix objects
        legacy_fixes = []
        for fix_data in request.legacy_fixes:
            legacy_fix = AutomatedFix(
                fix_id=fix_data.get("fix_id", ""),
                description=fix_data.get("description", ""),
                requires_sudo=fix_data.get("requires_sudo", False),
                estimated_time=fix_data.get("estimated_time", 30),
                command=fix_data.get("command"),
                is_safe=fix_data.get("is_safe", True),
                rollback_command=fix_data.get("rollback_command"),
            )
            legacy_fixes.append(legacy_fix)

        # Evaluate secure options
        secure_options = await secure_fix_executor.evaluate_fix_options(
            legacy_fixes=legacy_fixes, target_host=request.target_host
        )

        logger.info(
            f"Evaluated {len(secure_options)} fix options for {request.target_host} by {current_user.get('username')}"
        )

        return {
            "secure_options": secure_options,
            "total_options": len(secure_options),
            "safe_options": len([opt for opt in secure_options if opt.get("is_safe", False)]),
            "blocked_options": len([opt for opt in secure_options if opt.get("security_level") == "blocked"]),
            "evaluation_timestamp": datetime.utcnow().isoformat(),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to evaluate fix options: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to evaluate fix options: {str(e)}",
        )


@router.post("/request-execution")
async def request_fix_execution(
    request: FixExecutionRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Request execution of a secure automated fix

    Requires: scan:write permission
    """
    try:
        # Check permissions (sync function, no await needed)
        check_permission_async(current_user, Permission.SCAN_WRITE, db)

        # Request fix execution
        result = await secure_fix_executor.request_fix_execution(
            fix_id=request.fix_id,
            secure_command_id=request.secure_command_id,
            parameters=request.parameters,
            target_host=request.target_host,
            requested_by=current_user.get("username", "unknown"),
            justification=request.justification,
        )

        logger.info(f"Fix execution requested: {request.fix_id} by {current_user.get('username')}")

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to request fix execution: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to request fix execution: {str(e)}",
        )


@router.post("/approve/{request_id}")
async def approve_fix_request(
    request_id: str,
    approval_request: FixApprovalRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Approve a pending fix execution request

    Requires: admin role or scan:approve permission
    """
    try:
        # Check permissions - requires admin or special approval permission
        user_roles = current_user.get("roles", [])
        if "admin" not in user_roles:
            # Sync function, no await needed
            check_permission_async(current_user, Permission.SCAN_APPROVE, db)

        # Approve the request
        result = await secure_fix_executor.approve_fix_request(
            request_id=request_id,
            approved_by=current_user.get("username", "unknown"),
            approval_reason=approval_request.approval_reason,
        )

        if result["success"]:
            logger.info(f"Fix request approved: {request_id} by {current_user.get('username')}")
        else:
            logger.warning(f"Fix approval failed: {request_id} - {sanitize_for_log(result['message'])}")

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to approve fix request: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to approve fix request: {str(e)}",
        )


@router.post("/execute/{request_id}")
async def execute_approved_fix(
    request_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Execute an approved automated fix

    Requires: scan:write permission
    """
    try:
        # Check permissions (sync function, no await needed)
        check_permission_async(current_user, Permission.SCAN_WRITE, db)

        # Execute the fix
        result = await secure_fix_executor.execute_approved_fix(request_id)

        if result["success"]:
            logger.info(f"Fix executed successfully: {request_id}")
        else:
            logger.warning(f"Fix execution failed: {request_id} - {sanitize_for_log(result['message'])}")

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to execute fix: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to execute fix: {str(e)}",
        )


@router.post("/rollback/{request_id}")
async def rollback_fix(
    request_id: str,
    rollback_request: FixRollbackRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Rollback a previously executed fix

    Requires: admin role or scan:rollback permission
    """
    try:
        # Check permissions - requires admin or special rollback permission
        user_roles = current_user.get("roles", [])
        if "admin" not in user_roles:
            # Sync function, no await needed
            check_permission_async(current_user, Permission.SCAN_ROLLBACK, db)

        # Rollback the fix
        result = await secure_fix_executor.rollback_fix(
            request_id=request_id, rollback_by=current_user.get("username", "unknown")
        )

        if result["success"]:
            logger.info(f"Fix rolled back successfully: {request_id} by {current_user.get('username')}")
        else:
            logger.warning(f"Fix rollback failed: {request_id} - {sanitize_for_log(result['message'])}")

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to rollback fix: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to rollback fix: {str(e)}",
        )


@router.get("/status/{request_id}")
async def get_fix_status(
    request_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Get status of a fix execution request

    Requires: scan:read permission
    """
    try:
        # Check permissions (sync function, no await needed)
        check_permission_async(current_user, Permission.SCAN_READ, db)

        # Get fix status
        status_info = await secure_fix_executor.get_fix_status(request_id)

        if not status_info:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Fix request not found")

        return status_info

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get fix status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get fix status: {str(e)}",
        )


@router.get("/pending-approvals")
async def list_pending_approvals(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    List all fixes pending approval

    Requires: admin role or scan:approve permission
    """
    try:
        # Check permissions
        user_roles = current_user.get("roles", [])
        if "admin" not in user_roles:
            # Sync function, no await needed
            check_permission_async(current_user, Permission.SCAN_APPROVE, db)

        # Get pending approvals
        pending_fixes = await secure_fix_executor.list_pending_approvals()

        return {
            "pending_approvals": pending_fixes,
            "total_pending": len(pending_fixes),
            "retrieved_at": datetime.utcnow().isoformat(),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to list pending approvals: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list pending approvals: {str(e)}",
        )


@router.get("/secure-commands")
async def get_secure_command_catalog(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Get catalog of available secure commands

    Requires: scan:read permission
    """
    try:
        # Check permissions (sync function, no await needed)
        check_permission_async(current_user, Permission.SCAN_READ, db)

        # Get command catalog
        commands = await secure_fix_executor.get_secure_command_catalog()

        return {
            "secure_commands": commands,
            "total_commands": len(commands),
            "safe_commands": len([cmd for cmd in commands if cmd["security_level"] == "safe"]),
            "privileged_commands": len([cmd for cmd in commands if cmd["security_level"] == "privileged"]),
            "catalog_timestamp": datetime.utcnow().isoformat(),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get secure command catalog: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get secure command catalog: {str(e)}",
        )


@router.delete("/cleanup")
async def cleanup_old_requests(
    max_age_days: int = 30,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Clean up old execution requests

    Requires: admin role
    """
    try:
        # Check permissions - admin only
        user_roles = current_user.get("roles", [])
        if "admin" not in user_roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

        # Clean up old requests
        await secure_fix_executor.cleanup_old_requests(max_age_days=max_age_days)

        logger.info(f"Cleaned up old fix requests (max_age_days={max_age_days}) by {current_user.get('username')}")

        return {
            "success": True,
            "message": f"Cleaned up old requests older than {max_age_days} days",
            "cleanup_timestamp": datetime.utcnow().isoformat(),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to cleanup old requests: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to cleanup old requests: {str(e)}",
        )


@router.get("/health")
async def health_check() -> Union[Dict[str, Any], JSONResponse]:
    """Health check endpoint for automated fix service"""
    try:
        # Basic health checks
        sandbox_service_status = "healthy"  # Could add more detailed checks

        return {
            "status": "healthy",
            "service": "secure-automated-fixes",
            "sandbox_service": sandbox_service_status,
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "unhealthy",
                "service": "secure-automated-fixes",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            },
        )
