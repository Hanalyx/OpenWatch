"""
Authorization Management API Endpoints
REST APIs for managing host permissions and access policies

ZERO TRUST SECURITY:
These endpoints allow administrators to manage fine-grained permissions
for hosts and resources, implementing least privilege principles and
preventing unauthorized access through proper policy management.

Design by Emily (Security Engineer) & Implementation by Daniel (Backend Engineer)
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from ...auth import get_current_user
from ...database import get_db
from ...models.authorization_models import ActionType, ResourceIdentifier, ResourceType
from ...rbac import Permission, require_permission
from ...services.authorization import get_authorization_service
from ...utils.query_builder import QueryBuilder

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/authorization", tags=["authorization"])
security = HTTPBearer()


# Request/Response Models


class PermissionGrantRequest(BaseModel):
    """Request to grant permission to a user/group/role."""

    user_id: Optional[str] = None
    group_id: Optional[str] = None
    role_name: Optional[str] = None
    host_id: Optional[str] = None
    host_group_id: Optional[str] = None
    actions: Set[str] = Field(..., description="List of actions: read, write, execute, delete, manage, scan")
    effect: str = Field(default="allow", description="Permission effect: allow or deny")
    expires_at: Optional[datetime] = None
    conditions: Dict[str, Any] = Field(default_factory=dict)


class PermissionResponse(BaseModel):
    """Response containing permission details"""

    id: str
    user_id: Optional[str]
    group_id: Optional[str]
    role_name: Optional[str]
    host_id: Optional[str]
    host_group_id: Optional[str]
    actions: Set[str]
    effect: str
    granted_by: str
    granted_at: datetime
    expires_at: Optional[datetime]
    is_active: bool


class PermissionCheckRequest(BaseModel):
    """Request to check permissions for resources"""

    user_id: Optional[str] = None  # If not provided, uses current user
    resource_type: str = Field(..., description="Resource type: host, host_group, scan, etc.")
    resource_id: str = Field(..., description="Resource identifier")
    action: str = Field(..., description="Action to check: read, write, execute, etc.")


class PermissionCheckResponse(BaseModel):
    """Response for permission check"""

    allowed: bool
    decision: str
    reason: str
    evaluated_policies: List[str]
    evaluation_time_ms: int
    timestamp: datetime


class BulkPermissionCheckRequest(BaseModel):
    """Request for bulk permission checking."""

    user_id: Optional[str] = None
    resources: List[Dict[str, Any]] = Field(..., description="List of {resource_type, resource_id} dicts")
    action: str
    fail_fast: bool = True


class BulkPermissionCheckResponse(BaseModel):
    """Response for bulk permission check."""

    overall_allowed: bool
    allowed_resources: List[Dict[str, Any]]
    denied_resources: List[Dict[str, Any]]
    total_evaluation_time_ms: int
    summary: Dict[str, Any]


# Permission Management Endpoints


@router.post("/permissions/host", response_model=Dict[str, Any])
@require_permission(Permission.HOST_MANAGE_ACCESS)
async def grant_host_permission(
    request: PermissionGrantRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Grant permission for a specific host.

    SECURITY REQUIREMENT: Only users with HOST_MANAGE_ACCESS permission
    can grant host-level permissions to other users.

    Args:
        request: Permission grant request with subject and actions.
        current_user: Authenticated user dictionary from token.
        db: Database session dependency.

    Returns:
        Dictionary with success status, permission_id, and grant metadata.

    Raises:
        HTTPException: 400 if request validation fails, 500 on server error.
    """
    try:
        if not request.host_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="host_id is required for host permissions",
            )

        # Validate that exactly one subject is specified
        subject_count = sum(1 for x in [request.user_id, request.group_id, request.role_name] if x)
        if subject_count != 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Exactly one of user_id, group_id, or role_name must be specified",
            )

        # Validate actions
        valid_actions = {
            "read",
            "write",
            "execute",
            "delete",
            "manage",
            "scan",
            "export",
        }
        invalid_actions = set(request.actions) - valid_actions
        if invalid_actions:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid actions: {invalid_actions}. Valid actions: {valid_actions}",
            )

        # Convert string actions to ActionType enums
        action_types: Set[ActionType] = set()
        action_map = {
            "read": ActionType.READ,
            "write": ActionType.WRITE,
            "execute": ActionType.EXECUTE,
            "delete": ActionType.DELETE,
            "manage": ActionType.MANAGE,
            "scan": ActionType.SCAN,
            "export": ActionType.EXPORT,
        }

        for action in request.actions:
            action_types.add(action_map[action])

        # Grant permission using authorization service (sync method, no await)
        auth_service = get_authorization_service(db)
        permission_id = auth_service.grant_host_permission(
            user_id=request.user_id,
            group_id=request.group_id,
            role_name=request.role_name,
            host_id=request.host_id,
            actions=action_types,
            granted_by=str(current_user.get("id", "")),
            expires_at=request.expires_at,
            conditions=request.conditions,
        )

        logger.info(
            f"Host permission granted by {current_user.get('username', 'unknown')}: "
            f"{permission_id} for host {request.host_id}"
        )

        return {
            "success": True,
            "permission_id": permission_id,
            "message": f"Permission granted for host {request.host_id}",
            "granted_by": current_user.get("username", "unknown"),
            "granted_at": datetime.utcnow().isoformat(),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error granting host permission: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to grant permission: {str(e)}",
        )


@router.delete("/permissions/{permission_id}")
@require_permission(Permission.HOST_MANAGE_ACCESS)
async def revoke_permission(
    permission_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Revoke a specific permission.

    Args:
        permission_id: The unique ID of the permission to revoke.
        current_user: Authenticated user dictionary from token.
        db: Database session dependency.

    Returns:
        Dictionary with success status and revocation metadata.

    Raises:
        HTTPException: 404 if permission not found, 500 on server error.
    """
    try:
        # Revoke permission using authorization service (sync method, no await)
        auth_service = get_authorization_service(db)
        success = auth_service.revoke_permission(permission_id)

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Permission {permission_id} not found",
            )

        logger.info(f"Permission {permission_id} revoked by {current_user.get('username', 'unknown')}")

        return {
            "success": True,
            "message": f"Permission {permission_id} revoked",
            "revoked_by": current_user.get("username", "unknown"),
            "revoked_at": datetime.utcnow().isoformat(),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error revoking permission: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to revoke permission: {str(e)}",
        )


@router.get("/permissions/host/{host_id}")
@require_permission(Permission.HOST_READ)
async def get_host_permissions(
    host_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Get all permissions for a specific host.

    Args:
        host_id: The unique ID of the host to get permissions for.
        current_user: Authenticated user dictionary from token.
        db: Database session dependency.

    Returns:
        Dictionary containing host_id, list of permissions, and total count.

    Raises:
        HTTPException: 500 on server error.
    """
    try:
        builder = (
            QueryBuilder("host_permissions hp")
            .select(
                "hp.id",
                "hp.user_id",
                "hp.group_id",
                "hp.role_name",
                "hp.host_id",
                "hp.actions",
                "hp.effect",
                "hp.conditions",
                "hp.granted_by",
                "hp.granted_at",
                "hp.expires_at",
                "hp.is_active",
                "u_granted.username as granted_by_username",
                "u_target.username as target_username",
                "ug.name as target_group_name",
            )
            .join("users u_granted", "hp.granted_by = u_granted.id", "LEFT")
            .join("users u_target", "hp.user_id = u_target.id", "LEFT")
            .join("user_groups ug", "hp.group_id = ug.id", "LEFT")
            .where("hp.host_id = :host_id", host_id, "host_id")
            .where("hp.is_active = true")
            .order_by("hp.granted_at", "DESC")
        )
        query, params = builder.build()
        result = db.execute(text(query), params)

        permissions = []
        for row in result:
            import json

            actions = json.loads(row.actions) if isinstance(row.actions, str) else row.actions

            permissions.append(
                {
                    "id": row.id,
                    "user_id": row.user_id,
                    "username": row.target_username,
                    "group_id": row.group_id,
                    "group_name": row.target_group_name,
                    "role_name": row.role_name,
                    "host_id": row.host_id,
                    "actions": actions,
                    "effect": row.effect,
                    "conditions": row.conditions,
                    "granted_by": row.granted_by,
                    "granted_by_username": row.granted_by_username,
                    "granted_at": (row.granted_at.isoformat() if row.granted_at else None),
                    "expires_at": (row.expires_at.isoformat() if row.expires_at else None),
                    "is_active": row.is_active,
                }
            )

        return {
            "host_id": host_id,
            "permissions": permissions,
            "total_permissions": len(permissions),
        }

    except Exception as e:
        logger.error(f"Error getting host permissions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get host permissions: {str(e)}",
        )


# Permission Checking Endpoints


@router.post("/check", response_model=PermissionCheckResponse)
async def check_permission(
    request: PermissionCheckRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PermissionCheckResponse:
    """
    Check if a user has permission to perform an action on a resource.

    Args:
        request: Permission check request with resource and action details.
        current_user: Authenticated user dictionary from token.
        db: Database session dependency.

    Returns:
        PermissionCheckResponse with allowed status and decision details.

    Raises:
        HTTPException: 400 if invalid resource/action, 500 on server error.
    """
    try:
        # Use current user if no user_id specified
        user_id = request.user_id or str(current_user.get("id", ""))

        # Validate resource type and action
        try:
            resource_type = ResourceType(request.resource_type)
            action = ActionType(request.action)
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid resource_type or action: {str(e)}",
            )

        # Create resource identifier
        resource = ResourceIdentifier(resource_type=resource_type, resource_id=request.resource_id)

        # Perform authorization check
        auth_service = get_authorization_service(db)
        result = await auth_service.check_permission(user_id, resource, action)

        # PermissionPolicy is a dataclass with id attribute, not a dict
        evaluated_policy_ids = [getattr(p, "id", "unknown") for p in result.applied_policies]

        return PermissionCheckResponse(
            allowed=(result.decision.value == "allow"),
            decision=result.decision.value,
            reason=result.reason,
            evaluated_policies=evaluated_policy_ids,
            evaluation_time_ms=result.evaluation_time_ms,
            timestamp=result.timestamp,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error checking permission: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Permission check failed: {str(e)}",
        )


@router.post("/check/bulk", response_model=BulkPermissionCheckResponse)
async def check_bulk_permissions(
    request: BulkPermissionCheckRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> BulkPermissionCheckResponse:
    """
    Check permissions for multiple resources in bulk.

    CRITICAL SECURITY IMPLEMENTATION:
    This endpoint demonstrates the fixed bulk authorization logic that
    prevents users from accessing resources they don't have permissions for.

    Args:
        request: Bulk permission check request with resources and action.
        current_user: Authenticated user dictionary from token.
        db: Database session dependency.

    Returns:
        BulkPermissionCheckResponse with allowed/denied resources and summary.

    Raises:
        HTTPException: 400 if invalid resources/action, 500 on server error.
    """
    try:
        # Use current user if no user_id specified
        user_id = request.user_id or str(current_user.get("id", ""))

        # Validate and convert resources
        resources: List[ResourceIdentifier] = []
        for res_data in request.resources:
            try:
                resource = ResourceIdentifier(
                    resource_type=ResourceType(res_data["resource_type"]),
                    resource_id=res_data["resource_id"],
                )
                resources.append(resource)
            except (KeyError, ValueError) as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid resource data: {res_data}. Error: {str(e)}",
                )

        try:
            action = ActionType(request.action)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid action: {request.action}",
            )

        # Build authorization context (sync method, no await)
        auth_service = get_authorization_service(db)
        auth_context = auth_service._build_user_context(user_id)

        # Perform bulk authorization check
        from ..models.authorization_models import BulkAuthorizationRequest

        bulk_request = BulkAuthorizationRequest(
            user_id=user_id,
            resources=resources,
            action=action,
            context=auth_context,
            fail_fast=request.fail_fast,
            parallel_evaluation=True,
        )

        result = await auth_service.check_bulk_permissions(bulk_request)

        # Format response
        allowed_resources_list: List[Dict[str, Any]] = [
            {"resource_type": res.resource_type.value, "resource_id": res.resource_id}
            for res in result.allowed_resources
        ]

        denied_resources_list: List[Dict[str, Any]] = [
            {
                "resource_type": res.resource_type.value,
                "resource_id": res.resource_id,
                "reason": next(
                    (r.reason for r in result.individual_results if r.resource.resource_id == res.resource_id),
                    "Access denied",
                ),
            }
            for res in result.denied_resources
        ]

        return BulkPermissionCheckResponse(
            overall_allowed=(result.overall_decision.value == "allow"),
            allowed_resources=allowed_resources_list,
            denied_resources=denied_resources_list,
            total_evaluation_time_ms=result.total_evaluation_time_ms,
            summary={
                "total_resources": len(request.resources),
                "allowed_count": len(allowed_resources_list),
                "denied_count": len(denied_resources_list),
                "cached_results": result.cached_results,
                "fresh_evaluations": result.fresh_evaluations,
            },
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in bulk permission check: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Bulk permission check failed: {str(e)}",
        )


# Administrative Endpoints


@router.get("/audit")
@require_permission(Permission.AUDIT_READ)
async def get_authorization_audit_log(
    limit: int = Query(100, le=1000, description="Maximum number of records"),
    offset: int = Query(0, ge=0, description="Number of records to skip"),
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    decision: Optional[str] = Query(None, description="Filter by decision: allow/deny"),
    start_date: Optional[datetime] = Query(None, description="Filter from date"),
    end_date: Optional[datetime] = Query(None, description="Filter to date"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Get authorization audit log for security monitoring.

    Args:
        limit: Maximum number of records to return (max 1000).
        offset: Number of records to skip for pagination.
        user_id: Optional filter by user ID.
        resource_type: Optional filter by resource type.
        decision: Optional filter by decision (allow/deny).
        start_date: Optional filter for entries after this date.
        end_date: Optional filter for entries before this date.
        current_user: Authenticated user dictionary from token.
        db: Database session dependency.

    Returns:
        Dictionary with audit_entries list and pagination metadata.

    Raises:
        HTTPException: 500 on server error.
    """
    try:
        # Build query with QueryBuilder for parameterized filtering
        builder = QueryBuilder("authorization_audit_log").select(
            "id",
            "event_type",
            "user_id",
            "resource_type",
            "resource_id",
            "action",
            "decision",
            "policies_evaluated",
            "context",
            "ip_address",
            "user_agent",
            "session_id",
            "evaluation_time_ms",
            "reason",
            "risk_score",
            "timestamp",
        )

        if user_id:
            builder = builder.where("user_id = :user_id", user_id, "user_id")

        if resource_type:
            builder = builder.where(
                "resource_type = :resource_type",
                resource_type,
                "resource_type",
            )

        if decision:
            builder = builder.where("decision = :decision", decision, "decision")

        if start_date:
            builder = builder.where("timestamp >= :start_date", start_date, "start_date")

        if end_date:
            builder = builder.where("timestamp <= :end_date", end_date, "end_date")

        # Get total count with null safety
        count_sql, count_params = builder.count_query()
        count_result = db.execute(text(count_sql), count_params)
        count_row = count_result.fetchone()
        total_count: int = count_row.total if count_row else 0

        # Get paginated audit log entries
        page = (offset // limit) + 1 if limit > 0 else 1
        builder = builder.order_by("timestamp", "DESC").paginate(
            page=page,
            per_page=limit,
        )
        query, params = builder.build()
        result = db.execute(text(query), params)

        audit_entries: List[Dict[str, Any]] = []
        for row in result:
            audit_entries.append(
                {
                    "id": row.id,
                    "event_type": row.event_type,
                    "user_id": row.user_id,
                    "resource_type": row.resource_type,
                    "resource_id": row.resource_id,
                    "action": row.action,
                    "decision": row.decision,
                    "policies_evaluated": (row.policies_evaluated.split(",") if row.policies_evaluated else []),
                    "context": row.context,
                    "ip_address": row.ip_address,
                    "user_agent": row.user_agent,
                    "session_id": row.session_id,
                    "evaluation_time_ms": row.evaluation_time_ms,
                    "reason": row.reason,
                    "risk_score": row.risk_score,
                    "timestamp": row.timestamp.isoformat() if row.timestamp else None,
                }
            )

        return {
            "audit_entries": audit_entries,
            "pagination": {
                "total": total_count,
                "limit": limit,
                "offset": offset,
                "has_more": (offset + len(audit_entries)) < total_count,
            },
        }

    except Exception as e:
        logger.error(f"Error getting authorization audit log: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get audit log: {str(e)}",
        )


@router.get("/summary")
@require_permission(Permission.SYSTEM_CONFIG)
async def get_authorization_summary(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Get authorization system summary and statistics.

    Args:
        current_user: Authenticated user dictionary from token.
        db: Database session dependency.

    Returns:
        Dictionary with permission_statistics, recent_activity, and most_active_users.

    Raises:
        HTTPException: 500 on server error.
    """
    try:
        # Get permission statistics with null safety
        perm_stats_result = db.execute(
            text(
                """
            SELECT
                COUNT(*) as total_permissions,
                COUNT(CASE WHEN user_id IS NOT NULL THEN 1 END) as user_permissions,
                COUNT(CASE WHEN group_id IS NOT NULL THEN 1 END) as group_permissions,
                COUNT(CASE WHEN role_name IS NOT NULL THEN 1 END) as role_permissions,
                COUNT(CASE WHEN expires_at IS NOT NULL AND expires_at > NOW() THEN 1 END) as temporary_permissions,
                COUNT(CASE WHEN effect = 'deny' THEN 1 END) as deny_permissions
            FROM host_permissions
            WHERE is_active = true
        """
            )
        )
        perm_stats = perm_stats_result.fetchone()

        # Get recent audit statistics with null safety
        audit_stats_result = db.execute(
            text(
                """
            SELECT
                COUNT(*) as total_checks,
                COUNT(CASE WHEN decision = 'allow' THEN 1 END) as allowed_checks,
                COUNT(CASE WHEN decision = 'deny' THEN 1 END) as denied_checks,
                AVG(evaluation_time_ms) as avg_evaluation_time,
                AVG(risk_score) as avg_risk_score
            FROM authorization_audit_log
            WHERE timestamp > NOW() - INTERVAL '24 hours'
        """
            )
        )
        audit_stats = audit_stats_result.fetchone()

        # Get most active users
        active_users = db.execute(
            text(
                """
            SELECT u.username, COUNT(*) as check_count
            FROM authorization_audit_log aal
            JOIN users u ON aal.user_id = u.id
            WHERE aal.timestamp > NOW() - INTERVAL '24 hours'
            GROUP BY u.username
            ORDER BY check_count DESC
            LIMIT 10
        """
            )
        ).fetchall()

        # Build response with null safety for fetchone results
        permission_statistics: Dict[str, int] = {
            "total_permissions": (getattr(perm_stats, "total_permissions", 0) or 0 if perm_stats else 0),
            "user_permissions": (getattr(perm_stats, "user_permissions", 0) or 0 if perm_stats else 0),
            "group_permissions": (getattr(perm_stats, "group_permissions", 0) or 0 if perm_stats else 0),
            "role_permissions": (getattr(perm_stats, "role_permissions", 0) or 0 if perm_stats else 0),
            "temporary_permissions": (getattr(perm_stats, "temporary_permissions", 0) or 0 if perm_stats else 0),
            "deny_permissions": (getattr(perm_stats, "deny_permissions", 0) or 0 if perm_stats else 0),
        }

        # Calculate avg_evaluation_time_ms safely
        avg_eval_time = getattr(audit_stats, "avg_evaluation_time", None) if audit_stats else None
        avg_risk = getattr(audit_stats, "avg_risk_score", None) if audit_stats else None

        recent_activity: Dict[str, Any] = {
            "total_checks_24h": getattr(audit_stats, "total_checks", 0) or 0 if audit_stats else 0,
            "allowed_checks_24h": (getattr(audit_stats, "allowed_checks", 0) or 0 if audit_stats else 0),
            "denied_checks_24h": (getattr(audit_stats, "denied_checks", 0) or 0 if audit_stats else 0),
            "avg_evaluation_time_ms": float(avg_eval_time) if avg_eval_time else 0.0,
            "avg_risk_score": float(avg_risk) if avg_risk else 0.0,
        }

        most_active_users: List[Dict[str, Any]] = [
            {"username": row.username, "check_count": row.check_count} for row in active_users
        ]

        return {
            "permission_statistics": permission_statistics,
            "recent_activity": recent_activity,
            "most_active_users": most_active_users,
        }

    except Exception as e:
        logger.error(f"Error getting authorization summary: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get authorization summary: {str(e)}",
        )
