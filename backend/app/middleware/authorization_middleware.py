"""
Authorization Middleware for OpenWatch
Intercepts and validates all scan endpoint requests to ensure proper per-host authorization

CRITICAL SECURITY FIX:
This middleware prevents the vulnerability where users can initiate operations
on hosts without proper authorization checks. It implements Zero Trust principles
by validating every request at the operation boundary.

ZERO TRUST IMPLEMENTATION:
- All requests validated before processing
- No implicit trust or bypass mechanisms
- Comprehensive audit trail
- Fail-secure behavior on errors
- Resource-level permission validation

Design by Emily (Security Engineer) & Implementation by Daniel (Backend Engineer)
"""

import json
import logging
import time
from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, List, Optional

from fastapi import HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from ..auth import get_current_user
from ..database import get_db
from ..models.authorization_models import (
    ActionType,
    AuthorizationContext,
    AuthorizationDecision,
    BulkAuthorizationRequest,
    ResourceIdentifier,
    ResourceType,
)
from ..services.authorization_service import AuthorizationService, get_authorization_service
from ..utils.logging_security import sanitize_for_log, sanitize_id_for_log

logger = logging.getLogger(__name__)


class AuthorizationMiddleware(BaseHTTPMiddleware):
    """
    Authorization middleware that validates all requests against resource permissions

    SECURITY FEATURES:
    1. Request Interception - Validates all scan-related operations
    2. Resource Identification - Extracts resource information from requests
    3. Permission Validation - Checks user permissions for each resource
    4. Audit Logging - Records all authorization decisions
    5. Fail-Secure - Denies access on any error or uncertainty
    """

    def __init__(self, app, authorization_service_factory: Callable = None):
        super().__init__(app)
        self.authorization_service_factory = authorization_service_factory or get_authorization_service

        # Define which endpoints require authorization and what resource/action they map to
        self.protected_endpoints = {
            # Scan operations
            "POST /api/v1/scans": {
                "resource_type": ResourceType.HOST,
                "action": ActionType.SCAN,
                "bulk": False,
            },
            "PUT /api/v1/scans/{scan_id}": {
                "resource_type": ResourceType.SCAN,
                "action": ActionType.WRITE,
                "bulk": False,
            },
            "DELETE /api/v1/scans/{scan_id}": {
                "resource_type": ResourceType.SCAN,
                "action": ActionType.DELETE,
                "bulk": False,
            },
            "GET /api/v1/scans/{scan_id}": {
                "resource_type": ResourceType.SCAN,
                "action": ActionType.READ,
                "bulk": False,
            },
            "POST /api/v1/scans/{scan_id}/execute": {
                "resource_type": ResourceType.SCAN,
                "action": ActionType.EXECUTE,
                "bulk": False,
            },
            # Bulk scan operations - CRITICAL VULNERABILITY PREVENTION
            "POST /api/v1/bulk-scans": {
                "resource_type": ResourceType.HOST,
                "action": ActionType.SCAN,
                "bulk": True,
            },
            "POST /api/v1/bulk-scans/{session_id}/start": {
                "resource_type": ResourceType.HOST,
                "action": ActionType.EXECUTE,
                "bulk": True,
            },
            "DELETE /api/v1/bulk-scans/{session_id}": {
                "resource_type": ResourceType.HOST,
                "action": ActionType.DELETE,
                "bulk": True,
            },
            # Host operations
            "GET /api/v1/hosts/{host_id}": {
                "resource_type": ResourceType.HOST,
                "action": ActionType.READ,
                "bulk": False,
            },
            "PUT /api/v1/hosts/{host_id}": {
                "resource_type": ResourceType.HOST,
                "action": ActionType.WRITE,
                "bulk": False,
            },
            "DELETE /api/v1/hosts/{host_id}": {
                "resource_type": ResourceType.HOST,
                "action": ActionType.DELETE,
                "bulk": False,
            },
            "POST /api/v1/hosts/{host_id}/scan": {
                "resource_type": ResourceType.HOST,
                "action": ActionType.SCAN,
                "bulk": False,
            },
            # Host group operations
            "GET /api/v1/host-groups/{group_id}": {
                "resource_type": ResourceType.HOST_GROUP,
                "action": ActionType.READ,
                "bulk": False,
            },
            "PUT /api/v1/host-groups/{group_id}": {
                "resource_type": ResourceType.HOST_GROUP,
                "action": ActionType.WRITE,
                "bulk": False,
            },
            "DELETE /api/v1/host-groups/{group_id}": {
                "resource_type": ResourceType.HOST_GROUP,
                "action": ActionType.DELETE,
                "bulk": False,
            },
            "POST /api/v1/host-groups/{group_id}/scan": {
                "resource_type": ResourceType.HOST_GROUP,
                "action": ActionType.SCAN,
                "bulk": True,
            },
            # Rule scanning operations
            "POST /api/v1/rule-scan": {
                "resource_type": ResourceType.HOST,
                "action": ActionType.SCAN,
                "bulk": True,
            },
            # Remediation operations
            "POST /api/v1/scans/{scan_id}/remediate": {
                "resource_type": ResourceType.SCAN,
                "action": ActionType.EXECUTE,
                "bulk": False,
            },
            "POST /api/v1/bulk-remediate": {
                "resource_type": ResourceType.HOST,
                "action": ActionType.EXECUTE,
                "bulk": True,
            },
        }

        logger.info(f"Authorization middleware initialized with {len(self.protected_endpoints)} protected endpoints")

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        """
        Main middleware dispatch method - validates authorization for protected endpoints
        """
        start_time = time.time()

        try:
            # Check if this endpoint requires authorization
            endpoint_pattern = self._get_endpoint_pattern(request)
            if not endpoint_pattern or endpoint_pattern not in self.protected_endpoints:
                # Not a protected endpoint, pass through
                return await call_next(request)

            logger.debug(f"Authorizing request: {request.method} {request.url.path}")

            # Get current user from token
            current_user = await self._extract_current_user(request)
            if not current_user:
                logger.warning(
                    f"Authorization failed: No authenticated user for {request.method} {sanitize_for_log(str(request.url.path))}"
                )
                return self._create_error_response(
                    status.HTTP_401_UNAUTHORIZED,
                    "Authentication required",
                    request.url.path,
                )

            # Get endpoint configuration
            endpoint_config = self.protected_endpoints[endpoint_pattern]

            # Extract resources from request
            resources = await self._extract_resources(request, endpoint_config, current_user)
            if not resources:
                logger.warning(
                    f"Authorization failed: Could not extract resources from request {request.method} {sanitize_for_log(str(request.url.path))}"
                )
                return self._create_error_response(
                    status.HTTP_400_BAD_REQUEST,
                    "Could not determine resources for authorization",
                    request.url.path,
                )

            # Create authorization context
            auth_context = await self._build_authorization_context(request, current_user)

            # Perform authorization check
            authorization_result = await self._perform_authorization_check(
                current_user["id"],
                resources,
                endpoint_config["action"],
                endpoint_config["bulk"],
                auth_context,
            )

            if authorization_result.overall_decision != AuthorizationDecision.ALLOW:
                logger.warning(
                    f"Authorization denied for user {sanitize_id_for_log(current_user['id'])} on {request.method} {sanitize_for_log(str(request.url.path))}: "
                    f"{len(authorization_result.denied_resources)} resources denied"
                )
                return self._create_authorization_error_response(authorization_result, request.url.path)

            # Authorization successful - add context to request for downstream use
            request.state.authorization_result = authorization_result
            request.state.current_user = current_user

            # Process the request
            response = await call_next(request)

            # Log successful authorization
            processing_time = int((time.time() - start_time) * 1000)
            logger.info(
                f"Authorization successful for user {sanitize_id_for_log(current_user['id'])} on {request.method} {sanitize_for_log(str(request.url.path))} "
                f"({len(authorization_result.allowed_resources)} resources, {processing_time}ms)"
            )

            return response

        except Exception as e:
            logger.error(f"Authorization middleware error: {e}")

            # Fail securely - deny access on any error
            return self._create_error_response(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                "Authorization system error",
                request.url.path if hasattr(request, "url") else "unknown",
            )

    def _get_endpoint_pattern(self, request: Request) -> Optional[str]:
        """
        Match request path to endpoint pattern for authorization
        """
        method = request.method
        path = request.url.path

        # Direct match first
        direct_pattern = f"{method} {path}"
        if direct_pattern in self.protected_endpoints:
            return direct_pattern

        # Pattern matching with path parameters
        for pattern in self.protected_endpoints.keys():
            if self._match_pattern(f"{method} {path}", pattern):
                return pattern

        return None

    def _match_pattern(self, request_path: str, pattern: str) -> bool:
        """
        Match request path against pattern with path parameters
        """
        request_parts = request_path.split("/")
        pattern_parts = pattern.split("/")

        if len(request_parts) != len(pattern_parts):
            return False

        for req_part, pat_part in zip(request_parts, pattern_parts):
            if pat_part.startswith("{") and pat_part.endswith("}"):
                # Path parameter - matches anything
                continue
            elif req_part != pat_part:
                return False

        return True

    async def _extract_current_user(self, request: Request) -> Optional[Dict[str, Any]]:
        """
        Extract current user from request authentication
        """
        try:
            # Check for Authorization header
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return None

            token = auth_header.split(" ", 1)[1]

            # Use existing auth system to validate token
            # This would integrate with your JWT validation logic
            from ..auth import decode_token

            payload = decode_token(token)
            if not payload:
                return None

            # Get user details from database
            db = next(get_db())
            try:
                from sqlalchemy import text

                result = db.execute(
                    text(
                        """
                    SELECT id, username, email, role, is_active
                    FROM users WHERE id = :user_id AND is_active = true
                """
                    ),
                    {"user_id": payload.get("sub")},
                )

                user_row = result.fetchone()
                if not user_row:
                    return None

                return {
                    "id": str(user_row.id),
                    "username": user_row.username,
                    "email": user_row.email,
                    "role": user_row.role,
                    "is_active": user_row.is_active,
                }
            finally:
                db.close()

        except Exception as e:
            logger.error(f"Error extracting current user: {e}")
            return None

    async def _extract_resources(
        self,
        request: Request,
        endpoint_config: Dict[str, Any],
        current_user: Dict[str, Any],
    ) -> List[ResourceIdentifier]:
        """
        Extract resource identifiers from request based on endpoint configuration
        """
        try:
            resources = []
            resource_type = endpoint_config["resource_type"]
            is_bulk = endpoint_config["bulk"]

            # Extract path parameters
            path_params = self._extract_path_params(request)

            if not is_bulk:
                # Single resource operation
                if resource_type == ResourceType.HOST:
                    host_id = path_params.get("host_id")
                    if host_id:
                        resources.append(ResourceIdentifier(resource_type=ResourceType.HOST, resource_id=host_id))
                    else:
                        # Check request body for host_id
                        body_host_id = await self._extract_host_id_from_body(request)
                        if body_host_id:
                            resources.append(
                                ResourceIdentifier(
                                    resource_type=ResourceType.HOST,
                                    resource_id=body_host_id,
                                )
                            )

                elif resource_type == ResourceType.SCAN:
                    scan_id = path_params.get("scan_id")
                    if scan_id:
                        # For scan operations, we need to get the associated host
                        host_id = await self._get_host_id_from_scan_id(scan_id)
                        if host_id:
                            resources.append(ResourceIdentifier(resource_type=ResourceType.HOST, resource_id=host_id))

                elif resource_type == ResourceType.HOST_GROUP:
                    group_id = path_params.get("group_id")
                    if group_id:
                        # For host group operations, get all hosts in the group
                        host_ids = await self._get_host_ids_from_group_id(group_id)
                        for host_id in host_ids:
                            resources.append(ResourceIdentifier(resource_type=ResourceType.HOST, resource_id=host_id))

            else:
                # Bulk operation - extract multiple hosts
                host_ids = await self._extract_bulk_host_ids(request, endpoint_config)
                for host_id in host_ids:
                    resources.append(ResourceIdentifier(resource_type=ResourceType.HOST, resource_id=host_id))

            logger.debug(f"Extracted {len(resources)} resources from request")
            return resources

        except Exception as e:
            logger.error(f"Error extracting resources: {e}")
            return []

    def _extract_path_params(self, request: Request) -> Dict[str, str]:
        """
        Extract path parameters from request URL
        """
        path_params = {}

        # Get path parameters from FastAPI's path_params if available
        if hasattr(request, "path_params"):
            path_params.update(request.path_params)

        return path_params

    async def _extract_host_id_from_body(self, request: Request) -> Optional[str]:
        """
        Extract host_id from request body
        """
        try:
            if request.headers.get("content-type", "").startswith("application/json"):
                body = await request.body()
                if body:
                    data = json.loads(body)
                    return data.get("host_id")
        except Exception as e:
            logger.error(f"Error extracting host_id from body: {e}")

        return None

    async def _get_host_id_from_scan_id(self, scan_id: str) -> Optional[str]:
        """
        Get host_id associated with a scan_id
        """
        try:
            db = next(get_db())
            try:
                from sqlalchemy import text

                result = db.execute(
                    text(
                        """
                    SELECT host_id FROM scans WHERE id = :scan_id
                """
                    ),
                    {"scan_id": scan_id},
                )

                row = result.fetchone()
                return str(row.host_id) if row else None
            finally:
                db.close()
        except Exception as e:
            logger.error(f"Error getting host_id from scan_id {scan_id}: {e}")
            return None

    async def _get_host_ids_from_group_id(self, group_id: str) -> List[str]:
        """
        Get all host_ids in a host group
        """
        try:
            db = next(get_db())
            try:
                from sqlalchemy import text

                result = db.execute(
                    text(
                        """
                    SELECT hgm.host_id
                    FROM host_group_memberships hgm
                    WHERE hgm.group_id = :group_id
                """
                    ),
                    {"group_id": group_id},
                )

                return [str(row.host_id) for row in result]
            finally:
                db.close()
        except Exception as e:
            logger.error(f"Error getting host_ids from group_id {group_id}: {e}")
            return []

    async def _extract_bulk_host_ids(self, request: Request, endpoint_config: Dict[str, Any]) -> List[str]:
        """
        Extract host IDs for bulk operations from request body
        """
        try:
            if request.headers.get("content-type", "").startswith("application/json"):
                body = await request.body()
                if body:
                    data = json.loads(body)

                    # Different bulk operations have different request structures
                    if "host_ids" in data:
                        return data["host_ids"]
                    elif "hosts" in data:
                        return [host.get("id") for host in data["hosts"] if host.get("id")]
                    elif "host_id" in data:
                        # Single host in bulk format
                        return [data["host_id"]]
                    elif "target_hosts" in data:
                        return data["target_hosts"]

        except Exception as e:
            logger.error(f"Error extracting bulk host IDs: {e}")

        return []

    async def _build_authorization_context(
        self, request: Request, current_user: Dict[str, Any]
    ) -> AuthorizationContext:
        """
        Build authorization context from request and user information
        """
        try:
            # Get user groups and roles
            db = next(get_db())
            try:
                from sqlalchemy import text

                result = db.execute(
                    text(
                        """
                    SELECT COALESCE(
                        JSON_AGG(DISTINCT ug.name) FILTER (WHERE ug.name IS NOT NULL),
                        '[]'::json
                    ) as user_groups
                    FROM users u
                    LEFT JOIN user_group_memberships ugm ON u.id = ugm.user_id
                    LEFT JOIN user_groups ug ON ugm.group_id = ug.id
                    WHERE u.id = :user_id
                    GROUP BY u.id
                """
                    ),
                    {"user_id": current_user["id"]},
                )

                row = result.fetchone()
                user_groups = json.loads(row.user_groups) if row and row.user_groups else []
            finally:
                db.close()

            return AuthorizationContext(
                user_id=current_user["id"],
                user_roles=[current_user["role"]] if current_user.get("role") else [],
                user_groups=user_groups,
                ip_address=self._get_client_ip(request),
                user_agent=request.headers.get("user-agent"),
                session_id=request.headers.get("x-session-id"),
            )

        except Exception as e:
            logger.error(f"Error building authorization context: {e}")
            return AuthorizationContext(
                user_id=current_user["id"],
                user_roles=[current_user.get("role", "guest")],
                user_groups=[],
            )

    def _get_client_ip(self, request: Request) -> str:
        """
        Get client IP address from request
        """
        # Check for forwarded headers first (behind proxy)
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip

        # Fallback to client IP
        if hasattr(request, "client") and request.client:
            return request.client.host

        return "unknown"

    async def _perform_authorization_check(
        self,
        user_id: str,
        resources: List[ResourceIdentifier],
        action: ActionType,
        is_bulk: bool,
        context: AuthorizationContext,
    ):
        """
        Perform the actual authorization check using the authorization service
        """
        try:
            db = next(get_db())
            try:
                auth_service = self.authorization_service_factory(db)

                if len(resources) == 1 and not is_bulk:
                    # Single resource check
                    result = await auth_service.check_permission(user_id, resources[0], action, context)

                    # Convert single result to bulk result format
                    from ..models.authorization_models import BulkAuthorizationResult

                    return BulkAuthorizationResult(
                        overall_decision=result.decision,
                        individual_results=[result],
                        denied_resources=([result.resource] if result.decision == AuthorizationDecision.DENY else []),
                        allowed_resources=([result.resource] if result.decision == AuthorizationDecision.ALLOW else []),
                        total_evaluation_time_ms=result.evaluation_time_ms,
                        cached_results=1 if result.cached else 0,
                        fresh_evaluations=0 if result.cached else 1,
                    )

                else:
                    # Bulk authorization check - CRITICAL SECURITY IMPLEMENTATION
                    bulk_request = BulkAuthorizationRequest(
                        user_id=user_id,
                        resources=resources,
                        action=action,
                        context=context,
                        fail_fast=True,  # Stop on first denial for security
                        parallel_evaluation=True,  # Enable parallel processing for performance
                    )

                    return await auth_service.check_bulk_permissions(bulk_request)

            finally:
                db.close()

        except Exception as e:
            logger.error(f"Authorization check failed: {e}")

            # Fail securely
            from ..models.authorization_models import BulkAuthorizationResult

            return BulkAuthorizationResult(
                overall_decision=AuthorizationDecision.DENY,
                individual_results=[],
                denied_resources=resources,
                allowed_resources=[],
                total_evaluation_time_ms=0,
                cached_results=0,
                fresh_evaluations=0,
            )

    def _create_error_response(self, status_code: int, message: str, path: str) -> JSONResponse:
        """
        Create standardized error response
        """
        return JSONResponse(
            status_code=status_code,
            content={
                "error": message,
                "path": path,
                "timestamp": datetime.utcnow().isoformat(),
                "type": "authorization_error",
            },
        )

    def _create_authorization_error_response(self, auth_result, path: str) -> JSONResponse:
        """
        Create detailed authorization error response
        """
        denied_resources = [
            {
                "resource_type": res.resource_type.value,
                "resource_id": res.resource_id,
                "reason": next(
                    (r.reason for r in auth_result.individual_results if r.resource.resource_id == res.resource_id),
                    "Access denied",
                ),
            }
            for res in auth_result.denied_resources
        ]

        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": "Insufficient permissions",
                "message": f"Access denied to {len(auth_result.denied_resources)} resource(s)",
                "denied_resources": denied_resources,
                "path": path,
                "timestamp": datetime.utcnow().isoformat(),
                "type": "authorization_denied",
            },
        )


# Factory function to create middleware with proper dependency injection
def create_authorization_middleware(app, authorization_service_factory: Callable = None):
    """
    Factory function to create authorization middleware instance
    """
    return AuthorizationMiddleware(app, authorization_service_factory)
