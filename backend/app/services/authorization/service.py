"""
Resource-Based Access Control (ReBAC) Authorization Service
Core service for per-host permission validation with Zero Trust principles

CRITICAL SECURITY VULNERABILITY FIX:
This service prevents users from initiating bulk scans across multiple hosts
without proper per-host authorization checks, eliminating unauthorized access
to systems outside their permission scope.

ZERO TRUST IMPLEMENTATION:
- Every operation is validated at the resource level
- No implicit trust or permissions
- Comprehensive audit trail for all decisions
- Least privilege enforcement
- Cross-host validation to prevent privilege escalation

Design by Emily (Security Engineer) & Implementation by Daniel (Backend Engineer)
"""

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.models.authorization_models import (
    ActionType,
    AuthorizationAuditEvent,
    AuthorizationConfiguration,
    AuthorizationContext,
    AuthorizationDecision,
    AuthorizationResult,
    BulkAuthorizationRequest,
    BulkAuthorizationResult,
    HostPermission,
    PermissionCache,
    PolicyConflictResolution,
    ResourceIdentifier,
    ResourceType,
)
from app.rbac import Permission, RBACManager, UserRole

logger = logging.getLogger(__name__)


def sanitize_for_log(value: Any) -> str:
    """Sanitize user input for safe logging."""
    if value is None:
        return "None"
    str_value = str(value)
    # Remove newlines and control characters to prevent log injection
    return str_value.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")[:1000]


class AuthorizationService:
    """
    Core authorization service implementing Zero Trust principles

    SECURITY FEATURES:
    1. Resource-Based Access Control (ReBAC) - Permission validation per resource
    2. Zero Trust Architecture - Verify at every operation boundary
    3. Authorization Audit Trail - Complete logging of all access decisions
    4. Least Privilege Enforcement - Users access only explicitly permitted resources
    5. Cross-Host Validation - Prevents privilege escalation through bulk operations
    """

    def __init__(self, db: Session, config: Optional[AuthorizationConfiguration] = None):
        self.db = db
        self.config = config or AuthorizationConfiguration()
        self.permission_cache = PermissionCache(
            ttl_seconds=self.config.cache_ttl_seconds,
            max_size=self.config.max_cache_size,
        )
        self.executor = ThreadPoolExecutor(max_workers=10)

        logger.info(f"Authorization service initialized with config: {self.config}")

    async def check_permission(
        self,
        user_id: str,
        resource: ResourceIdentifier,
        action: ActionType,
        context: Optional[AuthorizationContext] = None,
    ) -> AuthorizationResult:
        """
        Check if a user has permission to perform an action on a resource.

        ZERO TRUST PRINCIPLE: Every resource access must be explicitly validated.
        No assumptions or inheritance without verification.

        Args:
            user_id: User requesting access
            resource: Resource being accessed
            action: Action being performed
            context: Additional context for decision

        Returns:
            AuthorizationResult: Detailed authorization decision
        """
        start_time = time.time()

        try:
            # Create default context if not provided
            if context is None:
                context = await self._build_user_context(user_id)

            # Check cache first for performance
            if self.config.cache_ttl_seconds > 0:
                cached_result = self.permission_cache.get(user_id, resource, action)
                if cached_result:
                    logger.debug(f"Cache hit for {user_id}:{resource.resource_type}:{resource.resource_id}:{action}")
                    return cached_result

            # Perform authorization evaluation
            result = await self._evaluate_permission(user_id, resource, action, context)

            # Calculate evaluation time
            evaluation_time = int((time.time() - start_time) * 1000)
            result.evaluation_time_ms = evaluation_time

            # Cache positive results if caching enabled
            if self.config.cache_ttl_seconds > 0 and result.decision == AuthorizationDecision.ALLOW:
                self.permission_cache.put(user_id, resource, action, result)

            # Audit log the decision
            if self.config.enable_audit_logging:
                await self._audit_authorization_decision(result, context)

            # Log security-relevant decisions
            if result.decision == AuthorizationDecision.DENY:
                logger.warning(
                    f"ACCESS DENIED: User {user_id} denied {action} on {resource.resource_type}:{resource.resource_id} - {sanitize_for_log(result.reason)}"  # noqa: E501
                )
            else:
                logger.debug(
                    f"ACCESS GRANTED: User {user_id} allowed {action} on {resource.resource_type}:{resource.resource_id}"  # noqa: E501
                )

            return result

        except Exception as e:
            logger.error(f"Authorization check failed for user {user_id}: {e}")

            # Fail securely - deny access on error
            return AuthorizationResult(
                decision=AuthorizationDecision.DENY,
                resource=resource,
                action=action,
                context=context or AuthorizationContext(user_id=user_id, user_roles=[], user_groups=[]),
                applied_policies=[],
                reason=f"Authorization system error: {str(e)}",
                confidence_score=0.0,
                evaluation_time_ms=int((time.time() - start_time) * 1000),
            )

    async def check_bulk_permissions(self, request: BulkAuthorizationRequest) -> BulkAuthorizationResult:
        """
        Check permissions for multiple resources in bulk.

        CRITICAL SECURITY FIX: This method prevents the vulnerability where
        bulk operations bypass per-host authorization checks.

        Each resource is individually validated to ensure users cannot
        access systems outside their permission scope.

        Args:
            request: Bulk authorization request

        Returns:
            BulkAuthorizationResult: Results for all resources
        """
        start_time = time.time()

        logger.info(
            f"Bulk authorization check for user {request.user_id}: {len(request.resources)} resources, action {request.action}"  # noqa: E501
        )

        try:
            individual_results = []
            denied_resources = []
            allowed_resources = []
            cached_count = 0
            fresh_count = 0

            # Process resources based on configuration
            if request.parallel_evaluation and len(request.resources) >= self.config.parallel_evaluation_threshold:
                # Parallel evaluation for large requests
                individual_results = await self._evaluate_parallel_permissions(
                    request.user_id, request.resources, request.action, request.context
                )
            else:
                # Sequential evaluation
                for resource in request.resources:
                    result = await self.check_permission(request.user_id, resource, request.action, request.context)
                    individual_results.append(result)

                    if result.cached:
                        cached_count += 1
                    else:
                        fresh_count += 1

                    # Fail fast if configured and we hit a deny
                    if request.fail_fast and result.decision == AuthorizationDecision.DENY:
                        logger.info(f"Fail-fast triggered: Access denied for resource {resource.resource_id}")
                        # Still need to create placeholder results for remaining resources
                        remaining_resources = request.resources[len(individual_results) :]
                        for remaining_resource in remaining_resources:
                            individual_results.append(
                                AuthorizationResult(
                                    decision=AuthorizationDecision.DENY,
                                    resource=remaining_resource,
                                    action=request.action,
                                    context=request.context,
                                    applied_policies=[],
                                    reason="Bulk operation failed fast on previous denial",
                                    confidence_score=1.0,
                                )
                            )
                        break

            # Categorize results
            for result in individual_results:
                if result.decision == AuthorizationDecision.ALLOW:
                    allowed_resources.append(result.resource)
                else:
                    denied_resources.append(result.resource)

            # Determine overall decision
            overall_decision = AuthorizationDecision.ALLOW if len(denied_resources) == 0 else AuthorizationDecision.DENY

            total_time = int((time.time() - start_time) * 1000)

            # Audit bulk authorization attempt
            if self.config.enable_audit_logging:
                await self._audit_bulk_authorization(
                    request,
                    overall_decision,
                    len(allowed_resources),
                    len(denied_resources),
                    total_time,
                )

            result = BulkAuthorizationResult(
                overall_decision=overall_decision,
                individual_results=individual_results,
                denied_resources=denied_resources,
                allowed_resources=allowed_resources,
                total_evaluation_time_ms=total_time,
                cached_results=cached_count,
                fresh_evaluations=fresh_count,
            )

            logger.info(
                f"Bulk authorization completed: {overall_decision.value} "
                f"({len(allowed_resources)} allowed, {len(denied_resources)} denied) "
                f"in {total_time}ms"
            )

            return result

        except Exception as e:
            logger.error(f"Bulk authorization failed: {e}")

            # Fail securely
            return BulkAuthorizationResult(
                overall_decision=AuthorizationDecision.DENY,
                individual_results=[
                    AuthorizationResult(
                        decision=AuthorizationDecision.DENY,
                        resource=resource,
                        action=request.action,
                        context=request.context,
                        applied_policies=[],
                        reason=f"Bulk authorization system error: {str(e)}",
                        confidence_score=0.0,
                    )
                    for resource in request.resources
                ],
                denied_resources=request.resources,
                allowed_resources=[],
                total_evaluation_time_ms=int((time.time() - start_time) * 1000),
                cached_results=0,
                fresh_evaluations=0,
            )

    async def _evaluate_permission(
        self,
        user_id: str,
        resource: ResourceIdentifier,
        action: ActionType,
        context: AuthorizationContext,
    ) -> AuthorizationResult:
        """
        Core permission evaluation logic implementing Zero Trust principles
        """
        applied_policies = []

        try:
            # Step 1: Check if user exists and is active
            user_valid = await self._validate_user(user_id)
            if not user_valid:
                return AuthorizationResult(
                    decision=AuthorizationDecision.DENY,
                    resource=resource,
                    action=action,
                    context=context,
                    applied_policies=[],
                    reason="User not found or inactive",
                )

            # Step 2: Get all applicable policies for this request
            policies = await self._get_applicable_policies(user_id, resource, action, context)

            # Step 3: Evaluate policies using conflict resolution strategy
            decision, reason = self._evaluate_policies(policies)
            applied_policies = policies

            # Step 4: Apply role-based permissions as additional validation
            role_decision = await self._evaluate_role_permissions(user_id, resource, action, context)

            # Step 5: Combine policy and role decisions
            final_decision, final_reason = self._combine_decisions(
                policy_decision=(decision, reason), role_decision=role_decision
            )

            return AuthorizationResult(
                decision=final_decision,
                resource=resource,
                action=action,
                context=context,
                applied_policies=applied_policies,
                reason=final_reason,
                confidence_score=1.0,
            )

        except Exception as e:
            logger.error(f"Permission evaluation error: {e}")

            return AuthorizationResult(
                decision=AuthorizationDecision.DENY,
                resource=resource,
                action=action,
                context=context,
                applied_policies=applied_policies,
                reason=f"Evaluation error: {str(e)}",
                confidence_score=0.0,
            )

    def _get_applicable_policies(
        self,
        user_id: str,
        resource: ResourceIdentifier,
        action: ActionType,
        context: AuthorizationContext,
    ) -> List[Dict]:
        """
        Get all policies that apply to this permission check
        """
        try:
            # Build query to find applicable policies
            query = text("""
                SELECT
                    hp.id, hp.user_id, hp.group_id, hp.role_name, hp.host_id,
                    hp.actions, hp.effect, hp.conditions, hp.granted_by,
                    hp.granted_at, hp.expires_at, 'host_permission' as policy_type
                FROM host_permissions hp
                WHERE hp.is_active = true
                    AND (hp.expires_at IS NULL OR hp.expires_at > :now)
                    AND (
                        (hp.user_id = :user_id) OR
                        (hp.group_id IN :user_groups) OR
                        (hp.role_name IN :user_roles)
                    )
                    AND (
                        (hp.host_id = :resource_id) OR
                        (hp.host_id IN (
                            SELECT hgm.host_id FROM host_group_memberships hgm
                            WHERE hgm.group_id IN (
                                SELECT hgp.host_group_id FROM host_group_permissions hgp
                                WHERE hgp.is_active = true
                                    AND (hgp.expires_at IS NULL OR hgp.expires_at > :now)
                                    AND hgp.inherit_to_hosts = true
                                    AND (
                                        (hgp.user_id = :user_id) OR
                                        (hgp.group_id IN :user_groups) OR
                                        (hgp.role_name IN :user_roles)
                                    )
                            )
                        ))
                    )

                UNION ALL

                SELECT
                    hgp.id, hgp.user_id, hgp.group_id, hgp.role_name, hgp.host_group_id as host_id,
                    hgp.actions, hgp.effect, hgp.conditions, hgp.granted_by,
                    hgp.granted_at, hgp.expires_at, 'host_group_permission' as policy_type
                FROM host_group_permissions hgp
                WHERE hgp.is_active = true
                    AND (hgp.expires_at IS NULL OR hgp.expires_at > :now)
                    AND hgp.inherit_to_hosts = true
                    AND (
                        (hgp.user_id = :user_id) OR
                        (hgp.group_id IN :user_groups) OR
                        (hgp.role_name IN :user_roles)
                    )
                    AND hgp.host_group_id IN (
                        SELECT hgm.group_id FROM host_group_memberships hgm
                        WHERE hgm.host_id = :resource_id
                    )

                ORDER BY granted_at DESC
            """)

            # Convert user groups and roles to tuples for SQL IN clause
            user_groups = tuple(context.user_groups) if context.user_groups else (None,)
            user_roles = tuple(context.user_roles) if context.user_roles else (None,)

            result = self.db.execute(
                query,
                {
                    "user_id": user_id,
                    "resource_id": resource.resource_id,
                    "user_groups": user_groups,
                    "user_roles": user_roles,
                    "now": datetime.utcnow(),
                },
            )

            policies = []
            for row in result:
                # Parse actions from JSON/string format
                try:
                    import json

                    actions = json.loads(row.actions) if isinstance(row.actions, str) else row.actions
                except Exception:
                    actions = [row.actions] if row.actions else []

                # Check if this policy applies to the requested action
                if action.value in actions or "all" in actions:
                    policies.append(
                        {
                            "id": row.id,
                            "user_id": row.user_id,
                            "group_id": row.group_id,
                            "role_name": row.role_name,
                            "resource_id": row.host_id,
                            "actions": actions,
                            "effect": row.effect,
                            "conditions": row.conditions,
                            "policy_type": row.policy_type,
                            "granted_by": row.granted_by,
                            "granted_at": row.granted_at,
                        }
                    )

            logger.debug(
                f"Found {len(policies)} applicable policies for user {user_id} on resource {resource.resource_id}"
            )
            return policies

        except Exception as e:
            logger.error(f"Error getting applicable policies: {e}")
            return []

    def _evaluate_policies(self, policies: List[Dict]) -> Tuple[AuthorizationDecision, str]:
        """
        Evaluate policies based on conflict resolution strategy
        """
        if not policies:
            return AuthorizationDecision.DENY, "No applicable policies found"

        allow_policies = [p for p in policies if p["effect"] == "allow"]
        deny_policies = [p for p in policies if p["effect"] == "deny"]

        if self.config.conflict_resolution == PolicyConflictResolution.DENY_OVERRIDES:
            if deny_policies:
                return (
                    AuthorizationDecision.DENY,
                    f"Access explicitly denied by {len(deny_policies)} deny policies",
                )
            elif allow_policies:
                return (
                    AuthorizationDecision.ALLOW,
                    f"Access granted by {len(allow_policies)} allow policies",
                )

        elif self.config.conflict_resolution == PolicyConflictResolution.ALLOW_OVERRIDES:
            if allow_policies:
                return (
                    AuthorizationDecision.ALLOW,
                    f"Access granted by {len(allow_policies)} allow policies",
                )
            elif deny_policies:
                return (
                    AuthorizationDecision.DENY,
                    f"Access denied by {len(deny_policies)} deny policies",
                )

        return self.config.default_decision, "Applied default decision"

    def _evaluate_role_permissions(
        self,
        user_id: str,
        resource: ResourceIdentifier,
        action: ActionType,
        context: AuthorizationContext,
    ) -> Tuple[AuthorizationDecision, str]:
        """
        Evaluate role-based permissions as additional validation layer
        """
        try:
            # Map action types to RBAC permissions
            action_permission_map = {
                ActionType.READ: Permission.HOST_READ,
                ActionType.SCAN: Permission.SCAN_EXECUTE,
                ActionType.EXECUTE: Permission.SCAN_EXECUTE,
                ActionType.WRITE: Permission.HOST_UPDATE,
                ActionType.DELETE: Permission.HOST_DELETE,
                ActionType.MANAGE: Permission.HOST_MANAGE_ACCESS,
            }

            required_permission = action_permission_map.get(action)
            if not required_permission:
                return (
                    AuthorizationDecision.DENY,
                    f"No role permission mapping for action {action}",
                )

            # Check if any user role has the required permission
            for role_name in context.user_roles:
                try:
                    user_role = UserRole(role_name)
                    if RBACManager.has_permission(user_role, required_permission):
                        return (
                            AuthorizationDecision.ALLOW,
                            f"Role {role_name} has permission {required_permission.value}",
                        )
                except ValueError:
                    logger.warning(f"Unknown role: {role_name}")
                    continue

            return (
                AuthorizationDecision.DENY,
                f"No user role has permission {required_permission.value}",
            )

        except Exception as e:
            logger.error(f"Role permission evaluation error: {e}")
            return AuthorizationDecision.DENY, f"Role evaluation error: {str(e)}"

    def _combine_decisions(
        self,
        policy_decision: Tuple[AuthorizationDecision, str],
        role_decision: Tuple[AuthorizationDecision, str],
    ) -> Tuple[AuthorizationDecision, str]:
        """
        Combine policy-based and role-based authorization decisions
        """
        policy_allow = policy_decision[0] == AuthorizationDecision.ALLOW
        role_allow = role_decision[0] == AuthorizationDecision.ALLOW

        # Both must allow for final allow decision (Zero Trust principle)
        if policy_allow and role_allow:
            return (
                AuthorizationDecision.ALLOW,
                f"Both policy and role checks passed: {policy_decision[1]} AND {role_decision[1]}",
            )

        # If either denies, deny access
        if not policy_allow and not role_allow:
            return (
                AuthorizationDecision.DENY,
                f"Both policy and role checks failed: {policy_decision[1]} AND {role_decision[1]}",
            )
        elif not policy_allow:
            return (
                AuthorizationDecision.DENY,
                f"Policy check failed: {policy_decision[1]}",
            )
        else:
            return AuthorizationDecision.DENY, f"Role check failed: {role_decision[1]}"

    def _build_user_context(self, user_id: str) -> AuthorizationContext:
        """
        Build authorization context for a user
        """
        try:
            # Get user information including roles and groups
            result = self.db.execute(
                text("""
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
            """),
                {"user_id": user_id},
            )

            row = result.fetchone()
            if not row:
                return AuthorizationContext(user_id=user_id, user_roles=[], user_groups=[])

            import json

            user_groups = json.loads(row.user_groups) if row.user_groups else []

            return AuthorizationContext(
                user_id=user_id,
                user_roles=[row.role] if row.role else [],
                user_groups=user_groups,
            )

        except Exception as e:
            logger.error(f"Error building user context for {user_id}: {e}")
            return AuthorizationContext(user_id=user_id, user_roles=[], user_groups=[])

    def _validate_user(self, user_id: str) -> bool:
        """
        Validate user exists and is active
        """
        try:
            result = self.db.execute(
                text("""
                SELECT id FROM users WHERE id = :user_id AND is_active = true
            """),
                {"user_id": user_id},
            )

            return result.fetchone() is not None

        except Exception as e:
            logger.error(f"User validation error for {user_id}: {e}")
            return False

    def _audit_authorization_decision(self, result: AuthorizationResult, context: AuthorizationContext):
        """
        Audit authorization decisions for security monitoring
        """
        try:
            audit_event = AuthorizationAuditEvent(
                event_type="permission_check",
                user_id=result.context.user_id,
                resource_type=result.resource.resource_type,
                resource_id=result.resource.resource_id,
                action=result.action,
                decision=result.decision,
                policies_evaluated=[p.get("id", "unknown") for p in result.applied_policies],
                context={
                    "user_roles": context.user_roles,
                    "user_groups": context.user_groups,
                    "ip_address": context.ip_address,
                    "user_agent": context.user_agent,
                    "session_id": context.session_id,
                },
                ip_address=context.ip_address,
                user_agent=context.user_agent,
                session_id=context.session_id,
                evaluation_time_ms=result.evaluation_time_ms,
                reason=result.reason,
                risk_score=self._calculate_risk_score(result),
            )

            # Store audit event in database
            self.db.execute(
                text("""
                INSERT INTO authorization_audit_log
                (id, event_type, user_id, resource_type, resource_id, action, decision,
                 policies_evaluated, context, ip_address, user_agent, session_id,
                 evaluation_time_ms, reason, risk_score, timestamp)
                VALUES (:id, :event_type, :user_id, :resource_type, :resource_id, :action,
                        :decision, :policies_evaluated, :context, :ip_address, :user_agent,
                        :session_id, :evaluation_time_ms, :reason, :risk_score, :timestamp)
            """),
                {
                    "id": audit_event.id,
                    "event_type": audit_event.event_type,
                    "user_id": audit_event.user_id,
                    "resource_type": audit_event.resource_type.value,
                    "resource_id": audit_event.resource_id,
                    "action": audit_event.action.value,
                    "decision": audit_event.decision.value,
                    "policies_evaluated": ",".join(audit_event.policies_evaluated),
                    "context": str(audit_event.context),
                    "ip_address": audit_event.ip_address,
                    "user_agent": audit_event.user_agent,
                    "session_id": audit_event.session_id,
                    "evaluation_time_ms": audit_event.evaluation_time_ms,
                    "reason": audit_event.reason,
                    "risk_score": audit_event.risk_score,
                    "timestamp": audit_event.timestamp,
                },
            )

            self.db.commit()

        except Exception as e:
            logger.error(f"Failed to audit authorization decision: {e}")

    def _audit_bulk_authorization(
        self,
        request: BulkAuthorizationRequest,
        decision: AuthorizationDecision,
        allowed_count: int,
        denied_count: int,
        evaluation_time_ms: int,
    ):
        """
        Audit bulk authorization attempts
        """
        try:
            audit_event = AuthorizationAuditEvent(
                event_type="bulk_permission_check",
                user_id=request.user_id,
                resource_type=ResourceType.HOST,  # Assuming bulk operations are typically on hosts
                resource_id=f"bulk_{len(request.resources)}_resources",
                action=request.action,
                decision=decision,
                policies_evaluated=[],
                context={
                    "resource_count": len(request.resources),
                    "allowed_count": allowed_count,
                    "denied_count": denied_count,
                    "fail_fast": request.fail_fast,
                    "parallel_evaluation": request.parallel_evaluation,
                },
                ip_address=request.context.ip_address,
                user_agent=request.context.user_agent,
                session_id=request.context.session_id,
                evaluation_time_ms=evaluation_time_ms,
                reason=f"Bulk authorization: {allowed_count} allowed, {denied_count} denied",
                risk_score=self._calculate_bulk_risk_score(denied_count, len(request.resources)),
            )

            # Store bulk audit event
            self.db.execute(
                text("""
                INSERT INTO authorization_audit_log
                (id, event_type, user_id, resource_type, resource_id, action, decision,
                 policies_evaluated, context, ip_address, user_agent, session_id,
                 evaluation_time_ms, reason, risk_score, timestamp)
                VALUES (:id, :event_type, :user_id, :resource_type, :resource_id, :action,
                        :decision, :policies_evaluated, :context, :ip_address, :user_agent,
                        :session_id, :evaluation_time_ms, :reason, :risk_score, :timestamp)
            """),
                {
                    "id": audit_event.id,
                    "event_type": audit_event.event_type,
                    "user_id": audit_event.user_id,
                    "resource_type": audit_event.resource_type.value,
                    "resource_id": audit_event.resource_id,
                    "action": audit_event.action.value,
                    "decision": audit_event.decision.value,
                    "policies_evaluated": "",
                    "context": str(audit_event.context),
                    "ip_address": audit_event.ip_address,
                    "user_agent": audit_event.user_agent,
                    "session_id": audit_event.session_id,
                    "evaluation_time_ms": audit_event.evaluation_time_ms,
                    "reason": audit_event.reason,
                    "risk_score": audit_event.risk_score,
                    "timestamp": audit_event.timestamp,
                },
            )

            self.db.commit()

        except Exception as e:
            logger.error(f"Failed to audit bulk authorization: {e}")

    def _calculate_risk_score(self, result: AuthorizationResult) -> float:
        """
        Calculate risk score for authorization decision
        """
        if not self.config.enable_risk_scoring:
            return 0.0

        risk_score = 0.0

        # Higher risk for denied access attempts
        if result.decision == AuthorizationDecision.DENY:
            risk_score += 0.3

        # Higher risk for sensitive actions
        if result.action in [ActionType.DELETE, ActionType.MANAGE]:
            risk_score += 0.2

        # Higher risk for system-level resources
        if result.resource.resource_type == ResourceType.SYSTEM:
            risk_score += 0.3

        # Higher risk for long evaluation times (possible attack)
        if result.evaluation_time_ms > 500:
            risk_score += 0.2

        return min(1.0, risk_score)

    def _calculate_bulk_risk_score(self, denied_count: int, total_count: int) -> float:
        """
        Calculate risk score for bulk operations
        """
        if total_count == 0:
            return 0.0

        denial_ratio = denied_count / total_count

        # High denial ratio indicates possible unauthorized access attempt
        if denial_ratio > 0.5:
            return 0.8
        elif denial_ratio > 0.2:
            return 0.5
        elif denied_count > 0:
            return 0.3
        else:
            return 0.1

    async def _evaluate_parallel_permissions(
        self,
        user_id: str,
        resources: List[ResourceIdentifier],
        action: ActionType,
        context: AuthorizationContext,
    ) -> List[AuthorizationResult]:
        """
        Evaluate permissions for multiple resources in parallel
        """
        try:
            tasks = []
            for resource in resources:
                task = self.check_permission(user_id, resource, action, context)
                tasks.append(task)

            results = await asyncio.gather(*tasks, return_exceptions=True)

            valid_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    # Handle exceptions by creating deny result
                    valid_results.append(
                        AuthorizationResult(
                            decision=AuthorizationDecision.DENY,
                            resource=resources[i],
                            action=action,
                            context=context,
                            applied_policies=[],
                            reason=f"Parallel evaluation error: {str(result)}",
                            confidence_score=0.0,
                        )
                    )
                else:
                    valid_results.append(result)

            return valid_results

        except Exception as e:
            logger.error(f"Parallel permission evaluation failed: {e}")
            # Return deny results for all resources
            return [
                AuthorizationResult(
                    decision=AuthorizationDecision.DENY,
                    resource=resource,
                    action=action,
                    context=context,
                    applied_policies=[],
                    reason=f"Parallel evaluation system error: {str(e)}",
                    confidence_score=0.0,
                )
                for resource in resources
            ]

    # Permission Management Methods

    def grant_host_permission(
        self,
        user_id: Optional[str],
        group_id: Optional[str],
        role_name: Optional[str],
        host_id: str,
        actions: Set[ActionType],
        granted_by: str,
        expires_at: Optional[datetime] = None,
        conditions: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Grant permission for a specific host
        """
        try:
            permission = HostPermission(
                user_id=user_id,
                group_id=group_id,
                role_name=role_name,
                host_id=host_id,
                actions=actions,
                granted_by=granted_by,
                expires_at=expires_at,
                conditions=conditions or {},
            )

            # Store in database
            import json

            self.db.execute(
                text("""
                INSERT INTO host_permissions
                (id, user_id, group_id, role_name, host_id, actions, effect, conditions,
                 granted_by, granted_at, expires_at, is_active)
                VALUES (:id, :user_id, :group_id, :role_name, :host_id, :actions, :effect,
                        :conditions, :granted_by, :granted_at, :expires_at, :is_active)
            """),
                {
                    "id": permission.id,
                    "user_id": permission.user_id,
                    "group_id": permission.group_id,
                    "role_name": permission.role_name,
                    "host_id": permission.host_id,
                    "actions": json.dumps(list(actions)),
                    "effect": permission.effect.value,
                    "conditions": json.dumps(permission.conditions),
                    "granted_by": permission.granted_by,
                    "granted_at": permission.granted_at,
                    "expires_at": permission.expires_at,
                    "is_active": permission.is_active,
                },
            )

            self.db.commit()

            # Invalidate cache for affected user/resource
            if user_id:
                self.permission_cache.invalidate_user(user_id)

            resource = ResourceIdentifier(ResourceType.HOST, host_id)
            self.permission_cache.invalidate_resource(resource)

            logger.info(f"Granted host permission {permission.id} for host {host_id}")
            return permission.id

        except Exception as e:
            logger.error(f"Failed to grant host permission: {e}")
            self.db.rollback()
            raise

    def revoke_permission(self, permission_id: str) -> bool:
        """
        Revoke a specific permission
        """
        try:
            result = self.db.execute(
                text("""
                UPDATE host_permissions
                SET is_active = false, updated_at = :now
                WHERE id = :permission_id
            """),
                {"permission_id": permission_id, "now": datetime.utcnow()},
            )

            if result.rowcount == 0:
                # Try host group permissions
                result = self.db.execute(
                    text("""
                    UPDATE host_group_permissions
                    SET is_active = false, updated_at = :now
                    WHERE id = :permission_id
                """),
                    {"permission_id": permission_id, "now": datetime.utcnow()},
                )

            self.db.commit()

            if result.rowcount > 0:
                # Clear entire cache since we don't know which users/resources were affected
                self.permission_cache.clear()
                logger.info(f"Revoked permission {sanitize_for_log(permission_id)}")
                return True
            else:
                logger.warning(f"Permission {sanitize_for_log(permission_id)} not found for revocation")
                return False

        except Exception as e:
            logger.error(f"Failed to revoke permission {sanitize_for_log(permission_id)}: {type(e).__name__}")
            self.db.rollback()
            return False


# Factory function
def get_authorization_service(db: Session, config: Optional[AuthorizationConfiguration] = None) -> AuthorizationService:
    """Factory function to create AuthorizationService instance"""
    return AuthorizationService(db, config)
