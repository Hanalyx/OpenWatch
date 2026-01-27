"""
Resource-Based Access Control (ReBAC) Models for OpenWatch
Defines data structures for resource-based permissions and authorization policies

SECURITY REQUIREMENT: Implement Zero Trust principles where every operation
is validated at the resource level, preventing privilege escalation through
bulk operations and ensuring least privilege enforcement.

Design by Emily (Security Engineer) - Implements ReBAC with audit trail
"""

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, Field


class ResourceType(str, Enum):
    """Types of resources that can be protected by authorization"""

    HOST = "host"
    HOST_GROUP = "host_group"
    SCAN = "scan"
    SCAP_CONTENT = "scap_content"
    SYSTEM = "system"


class ActionType(str, Enum):
    """Actions that can be performed on resources"""

    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    DELETE = "delete"
    MANAGE = "manage"  # Administrative actions
    SCAN = "scan"  # Specific to scan operations
    EXPORT = "export"  # Data export operations


class PermissionEffect(str, Enum):
    """Effect of a permission policy"""

    ALLOW = "allow"
    DENY = "deny"


class PermissionScope(str, Enum):
    """Scope of permission application"""

    DIRECT = "direct"  # Direct resource access
    INHERITED = "inherited"  # Inherited from parent resource
    GROUP = "group"  # Through group membership
    ROLE = "role"  # Through role assignment


class AuthorizationDecision(str, Enum):
    """Final authorization decision"""

    ALLOW = "allow"
    DENY = "deny"
    NOT_APPLICABLE = "not_applicable"


@dataclass
class ResourceIdentifier:
    """Identifies a specific resource for authorization"""

    resource_type: ResourceType
    resource_id: str
    parent_resource_id: Optional[str] = None
    attributes: Optional[Dict[str, Any]] = None

    def __post_init__(self) -> None:
        """Initialize default values for mutable fields."""
        if self.attributes is None:
            self.attributes = {}


@dataclass
class PermissionPolicy:
    """Defines a specific permission policy"""

    subject_type: str  # user, group, role
    subject_id: str
    resource_type: ResourceType
    action: ActionType
    effect: PermissionEffect
    scope: PermissionScope
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    resource_id: Optional[str] = None  # None means all resources of this type
    conditions: Optional[Dict[str, Any]] = None
    priority: int = 0  # Higher priority policies override lower priority
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    created_by: Optional[str] = None
    is_active: bool = True

    def __post_init__(self) -> None:
        """Initialize default values for mutable fields."""
        if self.conditions is None:
            self.conditions = {}


@dataclass
class AuthorizationContext:
    """Context information for authorization decisions"""

    user_id: str
    user_roles: List[str]
    user_groups: List[str]
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    request_time: datetime = Field(default_factory=datetime.utcnow)
    additional_attributes: Optional[Dict[str, Any]] = None

    def __post_init__(self) -> None:
        """Initialize default values for mutable fields."""
        if self.additional_attributes is None:
            self.additional_attributes = {}


@dataclass
class AuthorizationResult:
    """Result of an authorization check"""

    decision: AuthorizationDecision
    resource: ResourceIdentifier
    action: ActionType
    context: AuthorizationContext
    applied_policies: List[PermissionPolicy]
    reason: str
    confidence_score: float = 1.0  # 0.0 to 1.0
    cached: bool = False
    evaluation_time_ms: int = 0
    check_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class BulkAuthorizationRequest(BaseModel):
    """Request for bulk authorization checking"""

    user_id: str
    resources: List[ResourceIdentifier]
    action: ActionType
    context: AuthorizationContext
    fail_fast: bool = True  # Stop on first deny
    parallel_evaluation: bool = True  # Evaluate permissions in parallel


class BulkAuthorizationResult(BaseModel):
    """Result of bulk authorization check"""

    overall_decision: AuthorizationDecision
    individual_results: List[AuthorizationResult]
    denied_resources: List[ResourceIdentifier]
    allowed_resources: List[ResourceIdentifier]
    total_evaluation_time_ms: int
    cached_results: int
    fresh_evaluations: int


class HostPermission(BaseModel):
    """Specific host permission model"""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: Optional[str] = None
    group_id: Optional[str] = None
    role_name: Optional[str] = None
    host_id: str
    actions: Set[ActionType]
    effect: PermissionEffect = PermissionEffect.ALLOW
    conditions: Dict[str, Any] = Field(default_factory=dict)
    granted_by: str
    granted_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    is_active: bool = True


class HostGroupPermission(BaseModel):
    """Host group permission model"""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: Optional[str] = None
    group_id: Optional[str] = None
    role_name: Optional[str] = None
    host_group_id: str
    actions: Set[ActionType]
    effect: PermissionEffect = PermissionEffect.ALLOW
    inherit_to_hosts: bool = True  # Whether permissions propagate to individual hosts
    conditions: Dict[str, Any] = Field(default_factory=dict)
    granted_by: str
    granted_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    is_active: bool = True


class AuthorizationAuditEvent(BaseModel):
    """Audit event for authorization decisions"""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str  # permission_check, policy_created, access_granted, access_denied
    user_id: str
    resource_type: ResourceType
    resource_id: Optional[str]
    action: ActionType
    decision: AuthorizationDecision
    policies_evaluated: List[str]  # List of policy IDs
    context: Dict[str, Any]
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    evaluation_time_ms: int = 0
    reason: str
    risk_score: float = 0.0  # 0.0 = low risk, 1.0 = high risk
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class PolicyConflictResolution(str, Enum):
    """How to resolve conflicting policies"""

    DENY_OVERRIDES = "deny_overrides"  # Deny takes precedence
    ALLOW_OVERRIDES = "allow_overrides"  # Allow takes precedence
    FIRST_MATCH = "first_match"  # First matching policy wins
    PRIORITY_ORDER = "priority_order"  # Higher priority wins


class AuthorizationConfiguration(BaseModel):
    """Authorization system configuration"""

    default_decision: AuthorizationDecision = AuthorizationDecision.DENY
    conflict_resolution: PolicyConflictResolution = PolicyConflictResolution.DENY_OVERRIDES
    cache_ttl_seconds: int = 300  # 5 minutes
    max_cache_size: int = 10000
    enable_audit_logging: bool = True
    enable_risk_scoring: bool = True
    parallel_evaluation_threshold: int = 10  # Min resources for parallel evaluation
    max_evaluation_time_ms: int = 1000  # Max time allowed for evaluation
    enable_policy_inheritance: bool = True
    enable_group_permissions: bool = True


# Database Models for SQLAlchemy
class AuthorizationPolicy(BaseModel):
    """Database model for authorization policies"""

    id: str
    name: str
    description: Optional[str]
    subject_type: str
    subject_id: str
    resource_type: str
    resource_id: Optional[str]
    action: str
    effect: str
    scope: str
    conditions: Dict[str, Any]
    priority: int
    is_active: bool
    created_by: str
    created_at: datetime
    updated_at: datetime
    expires_at: Optional[datetime]


class PermissionCache:
    """In-memory cache for permission decisions"""

    def __init__(self, ttl_seconds: int = 300, max_size: int = 10000) -> None:
        """Initialize the permission cache."""
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.ttl_seconds = ttl_seconds
        self.max_size = max_size
        self.access_times: Dict[str, datetime] = {}

    def _generate_key(self, user_id: str, resource: ResourceIdentifier, action: ActionType) -> str:
        """Generate cache key for permission check"""
        return f"{user_id}:{resource.resource_type.value}:{resource.resource_id}:{action.value}"

    def get(self, user_id: str, resource: ResourceIdentifier, action: ActionType) -> Optional[AuthorizationResult]:
        """Get cached permission decision"""
        key = self._generate_key(user_id, resource, action)

        if key not in self.cache:
            return None

        cached_item = self.cache[key]
        cached_time = cached_item.get("timestamp")

        if not cached_time or datetime.utcnow() - cached_time > timedelta(seconds=self.ttl_seconds):
            # Cache expired
            del self.cache[key]
            if key in self.access_times:
                del self.access_times[key]
            return None

        # Update access time
        self.access_times[key] = datetime.utcnow()

        result = cached_item.get("result")
        if result:
            result.cached = True

        return result

    def put(
        self,
        user_id: str,
        resource: ResourceIdentifier,
        action: ActionType,
        result: AuthorizationResult,
    ) -> None:
        """Cache permission decision."""
        if len(self.cache) >= self.max_size:
            self._evict_least_recently_used()

        key = self._generate_key(user_id, resource, action)
        self.cache[key] = {"result": result, "timestamp": datetime.utcnow()}
        self.access_times[key] = datetime.utcnow()

    def invalidate_user(self, user_id: str) -> None:
        """Invalidate all cached permissions for a user."""
        keys_to_remove = [k for k in self.cache.keys() if k.startswith(f"{user_id}:")]
        for key in keys_to_remove:
            del self.cache[key]
            if key in self.access_times:
                del self.access_times[key]

    def invalidate_resource(self, resource: ResourceIdentifier) -> None:
        """Invalidate all cached permissions for a resource."""
        resource_prefix = f"{resource.resource_type.value}:{resource.resource_id}"
        keys_to_remove = [k for k in self.cache.keys() if resource_prefix in k]
        for key in keys_to_remove:
            del self.cache[key]
            if key in self.access_times:
                del self.access_times[key]

    def clear(self) -> None:
        """Clear all cached permissions."""
        self.cache.clear()
        self.access_times.clear()

    def _evict_least_recently_used(self) -> None:
        """Evict least recently used cache entries."""
        if not self.access_times:
            return

        # Remove 10% of cache entries (oldest first)
        remove_count = max(1, len(self.access_times) // 10)
        sorted_keys = sorted(self.access_times.items(), key=lambda x: x[1])

        for key, _ in sorted_keys[:remove_count]:
            if key in self.cache:
                del self.cache[key]
            del self.access_times[key]
