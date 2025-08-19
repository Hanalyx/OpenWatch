"""
Role-Based Access Control (RBAC) System for OpenWatch
Defines permissions, roles, and access control logic
"""
from enum import Enum
from typing import List, Dict, Set, Optional
from functools import wraps
from fastapi import HTTPException, status, Depends
import logging

logger = logging.getLogger(__name__)


class Permission(str, Enum):
    """System permissions"""
    # User Management
    USER_CREATE = "user:create"
    USER_READ = "user:read" 
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    USER_MANAGE_ROLES = "user:manage_roles"
    
    # Host Management
    HOST_CREATE = "host:create"
    HOST_READ = "host:read"
    HOST_UPDATE = "host:update"
    HOST_DELETE = "host:delete"
    HOST_MANAGE_ACCESS = "host:manage_access"
    
    # SCAP Content Management
    CONTENT_CREATE = "content:create"
    CONTENT_READ = "content:read"
    CONTENT_UPDATE = "content:update"
    CONTENT_DELETE = "content:delete"
    
    # Scan Operations
    SCAN_CREATE = "scan:create"
    SCAN_READ = "scan:read"
    SCAN_UPDATE = "scan:update"
    SCAN_DELETE = "scan:delete"
    SCAN_EXECUTE = "scan:execute"
    
    # Results and Reports
    RESULTS_READ = "results:read"
    RESULTS_READ_ALL = "results:read_all"
    REPORTS_GENERATE = "reports:generate"
    REPORTS_EXPORT = "reports:export"
    
    # System Administration
    SYSTEM_CONFIG = "system:config"
    SYSTEM_CREDENTIALS = "system:credentials"
    SYSTEM_LOGS = "system:logs"
    SYSTEM_MAINTENANCE = "system:maintenance"
    
    # Audit and Compliance
    AUDIT_READ = "audit:read"
    COMPLIANCE_VIEW = "compliance:view"
    COMPLIANCE_EXPORT = "compliance:export"


class UserRole(str, Enum):
    """User roles in the system"""
    SUPER_ADMIN = "super_admin"
    SECURITY_ADMIN = "security_admin"
    SECURITY_ANALYST = "security_analyst"
    COMPLIANCE_OFFICER = "compliance_officer"
    AUDITOR = "auditor"
    GUEST = "guest"


# Role permission mappings
ROLE_PERMISSIONS: Dict[UserRole, List[Permission]] = {
    UserRole.SUPER_ADMIN: [
        # All permissions - super admin has full access
        Permission.USER_CREATE, Permission.USER_READ, Permission.USER_UPDATE, 
        Permission.USER_DELETE, Permission.USER_MANAGE_ROLES,
        Permission.HOST_CREATE, Permission.HOST_READ, Permission.HOST_UPDATE, 
        Permission.HOST_DELETE, Permission.HOST_MANAGE_ACCESS,
        Permission.CONTENT_CREATE, Permission.CONTENT_READ, Permission.CONTENT_UPDATE, 
        Permission.CONTENT_DELETE,
        Permission.SCAN_CREATE, Permission.SCAN_READ, Permission.SCAN_UPDATE, 
        Permission.SCAN_DELETE, Permission.SCAN_EXECUTE,
        Permission.RESULTS_READ, Permission.RESULTS_READ_ALL, Permission.REPORTS_GENERATE, 
        Permission.REPORTS_EXPORT,
        Permission.SYSTEM_CONFIG, Permission.SYSTEM_CREDENTIALS, Permission.SYSTEM_LOGS, 
        Permission.SYSTEM_MAINTENANCE,
        Permission.AUDIT_READ, Permission.COMPLIANCE_VIEW, Permission.COMPLIANCE_EXPORT
    ],
    
    UserRole.SECURITY_ADMIN: [
        # Security-focused administration
        Permission.USER_READ,  # Can view users but not create/delete
        Permission.HOST_CREATE, Permission.HOST_READ, Permission.HOST_UPDATE, 
        Permission.HOST_DELETE, Permission.HOST_MANAGE_ACCESS,
        Permission.CONTENT_CREATE, Permission.CONTENT_READ, Permission.CONTENT_UPDATE, 
        Permission.CONTENT_DELETE,
        Permission.SCAN_CREATE, Permission.SCAN_READ, Permission.SCAN_UPDATE, 
        Permission.SCAN_DELETE, Permission.SCAN_EXECUTE,
        Permission.RESULTS_READ, Permission.RESULTS_READ_ALL, Permission.REPORTS_GENERATE, 
        Permission.REPORTS_EXPORT,
        Permission.SYSTEM_LOGS,  # Can view system logs
        Permission.AUDIT_READ, Permission.COMPLIANCE_VIEW, Permission.COMPLIANCE_EXPORT
    ],
    
    UserRole.SECURITY_ANALYST: [
        # Day-to-day security operations
        Permission.HOST_READ, Permission.HOST_UPDATE,  # Can manage assigned hosts
        Permission.CONTENT_READ,  # Read-only SCAP content
        Permission.SCAN_CREATE, Permission.SCAN_READ, Permission.SCAN_EXECUTE,
        Permission.RESULTS_READ, Permission.REPORTS_GENERATE, Permission.REPORTS_EXPORT,
        Permission.COMPLIANCE_VIEW
    ],
    
    UserRole.COMPLIANCE_OFFICER: [
        # Compliance and reporting focus
        Permission.HOST_READ,  # Read-only host access
        Permission.CONTENT_READ,  # Read-only SCAP content
        Permission.SCAN_READ,  # Read-only scan access
        Permission.RESULTS_READ, Permission.RESULTS_READ_ALL, Permission.REPORTS_GENERATE, 
        Permission.REPORTS_EXPORT,
        Permission.AUDIT_READ, Permission.COMPLIANCE_VIEW, Permission.COMPLIANCE_EXPORT
    ],
    
    UserRole.AUDITOR: [
        # External audit support
        Permission.HOST_READ, Permission.CONTENT_READ, Permission.SCAN_READ,
        Permission.RESULTS_READ, Permission.RESULTS_READ_ALL, Permission.REPORTS_EXPORT,
        Permission.AUDIT_READ, Permission.COMPLIANCE_VIEW, Permission.COMPLIANCE_EXPORT
    ],
    
    UserRole.GUEST: [
        # Very limited access
        Permission.HOST_READ,  # Read-only access to assigned hosts
        Permission.RESULTS_READ,  # Read-only access to assigned results
        Permission.COMPLIANCE_VIEW  # Basic compliance viewing
    ]
}


class RBACManager:
    """Role-Based Access Control Manager"""
    
    @staticmethod
    def get_role_permissions(role: UserRole) -> Set[Permission]:
        """Get all permissions for a role"""
        return set(ROLE_PERMISSIONS.get(role, []))
    
    @staticmethod
    def has_permission(user_role: UserRole, required_permission: Permission) -> bool:
        """Check if a role has a specific permission"""
        role_permissions = RBACManager.get_role_permissions(user_role)
        return required_permission in role_permissions
    
    @staticmethod
    def has_any_permission(user_role: UserRole, required_permissions: List[Permission]) -> bool:
        """Check if a role has any of the required permissions"""
        role_permissions = RBACManager.get_role_permissions(user_role)
        return any(perm in role_permissions for perm in required_permissions)
    
    @staticmethod
    def has_all_permissions(user_role: UserRole, required_permissions: List[Permission]) -> bool:
        """Check if a role has all required permissions"""
        role_permissions = RBACManager.get_role_permissions(user_role)
        return all(perm in role_permissions for perm in required_permissions)
    
    @staticmethod
    def can_access_resource(user_role: UserRole, resource_type: str, action: str) -> bool:
        """Check if a role can perform an action on a resource type"""
        permission_map = {
            "user": {
                "create": Permission.USER_CREATE,
                "read": Permission.USER_READ,
                "update": Permission.USER_UPDATE,
                "delete": Permission.USER_DELETE
            },
            "host": {
                "create": Permission.HOST_CREATE,
                "read": Permission.HOST_READ,
                "update": Permission.HOST_UPDATE,
                "delete": Permission.HOST_DELETE
            },
            "scan": {
                "create": Permission.SCAN_CREATE,
                "read": Permission.SCAN_READ,
                "update": Permission.SCAN_UPDATE,
                "delete": Permission.SCAN_DELETE,
                "execute": Permission.SCAN_EXECUTE
            },
            "content": {
                "create": Permission.CONTENT_CREATE,
                "read": Permission.CONTENT_READ,
                "update": Permission.CONTENT_UPDATE,
                "delete": Permission.CONTENT_DELETE
            },
            "audit": {
                "read": Permission.AUDIT_READ
            }
        }
        
        if resource_type not in permission_map or action not in permission_map[resource_type]:
            return False
            
        required_permission = permission_map[resource_type][action]
        return RBACManager.has_permission(user_role, required_permission)


def require_permission(permission: Permission):
    """Decorator to require a specific permission"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get current user from kwargs (injected by get_current_user dependency)
            current_user = kwargs.get('current_user')
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            user_role = UserRole(current_user.get('role', 'guest'))
            if not RBACManager.has_permission(user_role, permission):
                logger.warning(f"User {current_user.get('username')} with role {user_role} attempted to access {permission}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Required: {permission.value}"
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def require_any_permission(permissions: List[Permission]):
    """Decorator to require any of the specified permissions"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            current_user = kwargs.get('current_user')
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            user_role = UserRole(current_user.get('role', 'guest'))
            if not RBACManager.has_any_permission(user_role, permissions):
                logger.warning(f"User {current_user.get('username')} with role {user_role} attempted to access {[p.value for p in permissions]}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Required one of: {[p.value for p in permissions]}"
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def require_role(required_roles: List[UserRole]):
    """Decorator to require specific roles"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            current_user = kwargs.get('current_user')
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            user_role = UserRole(current_user.get('role', 'guest'))
            if user_role not in required_roles:
                logger.warning(f"User {current_user.get('username')} with role {user_role} attempted to access endpoint requiring {[r.value for r in required_roles]}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient role. Required one of: {[r.value for r in required_roles]}"
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


# Convenience decorators for common access patterns
def require_admin():
    """Require admin-level access (super_admin or security_admin)"""
    return require_role([UserRole.SUPER_ADMIN, UserRole.SECURITY_ADMIN])


def require_super_admin():
    """Require super admin access"""
    return require_role([UserRole.SUPER_ADMIN])


def require_analyst_or_above():
    """Require analyst level or above"""
    return require_role([
        UserRole.SUPER_ADMIN, 
        UserRole.SECURITY_ADMIN, 
        UserRole.SECURITY_ANALYST
    ])


def check_permission(user_role: str, resource_type: str, action: str):
    """Check if a user role has permission to perform an action on a resource.
    
    For API keys, we'll allow super_admin and security_admin to manage them.
    """
    # Special handling for API keys
    if resource_type == "api_keys":
        allowed_roles = [UserRole.SUPER_ADMIN, UserRole.SECURITY_ADMIN]
        if UserRole(user_role) not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Only administrators can manage API keys"
            )
        return
    
    # Use existing permission check for other resources
    if not RBACManager.can_access_resource(UserRole(user_role), resource_type, action):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Insufficient permissions to {action} {resource_type}"
        )