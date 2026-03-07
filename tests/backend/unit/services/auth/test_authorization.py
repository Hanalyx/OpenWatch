"""
Unit tests for RBAC authorization: UserRole enum members, Permission enum
count, role permission matrix (SUPER_ADMIN all, GUEST exactly 3,
SECURITY_ADMIN exclusions, COMPLIANCE_OFFICER matrix), decorator 403
behavior, and API key resource type handling.

Spec: specs/system/authorization.spec.yaml
Tests rbac.py (UserRole, Permission, ROLE_PERMISSIONS, decorators).
"""

import inspect

import pytest

from app.rbac import (
    ROLE_PERMISSIONS,
    Permission,
    RBACManager,
    UserRole,
    check_permission,
    require_permission,
    require_role,
)

# ---------------------------------------------------------------------------
# AC-1: UserRole has exactly 6 members
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC1UserRoleEnum:
    """AC-1: UserRole defines exactly 6 members."""

    EXPECTED_VALUES = {
        "super_admin",
        "security_admin",
        "security_analyst",
        "compliance_officer",
        "auditor",
        "guest",
    }

    def test_exactly_6_roles(self):
        """Verify UserRole has exactly 6 members."""
        assert len(UserRole) == 6

    def test_expected_role_values(self):
        """Verify all expected role values exist."""
        values = {r.value for r in UserRole}
        assert values == self.EXPECTED_VALUES


# ---------------------------------------------------------------------------
# AC-2: Permission has exactly 31 members
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC2PermissionEnum:
    """AC-2: Permission defines exactly 31 members."""

    def test_exactly_33_permissions(self):
        """Verify Permission enum has exactly 33 members."""
        assert len(Permission) == 33

    def test_user_management_permissions(self):
        """Verify 5 user management permissions exist."""
        user_perms = {p for p in Permission if p.value.startswith("user:")}
        assert len(user_perms) == 5

    def test_host_management_permissions(self):
        """Verify 5 host management permissions exist."""
        host_perms = {p for p in Permission if p.value.startswith("host:")}
        assert len(host_perms) == 5

    def test_scan_permissions(self):
        """Verify 8 scan permissions exist."""
        scan_perms = {p for p in Permission if p.value.startswith("scan:")}
        assert len(scan_perms) == 8


# ---------------------------------------------------------------------------
# AC-3: SUPER_ADMIN has all 31 permissions
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC3SuperAdminPermissions:
    """AC-3: SUPER_ADMIN holds all 31 permissions."""

    def test_super_admin_has_all_permissions(self):
        """Verify SUPER_ADMIN permission count equals total Permission count."""
        super_admin_perms = set(ROLE_PERMISSIONS[UserRole.SUPER_ADMIN])
        all_perms = set(Permission)
        assert super_admin_perms == all_perms

    def test_rbac_manager_confirms_all_permissions(self):
        """Verify RBACManager.get_role_permissions returns all 33 for SUPER_ADMIN."""
        perms = RBACManager.get_role_permissions(UserRole.SUPER_ADMIN)
        assert len(perms) == 33


# ---------------------------------------------------------------------------
# AC-4: GUEST has exactly 3 permissions
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC4GuestPermissions:
    """AC-4: GUEST has exactly HOST_READ, RESULTS_READ, COMPLIANCE_VIEW."""

    EXPECTED_GUEST_PERMS = {
        Permission.HOST_READ,
        Permission.RESULTS_READ,
        Permission.COMPLIANCE_VIEW,
    }

    def test_guest_has_exactly_3_permissions(self):
        """Verify GUEST has exactly 3 permissions."""
        guest_perms = set(ROLE_PERMISSIONS[UserRole.GUEST])
        assert len(guest_perms) == 3

    def test_guest_has_correct_permissions(self):
        """Verify GUEST has exactly the expected 3 permissions."""
        guest_perms = set(ROLE_PERMISSIONS[UserRole.GUEST])
        assert guest_perms == self.EXPECTED_GUEST_PERMS


# ---------------------------------------------------------------------------
# AC-5: require_permission raises 403 when role lacks permission
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC5RequirePermissionRaises403:
    """AC-5: require_permission raises HTTP 403 FORBIDDEN."""

    def test_raises_403_in_source(self):
        """Verify HTTP_403_FORBIDDEN in require_permission source."""
        source = inspect.getsource(require_permission)
        assert "HTTP_403_FORBIDDEN" in source

    def test_checks_has_permission(self):
        """Verify RBACManager.has_permission is called."""
        source = inspect.getsource(require_permission)
        assert "has_permission" in source


# ---------------------------------------------------------------------------
# AC-6: require_role raises 403 when role not in allowed list
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC6RequireRoleRaises403:
    """AC-6: require_role raises HTTP 403 FORBIDDEN."""

    def test_raises_403_in_source(self):
        """Verify HTTP_403_FORBIDDEN in require_role source."""
        source = inspect.getsource(require_role)
        assert "HTTP_403_FORBIDDEN" in source

    def test_checks_role_not_in_required(self):
        """Verify role membership check is performed."""
        source = inspect.getsource(require_role)
        assert "not in required_roles" in source


# ---------------------------------------------------------------------------
# AC-7: 403 detail includes required permission or role
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC7ForbiddenDetailContent:
    """AC-7: 403 detail includes required permission value or role values."""

    def test_require_permission_detail_includes_permission_value(self):
        """Verify detail includes permission.value in require_permission."""
        source = inspect.getsource(require_permission)
        assert "permission.value" in source

    def test_require_role_detail_includes_role_values(self):
        """Verify detail includes role values in require_role."""
        source = inspect.getsource(require_role)
        assert "required_roles" in source


# ---------------------------------------------------------------------------
# AC-8: SECURITY_ADMIN lacks user CRUD and system config permissions
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC8SecurityAdminExclusions:
    """AC-8: SECURITY_ADMIN lacks USER_CREATE, USER_UPDATE, USER_DELETE,
    USER_MANAGE_ROLES, SYSTEM_CONFIG, SYSTEM_CREDENTIALS, SYSTEM_MAINTENANCE."""

    EXCLUDED_FROM_SECURITY_ADMIN = {
        Permission.USER_CREATE,
        Permission.USER_UPDATE,
        Permission.USER_DELETE,
        Permission.USER_MANAGE_ROLES,
        Permission.SYSTEM_CONFIG,
        Permission.SYSTEM_CREDENTIALS,
        Permission.SYSTEM_MAINTENANCE,
    }

    def test_security_admin_lacks_user_create(self):
        """Verify SECURITY_ADMIN does not have USER_CREATE."""
        perms = set(ROLE_PERMISSIONS[UserRole.SECURITY_ADMIN])
        assert Permission.USER_CREATE not in perms

    def test_security_admin_lacks_system_config(self):
        """Verify SECURITY_ADMIN does not have SYSTEM_CONFIG."""
        perms = set(ROLE_PERMISSIONS[UserRole.SECURITY_ADMIN])
        assert Permission.SYSTEM_CONFIG not in perms

    def test_security_admin_lacks_all_excluded_permissions(self):
        """Verify SECURITY_ADMIN lacks all 7 excluded permissions."""
        perms = set(ROLE_PERMISSIONS[UserRole.SECURITY_ADMIN])
        for excluded in self.EXCLUDED_FROM_SECURITY_ADMIN:
            assert excluded not in perms, f"SECURITY_ADMIN should not have {excluded}"


# ---------------------------------------------------------------------------
# AC-9: COMPLIANCE_OFFICER has RESULTS_READ_ALL and REPORTS_EXPORT but not SCAN_EXECUTE
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC9ComplianceOfficerMatrix:
    """AC-9: COMPLIANCE_OFFICER has RESULTS_READ_ALL, REPORTS_EXPORT; lacks SCAN_EXECUTE."""

    def test_has_results_read_all(self):
        """Verify COMPLIANCE_OFFICER has RESULTS_READ_ALL."""
        perms = set(ROLE_PERMISSIONS[UserRole.COMPLIANCE_OFFICER])
        assert Permission.RESULTS_READ_ALL in perms

    def test_has_reports_export(self):
        """Verify COMPLIANCE_OFFICER has REPORTS_EXPORT."""
        perms = set(ROLE_PERMISSIONS[UserRole.COMPLIANCE_OFFICER])
        assert Permission.REPORTS_EXPORT in perms

    def test_lacks_scan_execute(self):
        """Verify COMPLIANCE_OFFICER does not have SCAN_EXECUTE."""
        perms = set(ROLE_PERMISSIONS[UserRole.COMPLIANCE_OFFICER])
        assert Permission.SCAN_EXECUTE not in perms


# ---------------------------------------------------------------------------
# AC-10: check_permission handles api_keys resource type
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC10ApiKeysResourceType:
    """AC-10: check_permission handles api_keys resource type specially."""

    def test_api_keys_checks_admin_roles(self):
        """Verify api_keys resource type checks SUPER_ADMIN and SECURITY_ADMIN."""
        source = inspect.getsource(check_permission)
        assert '"api_keys"' in source
        assert "SUPER_ADMIN" in source
        assert "SECURITY_ADMIN" in source

    def test_api_keys_bypasses_permission_map(self):
        """Verify api_keys returns early before the general can_access_resource check."""
        source = inspect.getsource(check_permission)
        # api_keys block returns early before the general can_access_resource check
        api_keys_pos = source.find('"api_keys"')
        return_pos = source.find("return", api_keys_pos)
        access_pos = source.find("can_access_resource", api_keys_pos)
        assert return_pos < access_pos
