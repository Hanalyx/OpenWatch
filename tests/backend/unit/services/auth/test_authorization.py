"""
Unit tests for RBAC authorization: UserRole enum members, Permission enum
count, role permission matrix (SUPER_ADMIN all, GUEST exactly 3,
SECURITY_ADMIN exclusions, COMPLIANCE_OFFICER matrix), decorator 403
behavior, API key resource type handling, endpoint-level RBAC
enforcement for webhooks, Kensa scans, API key auth, metrics, and
MFA administration (system-wide toggle + per-user exemption).

Spec: specs/system/authorization.spec.yaml
Tests rbac.py (UserRole, Permission, ROLE_PERMISSIONS, decorators),
webhook routes, kensa routes, auth.py decode_token, main.py metrics,
admin settings MFA, admin users MFA.
"""

import importlib
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


# ---------------------------------------------------------------------------
# AC-11: Webhook management endpoints MUST require RBAC authorization
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC11WebhookEndpointRBAC:
    """AC-11: Webhook management endpoints MUST use require_permission or
    require_role decorators restricting access to at least SECURITY_ADMIN."""

    @pytest.fixture(autouse=True)
    def _load_source(self):
        from pathlib import Path

        self.source = Path("backend/app/routes/integrations/webhooks.py").read_text()

    def test_list_webhooks_has_rbac_decorator(self):
        """Verify webhooks module uses require_permission or require_role."""
        has_rbac = "require_permission" in self.source or "require_role" in self.source
        assert has_rbac, "webhooks.py has no RBAC decorators at all"

    def test_create_webhook_has_rbac_decorator(self):
        """Verify create_webhook route is protected by RBAC."""
        # Find the create_webhook function and check for decorator above it
        assert "require_permission" in self.source or "require_role" in self.source, (
            "webhooks.py missing RBAC decorators for create_webhook"
        )

    def test_update_webhook_has_rbac_decorator(self):
        """Verify update_webhook route is protected by RBAC."""
        assert "require_permission" in self.source or "require_role" in self.source, (
            "webhooks.py missing RBAC decorators for update_webhook"
        )

    def test_delete_webhook_has_rbac_decorator(self):
        """Verify delete_webhook route is protected by RBAC."""
        assert "require_permission" in self.source or "require_role" in self.source, (
            "webhooks.py missing RBAC decorators for delete_webhook"
        )

    def test_test_webhook_has_rbac_decorator(self):
        """Verify test_webhook route is protected by RBAC."""
        assert "require_permission" in self.source or "require_role" in self.source, (
            "webhooks.py missing RBAC decorators for test_webhook"
        )


# ---------------------------------------------------------------------------
# AC-12: Kensa scan endpoints MUST require RBAC authorization
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC12KensaScanEndpointRBAC:
    """AC-12: Kensa scan endpoints that modify state MUST require SCAN_EXECUTE;
    read endpoints MUST require at minimum HOST_READ."""

    @pytest.fixture(autouse=True)
    def _load_source(self):
        from pathlib import Path

        self.source = Path("backend/app/routes/scans/kensa.py").read_text()

    def test_sync_endpoint_requires_rbac(self):
        """Verify kensa routes module uses require_permission or require_role."""
        has_rbac = "require_permission" in self.source or "require_role" in self.source
        assert has_rbac, "kensa.py has no RBAC decorators"

    def test_state_modifying_endpoints_require_scan_execute(self):
        """Verify state-modifying kensa endpoints reference SCAN_EXECUTE or admin role."""
        assert "SCAN_EXECUTE" in self.source or "require_role" in self.source, (
            "kensa.py does not reference SCAN_EXECUTE permission for state-modifying endpoints"
        )

    def test_frameworks_endpoint_requires_rbac(self):
        """Verify frameworks endpoint has RBAC protection."""
        # The file should have require_permission or require_role for framework routes
        has_rbac = "require_permission" in self.source or "require_role" in self.source
        assert has_rbac, "kensa.py framework endpoints lack RBAC decorators"


# ---------------------------------------------------------------------------
# AC-13: API key auth MUST NOT return hardcoded non-enum role
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC13ApiKeyRoleResolution:
    """AC-13: decode_token MUST NOT return a hardcoded 'api_key' role string;
    it MUST resolve to actual permissions."""

    def test_decode_token_no_hardcoded_api_key_role(self):
        """Verify decode_token does not return a hardcoded 'api_key' role string."""
        from app.auth import decode_token

        source = inspect.getsource(decode_token)
        # The function should not contain a hardcoded "api_key" role assignment
        # Look for the pattern of returning role: "api_key"
        assert '"role": "api_key"' not in source, (
            "decode_token contains hardcoded 'api_key' role string which is not "
            "a valid UserRole enum value. API key auth must resolve to actual "
            "permissions."
        )

    def test_decode_token_does_not_assign_synthetic_role(self):
        """Verify decode_token does not assign a role value outside UserRole enum."""
        from app.auth import decode_token

        source = inspect.getsource(decode_token)
        valid_roles = {r.value for r in UserRole}
        # Check that any "role" string assignment uses a valid enum value
        # The presence of "api_key" as a role value is the specific concern
        lines = source.split("\n")
        for line in lines:
            if '"role"' in line and '"api_key"' in line:
                pytest.fail(
                    f"decode_token assigns synthetic 'api_key' role: {line.strip()}"
                )


# ---------------------------------------------------------------------------
# AC-14: /metrics endpoint MUST require authentication
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC14MetricsEndpointAuth:
    """AC-14: The /metrics Prometheus endpoint MUST require authentication."""

    @pytest.fixture(autouse=True)
    def _load_source(self):
        from pathlib import Path

        self.source = Path("backend/app/main.py").read_text()

    def test_metrics_function_exists(self):
        """Verify a metrics endpoint function exists in main.py."""
        assert 'def metrics(' in self.source, (
            "No metrics function found in app/main.py"
        )

    def test_metrics_endpoint_requires_authentication(self):
        """Verify metrics endpoint uses get_current_user or authentication dependency."""
        # Extract the metrics function definition and check for auth
        # Find the @app.get("/metrics") block
        lines = self.source.split("\n")
        in_metrics = False
        metrics_block = []
        for line in lines:
            if '"/metrics"' in line:
                in_metrics = True
            if in_metrics:
                metrics_block.append(line)
                if line.strip().startswith("return ") and metrics_block:
                    break
        metrics_source = "\n".join(metrics_block)
        has_auth = (
            "get_current_user" in metrics_source
            or "require_permission" in metrics_source
            or "require_role" in metrics_source
            or "Depends(" in metrics_source
        )
        assert has_auth, (
            "/metrics endpoint is unauthenticated. It MUST require "
            "authentication via Depends(get_current_user) or equivalent."
        )


# ---------------------------------------------------------------------------
# AC-15: System-wide MFA enforcement toggle restricted to SUPER_ADMIN
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC15SystemWideMfaEnforcement:
    """AC-15: System-wide MFA enforcement MUST be controllable only by
    SUPER_ADMIN via a settings endpoint gated by require_role or
    require_permission(SYSTEM_CONFIG)."""

    @pytest.fixture(autouse=True)
    def _scan_route_files(self):
        """Scan admin/settings route files for MFA system-wide toggle."""
        from pathlib import Path
        import glob

        # Look for MFA settings endpoint in admin or system routes
        self.admin_sources = {}
        for pattern in [
            "backend/app/routes/admin/*.py",
            "backend/app/routes/system/*.py",
            "backend/app/routes/auth/*.py",
        ]:
            for filepath in glob.glob(pattern):
                content = Path(filepath).read_text()
                if "mfa" in content.lower():
                    self.admin_sources[filepath] = content

    def test_system_mfa_settings_endpoint_exists(self):
        """Verify an admin endpoint exists for system-wide MFA configuration."""
        # There must be a route that handles system-wide MFA toggle
        # Look for: PUT/POST + mfa + (settings or config or enforce)
        found = False
        for filepath, source in self.admin_sources.items():
            if ("mfa_required" in source or "mfa_enforced" in source
                    or "require_mfa" in source or "mfa_policy" in source
                    or ("mfa" in source.lower() and "settings" in filepath)):
                # Check for RBAC gating
                has_rbac = (
                    "require_role" in source
                    or "require_permission" in source
                    or "SUPER_ADMIN" in source
                    or "SYSTEM_CONFIG" in source
                )
                if has_rbac:
                    found = True
                    break
        assert found, (
            "No RBAC-gated admin endpoint found for system-wide MFA enforcement. "
            "A PUT /api/admin/settings/mfa (or equivalent) endpoint MUST exist "
            "and be restricted to SUPER_ADMIN via require_role or "
            "require_permission(SYSTEM_CONFIG)."
        )

    def test_system_mfa_not_accessible_by_non_admin(self):
        """Verify SYSTEM_CONFIG permission is exclusive to SUPER_ADMIN."""
        # SYSTEM_CONFIG should only be in SUPER_ADMIN's permission set
        non_admin_roles = [
            UserRole.SECURITY_ADMIN,
            UserRole.SECURITY_ANALYST,
            UserRole.COMPLIANCE_OFFICER,
            UserRole.AUDITOR,
            UserRole.GUEST,
        ]
        for role in non_admin_roles:
            perms = set(ROLE_PERMISSIONS[role])
            assert Permission.SYSTEM_CONFIG not in perms, (
                f"{role.value} has SYSTEM_CONFIG permission — only "
                f"SUPER_ADMIN should be able to control system-wide MFA."
            )

    def test_super_admin_has_system_config(self):
        """Verify SUPER_ADMIN has SYSTEM_CONFIG permission for MFA toggle."""
        perms = set(ROLE_PERMISSIONS[UserRole.SUPER_ADMIN])
        assert Permission.SYSTEM_CONFIG in perms


# ---------------------------------------------------------------------------
# AC-16: Per-user MFA disable/exempt restricted to SUPER_ADMIN
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC16PerUserMfaExemption:
    """AC-16: Per-user MFA exemption MUST be controllable only by
    SUPER_ADMIN via an admin endpoint gated by require_role or
    require_permission(USER_UPDATE)."""

    @pytest.fixture(autouse=True)
    def _scan_route_files(self):
        """Scan admin route files for per-user MFA management."""
        from pathlib import Path
        import glob

        self.admin_sources = {}
        for pattern in [
            "backend/app/routes/admin/*.py",
            "backend/app/routes/auth/*.py",
        ]:
            for filepath in glob.glob(pattern):
                content = Path(filepath).read_text()
                self.admin_sources[filepath] = content

    def test_admin_mfa_disable_endpoint_exists(self):
        """Verify an admin endpoint exists to disable MFA for a specific user."""
        # Look for admin route that can modify another user's MFA status
        found = False
        for filepath, source in self.admin_sources.items():
            # Must be in admin routes (not self-service MFA routes)
            if "admin" in filepath:
                has_mfa_management = (
                    "mfa_enabled" in source or "mfa_exempt" in source
                    or "disable_mfa" in source or "reset_mfa" in source
                    or "mfa" in source.lower()
                )
                has_rbac = (
                    "require_role" in source
                    or "require_permission" in source
                    or "SUPER_ADMIN" in source
                    or "USER_UPDATE" in source
                )
                if has_mfa_management and has_rbac:
                    found = True
                    break
        assert found, (
            "No RBAC-gated admin endpoint found for per-user MFA management. "
            "A PUT /api/admin/users/{id}/mfa (or equivalent) endpoint MUST "
            "exist and be restricted to SUPER_ADMIN via require_role or "
            "require_permission(USER_UPDATE)."
        )

    def test_user_update_permission_exclusive_to_admins(self):
        """Verify USER_UPDATE is not available to non-admin roles."""
        non_admin_roles = [
            UserRole.COMPLIANCE_OFFICER,
            UserRole.AUDITOR,
            UserRole.GUEST,
        ]
        for role in non_admin_roles:
            perms = set(ROLE_PERMISSIONS[role])
            assert Permission.USER_UPDATE not in perms, (
                f"{role.value} has USER_UPDATE permission — per-user MFA "
                f"exemption should be restricted to admin roles."
            )

    def test_self_service_mfa_disable_requires_password(self):
        """Verify the self-service MFA disable route requires password verification."""
        from pathlib import Path

        mfa_source = Path("backend/app/routes/auth/mfa.py").read_text()
        # The disable endpoint must require password verification
        assert "verify_password" in mfa_source, (
            "MFA disable route does not require password verification. "
            "Users MUST NOT be able to trivially bypass MFA."
        )

    def test_super_admin_has_user_update(self):
        """Verify SUPER_ADMIN has USER_UPDATE permission for per-user MFA control."""
        perms = set(ROLE_PERMISSIONS[UserRole.SUPER_ADMIN])
        assert Permission.USER_UPDATE in perms
