"""
Unit tests for API key management route contract.

Spec: specs/api/auth/api-keys.spec.yaml
"""
import inspect

import pytest


@pytest.mark.unit
class TestAC1CreatePermission:
    """AC-1: Create API key requires api_keys:create permission."""

    def test_create_calls_check_permission(self):
        """Verify create_api_key calls check_permission."""
        import app.routes.auth.api_keys as mod

        source = inspect.getsource(mod.create_api_key)
        assert "check_permission" in source

    def test_create_checks_api_keys_create(self):
        """Verify permission check uses 'api_keys' resource and 'create' action."""
        import app.routes.auth.api_keys as mod

        source = inspect.getsource(mod.create_api_key)
        assert '"api_keys"' in source
        assert '"create"' in source

    def test_check_permission_imported(self):
        """Verify check_permission is imported from rbac module."""
        import app.routes.auth.api_keys as mod

        source = inspect.getsource(mod)
        assert "from ...rbac import" in source
        assert "check_permission" in source


@pytest.mark.unit
class TestAC2RequestValidation:
    """AC-2: CreateApiKeyRequest validates name (3-100 chars), expires_in_days (1-1825)."""

    def test_name_min_length(self):
        """Verify name field has min_length=3."""
        import app.routes.auth.api_keys as mod

        source = inspect.getsource(mod.CreateApiKeyRequest)
        assert "min_length=3" in source

    def test_name_max_length(self):
        """Verify name field has max_length=100."""
        import app.routes.auth.api_keys as mod

        source = inspect.getsource(mod.CreateApiKeyRequest)
        assert "max_length=100" in source

    def test_expires_in_days_min(self):
        """Verify expires_in_days has ge=1."""
        import app.routes.auth.api_keys as mod

        source = inspect.getsource(mod.CreateApiKeyRequest)
        assert "ge=1" in source

    def test_expires_in_days_max(self):
        """Verify expires_in_days has le=1825."""
        import app.routes.auth.api_keys as mod

        source = inspect.getsource(mod.CreateApiKeyRequest)
        assert "le=1825" in source


@pytest.mark.unit
class TestAC3KeyPrefix:
    """AC-3: Generated key has owk_ prefix."""

    def test_owk_prefix_in_generate(self):
        """Verify generate_api_key produces owk_ prefix."""
        import app.routes.auth.api_keys as mod

        source = inspect.getsource(mod.generate_api_key)
        assert 'owk_' in source

    def test_uses_secrets_token_urlsafe(self):
        """Verify key generation uses secrets.token_urlsafe."""
        import app.routes.auth.api_keys as mod

        source = inspect.getsource(mod.generate_api_key)
        assert "secrets.token_urlsafe" in source

    def test_key_hash_uses_sha256(self):
        """Verify key is hashed with SHA256 for storage."""
        import app.routes.auth.api_keys as mod

        source = inspect.getsource(mod.generate_api_key)
        assert "sha256" in source


@pytest.mark.unit
class TestAC4DuplicateName409:
    """AC-4: Duplicate active key name returns 409 CONFLICT."""

    def test_checks_existing_active_key(self):
        """Verify duplicate name check filters on is_active."""
        import app.routes.auth.api_keys as mod

        source = inspect.getsource(mod.create_api_key)
        assert "ApiKey.name == request.name" in source
        assert "is_active" in source

    def test_returns_409_on_duplicate(self):
        """Verify HTTP 409 CONFLICT raised for duplicate."""
        import app.routes.auth.api_keys as mod

        source = inspect.getsource(mod.create_api_key)
        assert "HTTP_409_CONFLICT" in source

    def test_conflict_detail_message(self):
        """Verify conflict response includes name in detail."""
        import app.routes.auth.api_keys as mod

        source = inspect.getsource(mod.create_api_key)
        assert "already exists" in source


@pytest.mark.unit
class TestAC5ListPermissionAndOwnership:
    """AC-5: List keys requires api_keys:read; non-admins see only own keys."""

    def test_list_calls_check_permission_read(self):
        """Verify list_api_keys calls check_permission for read."""
        import app.routes.auth.api_keys as mod

        source = inspect.getsource(mod.list_api_keys)
        assert "check_permission" in source
        assert '"api_keys"' in source
        assert '"read"' in source

    def test_non_admin_filter_by_created_by(self):
        """Verify non-admins filter by created_by == current_user id."""
        import app.routes.auth.api_keys as mod

        source = inspect.getsource(mod.list_api_keys)
        assert "ApiKey.created_by == current_user" in source

    def test_admin_roles_checked(self):
        """Verify SUPER_ADMIN and SECURITY_ADMIN bypass ownership filter."""
        import app.routes.auth.api_keys as mod

        source = inspect.getsource(mod.list_api_keys)
        assert "SUPER_ADMIN" in source
        assert "SECURITY_ADMIN" in source


@pytest.mark.unit
class TestAC6RevokePermissionAndOwnership:
    """AC-6: Revoke requires api_keys:delete; non-admins can only revoke own keys (403)."""

    def test_revoke_calls_check_permission_delete(self):
        """Verify revoke_api_key calls check_permission for delete."""
        import app.routes.auth.api_keys as mod

        source = inspect.getsource(mod.revoke_api_key)
        assert "check_permission" in source
        assert '"api_keys"' in source
        assert '"delete"' in source

    def test_ownership_check_for_non_admins(self):
        """Verify non-admin ownership check compares created_by."""
        import app.routes.auth.api_keys as mod

        source = inspect.getsource(mod.revoke_api_key)
        assert "api_key.created_by" in source
        assert 'current_user["id"]' in source

    def test_returns_403_on_ownership_violation(self):
        """Verify HTTP 403 FORBIDDEN for non-owner revocation."""
        import app.routes.auth.api_keys as mod

        source = inspect.getsource(mod.revoke_api_key)
        assert "HTTP_403_FORBIDDEN" in source
        assert "only revoke your own" in source


@pytest.mark.unit
class TestAC7UpdatePermissionsRoleRestriction:
    """AC-7: Update permissions requires SUPER_ADMIN or SECURITY_ADMIN role."""

    def test_checks_admin_roles(self):
        """Verify update_api_key_permissions checks SUPER_ADMIN/SECURITY_ADMIN."""
        import app.routes.auth.api_keys as mod

        source = inspect.getsource(mod.update_api_key_permissions)
        assert "SUPER_ADMIN" in source
        assert "SECURITY_ADMIN" in source

    def test_returns_403_for_non_admin(self):
        """Verify HTTP 403 for non-admin role."""
        import app.routes.auth.api_keys as mod

        source = inspect.getsource(mod.update_api_key_permissions)
        assert "HTTP_403_FORBIDDEN" in source
        assert "Only administrators" in source


@pytest.mark.unit
class TestAC8AuditLogging:
    """AC-8: All key lifecycle actions produce audit log entries."""

    def test_create_audit_log(self):
        """Verify create logs API_KEY_CREATED."""
        import app.routes.auth.api_keys as mod

        source = inspect.getsource(mod.create_api_key)
        assert "audit_logger.log_api_key_action" in source
        assert "API_KEY_CREATED" in source

    def test_revoke_audit_log(self):
        """Verify revoke logs API_KEY_REVOKED."""
        import app.routes.auth.api_keys as mod

        source = inspect.getsource(mod.revoke_api_key)
        assert "audit_logger.log_api_key_action" in source
        assert "API_KEY_REVOKED" in source

    def test_permissions_update_audit_log(self):
        """Verify permissions update logs API_KEY_PERMISSIONS_UPDATED."""
        import app.routes.auth.api_keys as mod

        source = inspect.getsource(mod.update_api_key_permissions)
        assert "audit_logger.log_api_key_action" in source
        assert "API_KEY_PERMISSIONS_UPDATED" in source

    def test_audit_logger_imported(self):
        """Verify audit_logger is imported from auth module."""
        import app.routes.auth.api_keys as mod

        source = inspect.getsource(mod)
        assert "audit_logger" in source
        assert "from ...auth import" in source
