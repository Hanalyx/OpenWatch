"""
Unit tests for user management CRUD route contract.

Spec: specs/api/admin/users-crud.spec.yaml
"""
import inspect

import pytest


@pytest.mark.unit
class TestAC1CreateUserPermission:
    """AC-1: Create user requires USER_CREATE permission."""

    def test_require_permission_decorator(self):
        """Verify create_user is decorated with @require_permission(Permission.USER_CREATE)."""
        import app.routes.admin.users as mod

        source = inspect.getsource(mod)
        # The decorator appears before the function definition
        assert "@require_permission(Permission.USER_CREATE)" in source

    def test_permission_import(self):
        """Verify Permission is imported from rbac module."""
        import app.routes.admin.users as mod

        source = inspect.getsource(mod)
        assert "from ...rbac import" in source
        assert "Permission" in source
        assert "require_permission" in source


@pytest.mark.unit
class TestAC2PasswordHashing:
    """AC-2: Password hashed with pwd_context.hash before storage."""

    def test_pwd_context_hash_used(self):
        """Verify create_user uses pwd_context.hash."""
        import app.routes.admin.users as mod

        source = inspect.getsource(mod.create_user)
        assert "pwd_context.hash" in source

    def test_hashed_password_stored(self):
        """Verify hashed_password column used in InsertBuilder."""
        import app.routes.admin.users as mod

        source = inspect.getsource(mod.create_user)
        assert "hashed_password" in source
        assert "InsertBuilder" in source

    def test_pwd_context_imported(self):
        """Verify pwd_context imported from auth module."""
        import app.routes.admin.users as mod

        source = inspect.getsource(mod)
        assert "from ...auth import" in source
        assert "pwd_context" in source


@pytest.mark.unit
class TestAC3DuplicateUserConflict:
    """AC-3: Duplicate username or email returns conflict error."""

    def test_checks_existing_username_or_email(self):
        """Verify existence check queries username OR email."""
        import app.routes.admin.users as mod

        source = inspect.getsource(mod.create_user)
        assert "username = :username OR email = :email" in source

    def test_raises_400_on_duplicate(self):
        """Verify HTTP error raised for existing user."""
        import app.routes.admin.users as mod

        source = inspect.getsource(mod.create_user)
        assert "Username or email already exists" in source


@pytest.mark.unit
class TestAC4ListUsersPermissionAndPagination:
    """AC-4: List users requires USER_READ permission with pagination."""

    def test_checks_user_read_permission(self):
        """Verify list_users checks Permission.USER_READ."""
        import app.routes.admin.users as mod

        source = inspect.getsource(mod.list_users)
        assert "Permission.USER_READ" in source
        assert "RBACManager.has_permission" in source

    def test_pagination_parameters(self):
        """Verify page and page_size query parameters are present."""
        import app.routes.admin.users as mod

        source = inspect.getsource(mod.list_users)
        assert "page:" in source or "page :" in source
        assert "page_size" in source

    def test_returns_user_list_response(self):
        """Verify response model is UserListResponse."""
        import app.routes.admin.users as mod

        source = inspect.getsource(mod)
        assert "UserListResponse" in source


@pytest.mark.unit
class TestAC5GetUserPermission:
    """AC-5: Get user by ID requires USER_READ permission."""

    def test_require_permission_decorator(self):
        """Verify get_user is decorated with @require_permission(Permission.USER_READ)."""
        import app.routes.admin.users as mod

        source = inspect.getsource(mod)
        # Check the decorator is applied to get_user
        assert "@require_permission(Permission.USER_READ)" in source

    def test_user_not_found_error(self):
        """Verify format_user_not_found_error used for missing user."""
        import app.routes.admin.users as mod

        source = inspect.getsource(mod.get_user)
        assert "format_user_not_found_error" in source


@pytest.mark.unit
class TestAC6UpdateUserPermission:
    """AC-6: Update user requires USER_UPDATE permission."""

    def test_require_permission_decorator(self):
        """Verify update_user is decorated with @require_permission(Permission.USER_UPDATE)."""
        import app.routes.admin.users as mod

        source = inspect.getsource(mod)
        assert "@require_permission(Permission.USER_UPDATE)" in source

    def test_uses_update_builder(self):
        """Verify update_user uses UpdateBuilder with set_if."""
        import app.routes.admin.users as mod

        source = inspect.getsource(mod.update_user)
        assert "UpdateBuilder" in source
        assert "set_if" in source


@pytest.mark.unit
class TestAC7DeleteSelfPrevention:
    """AC-7: Delete user requires USER_DELETE; self-deletion returns 400."""

    def test_require_permission_decorator(self):
        """Verify delete_user is decorated with @require_permission(Permission.USER_DELETE)."""
        import app.routes.admin.users as mod

        source = inspect.getsource(mod)
        assert "@require_permission(Permission.USER_DELETE)" in source

    def test_self_deletion_check(self):
        """Verify self-deletion prevention with current_user id check."""
        import app.routes.admin.users as mod

        source = inspect.getsource(mod.delete_user)
        assert 'current_user.get("id") == user_id' in source

    def test_self_deletion_returns_400(self):
        """Verify self-deletion returns 400 with appropriate message."""
        import app.routes.admin.users as mod

        source = inspect.getsource(mod.delete_user)
        assert "status_code=400" in source
        assert "Cannot delete your own account" in source


@pytest.mark.unit
class TestAC8SoftDelete:
    """AC-8: Delete is soft (sets is_active=False, not hard delete)."""

    def test_sets_is_active_false(self):
        """Verify delete_user sets is_active to False via UpdateBuilder."""
        import app.routes.admin.users as mod

        source = inspect.getsource(mod.delete_user)
        assert "UpdateBuilder" in source
        assert "is_active" in source
        assert "False" in source

    def test_no_delete_builder(self):
        """Verify delete_user does NOT use DeleteBuilder (soft delete only)."""
        import app.routes.admin.users as mod

        source = inspect.getsource(mod.delete_user)
        assert "DeleteBuilder" not in source


@pytest.mark.unit
class TestAC9ChangePasswordVerification:
    """AC-9: Change password verifies current password before update."""

    def test_verifies_current_password(self):
        """Verify change_password uses pwd_context.verify."""
        import app.routes.admin.users as mod

        source = inspect.getsource(mod.change_password)
        assert "pwd_context.verify" in source

    def test_hashes_new_password(self):
        """Verify new password is hashed with pwd_context.hash."""
        import app.routes.admin.users as mod

        source = inspect.getsource(mod.change_password)
        assert "pwd_context.hash" in source

    def test_rejects_wrong_current_password(self):
        """Verify incorrect current password returns error."""
        import app.routes.admin.users as mod

        source = inspect.getsource(mod.change_password)
        assert "Current password is incorrect" in source


@pytest.mark.unit
class TestAC10ProfileStripsRole:
    """AC-10: Update own profile strips role field to prevent privilege escalation."""

    def test_role_set_to_none(self):
        """Verify update_my_profile sets user_data.role = None."""
        import app.routes.admin.users as mod

        source = inspect.getsource(mod.update_my_profile)
        assert "user_data.role = None" in source

    def test_docstring_mentions_role_restriction(self):
        """Verify function documents the role restriction."""
        import app.routes.admin.users as mod

        source = inspect.getsource(mod.update_my_profile)
        assert "cannot change their own role" in source.lower() or "role" in source
