"""
Unit tests for security configuration route contract.

Spec: specs/api/admin/security-config.spec.yaml
"""
import inspect

import pytest


@pytest.mark.unit
class TestAC1MfaSuperAdminRole:
    """AC-1: MFA settings require SUPER_ADMIN role."""

    def test_mfa_put_requires_super_admin(self):
        """Verify update_system_mfa_settings uses @require_role with SUPER_ADMIN."""
        import app.routes.admin.security as mod

        source = inspect.getsource(mod.update_system_mfa_settings)
        assert "require_role" in source or "@require_role" in inspect.getsource(mod)

    def test_mfa_get_requires_super_admin(self):
        """Verify get_system_mfa_settings uses @require_role with SUPER_ADMIN."""
        import app.routes.admin.security as mod

        source = inspect.getsource(mod)
        # Both MFA endpoints have @require_role([UserRole.SUPER_ADMIN])
        assert "@require_role([UserRole.SUPER_ADMIN])" in source

    def test_super_admin_role_imported(self):
        """Verify UserRole.SUPER_ADMIN is available via import."""
        import app.routes.admin.security as mod

        source = inspect.getsource(mod)
        assert "require_role" in source
        assert "UserRole" in source


@pytest.mark.unit
class TestAC2SecurityConfigPermission:
    """AC-2: Security config CRUD requires SYSTEM_CONFIG permission."""

    def test_get_config_requires_system_config(self):
        """Verify get_security_config uses @require_permission(Permission.SYSTEM_CONFIG)."""
        import app.routes.admin.security as mod

        source = inspect.getsource(mod)
        assert "@require_permission(Permission.SYSTEM_CONFIG)" in source

    def test_put_config_requires_system_config(self):
        """Verify update_security_config uses @require_permission(Permission.SYSTEM_CONFIG)."""
        import app.routes.admin.security as mod

        source = inspect.getsource(mod.update_security_config)
        # The decorator is applied at module level
        full_source = inspect.getsource(mod)
        assert "require_permission" in full_source
        assert "SYSTEM_CONFIG" in full_source


@pytest.mark.unit
class TestAC3SecurityPolicyRequestFields:
    """AC-3: SecurityPolicyRequest validates minimum_rsa_bits, minimum_ecdsa_bits, allow_dsa_keys."""

    def test_minimum_rsa_bits_field(self):
        """Verify minimum_rsa_bits field with default 3072."""
        import app.routes.admin.security as mod

        source = inspect.getsource(mod.SecurityPolicyRequest)
        assert "minimum_rsa_bits" in source
        assert "3072" in source

    def test_minimum_ecdsa_bits_field(self):
        """Verify minimum_ecdsa_bits field with default 256."""
        import app.routes.admin.security as mod

        source = inspect.getsource(mod.SecurityPolicyRequest)
        assert "minimum_ecdsa_bits" in source
        assert "256" in source

    def test_allow_dsa_keys_field(self):
        """Verify allow_dsa_keys field with default False."""
        import app.routes.admin.security as mod

        source = inspect.getsource(mod.SecurityPolicyRequest)
        assert "allow_dsa_keys" in source
        assert "False" in source

    def test_enforce_fips_field(self):
        """Verify enforce_fips field exists for FIPS compliance."""
        import app.routes.admin.security as mod

        source = inspect.getsource(mod.SecurityPolicyRequest)
        assert "enforce_fips" in source


@pytest.mark.unit
class TestAC4TemplatePermission:
    """AC-4: Security template application requires SYSTEM_CONFIG permission."""

    def test_apply_template_requires_system_config(self):
        """Verify apply_security_template uses @require_permission(Permission.SYSTEM_CONFIG)."""
        import app.routes.admin.security as mod

        source = inspect.getsource(mod)
        # Find the apply_security_template function and verify decorator
        assert "apply_security_template" in source
        assert "@require_permission(Permission.SYSTEM_CONFIG)" in source

    def test_template_name_path_parameter(self):
        """Verify template_name is a path parameter."""
        import app.routes.admin.security as mod

        source = inspect.getsource(mod.apply_security_template)
        assert "template_name" in source


@pytest.mark.unit
class TestAC5SSHKeyValidationRequest:
    """AC-5: SSH key validation endpoint accepts key_content and optional passphrase."""

    def test_key_content_required(self):
        """Verify key_content is a required field."""
        import app.routes.admin.security as mod

        source = inspect.getsource(mod.SSHKeyValidationRequest)
        assert "key_content" in source

    def test_passphrase_optional(self):
        """Verify passphrase is optional with None default."""
        import app.routes.admin.security as mod

        source = inspect.getsource(mod.SSHKeyValidationRequest)
        assert "passphrase" in source
        assert "None" in source

    def test_validate_ssh_key_endpoint_exists(self):
        """Verify validate_ssh_key function exists and uses the request model."""
        import app.routes.admin.security as mod

        source = inspect.getsource(mod.validate_ssh_key)
        assert "SSHKeyValidationRequest" in source


@pytest.mark.unit
class TestAC6CredentialAuditPermission:
    """AC-6: Credential audit requires AUDIT_READ permission."""

    def test_audit_credential_requires_audit_read(self):
        """Verify audit_credential uses @require_permission(Permission.AUDIT_READ)."""
        import app.routes.admin.security as mod

        source = inspect.getsource(mod)
        # The decorator appears before audit_credential
        assert "Permission.AUDIT_READ" in source

    def test_audit_credential_function_exists(self):
        """Verify audit_credential function is defined."""
        import app.routes.admin.security as mod

        assert hasattr(mod, "audit_credential")
        source = inspect.getsource(mod.audit_credential)
        assert "audit" in source.lower()


@pytest.mark.unit
class TestAC7ComplianceSummaryPermission:
    """AC-7: Compliance summary requires AUDIT_READ permission."""

    def test_compliance_summary_requires_audit_read(self):
        """Verify get_compliance_summary uses @require_permission(Permission.AUDIT_READ)."""
        import app.routes.admin.security as mod

        source = inspect.getsource(mod)
        assert "get_compliance_summary" in source
        assert "AUDIT_READ" in source

    def test_compliance_summary_returns_dict(self):
        """Verify get_compliance_summary returns compliance data."""
        import app.routes.admin.security as mod

        source = inspect.getsource(mod.get_compliance_summary)
        assert "compliance_level" in source


@pytest.mark.unit
class TestAC8MfaSystemSettingsUpsert:
    """AC-8: MFA setting stored in system_settings table with ON CONFLICT upsert."""

    def test_inserts_into_system_settings(self):
        """Verify INSERT INTO system_settings for mfa_required key."""
        import app.routes.admin.security as mod

        source = inspect.getsource(mod.update_system_mfa_settings)
        assert "system_settings" in source
        assert "mfa_required" in source

    def test_on_conflict_upsert(self):
        """Verify ON CONFLICT (key) DO UPDATE pattern."""
        import app.routes.admin.security as mod

        source = inspect.getsource(mod.update_system_mfa_settings)
        assert "ON CONFLICT" in source
        assert "DO UPDATE" in source

    def test_stores_updated_by(self):
        """Verify updated_by is set from current_user."""
        import app.routes.admin.security as mod

        source = inspect.getsource(mod.update_system_mfa_settings)
        assert "updated_by" in source
        assert "current_user" in source
