"""
Unit tests for credential sharing route contract (Kensa integration).

Spec: specs/api/admin/credentials.spec.yaml
"""
import inspect

import pytest


@pytest.mark.unit
class TestAC1KensaSignatureValidation:
    """AC-1: All credential endpoints require valid Kensa signature (X-Kensa-Signature header)."""

    def test_validate_kensa_request_dependency(self):
        """Verify validate_kensa_request is used as a dependency."""
        import app.routes.admin.credentials as mod

        source = inspect.getsource(mod)
        assert "validate_kensa_request" in source
        assert "Depends(validate_kensa_request)" in source

    def test_requires_x_kensa_signature_header(self):
        """Verify X-Kensa-Signature header is required."""
        import app.routes.admin.credentials as mod

        source = inspect.getsource(mod.validate_kensa_request)
        assert "X-Kensa-Signature" in source

    def test_missing_signature_returns_401(self):
        """Verify missing signature raises 401 UNAUTHORIZED."""
        import app.routes.admin.credentials as mod

        source = inspect.getsource(mod.validate_kensa_request)
        assert "HTTP_401_UNAUTHORIZED" in source
        assert "Missing Kensa signature header" in source

    def test_hmac_verification_function(self):
        """Verify HMAC-SHA256 verification function exists."""
        import app.routes.admin.credentials as mod

        source = inspect.getsource(mod.verify_kensa_signature)
        assert "hmac" in source
        assert "sha256" in source
        assert "compare_digest" in source


@pytest.mark.unit
class TestAC2HostNotFound404:
    """AC-2: Host credential lookup returns 404 for missing or inactive host."""

    def test_returns_404_for_missing_host(self):
        """Verify 404 NOT_FOUND raised when host not found."""
        import app.routes.admin.credentials as mod

        source = inspect.getsource(mod.get_host_credentials)
        assert "HTTP_404_NOT_FOUND" in source

    def test_detail_message(self):
        """Verify 404 detail says host not found or inactive."""
        import app.routes.admin.credentials as mod

        source = inspect.getsource(mod.get_host_credentials)
        assert "Host not found or inactive" in source

    def test_filters_active_hosts(self):
        """Verify query filters on is_active = true."""
        import app.routes.admin.credentials as mod

        source = inspect.getsource(mod.get_host_credentials)
        assert "is_active" in source


@pytest.mark.unit
class TestAC3CredentialDecryption:
    """AC-3: Credentials decrypted from encrypted_credentials (base64 + JSON)."""

    def test_base64_decode(self):
        """Verify base64.b64decode is used for decryption."""
        import app.routes.admin.credentials as mod

        source = inspect.getsource(mod.get_host_credentials)
        assert "base64.b64decode" in source

    def test_json_loads(self):
        """Verify json.loads is used to parse decoded credentials."""
        import app.routes.admin.credentials as mod

        source = inspect.getsource(mod.get_host_credentials)
        assert "json.loads" in source

    def test_extracts_ssh_key_and_password(self):
        """Verify ssh_key and password extracted from credentials data."""
        import app.routes.admin.credentials as mod

        source = inspect.getsource(mod.get_host_credentials)
        assert 'credentials_data.get("ssh_key")' in source
        assert 'credentials_data.get("password")' in source

    def test_detect_key_type_for_ssh_keys(self):
        """Verify detect_key_type called when SSH key present."""
        import app.routes.admin.credentials as mod

        source = inspect.getsource(mod.get_host_credentials)
        assert "detect_key_type" in source


@pytest.mark.unit
class TestAC4BatchLimit100:
    """AC-4: Batch endpoint limits to 100 hosts per request (400 if exceeded)."""

    def test_batch_size_check(self):
        """Verify batch size limited to 100."""
        import app.routes.admin.credentials as mod

        source = inspect.getsource(mod.get_multiple_host_credentials)
        assert "100" in source

    def test_returns_400_when_exceeded(self):
        """Verify 400 BAD_REQUEST raised when limit exceeded."""
        import app.routes.admin.credentials as mod

        source = inspect.getsource(mod.get_multiple_host_credentials)
        assert "HTTP_400_BAD_REQUEST" in source

    def test_batch_limit_detail_message(self):
        """Verify error detail mentions 100 hosts maximum."""
        import app.routes.admin.credentials as mod

        source = inspect.getsource(mod.get_multiple_host_credentials)
        assert "Maximum 100 hosts per batch request" in source


@pytest.mark.unit
class TestAC5SystemDefaultCredentials:
    """AC-5: System default credentials use CentralizedAuthService."""

    def test_uses_auth_service(self):
        """Verify get_default_system_credentials uses get_auth_service."""
        import app.routes.admin.credentials as mod

        source = inspect.getsource(mod.get_default_system_credentials)
        assert "get_auth_service" in source

    def test_resolve_credential_with_default(self):
        """Verify resolve_credential called with use_default=True."""
        import app.routes.admin.credentials as mod

        source = inspect.getsource(mod.get_default_system_credentials)
        assert "resolve_credential" in source
        assert "use_default=True" in source

    def test_returns_404_when_no_default(self):
        """Verify 404 when no default credentials configured."""
        import app.routes.admin.credentials as mod

        source = inspect.getsource(mod.get_default_system_credentials)
        assert "HTTP_404_NOT_FOUND" in source
        assert "No default system credentials" in source


@pytest.mark.unit
class TestAC6HealthNoAuth:
    """AC-6: Health endpoint requires no authentication."""

    def test_health_no_dependencies(self):
        """Verify health endpoint has no authentication dependencies."""
        import app.routes.admin.credentials as mod

        source = inspect.getsource(mod.credentials_health_check)
        # Health check should NOT have Depends(get_current_user) or validate_kensa_request
        assert "Depends" not in source
        assert "current_user" not in source

    def test_health_returns_status(self):
        """Verify health returns status healthy."""
        import app.routes.admin.credentials as mod

        source = inspect.getsource(mod.credentials_health_check)
        assert '"healthy"' in source

    def test_health_returns_service_name(self):
        """Verify health returns service name."""
        import app.routes.admin.credentials as mod

        source = inspect.getsource(mod.credentials_health_check)
        assert "credential-sharing" in source
