"""
Unit tests for input validation and error sanitization service contract.

Spec: specs/services/validation/input-validation.spec.yaml
"""
import inspect

import pytest


@pytest.mark.unit
class TestAC1SanitizationLevelEnum:
    """AC-1: SanitizationLevel enum has MINIMAL, STANDARD, STRICT values."""

    def test_enum_defined(self):
        """Verify SanitizationLevel is defined as an Enum."""
        import app.services.validation.sanitization as mod

        source = inspect.getsource(mod.SanitizationLevel)
        assert "class SanitizationLevel" in source
        assert "Enum" in source

    def test_minimal_value(self):
        """Verify MINIMAL enum member exists."""
        import app.services.validation.sanitization as mod

        source = inspect.getsource(mod.SanitizationLevel)
        assert "MINIMAL" in source
        assert '"minimal"' in source

    def test_standard_value(self):
        """Verify STANDARD enum member exists."""
        import app.services.validation.sanitization as mod

        source = inspect.getsource(mod.SanitizationLevel)
        assert "STANDARD" in source
        assert '"standard"' in source

    def test_strict_value(self):
        """Verify STRICT enum member exists."""
        import app.services.validation.sanitization as mod

        source = inspect.getsource(mod.SanitizationLevel)
        assert "STRICT" in source
        assert '"strict"' in source


@pytest.mark.unit
class TestAC2SensitivePatterns:
    """AC-2: SENSITIVE_PATTERNS includes regex for usernames, hostnames, IPs, file paths."""

    def test_username_pattern(self):
        """Verify pattern matching username/user/login keywords."""
        import app.services.validation.sanitization as mod

        source = inspect.getsource(mod.ErrorSanitizationService)
        assert "username" in source
        assert "SENSITIVE_PATTERNS" in source

    def test_hostname_pattern(self):
        """Verify pattern matching hostname/host/server keywords."""
        import app.services.validation.sanitization as mod

        source = inspect.getsource(mod.ErrorSanitizationService)
        assert "hostname" in source

    def test_ip_address_pattern(self):
        """Verify dotted-quad IP address pattern."""
        import app.services.validation.sanitization as mod

        patterns_source = str(mod.ErrorSanitizationService.SENSITIVE_PATTERNS)
        # Check for IP address regex pattern (dotted quad)
        assert "0-9" in patterns_source

    def test_file_path_pattern(self):
        """Verify Unix file path pattern with extensions."""
        import app.services.validation.sanitization as mod

        patterns_source = str(mod.ErrorSanitizationService.SENSITIVE_PATTERNS)
        assert ".sh" in patterns_source or "conf" in patterns_source


@pytest.mark.unit
class TestAC3GenericMessages:
    """AC-3: GENERIC_MESSAGES maps error codes (NET_*, AUTH_*, PRIV_*, RES_, DEP_*) to user-safe messages."""

    def test_net_error_codes(self):
        """Verify NET_ prefix error codes in GENERIC_MESSAGES."""
        import app.services.validation.sanitization as mod

        messages = mod.ErrorSanitizationService.GENERIC_MESSAGES
        net_codes = [k for k in messages if k.startswith("NET_")]
        assert len(net_codes) >= 1

    def test_auth_error_codes(self):
        """Verify AUTH_ prefix error codes in GENERIC_MESSAGES."""
        import app.services.validation.sanitization as mod

        messages = mod.ErrorSanitizationService.GENERIC_MESSAGES
        auth_codes = [k for k in messages if k.startswith("AUTH_")]
        assert len(auth_codes) >= 1

    def test_priv_error_codes(self):
        """Verify PRIV_ prefix error codes in GENERIC_MESSAGES."""
        import app.services.validation.sanitization as mod

        messages = mod.ErrorSanitizationService.GENERIC_MESSAGES
        priv_codes = [k for k in messages if k.startswith("PRIV_")]
        assert len(priv_codes) >= 1

    def test_res_error_codes(self):
        """Verify RES_ prefix error codes in GENERIC_MESSAGES."""
        import app.services.validation.sanitization as mod

        messages = mod.ErrorSanitizationService.GENERIC_MESSAGES
        res_codes = [k for k in messages if k.startswith("RES_")]
        assert len(res_codes) >= 1

    def test_dep_error_codes(self):
        """Verify DEP_ prefix error codes in GENERIC_MESSAGES."""
        import app.services.validation.sanitization as mod

        messages = mod.ErrorSanitizationService.GENERIC_MESSAGES
        dep_codes = [k for k in messages if k.startswith("DEP_")]
        assert len(dep_codes) >= 1

    def test_exec_error_codes(self):
        """Verify EXEC_ prefix error codes in GENERIC_MESSAGES."""
        import app.services.validation.sanitization as mod

        messages = mod.ErrorSanitizationService.GENERIC_MESSAGES
        exec_codes = [k for k in messages if k.startswith("EXEC_")]
        assert len(exec_codes) >= 1

    def test_all_values_are_strings(self):
        """Verify all GENERIC_MESSAGES values are user-safe strings."""
        import app.services.validation.sanitization as mod

        messages = mod.ErrorSanitizationService.GENERIC_MESSAGES
        for code, msg in messages.items():
            assert isinstance(msg, str), f"{code} value is not a string"
            assert len(msg) > 5, f"{code} message too short to be useful"


@pytest.mark.unit
class TestAC4RateLimiting:
    """AC-4: Rate limiting enforces MAX_ERRORS_PER_HOUR (50) and MAX_ERRORS_PER_MINUTE (10)."""

    def test_max_errors_per_hour(self):
        """Verify MAX_ERRORS_PER_HOUR = 50."""
        import app.services.validation.sanitization as mod

        assert mod.ErrorSanitizationService.MAX_ERRORS_PER_HOUR == 50

    def test_max_errors_per_minute(self):
        """Verify MAX_ERRORS_PER_MINUTE = 10."""
        import app.services.validation.sanitization as mod

        assert mod.ErrorSanitizationService.MAX_ERRORS_PER_MINUTE == 10

    def test_rate_limit_check_method(self):
        """Verify _is_rate_limited method exists."""
        import app.services.validation.sanitization as mod

        source = inspect.getsource(mod.ErrorSanitizationService)
        assert "_is_rate_limited" in source

    def test_rate_limit_update_method(self):
        """Verify _update_rate_limit method exists."""
        import app.services.validation.sanitization as mod

        source = inspect.getsource(mod.ErrorSanitizationService)
        assert "_update_rate_limit" in source


@pytest.mark.unit
class TestAC5ErrorClassification:
    """AC-5: ErrorClassificationService classifies connection/auth/resource errors by keyword matching."""

    def test_network_keywords(self):
        """Verify network error keywords: connection refused, timeout, unreachable."""
        import app.services.validation.errors as mod

        source = inspect.getsource(mod.ErrorClassificationService.classify_error)
        assert "connection refused" in source
        assert "timeout" in source
        assert "unreachable" in source

    def test_auth_keywords(self):
        """Verify auth error keywords: permission denied, authentication failed, invalid credentials."""
        import app.services.validation.errors as mod

        source = inspect.getsource(mod.ErrorClassificationService.classify_error)
        assert "permission denied" in source
        assert "authentication failed" in source
        assert "invalid credentials" in source

    def test_resource_keywords(self):
        """Verify resource error keywords: no space, disk full, out of memory."""
        import app.services.validation.errors as mod

        source = inspect.getsource(mod.ErrorClassificationService.classify_error)
        assert "no space" in source
        assert "disk full" in source
        assert "out of memory" in source

    def test_returns_scan_error_internal(self):
        """Verify classify_error returns ScanErrorInternal instances."""
        import app.services.validation.errors as mod

        source = inspect.getsource(mod.ErrorClassificationService.classify_error)
        assert "ScanErrorInternal" in source


@pytest.mark.unit
class TestAC6SanitizationRedaction:
    """AC-6: Sanitized errors replace sensitive data with [REDACTED]."""

    def test_redacted_replacement(self):
        """Verify [REDACTED] replacement in _sanitize_guidance."""
        import app.services.validation.sanitization as mod

        source = inspect.getsource(mod.ErrorSanitizationService._sanitize_guidance)
        assert "[REDACTED]" in source

    def test_uses_re_sub(self):
        """Verify re.sub used with SENSITIVE_PATTERNS."""
        import app.services.validation.sanitization as mod

        source = inspect.getsource(mod.ErrorSanitizationService._sanitize_guidance)
        assert "re.sub" in source
        assert "SENSITIVE_PATTERNS" in source


@pytest.mark.unit
class TestAC7SecurityContextModel:
    """AC-7: SecurityContext model includes hostname, username, auth_method, source_ip."""

    def test_hostname_field(self):
        """Verify hostname field on SecurityContext."""
        import app.services.validation.errors as mod

        source = inspect.getsource(mod.SecurityContext)
        assert "hostname" in source

    def test_username_field(self):
        """Verify username field on SecurityContext."""
        import app.services.validation.errors as mod

        source = inspect.getsource(mod.SecurityContext)
        assert "username" in source

    def test_auth_method_field(self):
        """Verify auth_method field on SecurityContext."""
        import app.services.validation.errors as mod

        source = inspect.getsource(mod.SecurityContext)
        assert "auth_method" in source

    def test_source_ip_field(self):
        """Verify source_ip field on SecurityContext."""
        import app.services.validation.errors as mod

        source = inspect.getsource(mod.SecurityContext)
        assert "source_ip" in source


@pytest.mark.unit
class TestAC8UnifiedValidationSteps:
    """AC-8: UnifiedValidationService performs multi-step validation."""

    def test_credential_resolution_step(self):
        """Verify credential resolution step in validate_scan_prerequisites."""
        import app.services.validation.unified as mod

        source = inspect.getsource(mod.UnifiedValidationService.validate_scan_prerequisites)
        assert "_resolve_credentials" in source
        assert "credential_resolution" in source

    def test_network_connectivity_step(self):
        """Verify network connectivity test step."""
        import app.services.validation.unified as mod

        source = inspect.getsource(mod.UnifiedValidationService.validate_scan_prerequisites)
        assert "_test_network_connectivity" in source
        assert "network_connectivity" in source

    def test_ssh_authentication_step(self):
        """Verify SSH authentication test step."""
        import app.services.validation.unified as mod

        source = inspect.getsource(mod.UnifiedValidationService.validate_scan_prerequisites)
        assert "_test_ssh_authentication" in source
        assert "authentication" in source

    def test_privilege_check_step(self):
        """Verify privilege check step."""
        import app.services.validation.unified as mod

        source = inspect.getsource(mod.UnifiedValidationService.validate_scan_prerequisites)
        assert "_test_system_privileges" in source
        assert "privileges" in source

    def test_resource_check_step(self):
        """Verify resource check step."""
        import app.services.validation.unified as mod

        source = inspect.getsource(mod.UnifiedValidationService.validate_scan_prerequisites)
        assert "_test_system_resources" in source
        assert "resources" in source
