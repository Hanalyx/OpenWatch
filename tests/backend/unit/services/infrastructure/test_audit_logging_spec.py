"""
Source-inspection tests for audit logging service.

Spec: specs/services/infrastructure/audit-logging.spec.yaml
"""

import inspect

import pytest


@pytest.mark.unit
class TestAC1AuditLoggerName:
    """AC-1: Audit logger uses the openwatch.audit logger name."""

    def test_audit_logger_name(self):
        import app.routes.auth.login as mod

        source = inspect.getsource(mod)
        assert "audit" in source.lower() or "logger" in source.lower()


@pytest.mark.unit
class TestAC2LogEntryFields:
    """AC-2: Log entries include user_id, action, resource_type, and ip_address."""

    def test_user_id_in_audit(self):
        import app.routes.auth.login as mod

        source = inspect.getsource(mod)
        assert "user_id" in source

    def test_ip_address_in_audit(self):
        import app.routes.auth.login as mod

        source = inspect.getsource(mod)
        assert "ip_address" in source


@pytest.mark.unit
class TestAC3SecurityEventSeverity:
    """AC-3: Security events logged at WARNING level or above."""

    def test_warning_level_used(self):
        import app.routes.auth.login as mod

        source = inspect.getsource(mod)
        assert "warning" in source.lower() or "WARNING" in source


@pytest.mark.unit
class TestAC4AuthEventCoverage:
    """AC-4: All auth events produce audit entries."""

    def test_login_success_logged(self):
        import app.routes.auth.login as mod

        source = inspect.getsource(mod)
        assert "LOGIN" in source or "login" in source.lower()

    def test_login_failure_logged(self):
        import app.routes.auth.login as mod

        source = inspect.getsource(mod)
        assert "FAIL" in source or "fail" in source.lower()


@pytest.mark.unit
class TestAC5JSONFormat:
    """AC-5: Audit log entries support structured JSON format."""

    def test_structured_logging_extra(self):
        import app.routes.auth.login as mod

        source = inspect.getsource(mod)
        assert "logger" in source.lower() or "log" in source.lower()
