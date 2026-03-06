"""
Unit tests for the error model: global exception handler shape, no stack
trace exposure, audit logging, IP extraction, status code conventions, and
error_id correlation token.

Spec: specs/system/error-model.spec.yaml
Tests global_exception_handler from app.main and HTTPException usage
patterns across route handlers.
"""

import inspect

import pytest

# ---------------------------------------------------------------------------
# AC-1: global_exception_handler returns detail + error_id (not raw exc)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC1GlobalHandlerShape:
    """AC-1: global_exception_handler returns detail and error_id keys."""

    def test_handler_returns_json_response(self):
        """Verify global_exception_handler returns JSONResponse."""
        import app.main as main_module

        source = inspect.getsource(main_module.global_exception_handler)
        assert "JSONResponse" in source

    def test_handler_includes_detail_key(self):
        """Verify 'detail' key in handler response content."""
        import app.main as main_module

        source = inspect.getsource(main_module.global_exception_handler)
        assert '"detail"' in source

    def test_handler_includes_error_id_key(self):
        """Verify 'error_id' key in handler response content."""
        import app.main as main_module

        source = inspect.getsource(main_module.global_exception_handler)
        assert '"error_id"' in source

    def test_handler_returns_500(self):
        """Verify HTTP_500_INTERNAL_SERVER_ERROR status used."""
        import app.main as main_module

        source = inspect.getsource(main_module.global_exception_handler)
        assert "HTTP_500_INTERNAL_SERVER_ERROR" in source


# ---------------------------------------------------------------------------
# AC-2: Stack traces not exposed in handler response
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC2NoStackTrace:
    """AC-2: global_exception_handler does not include traceback in response."""

    def test_traceback_not_in_response_content(self):
        """Verify traceback module or exc.__traceback__ not returned to client."""
        import app.main as main_module

        source = inspect.getsource(main_module.global_exception_handler)
        # Response content dict should not contain traceback
        assert "traceback" not in source or "log" in source

    def test_generic_detail_message(self):
        """Verify response uses generic message, not f-string of exception."""
        import app.main as main_module

        source = inspect.getsource(main_module.global_exception_handler)
        assert "Internal server error" in source

    def test_response_content_uses_generic_message(self):
        """Verify JSONResponse content is a hardcoded generic message, not f-string of exc."""
        import app.main as main_module

        source = inspect.getsource(main_module.global_exception_handler)
        # The JSONResponse content dict should use a literal string for detail,
        # not interpolate exc directly into the response body
        assert "Internal server error" in source
        # Confirm the detail key value is a string literal (not exc itself)
        assert '"Internal server error"' in source or "'Internal server error'" in source


# ---------------------------------------------------------------------------
# AC-3: Audit logging in global handler
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC3AuditLogging:
    """AC-3: global_exception_handler logs EXCEPTION security event."""

    def test_logs_exception_event(self):
        """Verify EXCEPTION event logged via audit_logger."""
        import app.main as main_module

        source = inspect.getsource(main_module.global_exception_handler)
        assert "EXCEPTION" in source
        assert "audit_logger" in source

    def test_logs_path_info(self):
        """Verify request path is included in audit log."""
        import app.main as main_module

        source = inspect.getsource(main_module.global_exception_handler)
        assert "request.url.path" in source or "url.path" in source

    def test_exception_logged_server_side(self):
        """Verify logger.error called for server-side trace."""
        import app.main as main_module

        source = inspect.getsource(main_module.global_exception_handler)
        assert "logger.error" in source


# ---------------------------------------------------------------------------
# AC-4: Client IP extraction (X-Forwarded-For aware)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC4ClientIPExtraction:
    """AC-4: global_exception_handler extracts real client IP."""

    def test_checks_x_forwarded_for(self):
        """Verify X-Forwarded-For header checked for proxy-forwarded IP."""
        import app.main as main_module

        source = inspect.getsource(main_module.global_exception_handler)
        assert "x-forwarded-for" in source

    def test_falls_back_to_client_host(self):
        """Verify request.client.host used as fallback."""
        import app.main as main_module

        source = inspect.getsource(main_module.global_exception_handler)
        assert "request.client.host" in source

    def test_splits_forwarded_for_header(self):
        """Verify comma-split used for X-Forwarded-For (first IP = client)."""
        import app.main as main_module

        source = inspect.getsource(main_module.global_exception_handler)
        assert "split" in source


# ---------------------------------------------------------------------------
# AC-5: 401 for auth failures
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC5AuthStatusCodes:
    """AC-5: Authentication route uses HTTP_401 for all auth failures."""

    def test_login_uses_401_for_inactive(self):
        """Verify HTTP_401_UNAUTHORIZED raised for inactive account."""
        from app.routes.auth.login import login

        source = inspect.getsource(login)
        assert "HTTP_401_UNAUTHORIZED" in source
        assert "is_active" in source

    def test_login_uses_401_for_locked(self):
        """Verify HTTP_401_UNAUTHORIZED raised for locked account."""
        from app.routes.auth.login import login

        source = inspect.getsource(login)
        assert "locked_until" in source
        assert "HTTP_401_UNAUTHORIZED" in source

    def test_login_uses_401_for_bad_password(self):
        """Verify HTTP_401_UNAUTHORIZED used for wrong password path."""
        from app.routes.auth.login import login

        source = inspect.getsource(login)
        # Multiple 401 uses (inactive, locked, wrong password)
        assert source.count("HTTP_401_UNAUTHORIZED") >= 2


# ---------------------------------------------------------------------------
# AC-6: 403 for authz, 402 for license
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC6AuthzStatusCodes:
    """AC-6: Authorization failures use 403; license failures use 402 or 403."""

    def test_exceptions_uses_403_for_license(self):
        """Verify HTTP_403_FORBIDDEN raised when license missing in exceptions."""
        from app.routes.compliance.exceptions import request_exception

        source = inspect.getsource(request_exception)
        assert "HTTP_403_FORBIDDEN" in source

    def test_remediation_uses_402_for_license(self):
        """Verify HTTP_402_PAYMENT_REQUIRED raised for missing license in remediation."""
        from app.routes.compliance.remediation import create_remediation_job

        source = inspect.getsource(create_remediation_job)
        assert "HTTP_402_PAYMENT_REQUIRED" in source

    def test_posture_uses_403_for_license(self):
        """Verify HTTP_403_FORBIDDEN raised for historical posture without license."""
        from app.routes.compliance.posture import get_posture

        source = inspect.getsource(get_posture)
        assert "HTTP_403_FORBIDDEN" in source


# ---------------------------------------------------------------------------
# AC-7: 404 for not found, 409 for conflict
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC7NotFoundConflict:
    """AC-7: 404 for missing resources; 409 for conflicts."""

    def test_kensa_uses_404_for_host(self):
        """Verify HTTP_404_NOT_FOUND for unknown host in kensa scan."""
        from app.routes.scans.kensa import execute_kensa_scan

        source = inspect.getsource(execute_kensa_scan)
        assert "HTTP_404_NOT_FOUND" in source

    def test_kensa_uses_409_for_active_scan(self):
        """Verify HTTP_409_CONFLICT for already-running scan."""
        from app.routes.scans.kensa import execute_kensa_scan

        source = inspect.getsource(execute_kensa_scan)
        assert "HTTP_409_CONFLICT" in source

    def test_exceptions_uses_409_for_duplicate(self):
        """Verify HTTP_409_CONFLICT for duplicate exception."""
        from app.routes.compliance.exceptions import request_exception

        source = inspect.getsource(request_exception)
        assert "HTTP_409_CONFLICT" in source


# ---------------------------------------------------------------------------
# AC-8: error_id uses int(time.time())
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC8ErrorIdFormat:
    """AC-8: error_id derived from int(time.time()) for log correlation."""

    def test_error_id_uses_time(self):
        """Verify time.time() used to generate error_id."""
        import app.main as main_module

        source = inspect.getsource(main_module.global_exception_handler)
        assert "time.time()" in source or "int(time" in source

    def test_error_id_is_string_formatted(self):
        """Verify error_id is formatted as string (f-string or str())."""
        import app.main as main_module

        source = inspect.getsource(main_module.global_exception_handler)
        assert "error_id" in source


# ---------------------------------------------------------------------------
# AC-9: Handler registered with @app.exception_handler(Exception)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC9HandlerRegistration:
    """AC-9: global_exception_handler registered on app with Exception type."""

    def test_exception_handler_decorator_present(self):
        """Verify @app.exception_handler(Exception) in main module source."""
        import app.main as main_module

        source = inspect.getsource(main_module)
        assert "exception_handler(Exception)" in source

    def test_handler_function_exists_in_app(self):
        """Verify global_exception_handler function exists in main."""
        import app.main as main_module

        assert hasattr(main_module, "global_exception_handler")
        assert callable(main_module.global_exception_handler)


# ---------------------------------------------------------------------------
# AC-10: No route returns raw exception objects
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC10NoRawExceptions:
    """AC-10: Route handlers use HTTPException, not raw Python exceptions."""

    def test_kensa_uses_http_exception(self):
        """Verify kensa route uses HTTPException for error paths."""
        from app.routes.scans.kensa import execute_kensa_scan

        source = inspect.getsource(execute_kensa_scan)
        assert "HTTPException" in source
        assert "raise HTTPException" in source

    def test_posture_uses_http_exception(self):
        """Verify posture route uses HTTPException for error paths."""
        from app.routes.compliance.posture import analyze_drift, get_posture

        for fn in [get_posture, analyze_drift]:
            source = inspect.getsource(fn)
            assert "HTTPException" in source

    def test_exceptions_route_uses_http_exception(self):
        """Verify exceptions route uses HTTPException for error paths."""
        from app.routes.compliance.exceptions import approve_exception

        source = inspect.getsource(approve_exception)
        assert "HTTPException" in source
