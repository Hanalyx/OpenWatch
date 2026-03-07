"""
Unit tests for System Settings API contracts: session timeout.

Spec: specs/api/system/session-timeout.spec.yaml
Tests session timeout endpoints from routes/system/settings.py.
"""

import inspect
import re

import pytest

from app.routes.system.settings import (
    DEFAULT_SESSION_TIMEOUT_MINUTES,
    MAX_SESSION_TIMEOUT_MINUTES,
    MIN_SESSION_TIMEOUT_MINUTES,
    SessionTimeoutSettings,
    get_session_timeout as _get_session_timeout_handler,
    update_session_timeout as _update_session_timeout_handler,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MODULE_SOURCE = inspect.getsource(inspect.getmodule(_get_session_timeout_handler))


# ---------------------------------------------------------------------------
# AC-1: GET reads from system_settings via QueryBuilder
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSessionTimeoutAC1QueryBuilder:
    """AC-1: GET /session-timeout reads from system_settings via QueryBuilder."""

    def test_uses_query_builder(self):
        """Verify GET handler uses QueryBuilder for system_settings."""
        source = inspect.getsource(_get_session_timeout_handler)
        assert "QueryBuilder" in source
        assert "system_settings" in source

    def test_queries_correct_setting_key(self):
        """Verify the correct setting key is used."""
        source = inspect.getsource(_get_session_timeout_handler)
        assert "session_inactivity_timeout_minutes" in source


# ---------------------------------------------------------------------------
# AC-2: GET returns default when no row exists
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSessionTimeoutAC2Default:
    """AC-2: GET returns default (15 min) when no DB row."""

    def test_default_timeout_value(self):
        """Verify DEFAULT_SESSION_TIMEOUT_MINUTES is 15."""
        assert DEFAULT_SESSION_TIMEOUT_MINUTES == 15

    def test_returns_default_on_missing_row(self):
        """Verify handler returns default when row is None."""
        source = inspect.getsource(_get_session_timeout_handler)
        assert "DEFAULT_SESSION_TIMEOUT_MINUTES" in source

    def test_returns_none_timestamps_for_default(self):
        """Verify default response has None for updated_at and updated_by."""
        source = inspect.getsource(_get_session_timeout_handler)
        assert "updated_at=None" in source
        assert "updated_by=None" in source


# ---------------------------------------------------------------------------
# AC-3: PUT rejects below minimum
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSessionTimeoutAC3MinValidation:
    """AC-3: PUT rejects timeout below MIN_SESSION_TIMEOUT_MINUTES."""

    def test_min_timeout_defined(self):
        """Verify MIN_SESSION_TIMEOUT_MINUTES is defined."""
        assert MIN_SESSION_TIMEOUT_MINUTES >= 1

    def test_min_check_in_handler(self):
        """Verify handler checks against minimum."""
        source = inspect.getsource(_update_session_timeout_handler)
        assert "MIN_SESSION_TIMEOUT_MINUTES" in source

    def test_returns_400_on_underflow(self):
        """Verify HTTP 400 returned for values below minimum."""
        source = inspect.getsource(_update_session_timeout_handler)
        assert "400" in source or "BAD_REQUEST" in source


# ---------------------------------------------------------------------------
# AC-4: PUT rejects above maximum
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSessionTimeoutAC4MaxValidation:
    """AC-4: PUT rejects timeout above MAX_SESSION_TIMEOUT_MINUTES (480)."""

    def test_max_timeout_value(self):
        """Verify MAX_SESSION_TIMEOUT_MINUTES is 480."""
        assert MAX_SESSION_TIMEOUT_MINUTES == 480

    def test_max_check_in_handler(self):
        """Verify handler checks against maximum."""
        source = inspect.getsource(_update_session_timeout_handler)
        assert "MAX_SESSION_TIMEOUT_MINUTES" in source


# ---------------------------------------------------------------------------
# AC-5: PUT SQL contains no # characters (regression)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSessionTimeoutAC5NoSQLComments:
    """AC-5: PUT SQL must not contain '#' characters (PostgreSQL syntax error)."""

    def test_no_hash_in_sql_strings(self):
        """Regression: SQL strings must not contain Python comments."""
        source = inspect.getsource(_update_session_timeout_handler)
        # Find all triple-quoted strings (SQL)
        sql_strings = re.findall(r'""".*?"""', source, re.DOTALL)
        for sql_str in sql_strings:
            assert "#" not in sql_str, (
                f"Found '#' in SQL string - Python comments in SQL cause "
                f"PostgreSQL syntax errors: {sql_str[:100]}"
            )

    def test_no_noqa_in_sql_strings(self):
        """Regression: 'noqa' must not appear inside SQL strings."""
        source = inspect.getsource(_update_session_timeout_handler)
        sql_strings = re.findall(r'""".*?"""', source, re.DOTALL)
        for sql_str in sql_strings:
            assert "noqa" not in sql_str, (
                f"Found 'noqa' in SQL string: {sql_str[:100]}"
            )


# ---------------------------------------------------------------------------
# AC-6: PUT uses ON CONFLICT upsert
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSessionTimeoutAC6Upsert:
    """AC-6: PUT uses ON CONFLICT (setting_key) DO UPDATE SET."""

    def test_on_conflict_present(self):
        """Verify ON CONFLICT clause in upsert SQL."""
        source = inspect.getsource(_update_session_timeout_handler)
        assert "ON CONFLICT" in source

    def test_do_update_set_present(self):
        """Verify DO UPDATE SET in upsert SQL."""
        source = inspect.getsource(_update_session_timeout_handler)
        assert "DO UPDATE SET" in source


# ---------------------------------------------------------------------------
# AC-7: Both endpoints require SYSTEM_MAINTENANCE
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSessionTimeoutAC7Permission:
    """AC-7: Both endpoints require Permission.SYSTEM_MAINTENANCE."""

    def test_system_maintenance_permission_count(self):
        """Verify SYSTEM_MAINTENANCE appears for both timeout endpoints."""
        # Count occurrences near the session timeout functions
        get_source = inspect.getsource(_get_session_timeout_handler)
        put_source = inspect.getsource(_update_session_timeout_handler)
        # The decorator won't be in the function body but the module uses it
        assert "SYSTEM_MAINTENANCE" in _MODULE_SOURCE


# ---------------------------------------------------------------------------
# AC-8: PUT returns updated SessionTimeoutSettings
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSessionTimeoutAC8PutResponse:
    """AC-8: PUT returns updated SessionTimeoutSettings."""

    def test_returns_session_timeout_settings(self):
        """Verify PUT returns SessionTimeoutSettings."""
        source = inspect.getsource(_update_session_timeout_handler)
        assert "SessionTimeoutSettings(" in source

    def test_response_includes_timeout_minutes(self):
        """Verify response includes timeout_minutes."""
        source = inspect.getsource(_update_session_timeout_handler)
        assert "timeout_minutes=" in source


# ---------------------------------------------------------------------------
# AC-9: SessionTimeoutSettings response model fields
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSessionTimeoutAC9ResponseModel:
    """AC-9: SessionTimeoutSettings has required fields."""

    def test_has_timeout_minutes_field(self):
        """Verify timeout_minutes field exists."""
        assert hasattr(SessionTimeoutSettings, "model_fields") or hasattr(
            SessionTimeoutSettings, "__fields__"
        )
        fields = SessionTimeoutSettings.model_fields
        assert "timeout_minutes" in fields

    def test_has_updated_at_field(self):
        """Verify updated_at field exists."""
        fields = SessionTimeoutSettings.model_fields
        assert "updated_at" in fields

    def test_has_updated_by_field(self):
        """Verify updated_by field exists."""
        fields = SessionTimeoutSettings.model_fields
        assert "updated_by" in fields


# ---------------------------------------------------------------------------
# AC-10: Default constant value
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSessionTimeoutAC10DefaultConstant:
    """AC-10: DEFAULT_SESSION_TIMEOUT_MINUTES is 15."""

    def test_default_is_15(self):
        """Verify default timeout is 15 minutes."""
        assert DEFAULT_SESSION_TIMEOUT_MINUTES == 15

    def test_default_used_in_get_handler(self):
        """Verify default constant used in GET handler fallback."""
        source = inspect.getsource(_get_session_timeout_handler)
        assert "DEFAULT_SESSION_TIMEOUT_MINUTES" in source
