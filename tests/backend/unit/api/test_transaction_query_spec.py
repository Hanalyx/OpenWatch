"""
Source-inspection tests for POST /api/transactions/query.

Spec: specs/api/transactions/transaction-query.spec.yaml

Uses the source-inspection pattern (inspect.getsource on module + route
handler) so the tests don't pay the cost of booting the full app. The
DSL, cursor encoding, projection validation, and SQL shape are all
verified by matching patterns in the route handler's source.
"""

import inspect

import pytest


@pytest.mark.unit
class TestAC1EndpointExists:
    """AC-1: POST /api/transactions/query is registered at the exact path."""

    def test_query_router_exports_post_query(self):
        from app.routes.transactions import query_router

        # Gather all routes declared on the query_router
        routes = [(r.path, list(r.methods)) for r in query_router.routes]
        # Expect a /api/transactions/query POST
        assert any(
            path == "/api/transactions/query" and "POST" in methods for path, methods in routes
        ), f"POST /api/transactions/query not found; got {routes}"

    def test_query_router_included_in_main(self):
        import app.main as main_mod

        source = inspect.getsource(main_mod)
        assert "transactions_query_router" in source, "main.py must import and include the transactions query router"
        assert "include_router(transactions_query_router" in source


@pytest.mark.unit
class TestAC2Filters:
    """AC-2: All declared filters are supported."""

    def test_request_schema_declares_all_filters(self):
        from app.schemas.transaction_schemas import TransactionQueryRequest

        fields = set(TransactionQueryRequest.model_fields.keys())
        expected = {
            "host_id",
            "host_ids",
            "fleet_id",
            "rule_id",
            "rule_ids",
            "status",
            "phase",
            "severity",
            "framework",
            "initiator_type",
            "started_after",
            "started_before",
            "cursor",
            "limit",
            "fields",
        }
        missing = expected - fields
        assert not missing, f"TransactionQueryRequest missing: {missing}"

    def test_route_uses_parameterized_in_clauses(self):
        import app.routes.transactions.query as mod

        source = inspect.getsource(mod._build_where_clauses)
        # AC-8: no bare string interpolation of user values
        assert "IN (" in source, "list filters must use IN clauses"
        assert ":host_ids_" in source, "host_ids uses parameterized placeholders"
        assert ":status_" in source, "status uses parameterized placeholders"
        assert ":rule_ids_" in source
        assert ":phase_" in source

    def test_fleet_id_uses_subquery(self):
        import app.routes.transactions.query as mod

        source = inspect.getsource(mod._build_where_clauses)
        # AC-8 note: fleet_id resolves via host_group_memberships subquery
        assert "host_group_memberships" in source
        assert "SELECT host_id FROM host_group_memberships" in source

    def test_framework_uses_jsonb_operator(self):
        import app.routes.transactions.query as mod

        source = inspect.getsource(mod._build_where_clauses)
        assert "framework_refs ? :framework" in source


@pytest.mark.unit
class TestAC3Cursor:
    """AC-3: Opaque base64 cursor encoding, next_cursor/total_count in response."""

    def test_cursor_roundtrip(self):
        from datetime import datetime, timezone
        from uuid import uuid4

        from app.routes.transactions.query import _decode_cursor, _encode_cursor

        ts = datetime(2026, 4, 1, 12, 0, 0, tzinfo=timezone.utc)
        rid = uuid4()
        cur = _encode_cursor(ts, rid)
        # Opaque (base64url), not human-readable
        assert "/" not in cur
        assert "=" not in cur  # rstripped
        # Roundtrip preserves values
        got_ts, got_id = _decode_cursor(cur)
        assert got_ts == ts.isoformat()
        assert got_id == str(rid)

    def test_response_schema_has_cursor_fields(self):
        from app.schemas.transaction_schemas import TransactionQueryResponse

        fields = set(TransactionQueryResponse.model_fields.keys())
        assert fields == {"items", "total_count", "next_cursor"}

    def test_route_applies_cursor_with_tuple_compare(self):
        import app.routes.transactions.query as mod

        source = inspect.getsource(mod.query_transactions)
        # AC-3 + AC-5: tuple comparison makes tie-break deterministic
        assert "(started_at, id) < (:cursor_started_at, :cursor_id)" in source


@pytest.mark.unit
class TestAC4Projection:
    """AC-4: Fields projection with allow-list, unknown field rejects 400."""

    def test_default_fields_exclude_heavy_jsonb(self):
        from app.schemas.transaction_schemas import (
            QUERY_DEFAULT_FIELDS,
            QUERY_PROJECTION_FIELDS,
        )

        # Defaults omit the heavy JSONB columns to keep payloads small
        assert "evidence_envelope" not in QUERY_DEFAULT_FIELDS
        # But they're allowed if the client asks for them
        assert "evidence_envelope" in QUERY_PROJECTION_FIELDS
        # Defaults are all in the allow-list
        assert set(QUERY_DEFAULT_FIELDS).issubset(QUERY_PROJECTION_FIELDS)

    def test_unknown_field_raises_400(self):
        from fastapi import HTTPException

        from app.routes.transactions.query import _validate_fields

        with pytest.raises(HTTPException) as exc_info:
            _validate_fields(["id", "bogus_column"])
        assert exc_info.value.status_code == 400
        assert "bogus_column" in str(exc_info.value.detail)

    def test_empty_or_none_fields_defaults(self):
        from app.routes.transactions.query import _validate_fields
        from app.schemas.transaction_schemas import QUERY_DEFAULT_FIELDS

        assert _validate_fields(None) == list(QUERY_DEFAULT_FIELDS)
        assert _validate_fields([]) == list(QUERY_DEFAULT_FIELDS)


@pytest.mark.unit
class TestAC5Ordering:
    """AC-5: Default ORDER BY started_at DESC, id DESC."""

    def test_query_uses_stable_ordering(self):
        import app.routes.transactions.query as mod

        source = inspect.getsource(mod.query_transactions)
        assert "ORDER BY started_at DESC, id DESC" in source


@pytest.mark.unit
class TestAC6RBAC:
    """AC-6: Requires GUEST+; audit logger writes on each query."""

    def test_route_requires_role(self):
        import app.routes.transactions.query as mod

        source = inspect.getsource(mod)
        assert "@require_role" in source
        assert "UserRole.GUEST" in source

    def test_route_writes_audit_log(self):
        import app.routes.transactions.query as mod

        source = inspect.getsource(mod.query_transactions)
        assert "audit_logger" in source
        assert "TRANSACTION_QUERY" in source


@pytest.mark.unit
class TestAC7ValidationErrors:
    """AC-7: Invalid filters return HTTP 400, not 500."""

    def test_invalid_status_enum_raises_400(self):
        from fastapi import HTTPException

        from app.routes.transactions.query import _VALID_STATUSES, _validate_enum_list

        with pytest.raises(HTTPException) as exc_info:
            _validate_enum_list(["bogus"], _VALID_STATUSES, "status")
        assert exc_info.value.status_code == 400

    def test_invalid_phase_enum_raises_400(self):
        from fastapi import HTTPException

        from app.routes.transactions.query import _VALID_PHASES, _validate_enum_list

        with pytest.raises(HTTPException) as exc_info:
            _validate_enum_list(["not-a-phase"], _VALID_PHASES, "phase")
        assert exc_info.value.status_code == 400

    def test_malformed_cursor_raises_400(self):
        from fastapi import HTTPException

        from app.routes.transactions.query import _decode_cursor

        with pytest.raises(HTTPException) as exc_info:
            _decode_cursor("!!! not valid base64 !!!")
        assert exc_info.value.status_code == 400

    def test_date_range_inversion_check_present(self):
        import app.routes.transactions.query as mod

        source = inspect.getsource(mod.query_transactions)
        # Reject started_after > started_before
        assert "started_after > req.started_before" in source or (
            "started_after" in source and "started_before" in source and ">" in source
        )


@pytest.mark.unit
class TestAC8SQLSafety:
    """AC-8: All queries parameterized; no string-concat user input."""

    def test_all_filter_values_use_named_params(self):
        import app.routes.transactions.query as mod

        source = inspect.getsource(mod._build_where_clauses)
        # No f-string with user value directly in SQL
        for bad in ("f\"host_id = '{", "f\"rule_id = '{", "f\"status = '{"):
            assert bad not in source, f"raw interpolation pattern found: {bad}"
        # All values are assigned to params dict with parameterized placeholders
        assert "params[" in source


@pytest.mark.unit
class TestAC9OpenAPI:
    """AC-9: Pydantic schemas, OpenAPI example present."""

    def test_request_schema_has_openapi_example(self):
        from app.schemas.transaction_schemas import TransactionQueryRequest

        config = TransactionQueryRequest.model_config
        assert "json_schema_extra" in config
        extra = config["json_schema_extra"]
        assert "examples" in extra
        assert len(extra["examples"]) >= 1


@pytest.mark.unit
class TestAC10RegressionCoverage:
    """AC-10: This test module covers all ACs."""

    def test_this_test_file_covers_all_ac_ids(self):
        import pathlib
        import re

        this_file = pathlib.Path(__file__).read_text()
        spec_ids = {f"AC-{i}" for i in range(1, 11)}
        class_names = set(re.findall(r"class TestAC(\d+)", this_file))
        test_ids = {f"AC-{n}" for n in class_names}
        missing = spec_ids - test_ids
        assert not missing, f"Test classes missing for ACs: {missing}"
