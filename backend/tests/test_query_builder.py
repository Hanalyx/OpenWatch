"""
Unit Tests for QueryBuilder Utility

Tests SQL query construction, parameterization, and security features.
Validates that QueryBuilder generates safe, parameterized SQL queries
to prevent SQL injection attacks (OWASP A03:2021 - Injection).

Test Categories:
- Basic query construction (SELECT, FROM)
- WHERE clause handling with parameterization
- Search functionality (ILIKE patterns)
- JOIN operations (LEFT, INNER, etc.)
- Ordering and pagination (ORDER BY, LIMIT, OFFSET)
- COUNT query generation
- SQL injection prevention
- Complex real-world query patterns
- Parameter isolation (immutability)
"""

import pytest

from app.utils.query_builder import QueryBuilder, build_paginated_query


class TestBasicQueries:
    """Test basic query construction"""

    def test_simple_select(self) -> None:
        """Test basic SELECT * query"""
        query, params = QueryBuilder("hosts").build()

        assert query == "SELECT * FROM hosts"
        assert params == {}

    def test_select_specific_columns(self) -> None:
        """Test SELECT with specific columns"""
        query, params = QueryBuilder("hosts").select("id", "hostname", "ip_address").build()

        assert "SELECT id, hostname, ip_address" in query
        assert "FROM hosts" in query
        assert params == {}

    def test_table_with_alias(self) -> None:
        """Test table name with alias"""
        query, params = QueryBuilder("hosts h").build()

        assert "FROM hosts h" in query


class TestWhereConditions:
    """Test WHERE clause construction"""

    def test_single_where_condition(self) -> None:
        """Test single WHERE condition with parameter"""
        query, params = QueryBuilder("hosts").where("status = :status", "online", "status").build()

        assert "WHERE status = :status" in query
        assert params == {"status": "online"}

    def test_multiple_where_conditions(self) -> None:
        """Test multiple WHERE conditions (AND)"""
        query, params = (
            QueryBuilder("hosts")
            .where("status = :status", "online", "status")
            .where("is_active = :active", True, "active")
            .build()
        )

        assert "WHERE status = :status AND is_active = :active" in query
        assert params == {"status": "online", "active": True}

    def test_where_without_parameters(self) -> None:
        """Test WHERE condition without parameters"""
        query, params = QueryBuilder("hosts").where("deleted_at IS NULL").build()

        assert "WHERE deleted_at IS NULL" in query
        assert params == {}

    def test_auto_parameter_naming(self) -> None:
        """Test automatic parameter name generation"""
        query, params = QueryBuilder("hosts").where("status = :param_0", "online").build()  # No param_name provided

        # Should auto-generate param name
        assert ":param_0" in query or len(params) == 1
        assert "online" in params.values()


class TestSearchFunctionality:
    """Test case-insensitive search"""

    def test_search_adds_ilike(self) -> None:
        """Test search generates ILIKE condition"""
        query, params = QueryBuilder("hosts").search("hostname", "web-server").build()

        assert "ILIKE" in query
        assert "hostname" in query
        assert params["search_hostname"] == "%web-server%"

    def test_search_none_skips_condition(self) -> None:
        """Test search with None doesn't add condition"""
        query, params = QueryBuilder("hosts").search("hostname", None).build()

        assert "ILIKE" not in query
        assert params == {}

    def test_search_empty_string_skips(self) -> None:
        """Test search with empty string doesn't add condition"""
        query, params = QueryBuilder("hosts").search("hostname", "").build()

        assert "ILIKE" not in query
        assert params == {}


class TestJoinOperations:
    """Test JOIN clause construction"""

    def test_left_join(self) -> None:
        """Test LEFT JOIN"""
        query, params = QueryBuilder("hosts h").join("scans s", "h.id = s.host_id", "LEFT").build()

        assert "LEFT JOIN scans s ON h.id = s.host_id" in query

    def test_inner_join(self) -> None:
        """Test INNER JOIN"""
        query, params = QueryBuilder("hosts h").join("host_groups hg", "h.group_id = hg.id", "INNER").build()

        assert "INNER JOIN host_groups hg ON h.group_id = hg.id" in query

    def test_multiple_joins(self) -> None:
        """Test multiple JOIN clauses"""
        query, params = (
            QueryBuilder("hosts h")
            .join("scans s", "h.id = s.host_id")
            .join("host_groups hg", "h.group_id = hg.id")
            .build()
        )

        assert "LEFT JOIN scans s ON h.id = s.host_id" in query
        assert "LEFT JOIN host_groups hg ON h.group_id = hg.id" in query

    def test_invalid_join_type_raises_error(self) -> None:
        """Test invalid JOIN type raises ValueError"""
        with pytest.raises(ValueError, match="Invalid join type"):
            QueryBuilder("hosts").join("scans", "h.id = s.id", "INVALID")


class TestOrderingAndPagination:
    """Test ORDER BY and pagination"""

    def test_order_by_asc(self) -> None:
        """Test ORDER BY ascending"""
        query, params = QueryBuilder("hosts").order_by("created_at", "ASC").build()

        assert "ORDER BY created_at ASC" in query

    def test_order_by_desc(self) -> None:
        """Test ORDER BY descending"""
        query, params = QueryBuilder("hosts").order_by("created_at", "DESC").build()

        assert "ORDER BY created_at DESC" in query

    def test_order_by_invalid_direction_raises_error(self) -> None:
        """Test invalid ORDER BY direction raises ValueError"""
        with pytest.raises(ValueError, match="Direction must be ASC or DESC"):
            QueryBuilder("hosts").order_by("id", "INVALID")

    def test_pagination_first_page(self) -> None:
        """Test pagination for first page"""
        query, params = QueryBuilder("hosts").paginate(page=1, per_page=50).build()

        assert "LIMIT 50" in query
        assert "OFFSET 0" in query

    def test_pagination_second_page(self) -> None:
        """Test pagination for second page"""
        query, params = QueryBuilder("hosts").paginate(page=2, per_page=50).build()

        assert "LIMIT 50" in query
        assert "OFFSET 50" in query

    def test_pagination_custom_per_page(self) -> None:
        """Test pagination with custom per_page"""
        query, params = QueryBuilder("hosts").paginate(page=3, per_page=20).build()

        assert "LIMIT 20" in query
        assert "OFFSET 40" in query  # (3-1) * 20


class TestCountQuery:
    """Test COUNT query generation"""

    def test_count_query_basic(self) -> None:
        """Test basic COUNT query"""
        count_query, params = QueryBuilder("hosts").count_query()

        assert "SELECT COUNT(*) as total" in count_query
        assert "FROM hosts" in count_query
        assert "LIMIT" not in count_query
        assert "OFFSET" not in count_query

    def test_count_query_preserves_where(self) -> None:
        """Test COUNT query preserves WHERE conditions"""
        count_query, params = QueryBuilder("hosts").where("status = :status", "online", "status").count_query()

        assert "WHERE status = :status" in count_query
        assert params == {"status": "online"}

    def test_count_query_preserves_joins(self) -> None:
        """Test COUNT query preserves JOIN clauses"""
        count_query, params = QueryBuilder("hosts h").join("scans s", "h.id = s.host_id").count_query()

        assert "LEFT JOIN scans s ON h.id = s.host_id" in count_query

    def test_count_query_removes_pagination(self) -> None:
        """Test COUNT query removes LIMIT/OFFSET"""
        count_query, params = (
            QueryBuilder("hosts")
            .where("status = :status", "online", "status")
            .paginate(page=2, per_page=50)
            .count_query()
        )

        assert "LIMIT" not in count_query
        assert "OFFSET" not in count_query
        assert "WHERE status = :status" in count_query


class TestSQLInjectionPrevention:
    """Test SQL injection protection (OWASP A03:2021)"""

    def test_malicious_search_input(self) -> None:
        """Test malicious search input is parameterized"""
        malicious_input = "'; DROP TABLE hosts; --"

        query, params = QueryBuilder("hosts").search("hostname", malicious_input).build()

        # Malicious input should be in params, NOT in query string
        assert "DROP TABLE" not in query
        assert ";" not in query or query.count(";") == 0  # No SQL terminators in query
        assert any(malicious_input in str(v) for v in params.values())

    def test_malicious_where_value(self) -> None:
        """Test malicious WHERE value is parameterized"""
        malicious_input = "online' OR '1'='1"

        query, params = QueryBuilder("hosts").where("status = :status", malicious_input, "status").build()

        # Malicious input in params, not query
        assert "OR '1'='1'" not in query
        assert params["status"] == malicious_input

    def test_null_byte_injection(self) -> None:
        """Test null byte injection is handled"""
        malicious_input = "test\x00hostname"

        query, params = QueryBuilder("hosts").search("hostname", malicious_input).build()

        # Should be parameterized safely
        assert params["search_hostname"] == f"%{malicious_input}%"


class TestComplexQueries:
    """Test complex real-world query patterns"""

    def test_host_list_query(self) -> None:
        """Test realistic host list query with joins, filters, search, pagination"""
        builder = (
            QueryBuilder("hosts h")
            .select("h.*", "hg.name as group_name", "hg.color as group_color", "s.status as scan_status")
            .join("host_groups hg", "h.group_id = hg.id")
            .join("scans s", "h.latest_scan_id = s.id")
            .where("h.is_active = :active", True, "active")
            .search("h.hostname", "web")
            .order_by("h.created_at", "DESC")
            .paginate(page=1, per_page=20)
        )

        query, params = builder.build()

        # Verify all components present
        assert "SELECT h.*, hg.name as group_name" in query
        assert "LEFT JOIN host_groups hg ON h.group_id = hg.id" in query
        assert "LEFT JOIN scans s ON h.latest_scan_id = s.id" in query
        assert "WHERE h.is_active = :active AND h.hostname ILIKE :search_h_hostname" in query
        assert "ORDER BY h.created_at DESC" in query
        assert "LIMIT 20" in query
        assert "OFFSET 0" in query

        assert params == {"active": True, "search_h_hostname": "%web%"}

    def test_conditional_filters(self) -> None:
        """Test conditional filter application"""
        builder = QueryBuilder("hosts")
        builder.where("is_active = :active", True, "active")

        # Conditionally add status filter
        status_filter = "online"
        if status_filter:
            builder.where("status = :status", status_filter, "status")

        query, params = builder.build()

        assert "WHERE is_active = :active AND status = :status" in query
        assert params == {"active": True, "status": "online"}


class TestConvenienceFunction:
    """Test build_paginated_query convenience function"""

    def test_basic_paginated_query(self) -> None:
        """Test basic paginated query"""
        data_query, count_query, params = build_paginated_query(table="hosts", page=1, limit=20)

        assert "SELECT * FROM hosts" in data_query
        assert "LIMIT 20" in data_query
        assert "SELECT COUNT(*)" in count_query

    def test_paginated_query_with_search(self) -> None:
        """Test paginated query with search"""
        data_query, count_query, params = build_paginated_query(
            table="hosts", page=1, limit=20, search="web", search_column="hostname"
        )

        assert "hostname ILIKE :search_hostname" in data_query
        assert params["search_hostname"] == "%web%"

    def test_paginated_query_with_filters(self) -> None:
        """Test paginated query with filters"""
        data_query, count_query, params = build_paginated_query(
            table="hosts", page=1, limit=20, filters={"status": "online", "is_active": True}
        )

        assert "status = :status" in data_query
        assert "is_active = :is_active" in data_query
        assert params == {"status": "online", "is_active": True}

    def test_paginated_query_with_ordering(self) -> None:
        """Test paginated query with custom ordering"""
        data_query, count_query, params = build_paginated_query(
            table="hosts", page=2, limit=50, order_by="hostname", order_direction="ASC"
        )

        assert "ORDER BY hostname ASC" in data_query
        assert "OFFSET 50" in data_query


class TestParameterIsolation:
    """Test parameter dictionaries are isolated"""

    def test_params_are_copied(self) -> None:
        """Test that build() returns copy of params, not reference"""
        builder = QueryBuilder("hosts").where("status = :status", "online", "status")

        query1, params1 = builder.build()
        query2, params2 = builder.build()

        # Modify params1
        params1["status"] = "offline"

        # params2 should be unchanged
        assert params2["status"] == "online"

    def test_count_query_independent_params(self) -> None:
        """Test count_query returns independent parameter dict"""
        builder = QueryBuilder("hosts").where("status = :status", "online", "status").paginate(1, 50)

        data_query, data_params = builder.build()
        count_query, count_params = builder.count_query()

        # Modify data_params
        data_params["status"] = "offline"

        # count_params should be unchanged
        assert count_params["status"] == "online"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
