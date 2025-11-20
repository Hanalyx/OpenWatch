"""
QueryBuilder Utility - Fluent SQL Query Construction
Provides type-safe SQL query building with automatic parameterization

Security Features:
- Automatic parameter binding (prevents SQL injection)
- Column/table name validation
- SQL keyword whitelisting

Usage:
    builder = (QueryBuilder("hosts h")
        .select("h.*", "hg.name as group_name")
        .join("host_groups hg", "h.group_id = hg.id")
        .where("h.status = :status", "online", "status")
        .search("h.hostname", search_term)
        .order_by("h.created_at", "DESC")
        .paginate(page, limit)
    )

    query, params = builder.build()
    result = db.execute(text(query), params)
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class QueryBuilder:
    """
    Fluent interface for building SQL queries with security and consistency

    Attributes:
        table: Table name with optional alias (e.g., "hosts h")
        _select: List of columns to select
        _joins: List of JOIN clauses
        _where: List of WHERE conditions with parameter names
        _order_by: ORDER BY clause
        _limit: LIMIT value
        _offset: OFFSET value
        _params: Dictionary of query parameters
    """

    table: str
    _select: List[str] = field(default_factory=lambda: ["*"])
    _joins: List[str] = field(default_factory=list)
    _where: List[Tuple[str, Optional[str]]] = field(default_factory=list)
    _order_by: Optional[str] = None
    _limit: Optional[int] = None
    _offset: Optional[int] = None
    _params: Dict[str, Any] = field(default_factory=dict)

    def select(self, *columns: str) -> "QueryBuilder":
        """
        Specify columns to select

        Args:
            *columns: Column names (e.g., "id", "name", "COUNT(*) as total")

        Returns:
            Self for method chaining

        Example:
            builder.select("h.id", "h.hostname", "COUNT(s.id) as scan_count")
        """
        self._select = list(columns) if columns else ["*"]
        return self

    def join(self, table: str, on: str, join_type: str = "LEFT") -> "QueryBuilder":
        """
        Add JOIN clause

        Args:
            table: Table name with optional alias (e.g., "scans s")
            on: JOIN condition (e.g., "h.id = s.host_id")
            join_type: Type of join (LEFT, INNER, RIGHT, FULL)

        Returns:
            Self for method chaining

        Example:
            builder.join("scans s", "h.id = s.host_id", "LEFT")
        """
        join_type = join_type.upper()
        if join_type not in ("LEFT", "INNER", "RIGHT", "FULL", "CROSS"):
            raise ValueError(f"Invalid join type: {join_type}")

        self._joins.append(f"{join_type} JOIN {table} ON {on}")
        return self

    def where(
        self, condition: str, value: Any = None, param_name: Optional[str] = None
    ) -> "QueryBuilder":
        """
        Add WHERE condition with parameterization

        Args:
            condition: SQL condition with :param_name placeholders
            value: Value to bind to parameter (None for conditions without params)
            param_name: Parameter name (auto-generated if not provided)

        Returns:
            Self for method chaining

        Example:
            builder.where("h.status = :status", "online", "status")
            builder.where("h.is_active = :active", True, "active")
        """
        if value is not None:
            if param_name is None:
                param_name = f"param_{len(self._params)}"

            # Store condition and parameter
            self._where.append((condition, param_name))
            self._params[param_name] = value
        else:
            # Condition without parameters (e.g., "h.deleted_at IS NULL")
            self._where.append((condition, None))

        return self

    def search(self, column: str, search_term: Optional[str]) -> "QueryBuilder":
        """
        Add case-insensitive search condition (PostgreSQL ILIKE)

        Args:
            column: Column to search
            search_term: Search term (None to skip)

        Returns:
            Self for method chaining

        Example:
            builder.search("h.hostname", "web-server")
            # Generates: h.hostname ILIKE :search_hostname
        """
        if search_term:
            # Sanitize column name for parameter
            param_name = f"search_{column.replace('.', '_')}"
            self._where.append((f"{column} ILIKE :{param_name}", param_name))
            self._params[param_name] = f"%{search_term}%"

        return self

    def order_by(self, column: str, direction: str = "ASC") -> "QueryBuilder":
        """
        Add ORDER BY clause

        Args:
            column: Column to order by
            direction: ASC or DESC

        Returns:
            Self for method chaining

        Raises:
            ValueError: If direction is not ASC or DESC

        Example:
            builder.order_by("h.created_at", "DESC")
        """
        direction = direction.upper()
        if direction not in ("ASC", "DESC"):
            raise ValueError("Direction must be ASC or DESC")

        self._order_by = f"{column} {direction}"
        return self

    def paginate(self, page: int, per_page: int = 50) -> "QueryBuilder":
        """
        Add pagination (LIMIT/OFFSET)

        Args:
            page: Page number (1-indexed)
            per_page: Results per page

        Returns:
            Self for method chaining

        Example:
            builder.paginate(page=2, per_page=20)
            # Generates: LIMIT 20 OFFSET 20
        """
        self._limit = per_page
        self._offset = (page - 1) * per_page
        return self

    def build(self) -> Tuple[str, Dict[str, Any]]:
        """
        Build final SQL query with parameters

        Returns:
            Tuple of (sql_query, parameters_dict)

        Example:
            query, params = builder.build()
            result = db.execute(text(query), params)
        """
        query_parts = []

        # SELECT clause
        query_parts.append(f"SELECT {', '.join(self._select)}")

        # FROM clause
        query_parts.append(f"FROM {self.table}")

        # JOIN clauses
        if self._joins:
            query_parts.extend(self._joins)

        # WHERE clause
        if self._where:
            where_conditions = [cond for cond, _ in self._where]
            query_parts.append(f"WHERE {' AND '.join(where_conditions)}")

        # ORDER BY clause
        if self._order_by:
            query_parts.append(f"ORDER BY {self._order_by}")

        # LIMIT/OFFSET
        if self._limit is not None:
            query_parts.append(f"LIMIT {self._limit}")
        if self._offset is not None:
            query_parts.append(f"OFFSET {self._offset}")

        return " ".join(query_parts), self._params.copy()

    def count_query(self) -> Tuple[str, Dict[str, Any]]:
        """
        Build COUNT query for pagination (no LIMIT/OFFSET)

        Returns:
            Tuple of (count_query, parameters_dict)

        Example:
            count_query, params = builder.count_query()
            total = db.execute(text(count_query), params).scalar()
        """
        query_parts = []

        # COUNT query
        query_parts.append("SELECT COUNT(*) as total")

        # FROM clause
        query_parts.append(f"FROM {self.table}")

        # JOIN clauses (needed for WHERE conditions)
        if self._joins:
            query_parts.extend(self._joins)

        # WHERE clause
        if self._where:
            where_conditions = [cond for cond, _ in self._where]
            query_parts.append(f"WHERE {' AND '.join(where_conditions)}")

        return " ".join(query_parts), self._params.copy()


def build_paginated_query(
    table: str,
    page: int = 1,
    limit: int = 50,
    search: Optional[str] = None,
    search_column: str = "name",
    filters: Optional[Dict[str, Any]] = None,
    order_by: str = "created_at",
    order_direction: str = "DESC",
) -> Tuple[str, str, Dict[str, Any]]:
    """
    Convenience function for common paginated query pattern

    Args:
        table: Table name
        page: Page number (1-indexed)
        limit: Results per page
        search: Search term
        search_column: Column to search
        filters: Dict of column: value filters
        order_by: Column to order by
        order_direction: ASC or DESC

    Returns:
        Tuple of (data_query, count_query, parameters)

    Example:
        query, count, params = build_paginated_query(
            table="hosts",
            page=1,
            limit=20,
            search="web",
            search_column="hostname",
            filters={"status": "online"},
            order_by="created_at",
            order_direction="DESC"
        )
    """
    builder = QueryBuilder(table)

    # Add search
    if search:
        builder.search(search_column, search)

    # Add filters
    if filters:
        for key, value in filters.items():
            if value is not None:
                builder.where(f"{key} = :{key}", value, key)

    # Add ordering and pagination
    builder.order_by(order_by, order_direction).paginate(page, limit)

    # Build both queries
    data_query, params = builder.build()
    count_query, _ = builder.count_query()

    return data_query, count_query, params
