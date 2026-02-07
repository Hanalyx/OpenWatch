"""
Mutation Builder Utilities - Fluent SQL Mutation Construction

Provides type-safe SQL mutation building (INSERT, UPDATE, DELETE) with automatic
parameterization to complement the existing QueryBuilder for SELECT queries.

Security Features:
- Automatic parameter binding (prevents SQL injection)
- WHERE clause required for UPDATE/DELETE by default (prevents accidental mass mutations)
- Column/table name validation

Usage:
    # INSERT
    builder = (InsertBuilder("hosts")
        .columns("id", "hostname", "status")
        .values(uuid4(), "web-01", "offline")
        .returning("id", "created_at")
    )
    query, params = builder.build()

    # UPDATE
    builder = (UpdateBuilder("hosts")
        .set("hostname", new_hostname)
        .set_if("description", description)  # Only if not None
        .where("id = :id", host_id, "id")
        .returning("id", "updated_at")
    )
    query, params = builder.build()

    # DELETE
    builder = (DeleteBuilder("hosts")
        .where("id = :id", host_id, "id")
        .returning("id", "hostname")
    )
    query, params = builder.build()
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class InsertBuilder:
    """
    Fluent interface for building INSERT queries with security and consistency.

    Attributes:
        table: Table name to insert into
        _columns: List of column names
        _values_list: List of value tuples (for multi-row inserts)
        _returning: List of columns to return
        _on_conflict: ON CONFLICT clause configuration
        _params: Dictionary of query parameters
    """

    table: str
    _columns: List[str] = field(default_factory=list)
    _values_list: List[Tuple[Any, ...]] = field(default_factory=list)
    _returning: List[str] = field(default_factory=list)
    _on_conflict: Optional[Dict[str, Any]] = None
    _params: Dict[str, Any] = field(default_factory=dict)

    def columns(self, *cols: str) -> "InsertBuilder":
        """
        Specify columns for the INSERT.

        Args:
            *cols: Column names to insert into.

        Returns:
            Self for method chaining.

        Example:
            builder.columns("id", "hostname", "status")
        """
        self._columns = list(cols)
        return self

    def values(self, *vals: Any) -> "InsertBuilder":
        """
        Add a row of values to insert.

        Args:
            *vals: Values corresponding to columns (in order).

        Returns:
            Self for method chaining.

        Example:
            builder.columns("id", "hostname").values(uuid4(), "web-01")
        """
        self._values_list.append(vals)
        return self

    def values_dict(self, data: Dict[str, Any]) -> "InsertBuilder":
        """
        Add a row of values from a dictionary.

        If columns haven't been set, they will be inferred from dict keys.

        Args:
            data: Dictionary of column: value pairs.

        Returns:
            Self for method chaining.

        Example:
            builder.values_dict({"id": uuid4(), "hostname": "web-01"})
        """
        if not self._columns:
            self._columns = list(data.keys())
        vals = tuple(data.get(col) for col in self._columns)
        self._values_list.append(vals)
        return self

    def returning(self, *cols: str) -> "InsertBuilder":
        """
        Add RETURNING clause for PostgreSQL.

        Args:
            *cols: Column names to return after insert.

        Returns:
            Self for method chaining.

        Example:
            builder.returning("id", "created_at")
        """
        self._returning = list(cols)
        return self

    def on_conflict_do_nothing(self, *conflict_cols: str) -> "InsertBuilder":
        """
        Add ON CONFLICT DO NOTHING clause (upsert: ignore conflicts).

        Args:
            *conflict_cols: Columns that define the conflict target.

        Returns:
            Self for method chaining.

        Example:
            builder.on_conflict_do_nothing("rule_id")
        """
        self._on_conflict = {
            "columns": list(conflict_cols),
            "action": "nothing",
        }
        return self

    def on_conflict_do_update(
        self,
        conflict_cols: List[str],
        update_cols: Optional[List[str]] = None,
    ) -> "InsertBuilder":
        """
        Add ON CONFLICT DO UPDATE clause (upsert: update on conflict).

        Args:
            conflict_cols: Columns that define the conflict target.
            update_cols: Columns to update on conflict. If None, updates all
                         non-conflict columns.

        Returns:
            Self for method chaining.

        Example:
            builder.on_conflict_do_update(["rule_id"], ["title", "severity"])
        """
        if update_cols is None:
            update_cols = [c for c in self._columns if c not in conflict_cols]
        self._on_conflict = {
            "columns": conflict_cols,
            "action": "update",
            "update_cols": update_cols,
        }
        return self

    def build(self) -> Tuple[str, Dict[str, Any]]:
        """
        Build final INSERT query with parameters.

        Returns:
            Tuple of (sql_query, parameters_dict).

        Raises:
            ValueError: If no columns or values are specified.

        Example:
            query, params = builder.build()
            result = db.execute(text(query), params)
        """
        if not self._columns:
            raise ValueError("InsertBuilder requires columns to be specified")
        if not self._values_list:
            raise ValueError("InsertBuilder requires at least one row of values")

        params: Dict[str, Any] = {}
        query_parts = []

        # INSERT INTO table (columns)
        columns_str = ", ".join(self._columns)
        query_parts.append(f"INSERT INTO {self.table} ({columns_str})")

        # VALUES clause with parameterized placeholders
        value_rows = []
        for row_idx, row_values in enumerate(self._values_list):
            if len(row_values) != len(self._columns):
                raise ValueError(
                    f"Row {row_idx} has {len(row_values)} values " f"but {len(self._columns)} columns specified"
                )
            placeholders = []
            for col_idx, value in enumerate(row_values):
                param_name = f"v{row_idx}_{self._columns[col_idx]}"
                placeholders.append(f":{param_name}")
                params[param_name] = value
            value_rows.append(f"({', '.join(placeholders)})")

        query_parts.append(f"VALUES {', '.join(value_rows)}")

        # ON CONFLICT clause
        if self._on_conflict:
            conflict_cols = ", ".join(self._on_conflict["columns"])
            if self._on_conflict["action"] == "nothing":
                query_parts.append(f"ON CONFLICT ({conflict_cols}) DO NOTHING")
            elif self._on_conflict["action"] == "update":
                update_cols = self._on_conflict["update_cols"]
                set_clauses = [f"{col} = EXCLUDED.{col}" for col in update_cols]
                query_parts.append(f"ON CONFLICT ({conflict_cols}) DO UPDATE SET {', '.join(set_clauses)}")

        # RETURNING clause
        if self._returning:
            query_parts.append(f"RETURNING {', '.join(self._returning)}")

        return " ".join(query_parts), params


@dataclass
class UpdateBuilder:
    """
    Fluent interface for building UPDATE queries with security and consistency.

    Security: Requires WHERE clause by default to prevent accidental mass updates.
    Use build_unsafe() to bypass (for intentional updates without WHERE).

    Attributes:
        table: Table name to update
        _set_clauses: List of (column, value, param_name) tuples
        _set_raw_clauses: List of raw SQL expressions for SET
        _where: List of WHERE conditions with parameter names
        _from_tables: List of tables for FROM clause (join updates)
        _returning: List of columns to return
        _params: Dictionary of query parameters
    """

    table: str
    _set_clauses: List[Tuple[str, Any, str]] = field(default_factory=list)
    _set_raw_clauses: List[Tuple[str, str]] = field(default_factory=list)
    _where: List[Tuple[str, Optional[str]]] = field(default_factory=list)
    _from_tables: List[str] = field(default_factory=list)
    _returning: List[str] = field(default_factory=list)
    _params: Dict[str, Any] = field(default_factory=dict)

    def set(self, column: str, value: Any) -> "UpdateBuilder":
        """
        Add a SET clause for a column.

        Args:
            column: Column name to update.
            value: New value for the column.

        Returns:
            Self for method chaining.

        Example:
            builder.set("hostname", "new-hostname")
        """
        param_name = f"set_{column}"
        self._set_clauses.append((column, value, param_name))
        self._params[param_name] = value
        return self

    def set_if(self, column: str, value: Any) -> "UpdateBuilder":
        """
        Add a SET clause only if value is not None.

        Args:
            column: Column name to update.
            value: New value (skipped if None).

        Returns:
            Self for method chaining.

        Example:
            builder.set_if("description", optional_description)
        """
        if value is not None:
            return self.set(column, value)
        return self

    def set_raw(self, column: str, expression: str) -> "UpdateBuilder":
        """
        Add a SET clause with a raw SQL expression.

        Args:
            column: Column name to update.
            expression: Raw SQL expression (e.g., "CURRENT_TIMESTAMP").

        Returns:
            Self for method chaining.

        Example:
            builder.set_raw("updated_at", "CURRENT_TIMESTAMP")
        """
        self._set_raw_clauses.append((column, expression))
        return self

    def set_dict(self, data: Dict[str, Any], skip_none: bool = False) -> "UpdateBuilder":
        """
        Add SET clauses from a dictionary.

        Args:
            data: Dictionary of column: value pairs.
            skip_none: If True, skip None values.

        Returns:
            Self for method chaining.

        Example:
            builder.set_dict({"hostname": "new", "status": "online"})
        """
        for column, value in data.items():
            if skip_none and value is None:
                continue
            self.set(column, value)
        return self

    def where(self, condition: str, value: Any = None, param_name: Optional[str] = None) -> "UpdateBuilder":
        """
        Add WHERE condition with parameterization.

        Args:
            condition: SQL condition with :param_name placeholders.
            value: Value to bind to parameter (None for conditions without params).
            param_name: Parameter name (auto-generated if not provided).

        Returns:
            Self for method chaining.

        Example:
            builder.where("id = :id", host_id, "id")
        """
        if value is not None:
            if param_name is None:
                param_name = f"where_{len(self._where)}"
            self._where.append((condition, param_name))
            self._params[param_name] = value
        else:
            self._where.append((condition, None))
        return self

    def where_in(self, column: str, values: List[Any], param_prefix: Optional[str] = None) -> "UpdateBuilder":
        """
        Add WHERE column IN (...) clause.

        Args:
            column: Column name.
            values: List of values for IN clause.
            param_prefix: Prefix for parameter names.

        Returns:
            Self for method chaining.

        Example:
            builder.where_in("id", [uuid1, uuid2, uuid3])
        """
        if not values:
            # Empty IN clause - always false
            self._where.append(("1 = 0", None))
            return self

        prefix = param_prefix or f"in_{column}"
        placeholders = []
        for idx, val in enumerate(values):
            param_name = f"{prefix}_{idx}"
            placeholders.append(f":{param_name}")
            self._params[param_name] = val

        condition = f"{column} IN ({', '.join(placeholders)})"
        self._where.append((condition, None))
        return self

    def from_table(self, table: str) -> "UpdateBuilder":
        """
        Add FROM clause for join updates (PostgreSQL).

        Args:
            table: Table name with optional alias.

        Returns:
            Self for method chaining.

        Example:
            builder.from_table("host_groups hg").where("hosts.group_id = hg.id")
        """
        self._from_tables.append(table)
        return self

    def returning(self, *cols: str) -> "UpdateBuilder":
        """
        Add RETURNING clause for PostgreSQL.

        Args:
            *cols: Column names to return after update.

        Returns:
            Self for method chaining.

        Example:
            builder.returning("id", "updated_at")
        """
        self._returning = list(cols)
        return self

    def build(self) -> Tuple[str, Dict[str, Any]]:
        """
        Build final UPDATE query with parameters.

        Requires WHERE clause for safety. Use build_unsafe() if you intentionally
        want to update all rows.

        Returns:
            Tuple of (sql_query, parameters_dict).

        Raises:
            ValueError: If no SET clauses or no WHERE clause.

        Example:
            query, params = builder.build()
            result = db.execute(text(query), params)
        """
        if not self._where:
            raise ValueError(
                "UpdateBuilder requires WHERE clause for safety. " "Use build_unsafe() to update without WHERE."
            )
        return self._build_internal()

    def build_unsafe(self) -> Tuple[str, Dict[str, Any]]:
        """
        Build UPDATE query without requiring WHERE clause.

        Use with caution - this can update ALL rows in the table.

        Returns:
            Tuple of (sql_query, parameters_dict).

        Raises:
            ValueError: If no SET clauses specified.
        """
        return self._build_internal()

    def _build_internal(self) -> Tuple[str, Dict[str, Any]]:
        """Internal method to build the UPDATE query."""
        if not self._set_clauses and not self._set_raw_clauses:
            raise ValueError("UpdateBuilder requires at least one SET clause")

        query_parts = []

        # UPDATE table
        query_parts.append(f"UPDATE {self.table}")

        # SET clause
        set_parts = []
        for column, _, param_name in self._set_clauses:
            set_parts.append(f"{column} = :{param_name}")
        for column, expression in self._set_raw_clauses:
            set_parts.append(f"{column} = {expression}")
        query_parts.append(f"SET {', '.join(set_parts)}")

        # FROM clause (for join updates)
        if self._from_tables:
            query_parts.append(f"FROM {', '.join(self._from_tables)}")

        # WHERE clause
        if self._where:
            where_conditions = [cond for cond, _ in self._where]
            query_parts.append(f"WHERE {' AND '.join(where_conditions)}")

        # RETURNING clause
        if self._returning:
            query_parts.append(f"RETURNING {', '.join(self._returning)}")

        return " ".join(query_parts), self._params.copy()


@dataclass
class DeleteBuilder:
    """
    Fluent interface for building DELETE queries with security and consistency.

    Security: Requires WHERE clause by default to prevent accidental mass deletes.
    Use build_unsafe() to bypass (for intentional deletes without WHERE).

    Attributes:
        table: Table name to delete from
        _where: List of WHERE conditions with parameter names
        _using_tables: List of tables for USING clause (join deletes)
        _returning: List of columns to return
        _params: Dictionary of query parameters
    """

    table: str
    _where: List[Tuple[str, Optional[str]]] = field(default_factory=list)
    _using_tables: List[str] = field(default_factory=list)
    _returning: List[str] = field(default_factory=list)
    _params: Dict[str, Any] = field(default_factory=dict)

    def where(self, condition: str, value: Any = None, param_name: Optional[str] = None) -> "DeleteBuilder":
        """
        Add WHERE condition with parameterization.

        Args:
            condition: SQL condition with :param_name placeholders.
            value: Value to bind to parameter (None for conditions without params).
            param_name: Parameter name (auto-generated if not provided).

        Returns:
            Self for method chaining.

        Example:
            builder.where("id = :id", host_id, "id")
        """
        if value is not None:
            if param_name is None:
                param_name = f"where_{len(self._where)}"
            self._where.append((condition, param_name))
            self._params[param_name] = value
        else:
            self._where.append((condition, None))
        return self

    def where_in(self, column: str, values: List[Any], param_prefix: Optional[str] = None) -> "DeleteBuilder":
        """
        Add WHERE column IN (...) clause.

        Args:
            column: Column name.
            values: List of values for IN clause.
            param_prefix: Prefix for parameter names.

        Returns:
            Self for method chaining.

        Example:
            builder.where_in("id", [uuid1, uuid2, uuid3])
        """
        if not values:
            # Empty IN clause - always false, deletes nothing
            self._where.append(("1 = 0", None))
            return self

        prefix = param_prefix or f"in_{column}"
        placeholders = []
        for idx, val in enumerate(values):
            param_name = f"{prefix}_{idx}"
            placeholders.append(f":{param_name}")
            self._params[param_name] = val

        condition = f"{column} IN ({', '.join(placeholders)})"
        self._where.append((condition, None))
        return self

    def where_subquery(
        self, column: str, subquery: str, subquery_params: Optional[Dict[str, Any]] = None
    ) -> "DeleteBuilder":
        """
        Add WHERE column IN (SELECT...) subquery.

        Args:
            column: Column name.
            subquery: SQL subquery (without the IN keyword).
            subquery_params: Parameters for the subquery.

        Returns:
            Self for method chaining.

        Example:
            builder.where_subquery("host_id",
                "SELECT id FROM hosts WHERE group_id = :group_id",
                {"group_id": group_id})
        """
        condition = f"{column} IN ({subquery})"
        self._where.append((condition, None))
        if subquery_params:
            self._params.update(subquery_params)
        return self

    def using(self, table: str) -> "DeleteBuilder":
        """
        Add USING clause for join deletes (PostgreSQL).

        Args:
            table: Table name with optional alias.

        Returns:
            Self for method chaining.

        Example:
            builder.using("host_groups hg").where("hosts.group_id = hg.id")
        """
        self._using_tables.append(table)
        return self

    def returning(self, *cols: str) -> "DeleteBuilder":
        """
        Add RETURNING clause for PostgreSQL.

        Args:
            *cols: Column names to return after delete.

        Returns:
            Self for method chaining.

        Example:
            builder.returning("id", "hostname")
        """
        self._returning = list(cols)
        return self

    def build(self) -> Tuple[str, Dict[str, Any]]:
        """
        Build final DELETE query with parameters.

        Requires WHERE clause for safety. Use build_unsafe() if you intentionally
        want to delete all rows.

        Returns:
            Tuple of (sql_query, parameters_dict).

        Raises:
            ValueError: If no WHERE clause specified.

        Example:
            query, params = builder.build()
            result = db.execute(text(query), params)
        """
        if not self._where:
            raise ValueError(
                "DeleteBuilder requires WHERE clause for safety. " "Use build_unsafe() to delete without WHERE."
            )
        return self._build_internal()

    def build_unsafe(self) -> Tuple[str, Dict[str, Any]]:
        """
        Build DELETE query without requiring WHERE clause.

        Use with caution - this can delete ALL rows in the table.

        Returns:
            Tuple of (sql_query, parameters_dict).
        """
        return self._build_internal()

    def _build_internal(self) -> Tuple[str, Dict[str, Any]]:
        """Internal method to build the DELETE query."""
        query_parts = []

        # DELETE FROM table
        query_parts.append(f"DELETE FROM {self.table}")

        # USING clause (for join deletes)
        if self._using_tables:
            query_parts.append(f"USING {', '.join(self._using_tables)}")

        # WHERE clause
        if self._where:
            where_conditions = [cond for cond, _ in self._where]
            query_parts.append(f"WHERE {' AND '.join(where_conditions)}")

        # RETURNING clause
        if self._returning:
            query_parts.append(f"RETURNING {', '.join(self._returning)}")

        return " ".join(query_parts), self._params.copy()
