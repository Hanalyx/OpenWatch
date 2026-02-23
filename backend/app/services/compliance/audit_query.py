"""
Audit Query Service

Manages saved queries for compliance evidence analysis.

Part of Phase 6: Audit Queries (Kensa Integration Plan)

OS Claim 3.3: "Audits are queries over canonical evidence"
"""

import logging
from datetime import datetime, timezone
from math import ceil
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Row
from sqlalchemy.orm import Session

from ...schemas.audit_query_schemas import (
    FindingResult,
    QueryDefinition,
    QueryExecuteResponse,
    QueryPreviewResponse,
    QueryStatsSummary,
    SavedQueryListResponse,
    SavedQueryResponse,
)
from ...utils.mutation_builders import InsertBuilder, UpdateBuilder
from ...utils.query_builder import QueryBuilder

logger = logging.getLogger(__name__)


class AuditQueryService:
    """
    Service for managing audit queries.

    Provides:
    - CRUD operations for saved queries
    - Query preview (sample results with counts)
    - Query execution with pagination
    - Dynamic SQL building for findings queries
    """

    def __init__(self, db: Session):
        self.db = db

    # =========================================================================
    # CRUD Operations
    # =========================================================================

    def create_query(
        self,
        name: str,
        query_definition: Dict[str, Any],
        owner_id: int,
        description: Optional[str] = None,
        visibility: str = "private",
    ) -> Optional[SavedQueryResponse]:
        """
        Create a new saved query.

        Args:
            name: Query name (unique per owner)
            query_definition: Query filter criteria (JSONB)
            owner_id: User ID creating the query
            description: Optional description
            visibility: 'private' or 'shared'

        Returns:
            Created query or None if name already exists
        """
        # Check for duplicate name
        existing = self._find_query_by_name(owner_id, name)
        if existing:
            logger.warning(
                "Query creation rejected: name '%s' already exists for user %d",
                name,
                owner_id,
            )
            return None

        from uuid import uuid4

        query_id = uuid4()

        builder = (
            InsertBuilder("saved_queries")
            .columns(
                "id",
                "name",
                "description",
                "query_definition",
                "owner_id",
                "visibility",
            )
            .values(
                query_id,
                name,
                description,
                query_definition,
                owner_id,
                visibility,
            )
            .returning("id")
        )

        query, params = builder.build()
        # Convert dict to JSON string for the parameter
        import json

        params["v0_query_definition"] = json.dumps(params["v0_query_definition"])

        result = self.db.execute(text(query), params)
        self.db.commit()

        row = result.fetchone()
        if row:
            logger.info(
                "Query created: %s (%s) by user %d",
                query_id,
                name,
                owner_id,
            )
            return self.get_query(query_id)

        return None

    def get_query(self, query_id: UUID) -> Optional[SavedQueryResponse]:
        """Get saved query by ID."""
        builder = QueryBuilder("saved_queries").where("id = :id", query_id, "id")
        query, params = builder.build()
        result = self.db.execute(text(query), params)
        row = result.fetchone()

        if row:
            return self._row_to_response(row)
        return None

    def update_query(
        self,
        query_id: UUID,
        owner_id: int,
        name: Optional[str] = None,
        description: Optional[str] = None,
        query_definition: Optional[Dict[str, Any]] = None,
        visibility: Optional[str] = None,
    ) -> Optional[SavedQueryResponse]:
        """
        Update a saved query.

        Only the owner can update their query.

        Args:
            query_id: Query ID to update
            owner_id: User ID (must match owner)
            name: New name (optional)
            description: New description (optional)
            query_definition: New filter criteria (optional)
            visibility: New visibility (optional)

        Returns:
            Updated query or None if not found/not owner
        """
        existing = self.get_query(query_id)
        if not existing:
            return None

        if existing.owner_id != owner_id:
            logger.warning(
                "Query update rejected: user %d is not owner of query %s",
                owner_id,
                query_id,
            )
            return None

        # Check for name conflict if changing name
        if name and name != existing.name:
            conflict = self._find_query_by_name(owner_id, name)
            if conflict and conflict.id != query_id:
                logger.warning(
                    "Query update rejected: name '%s' already exists",
                    name,
                )
                return None

        builder = UpdateBuilder("saved_queries")
        builder.set_if("name", name)
        builder.set_if("description", description)
        builder.set_if("visibility", visibility)
        builder.set_raw("updated_at", "CURRENT_TIMESTAMP")
        builder.where("id = :id", query_id, "id")
        builder.returning("id")

        if query_definition is not None:
            import json

            builder.set("query_definition", json.dumps(query_definition))

        query, params = builder.build()
        result = self.db.execute(text(query), params)
        self.db.commit()

        row = result.fetchone()
        if row:
            logger.info("Query updated: %s by user %d", query_id, owner_id)
            return self.get_query(query_id)

        return None

    def delete_query(self, query_id: UUID, owner_id: int) -> bool:
        """
        Delete a saved query.

        Only the owner can delete their query.

        Args:
            query_id: Query ID to delete
            owner_id: User ID (must match owner)

        Returns:
            True if deleted, False if not found/not owner
        """
        existing = self.get_query(query_id)
        if not existing:
            return False

        if existing.owner_id != owner_id:
            logger.warning(
                "Query delete rejected: user %d is not owner of query %s",
                owner_id,
                query_id,
            )
            return False

        from ...utils.mutation_builders import DeleteBuilder

        builder = DeleteBuilder("saved_queries").where("id = :id", query_id, "id").returning("id")

        query, params = builder.build()
        result = self.db.execute(text(query), params)
        self.db.commit()

        row = result.fetchone()
        if row:
            logger.info("Query deleted: %s by user %d", query_id, owner_id)
            return True

        return False

    def list_queries(
        self,
        user_id: int,
        page: int = 1,
        per_page: int = 20,
        include_shared: bool = True,
    ) -> SavedQueryListResponse:
        """
        List saved queries accessible to a user.

        Includes:
        - All queries owned by the user
        - All shared queries (if include_shared=True)

        Args:
            user_id: User ID
            page: Page number (1-indexed)
            per_page: Items per page
            include_shared: Include shared queries from other users

        Returns:
            Paginated query list
        """
        # Build query for user's queries + shared queries
        if include_shared:
            # Use raw SQL for OR condition
            base_query = """
                SELECT * FROM saved_queries
                WHERE owner_id = :user_id OR visibility = 'shared'
            """
            count_query = """
                SELECT COUNT(*) as total FROM saved_queries
                WHERE owner_id = :user_id OR visibility = 'shared'
            """
            params = {"user_id": user_id}

            # Get total count
            count_result = self.db.execute(text(count_query), params)
            total = count_result.scalar() or 0

            # Get paginated results
            offset = (page - 1) * per_page
            data_query = base_query + " ORDER BY created_at DESC LIMIT :limit OFFSET :offset"
            params["limit"] = per_page
            params["offset"] = offset

            result = self.db.execute(text(data_query), params)
        else:
            builder = QueryBuilder("saved_queries")
            builder.where("owner_id = :owner_id", user_id, "owner_id")

            # Get total count
            count_query, count_params = builder.count_query()
            count_result = self.db.execute(text(count_query), count_params)
            total = count_result.scalar() or 0

            # Get paginated results
            builder.order_by("created_at", "DESC")
            builder.paginate(page, per_page)
            data_query, data_params = builder.build()
            result = self.db.execute(text(data_query), data_params)

        rows = result.fetchall()
        queries = [self._row_to_response(row) for row in rows]

        return SavedQueryListResponse(
            items=queries,
            total=total,
            page=page,
            per_page=per_page,
            total_pages=ceil(total / per_page) if total > 0 else 1,
        )

    def get_stats(self, user_id: int) -> QueryStatsSummary:
        """Get query statistics for a user."""
        query = """
            SELECT
                COUNT(*) as total_queries,
                COUNT(*) FILTER (WHERE owner_id = :user_id) as my_queries,
                COUNT(*) FILTER (WHERE visibility = 'shared' AND owner_id != :user_id) as shared_queries,
                SUM(execution_count) as total_executions
            FROM saved_queries
            WHERE owner_id = :user_id OR visibility = 'shared'
        """
        result = self.db.execute(text(query), {"user_id": user_id})
        row = result.fetchone()

        if row:
            return QueryStatsSummary(
                total_queries=row.total_queries or 0,
                my_queries=row.my_queries or 0,
                shared_queries=row.shared_queries or 0,
                total_executions=row.total_executions or 0,
            )

        return QueryStatsSummary()

    # =========================================================================
    # Query Execution
    # =========================================================================

    def preview_query(
        self,
        query_definition: QueryDefinition,
        limit: int = 10,
    ) -> QueryPreviewResponse:
        """
        Preview query results (sample + total count).

        Args:
            query_definition: Filter criteria
            limit: Maximum sample results (default 10)

        Returns:
            Sample results and total count
        """
        # Build findings query
        data_sql, count_sql, params = self._build_findings_query(query_definition, limit=limit)

        # Get sample results
        result = self.db.execute(text(data_sql), params)
        rows = result.fetchall()
        findings = [self._row_to_finding(row) for row in rows]

        # Get total count
        count_result = self.db.execute(text(count_sql), params)
        total = count_result.scalar() or 0

        return QueryPreviewResponse(
            sample_results=findings,
            total_count=total,
            has_more=total > limit,
            query_definition=query_definition.model_dump(exclude_none=True),
        )

    def execute_query(
        self,
        query_id: UUID,
        user_id: int,
        page: int = 1,
        per_page: int = 50,
    ) -> Optional[QueryExecuteResponse]:
        """
        Execute a saved query with pagination.

        Args:
            query_id: Saved query ID
            user_id: User executing the query
            page: Page number
            per_page: Results per page

        Returns:
            Paginated results or None if query not found
        """
        saved_query = self.get_query(query_id)
        if not saved_query:
            return None

        # Check access (owner or shared)
        if saved_query.owner_id != user_id and saved_query.visibility != "shared":
            logger.warning(
                "Query execution rejected: user %d cannot access query %s",
                user_id,
                query_id,
            )
            return None

        # Parse query definition
        query_def = QueryDefinition.model_validate(saved_query.query_definition)

        # Build and execute query
        offset = (page - 1) * per_page
        data_sql, count_sql, params = self._build_findings_query(query_def, limit=per_page, offset=offset)

        # Get results
        result = self.db.execute(text(data_sql), params)
        rows = result.fetchall()
        findings = [self._row_to_finding(row) for row in rows]

        # Get total count
        count_result = self.db.execute(text(count_sql), params)
        total = count_result.scalar() or 0

        # Update execution stats
        self._update_execution_stats(query_id)

        return QueryExecuteResponse(
            items=findings,
            total=total,
            page=page,
            per_page=per_page,
            total_pages=ceil(total / per_page) if total > 0 else 1,
            query_id=query_id,
            executed_at=datetime.now(timezone.utc),
        )

    def execute_adhoc_query(
        self,
        query_definition: QueryDefinition,
        page: int = 1,
        per_page: int = 50,
    ) -> QueryExecuteResponse:
        """
        Execute an ad-hoc query with pagination.

        Args:
            query_definition: Filter criteria
            page: Page number
            per_page: Results per page

        Returns:
            Paginated results
        """
        offset = (page - 1) * per_page
        data_sql, count_sql, params = self._build_findings_query(query_definition, limit=per_page, offset=offset)

        # Get results
        result = self.db.execute(text(data_sql), params)
        rows = result.fetchall()
        findings = [self._row_to_finding(row) for row in rows]

        # Get total count
        count_result = self.db.execute(text(count_sql), params)
        total = count_result.scalar() or 0

        return QueryExecuteResponse(
            items=findings,
            total=total,
            page=page,
            per_page=per_page,
            total_pages=ceil(total / per_page) if total > 0 else 1,
            query_id=None,
            executed_at=datetime.now(timezone.utc),
        )

    # =========================================================================
    # Private Helpers
    # =========================================================================

    def _build_findings_query(
        self,
        query_def: QueryDefinition,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[str, str, Dict[str, Any]]:
        """
        Build SQL query for scan_findings based on query definition.

        Returns:
            Tuple of (data_query, count_query, params)
        """
        params: Dict[str, Any] = {}

        # Base query with host join for hostname
        select_cols = """
            sf.id,
            sf.scan_id,
            s.host_id,
            h.hostname,
            sf.rule_id,
            sf.title,
            sf.severity,
            sf.status,
            sf.detail,
            sf.framework_section,
            sf.created_at as scanned_at
        """

        base_from = """
            FROM scan_findings sf
            JOIN scans s ON sf.scan_id = s.id
            JOIN hosts h ON s.host_id = h.id
        """

        where_clauses: List[str] = []

        # Host filter
        if query_def.hosts:
            host_placeholders = []
            for i, host_id in enumerate(query_def.hosts):
                param_name = f"host_{i}"
                host_placeholders.append(f":{param_name}")
                params[param_name] = host_id
            where_clauses.append(f"s.host_id IN ({', '.join(host_placeholders)})")

        # Host group filter
        if query_def.host_groups:
            group_placeholders = []
            for i, group_id in enumerate(query_def.host_groups):
                param_name = f"group_{i}"
                group_placeholders.append(f":{param_name}")
                params[param_name] = group_id
            where_clauses.append(
                f"s.host_id IN (SELECT host_id FROM host_group_memberships "
                f"WHERE group_id IN ({', '.join(group_placeholders)}))"
            )

        # Rule filter
        if query_def.rules:
            rule_placeholders = []
            for i, rule_id in enumerate(query_def.rules):
                param_name = f"rule_{i}"
                rule_placeholders.append(f":{param_name}")
                params[param_name] = rule_id
            where_clauses.append(f"sf.rule_id IN ({', '.join(rule_placeholders)})")

        # Framework filter
        if query_def.frameworks:
            framework_placeholders = []
            for i, framework in enumerate(query_def.frameworks):
                param_name = f"framework_{i}"
                framework_placeholders.append(f":{param_name}")
                params[param_name] = framework
            where_clauses.append(f"sf.framework_section IN ({', '.join(framework_placeholders)})")

        # Severity filter
        if query_def.severities:
            sev_placeholders = []
            for i, severity in enumerate(query_def.severities):
                param_name = f"severity_{i}"
                sev_placeholders.append(f":{param_name}")
                params[param_name] = severity.lower()
            where_clauses.append(f"LOWER(sf.severity) IN ({', '.join(sev_placeholders)})")

        # Status filter
        if query_def.statuses:
            status_placeholders = []
            for i, status in enumerate(query_def.statuses):
                param_name = f"status_{i}"
                status_placeholders.append(f":{param_name}")
                params[param_name] = status.lower()
            where_clauses.append(f"LOWER(sf.status) IN ({', '.join(status_placeholders)})")

        # Date range filter (temporal queries)
        if query_def.date_range:
            where_clauses.append("sf.created_at >= :start_date")
            where_clauses.append("sf.created_at <= :end_date")
            params["start_date"] = datetime.combine(
                query_def.date_range.start_date,
                datetime.min.time(),
                tzinfo=timezone.utc,
            )
            params["end_date"] = datetime.combine(
                query_def.date_range.end_date,
                datetime.max.time(),
                tzinfo=timezone.utc,
            )

        # Build WHERE clause
        where_sql = ""
        if where_clauses:
            where_sql = "WHERE " + " AND ".join(where_clauses)

        # Data query with ordering and pagination
        data_query = f"""
            SELECT {select_cols}
            {base_from}
            {where_sql}
            ORDER BY sf.created_at DESC, sf.severity DESC
            LIMIT :limit OFFSET :offset
        """
        params["limit"] = limit
        params["offset"] = offset

        # Count query
        count_query = f"""
            SELECT COUNT(*) as total
            {base_from}
            {where_sql}
        """

        return data_query, count_query, params

    def _find_query_by_name(self, owner_id: int, name: str) -> Optional[Row[Any]]:
        """Find query by owner and name."""
        query = """
            SELECT id FROM saved_queries
            WHERE owner_id = :owner_id AND name = :name
        """
        result = self.db.execute(text(query), {"owner_id": owner_id, "name": name})
        return result.fetchone()

    def _update_execution_stats(self, query_id: UUID) -> None:
        """Update last_executed_at and execution_count."""
        query = """
            UPDATE saved_queries
            SET last_executed_at = CURRENT_TIMESTAMP,
                execution_count = execution_count + 1,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = :id
        """
        self.db.execute(text(query), {"id": query_id})
        self.db.commit()

    def _row_to_response(self, row: Row[Any]) -> SavedQueryResponse:
        """Convert database row to SavedQueryResponse."""
        query_def = row.query_definition
        has_date_range = bool(query_def.get("date_range") if isinstance(query_def, dict) else False)

        return SavedQueryResponse(
            id=row.id,
            name=row.name,
            description=row.description,
            query_definition=query_def,
            owner_id=row.owner_id,
            visibility=row.visibility,
            last_executed_at=row.last_executed_at,
            execution_count=row.execution_count,
            created_at=row.created_at,
            updated_at=row.updated_at,
            has_date_range=has_date_range,
        )

    def _row_to_finding(self, row: Row[Any]) -> FindingResult:
        """Convert database row to FindingResult."""
        return FindingResult(
            scan_id=row.scan_id,
            host_id=row.host_id,
            hostname=row.hostname,
            rule_id=row.rule_id,
            title=row.title or "",
            severity=row.severity or "unknown",
            status=row.status or "unknown",
            detail=row.detail,
            framework_section=row.framework_section,
            scanned_at=row.scanned_at,
        )


__all__ = ["AuditQueryService"]
