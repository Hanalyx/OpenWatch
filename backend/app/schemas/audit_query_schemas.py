"""
Audit Query Schemas

Pydantic models for audit query builder requests and responses.

Part of Phase 6: Audit Queries (Aegis Integration Plan)

OS Claim 3.3: "Audits are queries over canonical evidence"
"""

from datetime import date, datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field

# =============================================================================
# Query Definition Models
# =============================================================================


class DateRange(BaseModel):
    """Date range filter for temporal queries.

    Note: Requires OpenWatch+ license for historical queries.
    """

    start_date: date = Field(..., description="Start date (inclusive)")
    end_date: date = Field(..., description="End date (inclusive)")


class QueryDefinition(BaseModel):
    """Definition of an audit query's filter criteria.

    All fields are optional - an empty definition returns all findings.
    Multiple filters are combined with AND logic.
    """

    # Scope filters
    hosts: Optional[List[UUID]] = Field(None, description="Filter by specific host IDs")
    host_groups: Optional[List[int]] = Field(None, description="Filter by host group IDs")

    # Rule filters
    rules: Optional[List[str]] = Field(None, description="Filter by specific rule IDs")
    frameworks: Optional[List[str]] = Field(None, description="Filter by framework (e.g., 'cis_rhel9', 'stig_rhel9')")
    severities: Optional[List[str]] = Field(None, description="Filter by severity (critical, high, medium, low)")
    statuses: Optional[List[str]] = Field(None, description="Filter by status (pass, fail, error, skip)")

    # Temporal filter (OpenWatch+ only)
    date_range: Optional[DateRange] = Field(None, description="Filter by date range (requires OpenWatch+)")


# =============================================================================
# Saved Query Models
# =============================================================================


class SavedQueryCreate(BaseModel):
    """Request model for creating a saved query."""

    name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Query name (unique per user)",
    )
    description: Optional[str] = Field(None, max_length=2000, description="Optional description")
    query_definition: QueryDefinition = Field(..., description="Query filter criteria")
    visibility: str = Field(
        "private",
        pattern="^(private|shared)$",
        description="Query visibility: 'private' or 'shared'",
    )


class SavedQueryUpdate(BaseModel):
    """Request model for updating a saved query."""

    name: Optional[str] = Field(None, min_length=1, max_length=255, description="New name")
    description: Optional[str] = Field(None, max_length=2000, description="New description")
    query_definition: Optional[QueryDefinition] = Field(None, description="New filter criteria")
    visibility: Optional[str] = Field(
        None,
        pattern="^(private|shared)$",
        description="New visibility",
    )


class SavedQueryResponse(BaseModel):
    """Response model for a saved query."""

    id: UUID
    name: str
    description: Optional[str] = None
    query_definition: Dict[str, Any]  # JSONB from DB
    owner_id: int
    visibility: str
    last_executed_at: Optional[datetime] = None
    execution_count: int
    created_at: datetime
    updated_at: datetime

    # Computed fields
    has_date_range: bool = Field(False, description="True if query uses date range filter")

    class Config:
        from_attributes = True


class SavedQueryListResponse(BaseModel):
    """Response model for saved query list."""

    items: List[SavedQueryResponse]
    total: int
    page: int
    per_page: int
    total_pages: int


# =============================================================================
# Query Execution Models
# =============================================================================


class QueryPreviewRequest(BaseModel):
    """Request model for query preview."""

    query_definition: QueryDefinition = Field(..., description="Query filter criteria")
    limit: int = Field(10, ge=1, le=100, description="Maximum results to return")


class FindingResult(BaseModel):
    """Single finding result from query execution."""

    scan_id: UUID
    host_id: UUID
    hostname: str
    rule_id: str
    title: str
    severity: str
    status: str
    detail: Optional[str] = None
    framework_section: Optional[str] = None
    scanned_at: datetime


class QueryPreviewResponse(BaseModel):
    """Response model for query preview."""

    sample_results: List[FindingResult]
    total_count: int
    has_more: bool
    query_definition: Dict[str, Any]


class QueryExecuteRequest(BaseModel):
    """Request model for executing a saved query."""

    page: int = Field(1, ge=1, description="Page number")
    per_page: int = Field(50, ge=1, le=500, description="Results per page")


class QueryExecuteResponse(BaseModel):
    """Response model for query execution."""

    items: List[FindingResult]
    total: int
    page: int
    per_page: int
    total_pages: int
    query_id: Optional[UUID] = None
    executed_at: datetime


# =============================================================================
# Audit Export Models
# =============================================================================


class AuditExportCreate(BaseModel):
    """Request model for creating an audit export."""

    query_id: Optional[UUID] = Field(None, description="ID of saved query to export (optional)")
    query_definition: Optional[QueryDefinition] = Field(None, description="Ad-hoc query definition (if no query_id)")
    format: str = Field(
        ...,
        pattern="^(json|csv|pdf)$",
        description="Export format: json, csv, or pdf",
    )


class AuditExportResponse(BaseModel):
    """Response model for an audit export."""

    id: UUID
    query_id: Optional[UUID] = None
    query_definition: Dict[str, Any]
    format: str
    status: str
    file_path: Optional[str] = None
    file_size_bytes: Optional[int] = None
    file_checksum: Optional[str] = None
    error_message: Optional[str] = None
    requested_by: Optional[int] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    expires_at: datetime

    # Computed fields
    is_ready: bool = Field(False, description="True if export is ready to download")
    is_expired: bool = Field(False, description="True if export has expired")

    class Config:
        from_attributes = True


class AuditExportListResponse(BaseModel):
    """Response model for audit export list."""

    items: List[AuditExportResponse]
    total: int
    page: int
    per_page: int
    total_pages: int


# =============================================================================
# Summary Models
# =============================================================================


class QueryStatsSummary(BaseModel):
    """Summary statistics for saved queries."""

    total_queries: int = 0
    my_queries: int = 0
    shared_queries: int = 0
    total_executions: int = 0


class ExportStatsSummary(BaseModel):
    """Summary statistics for audit exports."""

    total_exports: int = 0
    pending: int = 0
    processing: int = 0
    completed: int = 0
    failed: int = 0


__all__ = [
    # Query Definition
    "DateRange",
    "QueryDefinition",
    # Saved Query
    "SavedQueryCreate",
    "SavedQueryUpdate",
    "SavedQueryResponse",
    "SavedQueryListResponse",
    # Query Execution
    "QueryPreviewRequest",
    "FindingResult",
    "QueryPreviewResponse",
    "QueryExecuteRequest",
    "QueryExecuteResponse",
    # Audit Export
    "AuditExportCreate",
    "AuditExportResponse",
    "AuditExportListResponse",
    # Summary
    "QueryStatsSummary",
    "ExportStatsSummary",
]
