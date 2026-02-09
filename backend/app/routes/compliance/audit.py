"""
Audit Query API Endpoints

Endpoints for managing saved queries and audit exports.

Part of Phase 6: Audit Queries (Aegis Integration Plan)

Endpoint Structure:
    GET    /audit/queries                    - List saved queries
    POST   /audit/queries                    - Create saved query
    GET    /audit/queries/stats              - Get query statistics
    GET    /audit/queries/{id}               - Get query by ID
    PUT    /audit/queries/{id}               - Update query
    DELETE /audit/queries/{id}               - Delete query
    POST   /audit/queries/preview            - Preview query results
    POST   /audit/queries/{id}/execute       - Execute saved query
    POST   /audit/queries/execute            - Execute ad-hoc query

    GET    /audit/exports                    - List exports
    POST   /audit/exports                    - Create export
    GET    /audit/exports/stats              - Get export statistics
    GET    /audit/exports/{id}               - Get export by ID
    GET    /audit/exports/{id}/download      - Download export file

OS Claim 3.3: "Audits are queries over canonical evidence"
"""

import logging
import os
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi import status as http_status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from ...auth import get_current_user
from ...database import User, get_db
from ...schemas.audit_query_schemas import (
    AuditExportCreate,
    AuditExportListResponse,
    AuditExportResponse,
    ExportStatsSummary,
    QueryDefinition,
    QueryExecuteRequest,
    QueryExecuteResponse,
    QueryPreviewRequest,
    QueryPreviewResponse,
    QueryStatsSummary,
    SavedQueryCreate,
    SavedQueryListResponse,
    SavedQueryResponse,
    SavedQueryUpdate,
)
from ...services.compliance.audit_export import AuditExportService
from ...services.compliance.audit_query import AuditQueryService
from ...services.licensing import LicenseService
from ...tasks.audit_export_tasks import generate_audit_export_task

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/audit", tags=["Audit Queries"])


# =============================================================================
# SAVED QUERIES ENDPOINTS
# =============================================================================


@router.get("/queries", response_model=SavedQueryListResponse)
async def list_queries(
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    include_shared: bool = Query(True, description="Include shared queries"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SavedQueryListResponse:
    """
    List saved queries accessible to the current user.

    Returns both owned and shared queries (if include_shared=True).
    """
    service = AuditQueryService(db)
    return service.list_queries(
        user_id=int(current_user.id),
        page=page,
        per_page=per_page,
        include_shared=include_shared,
    )


@router.get("/queries/stats", response_model=QueryStatsSummary)
async def get_query_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> QueryStatsSummary:
    """Get query statistics for the current user."""
    service = AuditQueryService(db)
    return service.get_stats(int(current_user.id))


@router.post("/queries", response_model=SavedQueryResponse)
async def create_query(
    request: SavedQueryCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SavedQueryResponse:
    """
    Create a new saved query.

    Query names must be unique per user.
    """
    service = AuditQueryService(db)
    query = service.create_query(
        name=request.name,
        query_definition=request.query_definition.model_dump(exclude_none=True),
        owner_id=int(current_user.id),
        description=request.description,
        visibility=request.visibility,
    )

    if not query:
        raise HTTPException(
            status_code=http_status.HTTP_409_CONFLICT,
            detail=f"Query with name '{request.name}' already exists",
        )

    return query


@router.get("/queries/{query_id}", response_model=SavedQueryResponse)
async def get_query(
    query_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SavedQueryResponse:
    """Get saved query by ID."""
    service = AuditQueryService(db)
    query = service.get_query(query_id)

    if not query:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Query {query_id} not found",
        )

    # Check access (owner or shared)
    if query.owner_id != int(current_user.id) and query.visibility != "shared":
        raise HTTPException(
            status_code=http_status.HTTP_403_FORBIDDEN,
            detail="You do not have access to this query",
        )

    return query


@router.put("/queries/{query_id}", response_model=SavedQueryResponse)
async def update_query(
    query_id: UUID,
    request: SavedQueryUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SavedQueryResponse:
    """
    Update a saved query.

    Only the query owner can update it.
    """
    service = AuditQueryService(db)
    query = service.update_query(
        query_id=query_id,
        owner_id=int(current_user.id),
        name=request.name,
        description=request.description,
        query_definition=(request.query_definition.model_dump(exclude_none=True) if request.query_definition else None),
        visibility=request.visibility,
    )

    if not query:
        # Check if it exists
        existing = service.get_query(query_id)
        if not existing:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND,
                detail=f"Query {query_id} not found",
            )
        raise HTTPException(
            status_code=http_status.HTTP_403_FORBIDDEN,
            detail="You can only update your own queries",
        )

    return query


@router.delete("/queries/{query_id}", status_code=http_status.HTTP_204_NO_CONTENT)
async def delete_query(
    query_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    """
    Delete a saved query.

    Only the query owner can delete it.
    """
    service = AuditQueryService(db)
    deleted = service.delete_query(query_id, int(current_user.id))

    if not deleted:
        # Check if it exists
        existing = service.get_query(query_id)
        if not existing:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND,
                detail=f"Query {query_id} not found",
            )
        raise HTTPException(
            status_code=http_status.HTTP_403_FORBIDDEN,
            detail="You can only delete your own queries",
        )


# =============================================================================
# QUERY EXECUTION ENDPOINTS
# =============================================================================


@router.post("/queries/preview", response_model=QueryPreviewResponse)
async def preview_query(
    request: QueryPreviewRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> QueryPreviewResponse:
    """
    Preview query results (sample + count).

    Returns up to 100 sample results and total count.
    Date range filter requires OpenWatch+ license.
    """
    # Check license for date range
    if request.query_definition.date_range:
        license_service = LicenseService()
        if not await license_service.has_feature("temporal_queries"):
            raise HTTPException(
                status_code=http_status.HTTP_403_FORBIDDEN,
                detail="Date range queries require OpenWatch+ subscription",
            )

    service = AuditQueryService(db)
    return service.preview_query(
        query_definition=request.query_definition,
        limit=request.limit,
    )


@router.post("/queries/{query_id}/execute", response_model=QueryExecuteResponse)
async def execute_saved_query(
    query_id: UUID,
    request: QueryExecuteRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> QueryExecuteResponse:
    """
    Execute a saved query with pagination.

    Date range filter requires OpenWatch+ license.
    """
    service = AuditQueryService(db)
    saved_query = service.get_query(query_id)

    if not saved_query:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Query {query_id} not found",
        )

    # Check license for date range
    if saved_query.has_date_range:
        license_service = LicenseService()
        if not await license_service.has_feature("temporal_queries"):
            raise HTTPException(
                status_code=http_status.HTTP_403_FORBIDDEN,
                detail="Date range queries require OpenWatch+ subscription",
            )

    result = service.execute_query(
        query_id=query_id,
        user_id=int(current_user.id),
        page=request.page,
        per_page=request.per_page,
    )

    if not result:
        raise HTTPException(
            status_code=http_status.HTTP_403_FORBIDDEN,
            detail="You do not have access to this query",
        )

    return result


@router.post("/queries/execute", response_model=QueryExecuteResponse)
async def execute_adhoc_query(
    query_definition: QueryDefinition,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> QueryExecuteResponse:
    """
    Execute an ad-hoc query with pagination.

    Date range filter requires OpenWatch+ license.
    """
    # Check license for date range
    if query_definition.date_range:
        license_service = LicenseService()
        if not await license_service.has_feature("temporal_queries"):
            raise HTTPException(
                status_code=http_status.HTTP_403_FORBIDDEN,
                detail="Date range queries require OpenWatch+ subscription",
            )

    service = AuditQueryService(db)
    return service.execute_adhoc_query(
        query_definition=query_definition,
        page=page,
        per_page=per_page,
    )


# =============================================================================
# EXPORT ENDPOINTS
# =============================================================================


@router.get("/exports", response_model=AuditExportListResponse)
async def list_exports(
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    status: Optional[str] = Query(None, description="Filter by status"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AuditExportListResponse:
    """List exports for the current user."""
    service = AuditExportService(db)
    return service.list_exports(
        user_id=int(current_user.id),
        page=page,
        per_page=per_page,
        status=status,
    )


@router.get("/exports/stats", response_model=ExportStatsSummary)
async def get_export_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ExportStatsSummary:
    """Get export statistics for the current user."""
    service = AuditExportService(db)
    return service.get_stats(int(current_user.id))


@router.post("/exports", response_model=AuditExportResponse)
async def create_export(
    request: AuditExportCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AuditExportResponse:
    """
    Create a new export request.

    Provide either query_id (for saved query) or query_definition (for ad-hoc).
    Date range filter requires OpenWatch+ license.
    """
    # Validate input
    if not request.query_id and not request.query_definition:
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail="Either query_id or query_definition must be provided",
        )

    # Check license for date range
    if request.query_definition and request.query_definition.date_range:
        license_service = LicenseService()
        if not await license_service.has_feature("temporal_queries"):
            raise HTTPException(
                status_code=http_status.HTTP_403_FORBIDDEN,
                detail="Date range exports require OpenWatch+ subscription",
            )

    # If query_id provided, check if it has date range
    if request.query_id:
        query_service = AuditQueryService(db)
        saved_query = query_service.get_query(request.query_id)
        if saved_query and saved_query.has_date_range:
            license_service = LicenseService()
            if not await license_service.has_feature("temporal_queries"):
                raise HTTPException(
                    status_code=http_status.HTTP_403_FORBIDDEN,
                    detail="Date range exports require OpenWatch+ subscription",
                )

    service = AuditExportService(db)
    export = service.create_export(
        requested_by=int(current_user.id),
        export_format=request.format,
        query_id=request.query_id,
        query_definition=(request.query_definition.model_dump(exclude_none=True) if request.query_definition else None),
    )

    if not export:
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail="Failed to create export. Check query_id if provided.",
        )

    # Queue export generation task
    generate_audit_export_task.delay(str(export.id))

    return export


@router.get("/exports/{export_id}", response_model=AuditExportResponse)
async def get_export(
    export_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AuditExportResponse:
    """Get export by ID."""
    service = AuditExportService(db)
    export = service.get_export(export_id)

    if not export:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Export {export_id} not found",
        )

    # Check access
    if export.requested_by != int(current_user.id):
        raise HTTPException(
            status_code=http_status.HTTP_403_FORBIDDEN,
            detail="You can only access your own exports",
        )

    return export


@router.get("/exports/{export_id}/download")
async def download_export(
    export_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> FileResponse:
    """
    Download export file.

    Returns the generated file for completed exports.
    """
    service = AuditExportService(db)
    export = service.get_export(export_id)

    if not export:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Export {export_id} not found",
        )

    # Check access
    if export.requested_by != int(current_user.id):
        raise HTTPException(
            status_code=http_status.HTTP_403_FORBIDDEN,
            detail="You can only download your own exports",
        )

    # Check status
    if export.status != "completed":
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail=f"Export is not ready. Current status: {export.status}",
        )

    # Check if file exists
    if not export.file_path or not os.path.exists(export.file_path):
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail="Export file not found. It may have been cleaned up.",
        )

    # Check expiry
    if export.is_expired:
        raise HTTPException(
            status_code=http_status.HTTP_410_GONE,
            detail="Export has expired and is no longer available",
        )

    # Determine content type
    content_type_map = {
        "json": "application/json",
        "csv": "text/csv",
        "pdf": "application/pdf",
    }
    content_type = content_type_map.get(export.format, "application/octet-stream")

    # Generate filename
    filename = f"audit_export_{export_id}.{export.format}"

    return FileResponse(
        path=export.file_path,
        media_type=content_type,
        filename=filename,
    )


__all__ = ["router"]
