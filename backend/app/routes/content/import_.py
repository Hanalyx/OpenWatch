"""
SCAP Import API Endpoints for OpenWatch
REST API for importing SCAP files into MongoDB

This module uses the unified content module for SCAP processing.
Import execution is handled by a Celery task for timeout safety
and crash recovery.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ...services.content import ContentImporter

router = APIRouter(prefix="/scap-import", tags=["SCAP Import"])

# Global import service (will be initialized on first use)
import_service: Optional[ContentImporter] = None

# Maps import_id -> {"celery_task_id": ..., "file_path": ..., "started_at": ...}
# Lightweight tracking; actual progress lives in Celery result backend.
active_imports: Dict[str, Dict[str, Any]] = {}


class ImportRequest(BaseModel):
    """Request model for SCAP import"""

    file_path: str = Field(description="Path to SCAP XML file")
    deduplication_strategy: str = Field(
        default="skip_existing",
        pattern="^(skip_existing|update_existing|replace_all)$",
        description="Strategy for handling duplicate rules",
    )
    batch_size: int = Field(
        default=100,
        ge=1,
        le=1000,
        description="Number of rules to process in each batch",
    )


class ImportResponse(BaseModel):
    """Response model for import operations"""

    import_id: str
    status: str
    message: str
    estimated_duration_minutes: Optional[float] = None


class ImportStatus(BaseModel):
    """Status model for import progress"""

    import_id: str
    status: str
    progress: Dict[str, Any]
    result: Optional[Dict[str, Any]] = None


async def get_import_service() -> ContentImporter:
    """Get or initialize the import service"""
    global import_service

    if import_service is None:
        import_service = ContentImporter()

    return import_service


def _get_celery_import_state(import_id: str) -> Dict[str, Any]:
    """Read import state from Celery result backend."""
    from app.celery_app import celery_app

    import_info = active_imports.get(import_id)
    if not import_info:
        return {"status": "unknown", "progress": {}}

    task_id = import_info.get("celery_task_id")
    if not task_id:
        return {"status": "queued", "progress": {}}

    result = celery_app.AsyncResult(task_id)

    if result.state == "PENDING":
        return {"status": "queued", "progress": {}}
    elif result.state == "PROGRESS":
        meta = result.info or {}
        return {"status": "running", "progress": meta}
    elif result.state == "SUCCESS":
        task_result = result.result or {}
        return {
            "status": task_result.get("status", "completed"),
            "progress": {"progress_percentage": 100},
            "result": task_result,
        }
    elif result.state == "FAILURE":
        return {
            "status": "failed",
            "progress": {},
            "error": str(result.info) if result.info else "Unknown error",
        }
    else:
        return {"status": result.state.lower(), "progress": {}}


@router.post("/import", response_model=ImportResponse)
async def import_scap_file(
    request: ImportRequest,
) -> ImportResponse:
    """
    Import a SCAP XML file into MongoDB

    This endpoint starts an asynchronous import process and returns immediately
    with an import ID that can be used to track progress.
    """
    # Validate file exists
    file_path = Path(request.file_path)
    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"SCAP file not found: {request.file_path}")

    if not file_path.suffix.lower() == ".xml":
        raise HTTPException(status_code=400, detail="File must be an XML file")

    # Generate import ID
    import_id = f"import_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{file_path.stem}"

    # Dispatch Celery task
    from app.tasks.background_tasks import import_scap_content_celery

    task = import_scap_content_celery.delay(
        import_id=import_id,
        file_path=str(file_path),
        deduplication_strategy=request.deduplication_strategy,
        batch_size=request.batch_size,
    )

    # Track mapping from import_id to celery task
    active_imports[import_id] = {
        "celery_task_id": task.id,
        "file_path": str(file_path),
        "started_at": datetime.utcnow().isoformat(),
    }

    return ImportResponse(
        import_id=import_id,
        status="queued",
        message=f"Import queued for file: {file_path.name}",
        estimated_duration_minutes=estimate_import_duration(file_path),
    )


@router.get("/import/{import_id}/status", response_model=ImportStatus)
async def get_import_status(import_id: str) -> ImportStatus:
    """Get the status of an ongoing or completed import"""

    if import_id not in active_imports:
        raise HTTPException(status_code=404, detail=f"Import ID not found: {import_id}")

    state = _get_celery_import_state(import_id)

    return ImportStatus(
        import_id=import_id,
        status=state["status"],
        progress=state.get("progress", {}),
        result=state.get("result"),
    )


@router.get("/imports")
async def list_active_imports() -> Dict[str, Any]:
    """List all active and recent imports"""

    imports_list = []
    for import_id, info in active_imports.items():
        state = _get_celery_import_state(import_id)
        imports_list.append(
            {
                "import_id": import_id,
                "status": state["status"],
                "file_path": info["file_path"],
                "started_at": info["started_at"],
            }
        )

    return {"active_imports": imports_list}


@router.delete("/import/{import_id}")
async def cancel_import(import_id: str) -> Dict[str, str]:
    """Cancel an ongoing import (if possible)"""

    if import_id not in active_imports:
        raise HTTPException(status_code=404, detail=f"Import ID not found: {import_id}")

    state = _get_celery_import_state(import_id)

    if state["status"] in ["completed", "failed"]:
        raise HTTPException(status_code=400, detail="Cannot cancel completed or failed import")

    # Revoke Celery task
    from app.celery_app import celery_app

    task_id = active_imports[import_id].get("celery_task_id")
    if task_id:
        celery_app.control.revoke(task_id, terminate=True)

    return {"message": f"Import {import_id} marked for cancellation"}


@router.get("/files")
async def list_imported_files(
    service: ContentImporter = Depends(get_import_service),
) -> Dict[str, Any]:
    """List all previously imported SCAP files"""

    try:
        files = await service.list_imported_files()
        return {"imported_files": files, "total_files": len(files)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list imported files: {str(e)}")


@router.post("/validate/{import_id}")
async def validate_import(import_id: str, service: ContentImporter = Depends(get_import_service)) -> Dict[str, Any]:
    """Validate the integrity of an imported file"""

    if import_id not in active_imports:
        raise HTTPException(status_code=404, detail=f"Import ID not found: {import_id}")

    import_info = active_imports[import_id]
    state = _get_celery_import_state(import_id)

    if state["status"] != "completed":
        raise HTTPException(status_code=400, detail="Can only validate completed imports")

    try:
        validation = await service.validate_import_integrity_by_path(import_info["file_path"])
        return validation
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Validation failed: {str(e)}")


@router.get("/statistics")
async def get_import_statistics(
    service: ContentImporter = Depends(get_import_service),
) -> Dict[str, Any]:
    """Get overall import statistics"""

    try:
        # Get collection statistics from MongoDB
        # OW-REFACTOR-002: Repository Pattern (MANDATORY)
        from ...repositories import ComplianceRuleRepository, RemediationScriptRepository, RuleIntelligenceRepository

        compliance_repo = ComplianceRuleRepository()
        intelligence_repo = RuleIntelligenceRepository()
        remediation_repo = RemediationScriptRepository()

        stats = {
            "total_rules": await compliance_repo.count(),
            "rules_by_severity": {},
            "rules_by_category": {},
            "rules_with_fixes": await compliance_repo.count({"fix_available": True}),
            "total_intelligence_records": await intelligence_repo.count(),
            "total_remediation_scripts": await remediation_repo.count(),
        }

        # Get severity distribution
        severity_pipeline = [
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
        ]

        severity_results = await compliance_repo.aggregate(severity_pipeline)

        for result in severity_results:
            stats["rules_by_severity"][result["_id"]] = result["count"]

        # Get category distribution
        category_pipeline = [
            {"$group": {"_id": "$category", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10},
        ]

        category_results = await compliance_repo.aggregate(category_pipeline)

        for result in category_results:
            stats["rules_by_category"][result["_id"]] = result["count"]

        return stats

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {str(e)}")


def estimate_import_duration(file_path: Path) -> float:
    """Estimate import duration based on file size"""
    try:
        file_size_mb = file_path.stat().st_size / (1024 * 1024)
        # Rough estimate: 1MB per minute for processing
        return max(1.0, file_size_mb * 1.0)
    except Exception:
        return 5.0  # Default estimate
