"""
SCAP Import API Endpoints for OpenWatch
REST API for importing SCAP files into MongoDB

This module uses the unified content module for SCAP processing.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field

from ....services.content import ContentImporter, ImportProgress, ImportResult, process_scap_content

router = APIRouter(prefix="/scap-import", tags=["SCAP Import"])

# Global import service (will be initialized on first use)
import_service: Optional[ContentImporter] = None
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


@router.post("/import", response_model=ImportResponse)
async def import_scap_file(
    request: ImportRequest,
    background_tasks: BackgroundTasks,
    service: ContentImporter = Depends(get_import_service),
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

    # Initialize import tracking
    active_imports[import_id] = {
        "status": "queued",
        "file_path": str(file_path),
        "started_at": datetime.utcnow().isoformat(),
        "request": request.dict(),
    }

    # Start background import task
    background_tasks.add_task(
        run_import_task,
        import_id,
        str(file_path),
        request.deduplication_strategy,
        request.batch_size,
        service,
    )

    return ImportResponse(
        import_id=import_id,
        status="queued",
        message=f"Import queued for file: {file_path.name}",
        estimated_duration_minutes=estimate_import_duration(file_path),
    )


@router.get("/import/{import_id}/status", response_model=ImportStatus)
async def get_import_status(
    import_id: str, service: ContentImporter = Depends(get_import_service)
) -> ImportStatus:
    """Get the status of an ongoing or completed import"""

    if import_id not in active_imports:
        raise HTTPException(status_code=404, detail=f"Import ID not found: {import_id}")

    import_info = active_imports[import_id]

    # Get progress from active imports tracking
    progress_data = import_info.get("progress", {})

    return ImportStatus(
        import_id=import_id,
        status=import_info["status"],
        progress=progress_data,
        result=import_info.get("result"),
    )


@router.get("/imports")
async def list_active_imports() -> Dict[str, Any]:
    """List all active and recent imports"""

    return {
        "active_imports": [
            {
                "import_id": import_id,
                "status": info["status"],
                "file_path": info["file_path"],
                "started_at": info["started_at"],
            }
            for import_id, info in active_imports.items()
        ]
    }


@router.delete("/import/{import_id}")
async def cancel_import(import_id: str) -> Dict[str, str]:
    """Cancel an ongoing import (if possible)"""

    if import_id not in active_imports:
        raise HTTPException(status_code=404, detail=f"Import ID not found: {import_id}")

    import_info = active_imports[import_id]

    if import_info["status"] in ["completed", "failed"]:
        raise HTTPException(status_code=400, detail="Cannot cancel completed or failed import")

    # Update status (actual cancellation would require more complex implementation)
    active_imports[import_id]["status"] = "cancelled"
    active_imports[import_id]["cancelled_at"] = datetime.utcnow().isoformat()

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
async def validate_import(
    import_id: str, service: ContentImporter = Depends(get_import_service)
) -> Dict[str, Any]:
    """Validate the integrity of an imported file"""

    if import_id not in active_imports:
        raise HTTPException(status_code=404, detail=f"Import ID not found: {import_id}")

    import_info = active_imports[import_id]

    if import_info["status"] != "completed":
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
        from ....models.mongo_models import ComplianceRule, RemediationScript, RuleIntelligence

        stats = {
            "total_rules": await ComplianceRule.count(),
            "rules_by_severity": {},
            "rules_by_category": {},
            "rules_with_fixes": await ComplianceRule.count(ComplianceRule.fix_available is True),
            "total_intelligence_records": await RuleIntelligence.count(),
            "total_remediation_scripts": await RemediationScript.count(),
        }

        # Get severity distribution
        severity_pipeline = [
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
        ]

        collection = ComplianceRule.get_motor_collection()
        cursor = collection.aggregate(severity_pipeline)
        severity_results = await cursor.to_list(length=None)

        for result in severity_results:
            stats["rules_by_severity"][result["_id"]] = result["count"]

        # Get category distribution
        category_pipeline = [
            {"$group": {"_id": "$category", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10},
        ]

        cursor = collection.aggregate(category_pipeline)
        category_results = await cursor.to_list(length=None)

        for result in category_results:
            stats["rules_by_category"][result["_id"]] = result["count"]

        return stats

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {str(e)}")


# Background task functions


async def run_import_task(
    import_id: str,
    file_path: str,
    deduplication_strategy: str,
    batch_size: int,
    service: ContentImporter,
) -> None:
    """Run the import task in the background"""

    try:
        # Update status to running
        active_imports[import_id]["status"] = "running"
        active_imports[import_id]["progress"] = {"current_phase": "starting"}

        # Progress callback to update status
        def progress_callback(progress: ImportProgress) -> None:
            active_imports[import_id]["progress"] = {
                "current_phase": progress.stage.value if progress.stage else "processing",
                "processed_rules": progress.processed_count,
                "total_rules": progress.total_count,
                "progress_percentage": progress.percent_complete,
            }

        # Run the import using content module
        result: ImportResult = process_scap_content(
            source_path=file_path,
            progress_callback=progress_callback,
            batch_size=batch_size,
            deduplication=deduplication_strategy,
        )

        # Update final status
        active_imports[import_id]["status"] = "completed"
        active_imports[import_id]["result"] = {
            "status": "completed",
            "statistics": {
                "imported": result.imported_count,
                "updated": result.updated_count,
                "skipped": result.skipped_count,
                "errors": result.failed_count,
            },
        }
        active_imports[import_id]["completed_at"] = datetime.utcnow().isoformat()

    except Exception as e:
        # Handle import failure
        active_imports[import_id]["status"] = "failed"
        active_imports[import_id]["error"] = str(e)
        active_imports[import_id]["failed_at"] = datetime.utcnow().isoformat()


def estimate_import_duration(file_path: Path) -> float:
    """Estimate import duration based on file size"""
    try:
        file_size_mb = file_path.stat().st_size / (1024 * 1024)
        # Rough estimate: 1MB per minute for processing
        return max(1.0, file_size_mb * 1.0)
    except Exception:
        return 5.0  # Default estimate
