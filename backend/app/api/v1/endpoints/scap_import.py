"""
SCAP Import API Endpoints for OpenWatch
REST API for importing SCAP files into MongoDB
"""
import asyncio
from pathlib import Path
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks, Query, Depends
from pydantic import BaseModel, Field
from datetime import datetime

from backend.app.services.scap_import_service import SCAPImportService
from backend.app.services.mongo_integration_service import MongoIntegrationService

router = APIRouter(prefix="/scap-import", tags=["SCAP Import"])

# Global import service (will be initialized on first use)
import_service: Optional[SCAPImportService] = None
active_imports: Dict[str, Dict[str, Any]] = {}

class ImportRequest(BaseModel):
    """Request model for SCAP import"""
    file_path: str = Field(description="Path to SCAP XML file")
    deduplication_strategy: str = Field(
        default="skip_existing",
        pattern="^(skip_existing|update_existing|replace_all)$",
        description="Strategy for handling duplicate rules"
    )
    batch_size: int = Field(
        default=100,
        ge=1,
        le=1000,
        description="Number of rules to process in each batch"
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

async def get_import_service() -> SCAPImportService:
    """Get or initialize the import service"""
    global import_service
    
    if import_service is None:
        mongo_service = MongoIntegrationService()
        await mongo_service.initialize()
        import_service = SCAPImportService(mongo_service)
        
    return import_service

@router.post("/import", response_model=ImportResponse)
async def import_scap_file(
    request: ImportRequest,
    background_tasks: BackgroundTasks,
    service: SCAPImportService = Depends(get_import_service)
):
    """
    Import a SCAP XML file into MongoDB
    
    This endpoint starts an asynchronous import process and returns immediately
    with an import ID that can be used to track progress.
    """
    # Validate file exists
    file_path = Path(request.file_path)
    if not file_path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"SCAP file not found: {request.file_path}"
        )
        
    if not file_path.suffix.lower() == '.xml':
        raise HTTPException(
            status_code=400,
            detail="File must be an XML file"
        )
    
    # Generate import ID
    import_id = f"import_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{file_path.stem}"
    
    # Initialize import tracking
    active_imports[import_id] = {
        'status': 'queued',
        'file_path': str(file_path),
        'started_at': datetime.utcnow().isoformat(),
        'request': request.dict()
    }
    
    # Start background import task
    background_tasks.add_task(
        run_import_task,
        import_id,
        str(file_path),
        request.deduplication_strategy,
        request.batch_size,
        service
    )
    
    return ImportResponse(
        import_id=import_id,
        status="queued",
        message=f"Import queued for file: {file_path.name}",
        estimated_duration_minutes=estimate_import_duration(file_path)
    )

@router.get("/import/{import_id}/status", response_model=ImportStatus)
async def get_import_status(
    import_id: str,
    service: SCAPImportService = Depends(get_import_service)
):
    """Get the status of an ongoing or completed import"""
    
    if import_id not in active_imports:
        raise HTTPException(
            status_code=404,
            detail=f"Import ID not found: {import_id}"
        )
    
    import_info = active_imports[import_id]
    
    # Get progress from service if import is running
    progress_data = {}
    if import_info['status'] == 'running':
        current_progress = await service.get_import_status()
        if current_progress:
            progress_data = current_progress
    
    return ImportStatus(
        import_id=import_id,
        status=import_info['status'],
        progress=progress_data,
        result=import_info.get('result')
    )

@router.get("/imports")
async def list_active_imports():
    """List all active and recent imports"""
    
    return {
        'active_imports': [
            {
                'import_id': import_id,
                'status': info['status'],
                'file_path': info['file_path'],
                'started_at': info['started_at']
            }
            for import_id, info in active_imports.items()
        ]
    }

@router.delete("/import/{import_id}")
async def cancel_import(import_id: str):
    """Cancel an ongoing import (if possible)"""
    
    if import_id not in active_imports:
        raise HTTPException(
            status_code=404,
            detail=f"Import ID not found: {import_id}"
        )
    
    import_info = active_imports[import_id]
    
    if import_info['status'] in ['completed', 'failed']:
        raise HTTPException(
            status_code=400,
            detail="Cannot cancel completed or failed import"
        )
    
    # Update status (actual cancellation would require more complex implementation)
    active_imports[import_id]['status'] = 'cancelled'
    active_imports[import_id]['cancelled_at'] = datetime.utcnow().isoformat()
    
    return {'message': f'Import {import_id} marked for cancellation'}

@router.get("/files")
async def list_imported_files(service: SCAPImportService = Depends(get_import_service)):
    """List all previously imported SCAP files"""
    
    try:
        files = await service.list_imported_files()
        return {
            'imported_files': files,
            'total_files': len(files)
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to list imported files: {str(e)}"
        )

@router.post("/validate/{import_id}")
async def validate_import(
    import_id: str,
    service: SCAPImportService = Depends(get_import_service)
):
    """Validate the integrity of an imported file"""
    
    if import_id not in active_imports:
        raise HTTPException(
            status_code=404,
            detail=f"Import ID not found: {import_id}"
        )
    
    import_info = active_imports[import_id]
    
    if import_info['status'] != 'completed':
        raise HTTPException(
            status_code=400,
            detail="Can only validate completed imports"
        )
    
    try:
        validation = await service.validate_import_integrity(import_info['file_path'])
        return validation
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Validation failed: {str(e)}"
        )

@router.get("/statistics")
async def get_import_statistics(service: SCAPImportService = Depends(get_import_service)):
    """Get overall import statistics"""
    
    try:
        # Get collection statistics from MongoDB
        from backend.app.models.mongo_models import ComplianceRule, RuleIntelligence, RemediationScript
        
        stats = {
            'total_rules': await ComplianceRule.count(),
            'rules_by_severity': {},
            'rules_by_category': {},
            'rules_with_fixes': await ComplianceRule.count(ComplianceRule.fix_available == True),
            'total_intelligence_records': await RuleIntelligence.count(),
            'total_remediation_scripts': await RemediationScript.count()
        }
        
        # Get severity distribution
        severity_pipeline = [
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        
        collection = ComplianceRule.get_motor_collection()
        cursor = collection.aggregate(severity_pipeline)
        severity_results = await cursor.to_list(length=None)
        
        for result in severity_results:
            stats['rules_by_severity'][result['_id']] = result['count']
            
        # Get category distribution
        category_pipeline = [
            {"$group": {"_id": "$category", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        
        cursor = collection.aggregate(category_pipeline)
        category_results = await cursor.to_list(length=None)
        
        for result in category_results:
            stats['rules_by_category'][result['_id']] = result['count']
            
        return stats
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get statistics: {str(e)}"
        )

# Background task functions

async def run_import_task(
    import_id: str,
    file_path: str,
    deduplication_strategy: str,
    batch_size: int,
    service: SCAPImportService
):
    """Run the import task in the background"""
    
    try:
        # Update status to running
        active_imports[import_id]['status'] = 'running'
        active_imports[import_id]['progress'] = {'current_phase': 'starting'}
        
        # Progress callback to update status
        async def progress_callback(progress_data: Dict[str, Any]):
            active_imports[import_id]['progress'] = progress_data
            
        # Run the import
        result = await service.import_scap_file(
            file_path=file_path,
            progress_callback=progress_callback,
            deduplication_strategy=deduplication_strategy,
            batch_size=batch_size
        )
        
        # Update final status
        active_imports[import_id]['status'] = result['status']
        active_imports[import_id]['result'] = result
        active_imports[import_id]['completed_at'] = datetime.utcnow().isoformat()
        
    except Exception as e:
        # Handle import failure
        active_imports[import_id]['status'] = 'failed'
        active_imports[import_id]['error'] = str(e)
        active_imports[import_id]['failed_at'] = datetime.utcnow().isoformat()

def estimate_import_duration(file_path: Path) -> float:
    """Estimate import duration based on file size"""
    try:
        file_size_mb = file_path.stat().st_size / (1024 * 1024)
        # Rough estimate: 1MB per minute for processing
        return max(1.0, file_size_mb * 1.0)
    except:
        return 5.0  # Default estimate