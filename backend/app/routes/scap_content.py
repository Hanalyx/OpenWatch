"""
SCAP Content Management API Routes
Handles SCAP content upload, validation, and management
"""
import os
import hashlib
import tempfile
import uuid
from typing import List, Optional
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import text

from ..database import get_db, DatabaseManager
from ..services.scap_scanner import SCAPScanner, SCAPContentError
from ..services.scap_repository import scap_repository_manager
from ..services.scap_datastream_processor import SCAPDataStreamProcessor, DataStreamError
from ..services.compliance_framework_mapper import ComplianceFrameworkMapper
from ..auth import get_current_user
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scap-content", tags=["SCAP Content"])

# Initialize SCAP scanner and processors
scap_scanner = SCAPScanner()
datastream_processor = SCAPDataStreamProcessor()
framework_mapper = ComplianceFrameworkMapper()

@router.get("/")
async def list_scap_content(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """List all uploaded SCAP content"""
    try:
        result = db.execute(text("""
            SELECT id, name, filename, content_type, description, version, 
                   profiles, uploaded_at, uploaded_by, os_family, os_version,
                   compliance_framework, source, status, update_available
            FROM scap_content 
            ORDER BY os_family, os_version, uploaded_at DESC
        """))
        
        content_list = []
        for row in result:
            profiles = []
            if row.profiles:
                try:
                    import json
                    profiles = json.loads(row.profiles)
                except:
                    profiles = []
            
            content_list.append({
                "id": row.id,
                "name": row.name,
                "filename": row.filename,
                "content_type": row.content_type,
                "description": row.description,
                "version": row.version,
                "profiles": profiles,
                "uploaded_at": row.uploaded_at.isoformat(),
                "uploaded_by": row.uploaded_by,
                "os_family": row.os_family or "unknown",
                "os_version": row.os_version or "unknown",
                "compliance_framework": row.compliance_framework or "unknown",
                "source": row.source or "manual",
                "status": row.status or "current",
                "update_available": row.update_available or False
            })
        
        return {"scap_content": content_list}
        
    except Exception as e:
        logger.error(f"Error listing SCAP content: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve SCAP content")


@router.get("/statistics")
async def get_scap_content_stats(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get SCAP content statistics"""
    try:
        # Get content counts by OS family
        result = db.execute(text("""
            SELECT 
                os_family,
                COUNT(*) as total_content,
                COUNT(DISTINCT os_version) as versions,
                SUM(CASE WHEN status = 'outdated' THEN 1 ELSE 0 END) as outdated,
                SUM(CASE WHEN update_available = true THEN 1 ELSE 0 END) as updates_available,
                COUNT(*) as total_profiles
            FROM scap_content 
            WHERE os_family IS NOT NULL
            GROUP BY os_family
            ORDER BY os_family
        """))
        
        os_stats = []
        for row in result:
            os_stats.append({
                "os_family": row.os_family,
                "total_content": row.total_content,
                "versions": row.versions,
                "outdated": row.outdated,
                "updates_available": row.updates_available,
                "total_profiles": row.total_profiles or 0
            })
        
        # Get overall statistics
        overall_result = db.execute(text("""
            SELECT 
                COUNT(*) as total_content,
                COUNT(DISTINCT os_family) as os_types,
                COUNT(DISTINCT compliance_framework) as frameworks,
                SUM(CASE WHEN status = 'outdated' THEN 1 ELSE 0 END) as outdated,
                SUM(CASE WHEN update_available = true THEN 1 ELSE 0 END) as updates_available
            FROM scap_content
        """)).fetchone()
        
        return {
            "overall": {
                "total_content": overall_result.total_content,
                "os_types": overall_result.os_types,
                "frameworks": overall_result.frameworks,
                "outdated": overall_result.outdated,
                "updates_available": overall_result.updates_available
            },
            "by_os_family": os_stats
        }
    except Exception as e:
        logger.error(f"Error getting SCAP content stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get content statistics")


@router.post("/upload")
async def upload_scap_content(
    file: UploadFile = File(...),
    name: str = Form(...),
    description: str = Form(""),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Upload and validate SCAP content file"""
    try:
        # Validate file type
        allowed_extensions = ['.xml', '.zip']
        file_ext = Path(file.filename).suffix.lower()
        if file_ext not in allowed_extensions:
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid file type. Allowed: {', '.join(allowed_extensions)}"
            )
        
        # Read file content
        content = await file.read()
        if len(content) == 0:
            raise HTTPException(status_code=400, detail="Empty file uploaded")
        
        # Calculate file hash
        file_hash = hashlib.sha256(content).hexdigest()
        
        # Check if file already exists
        existing = db.execute(text("""
            SELECT id FROM scap_content WHERE file_hash = :hash
        """), {"hash": file_hash}).fetchone()
        
        if existing:
            raise HTTPException(status_code=409, detail="File already exists")
        
        # Save file to temporary location for validation
        with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as temp_file:
            temp_file.write(content)
            temp_path = temp_file.name
        
        try:
            # Validate SCAP content using data-stream processor
            validation_result = datastream_processor.validate_datastream(temp_path)
            
            # Extract profiles with metadata
            profiles = datastream_processor.extract_profiles_with_metadata(temp_path)
            
            # Extract content components for framework mapping
            content_components = datastream_processor.extract_content_components(temp_path)
            
            # Create permanent storage location
            content_id = str(uuid.uuid4())
            storage_dir = Path("/app/data/scap") / content_id
            storage_dir.mkdir(parents=True, exist_ok=True)
            
            permanent_path = storage_dir / file.filename
            with open(permanent_path, 'wb') as f:
                f.write(content)
            
            # Extract OS and framework information
            os_family, os_version = _extract_os_info(file.filename, validation_result)
            compliance_framework = _extract_framework_info(file.filename, validation_result)
            
            # Save to database with enhanced metadata
            import json
            db.execute(text("""
                INSERT INTO scap_content 
                (name, filename, file_path, content_type, profiles, description, 
                 version, uploaded_by, file_hash, uploaded_at,
                 os_family, os_version, compliance_framework, source, status,
                 data_stream_id, benchmark_id, benchmark_version, profile_metadata)
                VALUES (:name, :filename, :file_path, :content_type, :profiles, 
                        :description, :version, :uploaded_by, :file_hash, NOW(),
                        :os_family, :os_version, :compliance_framework, :source, :status,
                        :data_stream_id, :benchmark_id, :benchmark_version, :profile_metadata)
            """), {
                "name": name,
                "filename": file.filename,
                "file_path": str(permanent_path),
                "content_type": validation_result.get("content_type", validation_result.get("document_type", "unknown")),
                "profiles": json.dumps(profiles),
                "description": description,
                "version": validation_result.get("version", ""),
                "uploaded_by": current_user["id"],
                "file_hash": file_hash,
                "os_family": os_family,
                "os_version": os_version,
                "compliance_framework": compliance_framework,
                "source": "manual",
                "status": "current",
                "data_stream_id": content_components.get("data_streams", [{}])[0].get("id") if content_components.get("data_streams") else None,
                "benchmark_id": validation_result.get("benchmark_id", ""),
                "benchmark_version": validation_result.get("benchmark_version", ""),
                "profile_metadata": json.dumps({p["id"]: p.get("metadata", {}) for p in profiles})
            })
            db.commit()
            
            # Get the inserted record
            result = db.execute(text("""
                SELECT id FROM scap_content WHERE file_hash = :hash
            """), {"hash": file_hash}).fetchone()
            
            logger.info(f"SCAP content uploaded: {name} ({file.filename})")
            
            return {
                "id": result.id,
                "message": "SCAP content uploaded successfully",
                "validation": validation_result,
                "profiles": profiles,
                "content_info": {
                    "format": content_components.get("format", "unknown"),
                    "rules_count": len(content_components.get("rules", [])),
                    "os_family": os_family,
                    "os_version": os_version,
                    "compliance_framework": compliance_framework
                }
            }
            
        finally:
            # Clean up temp file
            try:
                os.unlink(temp_path)
            except:
                pass
        
    except SCAPContentError as e:
        logger.error(f"SCAP validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error uploading SCAP content: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to upload SCAP content: {str(e)}")


@router.get("/{content_id}")
async def get_scap_content(
    content_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get SCAP content details"""
    try:
        result = db.execute(text("""
            SELECT id, name, filename, content_type, description, version, 
                   profiles, uploaded_at, uploaded_by, file_path
            FROM scap_content WHERE id = :id
        """), {"id": content_id}).fetchone()
        
        if not result:
            raise HTTPException(status_code=404, detail="SCAP content not found")
        
        profiles = []
        if result.profiles:
            try:
                import json
                profiles = json.loads(result.profiles)
            except:
                profiles = []
        
        return {
            "id": result.id,
            "name": result.name,
            "filename": result.filename,
            "content_type": result.content_type,
            "description": result.description,
            "version": result.version,
            "profiles": profiles,
            "uploaded_at": result.uploaded_at.isoformat(),
            "uploaded_by": result.uploaded_by,
            "has_file": os.path.exists(result.file_path)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting SCAP content: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve SCAP content")


@router.get("/{content_id}/profiles")
async def get_scap_profiles(
    content_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get available profiles for SCAP content"""
    try:
        result = db.execute(text("""
            SELECT profiles, file_path FROM scap_content WHERE id = :id
        """), {"id": content_id}).fetchone()
        
        if not result:
            raise HTTPException(status_code=404, detail="SCAP content not found")
        
        profiles = []
        if result.profiles:
            try:
                import json
                profiles = json.loads(result.profiles)
            except:
                # Re-extract profiles from file if cached version is invalid
                if os.path.exists(result.file_path):
                    profiles = scap_scanner.extract_profiles(result.file_path)
        
        return {"profiles": profiles}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting SCAP profiles: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve profiles")


@router.delete("/{content_id}")
async def delete_scap_content(
    content_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Delete SCAP content"""
    try:
        # Check if content exists and get file path
        result = db.execute(text("""
            SELECT file_path FROM scap_content WHERE id = :id
        """), {"id": content_id}).fetchone()
        
        if not result:
            raise HTTPException(status_code=404, detail="SCAP content not found")
        
        # Check for active scans using this content
        active_scans = db.execute(text("""
            SELECT COUNT(*) as count FROM scans 
            WHERE content_id = :id AND status IN ('pending', 'running')
        """), {"id": content_id}).fetchone()
        
        if active_scans.count > 0:
            raise HTTPException(
                status_code=409, 
                detail="Cannot delete SCAP content with active scans"
            )
        
        # Delete file from storage
        file_path = result.file_path
        if os.path.exists(file_path):
            try:
                # Remove file and parent directory if empty
                os.unlink(file_path)
                parent_dir = Path(file_path).parent
                if parent_dir.name != "scap":  # Don't remove main scap dir
                    try:
                        parent_dir.rmdir()  # Only removes if empty
                    except:
                        pass
            except Exception as e:
                logger.warning(f"Failed to delete file {file_path}: {e}")
        
        # Delete from database
        db.execute(text("""
            DELETE FROM scap_content WHERE id = :id
        """), {"id": content_id})
        db.commit()
        
        logger.info(f"SCAP content deleted: {content_id}")
        return {"message": "SCAP content deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting SCAP content: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete SCAP content")


@router.get("/{content_id}/download")
async def download_scap_content(
    content_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Download SCAP content file"""
    try:
        result = db.execute(text("""
            SELECT filename, file_path FROM scap_content WHERE id = :id
        """), {"id": content_id}).fetchone()
        
        if not result:
            raise HTTPException(status_code=404, detail="SCAP content not found")
        
        if not os.path.exists(result.file_path):
            raise HTTPException(status_code=404, detail="SCAP content file not found")
        
        return FileResponse(
            path=result.file_path,
            filename=result.filename,
            media_type='application/octet-stream'
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error downloading SCAP content: {e}")
        raise HTTPException(status_code=500, detail="Failed to download SCAP content")


# Repository Management Endpoints

@router.get("/repositories/status")
async def get_repository_status(
    current_user: dict = Depends(get_current_user)
):
    """Get status of all SCAP repositories"""
    try:
        status = scap_repository_manager.get_repository_status()
        return status
    except Exception as e:
        logger.error(f"Error getting repository status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get repository status")


@router.post("/repositories/sync")
async def sync_repositories(
    repository_ids: Optional[List[str]] = None,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Synchronize SCAP content from repositories"""
    try:
        if scap_repository_manager.sync_running:
            raise HTTPException(status_code=409, detail="Sync already in progress")
        
        # Start sync in background
        results = await scap_repository_manager.sync_repositories(db, repository_ids)
        
        return {
            "message": "Repository sync completed",
            "results": results
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error syncing repositories: {e}")
        raise HTTPException(status_code=500, detail="Failed to sync repositories")


def _extract_os_info(filename: str, validation_result: Dict) -> Tuple[str, str]:
    """Extract OS family and version from filename and validation result"""
    filename_lower = filename.lower()
    
    # Check filename patterns
    if 'rhel' in filename_lower:
        os_family = 'rhel'
        if 'rhel_9' in filename_lower or 'rhel9' in filename_lower:
            os_version = '9'
        elif 'rhel_8' in filename_lower or 'rhel8' in filename_lower:
            os_version = '8'
        else:
            os_version = 'unknown'
    elif 'ubuntu' in filename_lower:
        os_family = 'ubuntu'
        if '22.04' in filename_lower or '22_04' in filename_lower or '2204' in filename_lower:
            os_version = '22.04'
        elif '20.04' in filename_lower or '20_04' in filename_lower or '2004' in filename_lower:
            os_version = '20.04'
        else:
            os_version = 'unknown'
    elif 'oracle' in filename_lower:
        os_family = 'oracle_linux'
        if 'oracle_linux_8' in filename_lower:
            os_version = '8'
        else:
            os_version = 'unknown'
    elif 'centos' in filename_lower:
        os_family = 'centos'
        os_version = 'unknown'
    else:
        # Try to extract from validation result
        title = validation_result.get('title', '').lower()
        if 'red hat' in title:
            os_family = 'rhel'
        elif 'ubuntu' in title:
            os_family = 'ubuntu'
        elif 'oracle' in title:
            os_family = 'oracle_linux'
        else:
            os_family = 'unknown'
        os_version = 'unknown'
    
    return os_family, os_version


def _extract_framework_info(filename: str, validation_result: Dict) -> str:
    """Extract compliance framework from filename and validation result"""
    filename_lower = filename.lower()
    title_lower = validation_result.get('title', '').lower()
    
    # Check for framework indicators
    if 'stig' in filename_lower or 'stig' in title_lower or 'disa' in filename_lower:
        return 'DISA-STIG'
    elif 'cis' in filename_lower or 'cis' in title_lower:
        return 'CIS-Controls'
    elif 'nist' in filename_lower or 'nist' in title_lower:
        return 'NIST-800-53'
    elif 'pci' in filename_lower or 'pci-dss' in title_lower:
        return 'PCI-DSS'
    elif 'hipaa' in filename_lower:
        return 'HIPAA'
    elif 'cmmc' in filename_lower:
        return 'CMMC-2.0'
    else:
        return 'unknown'


@router.get("/{content_id}/compliance-analysis")
async def get_compliance_analysis(
    content_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get compliance framework analysis for SCAP content"""
    try:
        # Get content info
        result = db.execute(text("""
            SELECT file_path, profiles FROM scap_content WHERE id = :id
        """), {"id": content_id}).fetchone()
        
        if not result:
            raise HTTPException(status_code=404, detail="SCAP content not found")
        
        # Extract content components
        content_components = datastream_processor.extract_content_components(result.file_path)
        
        # Get compliance framework summary
        rule_ids = [rule["id"] for rule in content_components.get("rules", [])]
        framework_summary = framework_mapper.get_framework_summary(rule_ids)
        
        # Get compliance matrix
        compliance_matrix = framework_mapper.export_compliance_matrix(rule_ids)
        
        return {
            "content_id": content_id,
            "total_rules": len(rule_ids),
            "framework_summary": framework_summary,
            "compliance_matrix": compliance_matrix,
            "content_components": {
                "format": content_components.get("format"),
                "profiles": content_components.get("profiles", []),
                "data_streams": content_components.get("data_streams", [])
            }
        }
        
    except Exception as e:
        logger.error(f"Error analyzing compliance content: {e}")
        raise HTTPException(status_code=500, detail="Failed to analyze compliance content")


@router.post("/{content_id}/validate-datastream")
async def validate_datastream_content(
    content_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Create comprehensive validation report for SCAP content"""
    try:
        # Get content file path
        result = db.execute(text("""
            SELECT file_path, filename FROM scap_content WHERE id = :id
        """), {"id": content_id}).fetchone()
        
        if not result:
            raise HTTPException(status_code=404, detail="SCAP content not found")
        
        # Create validation report
        validation_report = datastream_processor.create_content_validation_report(result.file_path)
        
        return {
            "content_id": content_id,
            "filename": result.filename,
            "validation_report": validation_report
        }
        
    except Exception as e:
        logger.error(f"Error validating datastream content: {e}")
        raise HTTPException(status_code=500, detail="Failed to validate datastream content")


@router.get("/framework-mappings")
async def get_framework_mappings(
    framework: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get compliance framework mappings"""
    try:
        # This would query the database for framework mappings
        # For now, return sample data structure
        return {
            "frameworks": list(framework_mapper.control_families.keys()),
            "mappings_available": len(framework_mapper.framework_mappings),
            "supported_platforms": ["rhel8", "rhel9", "ubuntu20", "ubuntu22"],
            "framework_info": framework_mapper.control_families.get(framework) if framework else None
        }
        
    except Exception as e:
        logger.error(f"Error getting framework mappings: {e}")
        raise HTTPException(status_code=500, detail="Failed to get framework mappings")


@router.put("/repositories/{repository_id}/enable")
async def enable_repository(
    repository_id: str,
    enabled: bool = True,
    current_user: dict = Depends(get_current_user)
):
    """Enable or disable a repository"""
    try:
        scap_repository_manager.enable_repository(repository_id, enabled)
        return {
            "message": f"Repository {repository_id} {'enabled' if enabled else 'disabled'}"
        }
    except Exception as e:
        logger.error(f"Error updating repository: {e}")
        raise HTTPException(status_code=500, detail="Failed to update repository")


@router.get("/environment/info")
async def get_environment_info(
    current_user: dict = Depends(get_current_user)
):
    """Get environment information (connected/air-gapped)"""
    try:
        # Determine environment type based on repository connectivity
        repositories = scap_repository_manager.get_repository_status()["repositories"]
        
        # Simple connectivity test
        has_internet = False
        try:
            import asyncio
            import aiohttp
            
            async def test_connectivity():
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get('https://www.google.com', timeout=5) as response:
                            return response.status == 200
                except:
                    return False
            
            has_internet = await test_connectivity()
        except:
            has_internet = False
        
        environment_type = 'connected' if has_internet else 'air-gapped'
        
        return {
            "type": environment_type,
            "repositories": repositories,
            "auto_sync_enabled": has_internet and any(r["enabled"] for r in repositories),
            "last_global_sync": scap_repository_manager.last_global_sync.isoformat() if scap_repository_manager.last_global_sync else None,
            "next_scheduled_sync": None  # Would be calculated based on schedule settings
        }
    except Exception as e:
        logger.error(f"Error getting environment info: {e}")
        raise HTTPException(status_code=500, detail="Failed to get environment information")