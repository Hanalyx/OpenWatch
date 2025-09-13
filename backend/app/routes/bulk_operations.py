"""
Bulk Operations API Routes
Handles bulk import/export operations for hosts and other entities
"""
import csv
import io
import json
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field, validator
import ipaddress

from ..database import get_db, Host
from ..auth import get_current_user
from ..rbac import require_role, UserRole
from ..audit_db import log_security_event
from ..services.csv_analyzer import CSVAnalyzer, FieldAnalysis, CSVAnalysis

router = APIRouter()

class BulkHostImport(BaseModel):
    """Single host entry for bulk import"""
    hostname: str = Field(..., min_length=1, max_length=255)
    ip_address: str = Field(..., min_length=7, max_length=45)
    display_name: Optional[str] = Field(None, max_length=255)
    operating_system: Optional[str] = Field(None, max_length=100)
    port: Optional[int] = Field(22, ge=1, le=65535)
    username: Optional[str] = Field(None, max_length=100)
    auth_method: Optional[str] = Field("password", pattern="^(password|ssh_key|system_default)$")
    environment: Optional[str] = Field("production", max_length=50)
    tags: Optional[str] = Field(None, max_length=500)  # Comma-separated tags
    owner: Optional[str] = Field(None, max_length=100)
    
    @validator('ip_address')
    def validate_ip(cls, v):
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")

class BulkImportRequest(BaseModel):
    """Request body for JSON-based bulk import"""
    hosts: List[BulkHostImport]
    update_existing: bool = Field(False, description="Update existing hosts instead of skipping")
    dry_run: bool = Field(False, description="Validate without importing")

class BulkImportResult(BaseModel):
    """Result of bulk import operation"""
    total_processed: int
    successful_imports: int
    failed_imports: int
    skipped_duplicates: int
    errors: List[Dict[str, Any]]
    imported_hosts: List[Dict[str, Any]]


# Enhanced CSV Import Models
class FieldAnalysisResponse(BaseModel):
    """Field analysis response model"""
    column_name: str
    detected_type: str
    confidence: float
    sample_values: List[str]
    unique_count: int
    null_count: int
    suggestions: List[str]


class CSVAnalysisResponse(BaseModel):
    """CSV analysis response model"""
    total_rows: int
    total_columns: int
    headers: List[str]
    field_analyses: List[FieldAnalysisResponse]
    auto_mappings: Dict[str, str]
    template_matches: List[str]


class FieldMapping(BaseModel):
    """Field mapping configuration"""
    source_column: str
    target_field: str
    transform_function: Optional[str] = None  # For future use


class EnhancedImportRequest(BaseModel):
    """Enhanced import request with field mappings"""
    csv_data: str
    field_mappings: List[FieldMapping]
    update_existing: bool = Field(False, description="Update existing hosts instead of skipping")
    dry_run: bool = Field(False, description="Validate without importing")
    default_values: Optional[Dict[str, Any]] = None  # Default values for missing fields


@router.post("/hosts/bulk-import", response_model=BulkImportResult)
@require_role([UserRole.SUPER_ADMIN.value, UserRole.SECURITY_ADMIN.value])
async def bulk_import_hosts(
    request: BulkImportRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Bulk import hosts from JSON payload
    
    Supports:
    - Creating multiple hosts at once
    - Updating existing hosts (with update_existing flag)
    - Dry run mode for validation
    - Detailed error reporting per host
    """
    result = BulkImportResult(
        total_processed=len(request.hosts),
        successful_imports=0,
        failed_imports=0,
        skipped_duplicates=0,
        errors=[],
        imported_hosts=[]
    )
    
    # Process each host
    for idx, host_data in enumerate(request.hosts):
        try:
            # Check if host already exists
            existing_host = db.query(Host).filter(
                (Host.hostname == host_data.hostname) | 
                (Host.ip_address == host_data.ip_address)
            ).first()
            
            if existing_host:
                if request.update_existing and not request.dry_run:
                    # Update existing host
                    for field, value in host_data.dict(exclude_unset=True).items():
                        setattr(existing_host, field, value)
                    db.commit()
                    result.successful_imports += 1
                    result.imported_hosts.append({
                        "hostname": existing_host.hostname,
                        "ip_address": existing_host.ip_address,
                        "action": "updated"
                    })
                else:
                    result.skipped_duplicates += 1
                    result.errors.append({
                        "row": idx + 1,
                        "hostname": host_data.hostname,
                        "error": "Host already exists",
                        "action": "skipped"
                    })
                continue
            
            if not request.dry_run:
                # Create new host
                new_host = Host(
                    hostname=host_data.hostname,
                    ip_address=host_data.ip_address,
                    display_name=host_data.display_name or host_data.hostname,
                    operating_system=host_data.operating_system or "RHEL",
                    port=host_data.port,  # Fixed: use 'port' instead of 'ssh_port'
                    username=host_data.username,  # Fixed: use 'username' instead of 'ssh_username'
                    auth_method=host_data.auth_method,
                    environment=host_data.environment,
                    tags=host_data.tags,
                    owner=host_data.owner,
                    is_active=True,
                    created_by=current_user["id"]
                )
                db.add(new_host)
                db.commit()
                
                result.successful_imports += 1
                result.imported_hosts.append({
                    "hostname": new_host.hostname,
                    "ip_address": new_host.ip_address,
                    "action": "created"
                })
            else:
                # Dry run - just validate
                result.successful_imports += 1
                result.imported_hosts.append({
                    "hostname": host_data.hostname,
                    "ip_address": host_data.ip_address,
                    "action": "would_create"
                })
                
        except Exception as e:
            result.failed_imports += 1
            result.errors.append({
                "row": idx + 1,
                "hostname": host_data.hostname if hasattr(host_data, 'hostname') else "unknown",
                "error": str(e)
            })
            # Continue processing other hosts
            continue
    
    # Log the bulk import operation
    log_security_event(
        db=db,
        event_type="BULK_HOST_IMPORT",
        user_id=current_user["id"],
        ip_address=current_user.get("ip_address", "unknown"),
        details=f"Imported {result.successful_imports} hosts, {result.failed_imports} failed, {result.skipped_duplicates} skipped"
    )
    
    return result




@router.get("/hosts/import-template")
async def download_import_template():
    """
    Download CSV template for bulk host import
    """
    # Create CSV content
    csv_content = io.StringIO()
    writer = csv.writer(csv_content)
    
    # Write headers
    headers = [
        "hostname", "ip_address", "display_name", "operating_system", 
        "port", "username", "auth_method", "environment", "tags", "owner"
    ]
    writer.writerow(headers)
    
    # Write example rows
    examples = [
        ["web-server-01", "192.168.1.10", "Web Server 01", "RHEL 9", "22", "admin", "ssh_key", "production", "web,frontend", "john.doe"],
        ["db-server-01", "192.168.1.20", "Database Server", "RHEL 8", "22", "admin", "password", "production", "database,backend", "jane.smith"],
        ["app-server-01", "192.168.1.30", "", "RHEL 9", "22", "", "system_default", "staging", "application", ""],
    ]
    writer.writerows(examples)
    
    # Return as downloadable file
    return Response(
        content=csv_content.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=host_import_template.csv"
        }
    )


@router.get("/hosts/export-csv")
@require_role([UserRole.SUPER_ADMIN.value, UserRole.SECURITY_ADMIN.value, UserRole.SECURITY_ANALYST.value])
async def export_hosts_csv(
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Export all hosts to CSV format
    Useful for backing up host configurations or as a template
    """
    hosts = db.query(Host).filter(Host.is_active == True).all()
    
    # Create CSV content
    csv_content = io.StringIO()
    writer = csv.writer(csv_content)
    
    # Write headers
    headers = [
        "hostname", "ip_address", "display_name", "operating_system", 
        "port", "username", "auth_method", "environment", "tags", "owner"
    ]
    writer.writerow(headers)
    
    # Write host data
    for host in hosts:
        writer.writerow([
            host.hostname,
            host.ip_address,
            host.display_name or "",
            host.operating_system or "",
            host.ssh_port or 22,
            host.ssh_username or "",
            host.auth_method or "password",
            host.environment or "production",
            host.tags or "",
            host.owner or ""
        ])
    
    # Log export operation
    log_security_event(
        db=db,
        event_type="HOST_EXPORT",
        user_id=current_user["id"],
        ip_address=current_user.get("ip_address", "unknown"),
        details=f"Exported {len(hosts)} hosts to CSV"
    )
    
    return Response(
        content=csv_content.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=hosts_export.csv"
        }
    )


# Enhanced CSV Import Endpoints
@router.post("/hosts/analyze-csv", response_model=CSVAnalysisResponse)
@require_role([UserRole.SUPER_ADMIN.value, UserRole.SECURITY_ADMIN.value])
async def analyze_csv(
    file: UploadFile = File(...),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Analyze uploaded CSV file and provide intelligent field mapping suggestions
    
    This endpoint accepts any CSV format and returns:
    - Column analysis with detected field types
    - Confidence scores for each detection
    - Auto-mapping suggestions
    - Template matches for known formats
    """
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="File must be a CSV")
    
    try:
        # Read CSV content
        contents = await file.read()
        csv_text = contents.decode('utf-8-sig')  # Handle BOM if present
        
        # Analyze with CSV analyzer
        analyzer = CSVAnalyzer()
        analysis = analyzer.analyze_csv(csv_text)
        
        # Convert to response model
        field_analyses = [
            FieldAnalysisResponse(
                column_name=fa.column_name,
                detected_type=fa.detected_type.value,
                confidence=fa.confidence,
                sample_values=fa.sample_values,
                unique_count=fa.unique_count,
                null_count=fa.null_count,
                suggestions=fa.suggestions
            )
            for fa in analysis.field_analyses
        ]
        
        return CSVAnalysisResponse(
            total_rows=analysis.total_rows,
            total_columns=analysis.total_columns,
            headers=analysis.headers,
            field_analyses=field_analyses,
            auto_mappings=analysis.auto_mappings,
            template_matches=analysis.template_matches
        )
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"CSV analysis failed: {str(e)}")


@router.post("/hosts/import-with-mapping", response_model=BulkImportResult)
@require_role([UserRole.SUPER_ADMIN.value, UserRole.SECURITY_ADMIN.value])
async def import_with_mapping(
    request: EnhancedImportRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Import hosts using custom field mappings
    
    This endpoint allows importing CSV data with flexible field mapping,
    supporting any CSV format with user-defined column mappings.
    """
    try:
        # Parse CSV data
        csv_reader = csv.DictReader(io.StringIO(request.csv_data))
        rows = list(csv_reader)
        
        if not rows:
            raise HTTPException(status_code=400, detail="CSV contains no data rows")
        
        # Create field mapping dictionary
        field_map = {fm.source_column: fm.target_field for fm in request.field_mappings}
        
        # Prepare default values
        defaults = request.default_values or {}
        defaults.setdefault('environment', 'production')
        defaults.setdefault('port', 22)
        defaults.setdefault('auth_method', 'ssh_key')
        
        result = BulkImportResult(
            total_processed=len(rows),
            successful_imports=0,
            failed_imports=0,
            skipped_duplicates=0,
            errors=[],
            imported_hosts=[]
        )
        
        # Process each row
        for idx, row in enumerate(rows):
            try:
                # Map fields according to user configuration
                mapped_data = {}
                
                # Apply field mappings
                for source_col, target_field in field_map.items():
                    if source_col in row and row[source_col]:
                        value = row[source_col].strip()
                        
                        # Apply type conversions
                        if target_field == 'port' and value:
                            try:
                                mapped_data[target_field] = int(value)
                            except ValueError:
                                raise ValueError(f"Invalid port number: {value}")
                        else:
                            mapped_data[target_field] = value
                
                # Apply default values for missing required fields
                for field, default_value in defaults.items():
                    if field not in mapped_data:
                        mapped_data[field] = default_value
                
                # Ensure required fields are present
                if 'hostname' not in mapped_data or not mapped_data['hostname']:
                    raise ValueError("Hostname is required")
                if 'ip_address' not in mapped_data or not mapped_data['ip_address']:
                    raise ValueError("IP address is required")
                
                # Validate IP address
                try:
                    ipaddress.ip_address(mapped_data['ip_address'])
                except ValueError:
                    raise ValueError(f"Invalid IP address: {mapped_data['ip_address']}")
                
                # Check for existing host
                existing_host = db.query(Host).filter(
                    (Host.hostname == mapped_data['hostname']) | 
                    (Host.ip_address == mapped_data['ip_address'])
                ).first()
                
                if existing_host:
                    if request.update_existing and not request.dry_run:
                        # Update existing host
                        for field, value in mapped_data.items():
                            if hasattr(existing_host, field):
                                setattr(existing_host, field, value)
                        db.commit()
                        result.successful_imports += 1
                        result.imported_hosts.append({
                            "hostname": existing_host.hostname,
                            "ip_address": existing_host.ip_address,
                            "action": "updated"
                        })
                    else:
                        result.skipped_duplicates += 1
                        result.errors.append({
                            "row": idx + 1,
                            "hostname": mapped_data['hostname'],
                            "error": "Host already exists",
                            "action": "skipped"
                        })
                    continue
                
                if not request.dry_run:
                    # Create new host
                    new_host = Host(
                        hostname=mapped_data['hostname'],
                        ip_address=mapped_data['ip_address'],
                        display_name=mapped_data.get('display_name') or mapped_data['hostname'],
                        operating_system=mapped_data.get('operating_system') or "RHEL",
                        port=mapped_data.get('port', 22),
                        username=mapped_data.get('username'),
                        auth_method=mapped_data.get('auth_method', 'ssh_key'),
                        environment=mapped_data.get('environment', 'production'),
                        tags=mapped_data.get('tags'),
                        owner=mapped_data.get('owner'),
                        is_active=True,
                        created_by=current_user["id"]
                    )
                    db.add(new_host)
                    db.commit()
                    
                    result.successful_imports += 1
                    result.imported_hosts.append({
                        "hostname": new_host.hostname,
                        "ip_address": new_host.ip_address,
                        "action": "created"
                    })
                else:
                    # Dry run - just validate
                    result.successful_imports += 1
                    result.imported_hosts.append({
                        "hostname": mapped_data['hostname'],
                        "ip_address": mapped_data['ip_address'],
                        "action": "would_create"
                    })
                    
            except Exception as e:
                result.failed_imports += 1
                result.errors.append({
                    "row": idx + 1,
                    "hostname": row.get(field_map.get('hostname', ''), 'unknown'),
                    "error": str(e)
                })
                continue
        
        # Log the import operation
        log_security_event(
            db=db,
            event_type="ENHANCED_BULK_IMPORT",
            user_id=current_user["id"],
            ip_address=current_user.get("ip_address", "unknown"),
            details=f"Enhanced import: {result.successful_imports} hosts, {result.failed_imports} failed, {result.skipped_duplicates} skipped"
        )
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Import failed: {str(e)}")