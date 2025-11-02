"""
SCAP Content Management Routes
"""

from fastapi import APIRouter, HTTPException, Depends, status, UploadFile, File
from fastapi.security import HTTPBearer
from pydantic import BaseModel
from typing import List, Optional
import logging

from ..utils.file_security import sanitize_filename, validate_file_extension

logger = logging.getLogger(__name__)
security = HTTPBearer()

router = APIRouter()


class SCAPContent(BaseModel):
    id: Optional[str] = None
    name: str
    version: str
    description: str
    content_type: str  # "benchmark", "profile", "datastream"
    file_path: Optional[str] = None
    upload_date: Optional[str] = None
    profiles: Optional[List[str]] = None


class ContentCreate(BaseModel):
    name: str
    version: str
    description: str
    content_type: str


@router.get("/", response_model=List[SCAPContent])
async def list_content(token: str = Depends(security)):
    """List all SCAP content"""
    # Mock data
    mock_content = [
        SCAPContent(
            id="1",
            name="RHEL 9 STIG",
            version="1.0.2",
            description="Red Hat Enterprise Linux 9 Security Technical Implementation Guide",
            content_type="benchmark",
            file_path="/scap/rhel9-stig.xml",
            upload_date="2024-01-10T09:00:00Z",
            profiles=["stig-rhel9-server", "stig-rhel9-workstation"],
        ),
        SCAPContent(
            id="2",
            name="Ubuntu 22.04 CIS Benchmark",
            version="1.1.0",
            description="Center for Internet Security Benchmark for Ubuntu 22.04",
            content_type="benchmark",
            file_path="/scap/ubuntu22-cis.xml",
            upload_date="2024-01-12T14:30:00Z",
            profiles=["cis-ubuntu22-l1-server", "cis-ubuntu22-l2-server"],
        ),
    ]

    return mock_content


@router.post("/upload")
async def upload_content(file: UploadFile = File(...), token: str = Depends(security)):
    """Upload new SCAP content file"""
    # Sanitize filename to prevent path traversal
    safe_filename = sanitize_filename(file.filename)

    # Validate file extension
    allowed_extensions = [".xml", ".zip", ".bz2"]
    if not validate_file_extension(safe_filename, allowed_extensions):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file type. Only XML, ZIP, and BZ2 files are allowed.",
        )

    # Mock upload processing
    content_info = {
        "id": "3",
        "filename": safe_filename,
        "size": file.size,
        "content_type": file.content_type,
        "status": "uploaded",
        "message": "File uploaded successfully. Processing will begin shortly.",
    }

    logger.info(f"SCAP content uploaded: {safe_filename}")
    return content_info


@router.get("/{content_id}", response_model=SCAPContent)
async def get_content(content_id: str, token: str = Depends(security)):
    """Get SCAP content details by ID"""
    # Mock data
    if content_id == "1":
        return SCAPContent(
            id="1",
            name="RHEL 9 STIG",
            version="1.0.2",
            description="Red Hat Enterprise Linux 9 Security Technical Implementation Guide",
            content_type="benchmark",
            file_path="/scap/rhel9-stig.xml",
            upload_date="2024-01-10T09:00:00Z",
            profiles=["stig-rhel9-server", "stig-rhel9-workstation"],
        )

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail="SCAP content not found"
    )


@router.get("/{content_id}/profiles")
async def get_content_profiles(content_id: str, token: str = Depends(security)):
    """Get available profiles for SCAP content"""
    # Mock profiles
    mock_profiles = [
        {
            "id": "stig-rhel9-server",
            "title": "Red Hat Enterprise Linux 9 STIG for Servers",
            "description": "Security configuration for RHEL 9 servers",
        },
        {
            "id": "stig-rhel9-workstation",
            "title": "Red Hat Enterprise Linux 9 STIG for Workstations",
            "description": "Security configuration for RHEL 9 workstations",
        },
    ]

    return mock_profiles


@router.delete("/{content_id}")
async def delete_content(content_id: str, token: str = Depends(security)):
    """Delete SCAP content"""
    logger.info(f"Deleted SCAP content {content_id}")
    return {"message": "SCAP content deleted successfully"}
