"""
Scan Template Routes - Quick Scan Configuration
"""

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db

router = APIRouter(prefix="/scan-templates", tags=["Scan Templates"])


class ScanTemplate(BaseModel):
    id: str
    name: str
    description: str
    contentId: int = 1  # Default SCAP content ID
    profileId: str
    scope: str = "system"
    scopeId: Optional[str] = None
    isDefault: bool = False
    estimatedDuration: str
    ruleCount: Optional[int] = None


@router.get("/")
async def list_scan_templates(
    db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)
):
    """List available scan templates"""
    # For now, return predefined templates
    # In a full implementation, these would be stored in database
    templates = [
        {
            "id": "quick-compliance",
            "name": "Quick Compliance",
            "description": "Essential compliance checks for regulatory requirements",
            "contentId": 1,
            "profileId": "xccdf_org.ssgproject.content_profile_cui",
            "scope": "system",
            "isDefault": True,
            "estimatedDuration": "5-10 min",
            "ruleCount": 120,
        },
        {
            "id": "security-audit",
            "name": "Security Audit",
            "description": "Comprehensive security configuration review",
            "contentId": 1,
            "profileId": "xccdf_org.ssgproject.content_profile_stig",
            "scope": "system",
            "isDefault": False,
            "estimatedDuration": "15-25 min",
            "ruleCount": 340,
        },
        {
            "id": "vulnerability-scan",
            "name": "Vulnerability Check",
            "description": "Scan for known security vulnerabilities",
            "contentId": 1,
            "profileId": "xccdf_org.ssgproject.content_profile_cis",
            "scope": "system",
            "isDefault": False,
            "estimatedDuration": "10-15 min",
            "ruleCount": 200,
        },
    ]

    return {"templates": templates}


@router.get("/host/{host_id}")
async def get_host_scan_templates(
    host_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get scan templates available for a specific host"""
    # For now, return the same system templates
    # In full implementation, would include host-specific templates
    templates = await list_scan_templates(db, current_user)
    return templates


@router.post("/")
async def create_scan_template(
    template: ScanTemplate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Create a new scan template"""
    # Basic validation
    if not template.name or not template.profileId:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Template name and profile ID are required",
        )

    # In full implementation, would save to database
    # For now, just return success
    return {"message": "Scan template created successfully", "template_id": template.id}


@router.delete("/{template_id}")
async def delete_scan_template(
    template_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Delete a scan template"""
    # In full implementation, would delete from database
    return {"message": f"Scan template {template_id} deleted successfully"}
