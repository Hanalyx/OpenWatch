"""
Host Groups API Routes
Handles host group creation, management, and host assignment with smart validation
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import Host, HostGroup, ScapContent, get_db
from ..rbac import check_permission
from ..services.group_validation_service import GroupValidationService, ValidationError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/host-groups", tags=["Host Groups"])


class HostGroupCreate(BaseModel):
    name: str
    description: Optional[str] = None
    color: Optional[str] = None
    os_family: Optional[str] = None
    os_version_pattern: Optional[str] = None
    architecture: Optional[str] = None
    scap_content_id: Optional[int] = None
    default_profile_id: Optional[str] = None
    compliance_framework: Optional[str] = None
    auto_scan_enabled: Optional[bool] = False
    scan_schedule: Optional[str] = None
    validation_rules: Optional[Dict[str, Any]] = None


class HostGroupUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    color: Optional[str] = None
    os_family: Optional[str] = None
    os_version_pattern: Optional[str] = None
    architecture: Optional[str] = None
    scap_content_id: Optional[int] = None
    default_profile_id: Optional[str] = None
    compliance_framework: Optional[str] = None
    auto_scan_enabled: Optional[bool] = None
    scan_schedule: Optional[str] = None
    validation_rules: Optional[Dict[str, Any]] = None


class HostGroupResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    color: Optional[str]
    host_count: int
    created_by: int
    created_at: datetime
    updated_at: datetime
    os_family: Optional[str]
    os_version_pattern: Optional[str]
    architecture: Optional[str]
    scap_content_id: Optional[int]
    default_profile_id: Optional[str]
    compliance_framework: Optional[str]
    auto_scan_enabled: bool
    scan_schedule: Optional[str]
    validation_rules: Optional[Dict[str, Any]]
    scap_content_name: Optional[str] = None
    compatibility_summary: Optional[Dict[str, Any]] = None


class AssignHostsRequest(BaseModel):
    host_ids: List[str]
    validate_compatibility: Optional[bool] = True
    force_assignment: Optional[bool] = False


class ValidateHostsRequest(BaseModel):
    host_ids: List[str]


class SmartGroupCreateRequest(BaseModel):
    host_ids: List[str]
    group_name: str
    description: Optional[str] = None
    auto_configure: Optional[bool] = True


class CompatibilityValidationResponse(BaseModel):
    group: Dict[str, Any]
    compatible: List[Dict[str, Any]]
    incompatible: List[Dict[str, Any]]
    warnings: List[str]
    suggestions: Dict[str, Any]
    summary: Dict[str, Any]


@router.get("/", response_model=List[HostGroupResponse])
async def list_host_groups(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """List all host groups with host counts"""
    try:
        result = db.execute(
            text(
                """
            SELECT
                hg.id, hg.name, hg.description, hg.color, hg.created_by, hg.created_at, hg.updated_at,
                hg.os_family, hg.os_version_pattern, hg.architecture, hg.scap_content_id,
                hg.default_profile_id, hg.compliance_framework, hg.auto_scan_enabled,
                hg.scan_schedule, hg.validation_rules,
                COALESCE(COUNT(hgm.host_id), 0) as host_count,
                sc.name as scap_content_name
            FROM host_groups hg
            LEFT JOIN host_group_memberships hgm ON hg.id = hgm.group_id
            LEFT JOIN scap_content sc ON hg.scap_content_id = sc.id
            GROUP BY hg.id, hg.name, hg.description, hg.color, hg.created_by, hg.created_at,
                     hg.updated_at, hg.os_family, hg.os_version_pattern, hg.architecture,
                     hg.scap_content_id, hg.default_profile_id, hg.compliance_framework,
                     hg.auto_scan_enabled, hg.scan_schedule, hg.validation_rules, sc.name
            ORDER BY hg.name
        """
            )
        )

        groups = []
        for row in result:
            logger.info(
                f"Raw row data for group {row.id}: scap_content_id={row.scap_content_id}, default_profile_id={row.default_profile_id}"
            )
            group_data = {
                "id": row.id,
                "name": row.name,
                "description": row.description,
                "color": row.color,
                "host_count": row.host_count,
                "created_by": row.created_by,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
                "os_family": row.os_family,
                "os_version_pattern": row.os_version_pattern,
                "architecture": row.architecture,
                "scap_content_id": row.scap_content_id,
                "default_profile_id": row.default_profile_id,
                "compliance_framework": row.compliance_framework,
                "auto_scan_enabled": (row.auto_scan_enabled if row.auto_scan_enabled is not None else False),
                "scan_schedule": row.scan_schedule,
                "validation_rules": (json.loads(row.validation_rules) if row.validation_rules else None),
                "scap_content_name": row.scap_content_name,
            }
            logger.info(
                f"Group data includes SCAP fields: scap_content_id={group_data.get('scap_content_id')}, default_profile_id={group_data.get('default_profile_id')}"
            )
            groups.append(group_data)

        return groups

    except Exception as e:
        logger.error(f"Error listing host groups: {e}")
        raise HTTPException(status_code=500, detail="Failed to list host groups")


@router.get("/{group_id}", response_model=HostGroupResponse)
async def get_host_group(
    group_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get a specific host group by ID"""
    try:
        result = db.execute(
            text(
                """
            SELECT
                hg.id, hg.name, hg.description, hg.color, hg.created_by, hg.created_at, hg.updated_at,
                hg.os_family, hg.os_version_pattern, hg.architecture, hg.scap_content_id,
                hg.default_profile_id, hg.compliance_framework, hg.auto_scan_enabled,
                hg.scan_schedule, hg.validation_rules,
                COALESCE(COUNT(hgm.host_id), 0) as host_count,
                sc.name as scap_content_name
            FROM host_groups hg
            LEFT JOIN host_group_memberships hgm ON hg.id = hgm.group_id
            LEFT JOIN scap_content sc ON hg.scap_content_id = sc.id
            WHERE hg.id = :group_id
            GROUP BY hg.id, hg.name, hg.description, hg.color, hg.created_by, hg.created_at,
                     hg.updated_at, hg.os_family, hg.os_version_pattern, hg.architecture,
                     hg.scap_content_id, hg.default_profile_id, hg.compliance_framework,
                     hg.auto_scan_enabled, hg.scan_schedule, hg.validation_rules, sc.name
        """
            ),
            {"group_id": group_id},
        )

        row = result.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Host group not found")

        return {
            "id": row.id,
            "name": row.name,
            "description": row.description,
            "color": row.color,
            "host_count": row.host_count,
            "created_by": row.created_by,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
            "os_family": row.os_family,
            "os_version_pattern": row.os_version_pattern,
            "architecture": row.architecture,
            "scap_content_id": row.scap_content_id,
            "default_profile_id": row.default_profile_id,
            "compliance_framework": row.compliance_framework,
            "auto_scan_enabled": (row.auto_scan_enabled if row.auto_scan_enabled is not None else False),
            "scan_schedule": row.scan_schedule,
            "validation_rules": (json.loads(row.validation_rules) if row.validation_rules else None),
            "scap_content_name": row.scap_content_name,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting host group: {e}")
        raise HTTPException(status_code=500, detail="Failed to get host group")


@router.post("/", response_model=HostGroupResponse)
async def create_host_group(
    group_data: HostGroupCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Create a new host group"""
    try:
        # Check if group name already exists
        existing = db.execute(
            text(
                """
            SELECT id FROM host_groups WHERE name = :name
        """
            ),
            {"name": group_data.name},
        ).fetchone()

        if existing:
            raise HTTPException(status_code=400, detail="Group name already exists")

        # Validate SCAP content if provided
        if group_data.scap_content_id:
            scap_check = db.execute(
                text(
                    """
                SELECT id, name FROM scap_content WHERE id = :content_id
            """
                ),
                {"content_id": group_data.scap_content_id},
            ).fetchone()

            if not scap_check:
                raise HTTPException(status_code=400, detail="Invalid SCAP content ID")

        # Create the group
        result = db.execute(
            text(
                """
            INSERT INTO host_groups (
                name, description, color, created_by, created_at, updated_at,
                os_family, os_version_pattern, architecture, scap_content_id,
                default_profile_id, compliance_framework, auto_scan_enabled,
                scan_schedule, validation_rules
            )
            VALUES (
                :name, :description, :color, :created_by, :created_at, :updated_at,
                :os_family, :os_version_pattern, :architecture, :scap_content_id,
                :default_profile_id, :compliance_framework, :auto_scan_enabled,
                :scan_schedule, :validation_rules
            )
            RETURNING id, name, description, color, created_by, created_at, updated_at,
                      os_family, os_version_pattern, architecture, scap_content_id,
                      default_profile_id, compliance_framework, auto_scan_enabled,
                      scan_schedule, validation_rules
        """
            ),
            {
                "name": group_data.name,
                "description": group_data.description,
                "color": group_data.color,
                "created_by": current_user["id"],
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
                "os_family": group_data.os_family,
                "os_version_pattern": group_data.os_version_pattern,
                "architecture": group_data.architecture,
                "scap_content_id": group_data.scap_content_id,
                "default_profile_id": group_data.default_profile_id,
                "compliance_framework": group_data.compliance_framework,
                "auto_scan_enabled": group_data.auto_scan_enabled or False,
                "scan_schedule": group_data.scan_schedule,
                "validation_rules": (json.dumps(group_data.validation_rules) if group_data.validation_rules else None),
            },
        )

        group = result.fetchone()
        db.commit()

        return {
            "id": group.id,
            "name": group.name,
            "description": group.description,
            "color": group.color,
            "host_count": 0,
            "created_by": group.created_by,
            "created_at": group.created_at,
            "updated_at": group.updated_at,
            "os_family": group.os_family,
            "os_version_pattern": group.os_version_pattern,
            "architecture": group.architecture,
            "scap_content_id": group.scap_content_id,
            "default_profile_id": group.default_profile_id,
            "compliance_framework": group.compliance_framework,
            "auto_scan_enabled": (group.auto_scan_enabled if group.auto_scan_enabled is not None else False),
            "scan_schedule": group.scan_schedule,
            "validation_rules": (json.loads(group.validation_rules) if group.validation_rules else None),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating host group: {e}")
        raise HTTPException(status_code=500, detail="Failed to create host group")


@router.put("/{group_id}", response_model=HostGroupResponse)
async def update_host_group(
    group_id: int,
    group_data: HostGroupUpdate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Update a host group"""
    try:
        # Check if group exists
        existing = db.execute(
            text(
                """
            SELECT id FROM host_groups WHERE id = :group_id
        """
            ),
            {"group_id": group_id},
        ).fetchone()

        if not existing:
            raise HTTPException(status_code=404, detail="Group not found")

        # Check if new name conflicts (if name is being updated)
        if group_data.name:
            name_conflict = db.execute(
                text(
                    """
                SELECT id FROM host_groups WHERE name = :name AND id != :group_id
            """
                ),
                {"name": group_data.name, "group_id": group_id},
            ).fetchone()

            if name_conflict:
                raise HTTPException(status_code=400, detail="Group name already exists")

        # Validate SCAP content if provided
        if group_data.scap_content_id is not None:
            scap_check = db.execute(
                text(
                    """
                SELECT id FROM scap_content WHERE id = :content_id
            """
                ),
                {"content_id": group_data.scap_content_id},
            ).fetchone()

            if not scap_check:
                raise HTTPException(status_code=400, detail="Invalid SCAP content ID")

        # Build update query dynamically
        update_fields = []
        update_params = {"group_id": group_id, "updated_at": datetime.utcnow()}

        if group_data.name is not None:
            update_fields.append("name = :name")
            update_params["name"] = group_data.name

        if group_data.description is not None:
            update_fields.append("description = :description")
            update_params["description"] = group_data.description

        if group_data.color is not None:
            update_fields.append("color = :color")
            update_params["color"] = group_data.color

        if group_data.os_family is not None:
            update_fields.append("os_family = :os_family")
            update_params["os_family"] = group_data.os_family

        if group_data.os_version_pattern is not None:
            update_fields.append("os_version_pattern = :os_version_pattern")
            update_params["os_version_pattern"] = group_data.os_version_pattern

        if group_data.architecture is not None:
            update_fields.append("architecture = :architecture")
            update_params["architecture"] = group_data.architecture

        if group_data.scap_content_id is not None:
            update_fields.append("scap_content_id = :scap_content_id")
            update_params["scap_content_id"] = group_data.scap_content_id

        if group_data.default_profile_id is not None:
            update_fields.append("default_profile_id = :default_profile_id")
            update_params["default_profile_id"] = group_data.default_profile_id

        if group_data.compliance_framework is not None:
            update_fields.append("compliance_framework = :compliance_framework")
            update_params["compliance_framework"] = group_data.compliance_framework

        if group_data.auto_scan_enabled is not None:
            update_fields.append("auto_scan_enabled = :auto_scan_enabled")
            update_params["auto_scan_enabled"] = group_data.auto_scan_enabled

        if group_data.scan_schedule is not None:
            update_fields.append("scan_schedule = :scan_schedule")
            update_params["scan_schedule"] = group_data.scan_schedule

        if group_data.validation_rules is not None:
            update_fields.append("validation_rules = :validation_rules")
            update_params["validation_rules"] = (
                json.dumps(group_data.validation_rules) if group_data.validation_rules else None
            )

        update_fields.append("updated_at = :updated_at")

        if not update_fields:
            raise HTTPException(status_code=400, detail="No fields to update")

        # Update the group
        result = db.execute(
            text(
                f"""
            UPDATE host_groups SET {', '.join(update_fields)}
            WHERE id = :group_id
            RETURNING id, name, description, color, created_by, created_at, updated_at,
                      os_family, os_version_pattern, architecture, scap_content_id,
                      default_profile_id, compliance_framework, auto_scan_enabled,
                      scan_schedule, validation_rules
        """
            ),
            update_params,
        )

        group = result.fetchone()
        db.commit()

        # Get host count and SCAP content name
        count_result = db.execute(
            text(
                """
            SELECT COUNT(*) as host_count FROM host_group_memberships WHERE group_id = :group_id
        """
            ),
            {"group_id": group_id},
        )
        host_count = count_result.fetchone().host_count

        # Get SCAP content name if applicable
        scap_content_name = None
        if group.scap_content_id:
            scap_result = db.execute(
                text(
                    """
                SELECT name FROM scap_content WHERE id = :content_id
            """
                ),
                {"content_id": group.scap_content_id},
            )
            scap_row = scap_result.fetchone()
            if scap_row:
                scap_content_name = scap_row.name

        return {
            "id": group.id,
            "name": group.name,
            "description": group.description,
            "color": group.color,
            "host_count": host_count,
            "created_by": group.created_by,
            "created_at": group.created_at,
            "updated_at": group.updated_at,
            "os_family": group.os_family,
            "os_version_pattern": group.os_version_pattern,
            "architecture": group.architecture,
            "scap_content_id": group.scap_content_id,
            "default_profile_id": group.default_profile_id,
            "compliance_framework": group.compliance_framework,
            "auto_scan_enabled": (group.auto_scan_enabled if group.auto_scan_enabled is not None else False),
            "scan_schedule": group.scan_schedule,
            "validation_rules": (json.loads(group.validation_rules) if group.validation_rules else None),
            "scap_content_name": scap_content_name,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating host group: {e}")
        raise HTTPException(status_code=500, detail="Failed to update host group")


@router.delete("/{group_id}")
async def delete_host_group(
    group_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Delete a host group"""
    try:
        # Check if group exists
        existing = db.execute(
            text(
                """
            SELECT id FROM host_groups WHERE id = :group_id
        """
            ),
            {"group_id": group_id},
        ).fetchone()

        if not existing:
            raise HTTPException(status_code=404, detail="Group not found")

        # Remove all host assignments first
        db.execute(
            text(
                """
            DELETE FROM host_group_memberships WHERE group_id = :group_id
        """
            ),
            {"group_id": group_id},
        )

        # Delete the group
        db.execute(
            text(
                """
            DELETE FROM host_groups WHERE id = :group_id
        """
            ),
            {"group_id": group_id},
        )

        db.commit()

        return {"message": "Host group deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting host group: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete host group")


@router.post("/{group_id}/hosts")
async def assign_hosts_to_group(
    group_id: int,
    request: AssignHostsRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Assign hosts to a group"""
    try:
        # Check if group exists
        existing = db.execute(
            text(
                """
            SELECT id FROM host_groups WHERE id = :group_id
        """
            ),
            {"group_id": group_id},
        ).fetchone()

        if not existing:
            raise HTTPException(status_code=404, detail="Group not found")

        # Remove hosts from any existing groups first (each host can only be in one group)
        if request.host_ids:
            placeholders = ",".join([f"'{host_id}'" for host_id in request.host_ids])
            db.execute(
                text(
                    f"""
                DELETE FROM host_group_memberships WHERE host_id IN ({placeholders})
            """
                )
            )

        # Add hosts to the new group
        for host_id in request.host_ids:
            db.execute(
                text(
                    """
                INSERT INTO host_group_memberships (host_id, group_id, assigned_by, assigned_at)
                VALUES (:host_id, :group_id, :assigned_by, :assigned_at)
            """
                ),
                {
                    "host_id": host_id,
                    "group_id": group_id,
                    "assigned_by": current_user["id"],
                    "assigned_at": datetime.utcnow(),
                },
            )

        db.commit()

        return {"message": f"Successfully assigned {len(request.host_ids)} hosts to group"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error assigning hosts to group: {e}")
        raise HTTPException(status_code=500, detail="Failed to assign hosts to group")


@router.delete("/{group_id}/hosts/{host_id}")
async def remove_host_from_group(
    group_id: int,
    host_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Remove a host from a group"""
    try:
        # Remove the host from the group
        result = db.execute(
            text(
                """
            DELETE FROM host_group_memberships
            WHERE group_id = :group_id AND host_id = :host_id
        """
            ),
            {"group_id": group_id, "host_id": host_id},
        )

        db.commit()

        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Host not found in group")

        return {"message": "Host removed from group successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing host from group: {e}")
        raise HTTPException(status_code=500, detail="Failed to remove host from group")


# Smart validation endpoints


@router.post("/{group_id}/validate-hosts", response_model=CompatibilityValidationResponse)
async def validate_host_compatibility(
    group_id: int,
    request: ValidateHostsRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Validate host compatibility with a group

    Checks OS family, version, architecture, and SCAP content compatibility
    Returns detailed validation results including suggestions for incompatible hosts
    """
    try:
        validation_service = GroupValidationService(db)
        results = validation_service.validate_host_group_compatibility(
            host_ids=request.host_ids,
            group_id=group_id,
            user_role=current_user.get("role"),
        )

        return results

    except ValidationError as e:
        raise HTTPException(status_code=e.status_code or 400, detail=e.message)
    except Exception as e:
        logger.error(f"Error validating host compatibility: {e}")
        raise HTTPException(status_code=500, detail="Failed to validate host compatibility")


@router.post("/smart-create")
async def create_smart_group(
    request: SmartGroupCreateRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Create a smart group based on host characteristics

    Analyzes selected hosts and automatically configures group settings
    including OS requirements, SCAP content, and validation rules
    """
    try:
        validation_service = GroupValidationService(db)

        # Analyze hosts to determine group characteristics
        analysis = validation_service.create_smart_group_from_hosts(
            host_ids=request.host_ids,
            group_name=request.group_name,
            description=request.description,
            created_by=current_user["id"],
        )

        # If auto_configure is enabled and hosts are homogeneous, create the group
        if request.auto_configure and "recommendations" in analysis:
            recommendations = analysis["recommendations"]

            # Create the group with recommended settings
            group_data = HostGroupCreate(
                name=request.group_name,
                description=request.description or f"Smart group for {recommendations.get('os_family', 'mixed')} hosts",
                os_family=recommendations.get("os_family"),
                os_version_pattern=recommendations.get("os_version_pattern"),
                scap_content_id=(
                    recommendations.get("scap_content", {}).get("id") if "scap_content" in recommendations else None
                ),
                compliance_framework=(
                    recommendations.get("scap_content", {}).get("compliance_framework")
                    if "scap_content" in recommendations
                    else None
                ),
            )

            # Create the group using the existing endpoint logic
            group_response = await create_host_group(group_data, db, current_user)

            # Assign the hosts to the group
            assign_request = AssignHostsRequest(
                host_ids=request.host_ids,
                validate_compatibility=False,  # Already validated
                force_assignment=True,
            )

            await assign_hosts_to_group(group_response["id"], assign_request, db, current_user)

            return {
                "group": group_response,
                "analysis": analysis,
                "hosts_assigned": len(request.host_ids),
            }

        # Return analysis results without creating the group
        return {
            "analysis": analysis,
            "message": "Group analysis complete. Review recommendations before creating the group.",
        }

    except Exception as e:
        logger.error(f"Error creating smart group: {e}")
        raise HTTPException(status_code=500, detail="Failed to create smart group")


@router.get("/{group_id}/compatibility-report")
async def get_group_compatibility_report(
    group_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Get a comprehensive compatibility report for a group

    Shows all hosts in the group with their compatibility status,
    issues, and recommendations for improving group coherence
    """
    try:
        validation_service = GroupValidationService(db)
        report = validation_service.get_group_compatibility_report(group_id)

        return report

    except ValidationError as e:
        raise HTTPException(status_code=e.status_code or 404, detail=e.message)
    except Exception as e:
        logger.error(f"Error generating compatibility report: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate compatibility report")


@router.post("/{group_id}/hosts/validate")
async def validate_and_assign_hosts(
    group_id: int,
    request: AssignHostsRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Validate and assign hosts to a group with smart validation

    If validate_compatibility is True (default), checks compatibility before assignment
    If force_assignment is True, assigns compatible hosts and rejects incompatible ones
    """
    try:
        if request.validate_compatibility:
            # Validate compatibility first
            validation_service = GroupValidationService(db)
            validation_results = validation_service.validate_host_group_compatibility(
                host_ids=request.host_ids,
                group_id=group_id,
                user_role=current_user.get("role"),
            )

            # Check if there are incompatible hosts
            if validation_results["incompatible"] and not request.force_assignment:
                # Return validation results without assigning
                return {
                    "status": "validation_failed",
                    "message": f"{len(validation_results['incompatible'])} hosts are incompatible",
                    "validation_results": validation_results,
                }

            # If force_assignment is True, only assign compatible hosts
            hosts_to_assign = (
                [h["id"] for h in validation_results["compatible"]] if request.force_assignment else request.host_ids
            )
        else:
            hosts_to_assign = request.host_ids

        # Check if group exists
        existing = db.execute(
            text(
                """
            SELECT id FROM host_groups WHERE id = :group_id
        """
            ),
            {"group_id": group_id},
        ).fetchone()

        if not existing:
            raise HTTPException(status_code=404, detail="Group not found")

        # Remove hosts from any existing groups first
        if hosts_to_assign:
            placeholders = ",".join([f"'{host_id}'" for host_id in hosts_to_assign])
            db.execute(
                text(
                    f"""
                DELETE FROM host_group_memberships WHERE host_id IN ({placeholders})
            """
                )
            )

        # Add hosts to the new group
        assigned_count = 0
        for host_id in hosts_to_assign:
            db.execute(
                text(
                    """
                INSERT INTO host_group_memberships (host_id, group_id, assigned_by, assigned_at)
                VALUES (:host_id, :group_id, :assigned_by, :assigned_at)
            """
                ),
                {
                    "host_id": host_id,
                    "group_id": group_id,
                    "assigned_by": current_user["id"],
                    "assigned_at": datetime.utcnow(),
                },
            )
            assigned_count += 1

        db.commit()

        response = {
            "status": "success",
            "message": f"Successfully assigned {assigned_count} hosts to group",
            "assigned_count": assigned_count,
            "total_requested": len(request.host_ids),
        }

        if request.validate_compatibility and validation_results.get("incompatible"):
            response["incompatible_hosts"] = validation_results["incompatible"]
            response["suggestions"] = validation_results.get("suggestions", {})

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error validating and assigning hosts: {e}")
        raise HTTPException(status_code=500, detail="Failed to validate and assign hosts")
