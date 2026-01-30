"""
Host Groups CRUD Router

Handles create, read, update, delete operations for host groups.
Also includes host membership management and smart validation endpoints.

Endpoint Summary:
    GET    /                           - List all host groups
    GET    /{group_id}                 - Get specific host group
    POST   /                           - Create new host group
    PUT    /{group_id}                 - Update host group
    DELETE /{group_id}                 - Delete host group
    POST   /{group_id}/hosts           - Assign hosts to group
    DELETE /{group_id}/hosts/{host_id} - Remove host from group
    POST   /{group_id}/validate-hosts  - Validate host compatibility
    POST   /smart-create               - Create smart group from analysis
    GET    /{group_id}/compatibility-report - Get compatibility report
    POST   /{group_id}/hosts/validate  - Validate and assign hosts

Security:
    - All endpoints require authentication via get_current_user
    - SQL injection prevented via parameterized queries
    - Input validation via Pydantic models
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.services.validation import GroupValidationService, ValidationError

from .models import (
    AssignHostsRequest,
    CompatibilityValidationResponse,
    HostGroupCreate,
    HostGroupResponse,
    HostGroupUpdate,
    SmartGroupCreateRequest,
    ValidateHostsRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# =============================================================================
# HOST GROUP CRUD OPERATIONS
# =============================================================================


@router.get("/", response_model=List[HostGroupResponse])
async def list_host_groups(
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """
    List all host groups with host counts.

    Retrieves all host groups from the database with aggregated host counts
    from the host_group_memberships table.

    Args:
        db: Database session dependency.
        current_user: Authenticated user dictionary.

    Returns:
        List of host group dictionaries with host counts.

    Raises:
        HTTPException: 500 if database query fails.
    """
    try:
        result = db.execute(
            text(
                """
            SELECT
                hg.id, hg.name, hg.description, hg.color, hg.created_by, hg.created_at, hg.updated_at,
                hg.os_family, hg.os_version_pattern, hg.architecture,
                hg.default_profile_id, hg.compliance_framework, hg.auto_scan_enabled,
                hg.scan_schedule, hg.validation_rules,
                COALESCE(COUNT(hgm.host_id), 0) as host_count
            FROM host_groups hg
            LEFT JOIN host_group_memberships hgm ON hg.id = hgm.group_id
            GROUP BY hg.id, hg.name, hg.description, hg.color, hg.created_by, hg.created_at,
                     hg.updated_at, hg.os_family, hg.os_version_pattern, hg.architecture,
                     hg.default_profile_id, hg.compliance_framework,
                     hg.auto_scan_enabled, hg.scan_schedule, hg.validation_rules
            ORDER BY hg.name
        """
            )
        )

        groups = []
        for row in result:
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
                "default_profile_id": row.default_profile_id,
                "compliance_framework": row.compliance_framework,
                "auto_scan_enabled": (row.auto_scan_enabled if row.auto_scan_enabled is not None else False),
                "scan_schedule": row.scan_schedule,
                "validation_rules": (json.loads(row.validation_rules) if row.validation_rules else None),
            }
            groups.append(group_data)

        return groups

    except Exception as e:
        logger.error(f"Error listing host groups: {e}")
        raise HTTPException(status_code=500, detail="Failed to list host groups")


@router.get("/{group_id}", response_model=HostGroupResponse)
async def get_host_group(
    group_id: int,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get a specific host group by ID.

    Args:
        group_id: The ID of the host group to retrieve.
        db: Database session dependency.
        current_user: Authenticated user dictionary.

    Returns:
        Host group dictionary with details.

    Raises:
        HTTPException: 404 if group not found, 500 if query fails.
    """
    try:
        result = db.execute(
            text(
                """
            SELECT
                hg.id, hg.name, hg.description, hg.color, hg.created_by, hg.created_at, hg.updated_at,
                hg.os_family, hg.os_version_pattern, hg.architecture,
                hg.default_profile_id, hg.compliance_framework, hg.auto_scan_enabled,
                hg.scan_schedule, hg.validation_rules,
                COALESCE(COUNT(hgm.host_id), 0) as host_count
            FROM host_groups hg
            LEFT JOIN host_group_memberships hgm ON hg.id = hgm.group_id
            WHERE hg.id = :group_id
            GROUP BY hg.id, hg.name, hg.description, hg.color, hg.created_by, hg.created_at,
                     hg.updated_at, hg.os_family, hg.os_version_pattern, hg.architecture,
                     hg.default_profile_id, hg.compliance_framework,
                     hg.auto_scan_enabled, hg.scan_schedule, hg.validation_rules
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
            "default_profile_id": row.default_profile_id,
            "compliance_framework": row.compliance_framework,
            "auto_scan_enabled": (row.auto_scan_enabled if row.auto_scan_enabled is not None else False),
            "scan_schedule": row.scan_schedule,
            "validation_rules": json.loads(row.validation_rules) if row.validation_rules else None,
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
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Create a new host group.

    Args:
        group_data: Pydantic model with group creation data.
        db: Database session dependency.
        current_user: Authenticated user dictionary.

    Returns:
        Created host group dictionary.

    Raises:
        HTTPException: 400 if name exists, 500 if creation fails.
    """
    try:
        # Check if group name already exists using parameterized query
        existing = db.execute(
            text("SELECT id FROM host_groups WHERE name = :name"),
            {"name": group_data.name},
        ).fetchone()

        if existing:
            raise HTTPException(status_code=400, detail="Group name already exists")

        # Create the group with parameterized query
        result = db.execute(
            text(
                """
            INSERT INTO host_groups (
                name, description, color, created_by, created_at, updated_at,
                os_family, os_version_pattern, architecture,
                default_profile_id, compliance_framework, auto_scan_enabled,
                scan_schedule, validation_rules
            )
            VALUES (
                :name, :description, :color, :created_by, :created_at, :updated_at,
                :os_family, :os_version_pattern, :architecture,
                :default_profile_id, :compliance_framework, :auto_scan_enabled,
                :scan_schedule, :validation_rules
            )
            RETURNING id, name, description, color, created_by, created_at, updated_at,
                      os_family, os_version_pattern, architecture,
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
                "default_profile_id": group_data.default_profile_id,
                "compliance_framework": group_data.compliance_framework,
                "auto_scan_enabled": group_data.auto_scan_enabled or False,
                "scan_schedule": group_data.scan_schedule,
                "validation_rules": (json.dumps(group_data.validation_rules) if group_data.validation_rules else None),
            },
        )

        group = result.fetchone()
        db.commit()

        if group is None:
            raise HTTPException(status_code=500, detail="Failed to create host group - no data returned")

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
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Update a host group.

    Args:
        group_id: The ID of the host group to update.
        group_data: Pydantic model with update data.
        db: Database session dependency.
        current_user: Authenticated user dictionary.

    Returns:
        Updated host group dictionary.

    Raises:
        HTTPException: 400 if name conflict, 404 if not found, 500 if update fails.
    """
    try:
        # Check if group exists
        existing = db.execute(
            text("SELECT id FROM host_groups WHERE id = :group_id"),
            {"group_id": group_id},
        ).fetchone()

        if not existing:
            raise HTTPException(status_code=404, detail="Group not found")

        # Check if new name conflicts
        if group_data.name:
            name_conflict = db.execute(
                text("SELECT id FROM host_groups WHERE name = :name AND id != :group_id"),
                {"name": group_data.name, "group_id": group_id},
            ).fetchone()

            if name_conflict:
                raise HTTPException(status_code=400, detail="Group name already exists")

        # Build update query dynamically with safe parameterization
        update_fields = []
        update_params: Dict[str, Any] = {"group_id": group_id, "updated_at": datetime.utcnow()}

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

        if len(update_fields) == 1:  # Only updated_at
            raise HTTPException(status_code=400, detail="No fields to update")

        # Execute update with parameterized query
        result = db.execute(
            text(
                f"""
            UPDATE host_groups SET {', '.join(update_fields)}
            WHERE id = :group_id
            RETURNING id, name, description, color, created_by, created_at, updated_at,
                      os_family, os_version_pattern, architecture,
                      default_profile_id, compliance_framework, auto_scan_enabled,
                      scan_schedule, validation_rules
        """
            ),
            update_params,
        )

        group = result.fetchone()
        db.commit()

        if group is None:
            raise HTTPException(status_code=500, detail="Failed to update host group - no data returned")

        # Get host count
        count_result = db.execute(
            text("SELECT COUNT(*) as host_count FROM host_group_memberships WHERE group_id = :group_id"),
            {"group_id": group_id},
        )
        count_row = count_result.fetchone()
        host_count: int = count_row.host_count if count_row else 0

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
            "default_profile_id": group.default_profile_id,
            "compliance_framework": group.compliance_framework,
            "auto_scan_enabled": (group.auto_scan_enabled if group.auto_scan_enabled is not None else False),
            "scan_schedule": group.scan_schedule,
            "validation_rules": (json.loads(group.validation_rules) if group.validation_rules else None),
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
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Delete a host group.

    Removes all host-group memberships first, then deletes the group.

    Args:
        group_id: The ID of the host group to delete.
        db: Database session dependency.
        current_user: Authenticated user dictionary.

    Returns:
        Success message dictionary.

    Raises:
        HTTPException: 404 if not found, 500 if deletion fails.
    """
    try:
        # Check if group exists
        existing = db.execute(
            text("SELECT id FROM host_groups WHERE id = :group_id"),
            {"group_id": group_id},
        ).fetchone()

        if not existing:
            raise HTTPException(status_code=404, detail="Group not found")

        # Remove all host assignments first
        db.execute(
            text("DELETE FROM host_group_memberships WHERE group_id = :group_id"),
            {"group_id": group_id},
        )

        # Delete the group
        db.execute(
            text("DELETE FROM host_groups WHERE id = :group_id"),
            {"group_id": group_id},
        )

        db.commit()

        return {"message": "Host group deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting host group: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete host group")


# =============================================================================
# HOST MEMBERSHIP OPERATIONS
# =============================================================================


@router.post("/{group_id}/hosts")
async def assign_hosts_to_group(
    group_id: int,
    request: AssignHostsRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Assign hosts to a group.

    Removes hosts from any existing groups first since each host can only be in one group.

    Args:
        group_id: The ID of the target host group.
        request: Request with list of host IDs to assign.
        db: Database session dependency.
        current_user: Authenticated user dictionary.

    Returns:
        Success message dictionary.

    Raises:
        HTTPException: 404 if group not found, 500 if assignment fails.
    """
    try:
        # Check if group exists
        existing = db.execute(
            text("SELECT id FROM host_groups WHERE id = :group_id"),
            {"group_id": group_id},
        ).fetchone()

        if not existing:
            raise HTTPException(status_code=404, detail="Group not found")

        # Remove hosts from any existing groups first (each host can only be in one group)
        # Using parameterized query with array
        if request.host_ids:
            for host_id in request.host_ids:
                db.execute(
                    text("DELETE FROM host_group_memberships WHERE host_id = :host_id"),
                    {"host_id": host_id},
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
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Remove a host from a group.

    Args:
        group_id: The ID of the host group.
        host_id: The ID of the host to remove.
        db: Database session dependency.
        current_user: Authenticated user dictionary.

    Returns:
        Success message dictionary.

    Raises:
        HTTPException: 404 if host not in group, 500 if removal fails.
    """
    try:
        # Remove the host from the group
        result = db.execute(
            text("DELETE FROM host_group_memberships WHERE group_id = :group_id AND host_id = :host_id"),
            {"group_id": group_id, "host_id": host_id},
        )

        db.commit()

        # CursorResult has rowcount attribute
        rowcount = getattr(result, "rowcount", 0)
        if rowcount == 0:
            raise HTTPException(status_code=404, detail="Host not found in group")

        return {"message": "Host removed from group successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing host from group: {e}")
        raise HTTPException(status_code=500, detail="Failed to remove host from group")


# =============================================================================
# SMART VALIDATION ENDPOINTS
# =============================================================================


@router.post("/{group_id}/validate-hosts", response_model=CompatibilityValidationResponse)
async def validate_host_compatibility(
    group_id: int,
    request: ValidateHostsRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Validate host compatibility with a group.

    Checks OS family, version, architecture, and SCAP content compatibility.
    Returns detailed validation results including suggestions for incompatible hosts.

    Args:
        group_id: The ID of the host group to validate against.
        request: Request with list of host IDs to validate.
        db: Database session dependency.
        current_user: Authenticated user dictionary.

    Returns:
        Compatibility validation response with compatible/incompatible hosts.

    Raises:
        HTTPException: 400 if validation fails, 500 if unexpected error.
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
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error validating host compatibility: {e}")
        raise HTTPException(status_code=500, detail="Failed to validate host compatibility")


@router.post("/smart-create")
async def create_smart_group(
    request: SmartGroupCreateRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Create a smart group based on host characteristics.

    Analyzes selected hosts and automatically configures group settings
    including OS requirements and validation rules.

    Args:
        request: SmartGroupCreateRequest with host IDs and group configuration.
        db: Database session dependency.
        current_user: Authenticated user dictionary.

    Returns:
        Dictionary with created group and/or analysis results.

    Raises:
        HTTPException: 500 if smart group creation fails.
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
                compliance_framework=recommendations.get("compliance_framework"),
            )

            # Create the group using the existing endpoint logic
            group_response = await create_host_group(group_data, db, current_user)

            # Assign the hosts to the group
            assign_request = AssignHostsRequest(
                host_ids=request.host_ids,
                validate_compatibility=False,
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
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get a comprehensive compatibility report for a group.

    Shows all hosts in the group with their compatibility status,
    issues, and recommendations for improving group coherence.

    Args:
        group_id: The ID of the host group to report on.
        db: Database session dependency.
        current_user: Authenticated user dictionary.

    Returns:
        Compatibility report dictionary.

    Raises:
        HTTPException: 404 if group not found, 500 if report generation fails.
    """
    try:
        validation_service = GroupValidationService(db)
        report = validation_service.get_group_compatibility_report(group_id)

        return report

    except ValidationError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error generating compatibility report: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate compatibility report")


@router.post("/{group_id}/hosts/validate")
async def validate_and_assign_hosts(
    group_id: int,
    request: AssignHostsRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Validate and assign hosts to a group with smart validation.

    If validate_compatibility is True (default), checks compatibility before assignment.
    If force_assignment is True, assigns compatible hosts and rejects incompatible ones.

    Args:
        group_id: The ID of the target host group.
        request: AssignHostsRequest with host IDs and validation options.
        db: Database session dependency.
        current_user: Authenticated user dictionary.

    Returns:
        Assignment result dictionary with status and counts.

    Raises:
        HTTPException: 404 if group not found, 500 if assignment fails.
    """
    try:
        validation_results = None

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
            text("SELECT id FROM host_groups WHERE id = :group_id"),
            {"group_id": group_id},
        ).fetchone()

        if not existing:
            raise HTTPException(status_code=404, detail="Group not found")

        # Remove hosts from any existing groups first
        for host_id in hosts_to_assign:
            db.execute(
                text("DELETE FROM host_group_memberships WHERE host_id = :host_id"),
                {"host_id": host_id},
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

        response: Dict[str, Any] = {
            "status": "success",
            "message": f"Successfully assigned {assigned_count} hosts to group",
            "assigned_count": assigned_count,
            "total_requested": len(request.host_ids),
        }

        if validation_results and validation_results.get("incompatible"):
            response["incompatible_hosts"] = validation_results["incompatible"]
            response["suggestions"] = validation_results.get("suggestions", {})

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error validating and assigning hosts: {e}")
        raise HTTPException(status_code=500, detail="Failed to validate and assign hosts")
