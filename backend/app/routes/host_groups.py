"""
Host Groups API Routes
Handles host group creation, management, and host assignment
"""
import logging
from typing import List, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import text
from pydantic import BaseModel

from ..database import get_db
from ..auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/host-groups", tags=["Host Groups"])


class HostGroupCreate(BaseModel):
    name: str
    description: Optional[str] = None
    color: Optional[str] = None


class HostGroupUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    color: Optional[str] = None


class HostGroupResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    color: Optional[str]
    host_count: int
    created_by: int
    created_at: datetime
    updated_at: datetime


class AssignHostsRequest(BaseModel):
    host_ids: List[str]


@router.get("/", response_model=List[HostGroupResponse])
async def list_host_groups(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """List all host groups with host counts"""
    try:
        result = db.execute(text("""
            SELECT 
                hg.id, hg.name, hg.description, hg.color, hg.created_by, hg.created_at, hg.updated_at,
                COALESCE(COUNT(hgm.host_id), 0) as host_count
            FROM host_groups hg
            LEFT JOIN host_group_memberships hgm ON hg.id = hgm.group_id
            GROUP BY hg.id, hg.name, hg.description, hg.color, hg.created_by, hg.created_at, hg.updated_at
            ORDER BY hg.name
        """))
        
        groups = []
        for row in result:
            groups.append({
                "id": row.id,
                "name": row.name,
                "description": row.description,
                "color": row.color,
                "host_count": row.host_count,
                "created_by": row.created_by,
                "created_at": row.created_at,
                "updated_at": row.updated_at
            })
        
        return groups
        
    except Exception as e:
        logger.error(f"Error listing host groups: {e}")
        raise HTTPException(status_code=500, detail="Failed to list host groups")


@router.post("/", response_model=HostGroupResponse)
async def create_host_group(
    group_data: HostGroupCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Create a new host group"""
    try:
        # Check if group name already exists
        existing = db.execute(text("""
            SELECT id FROM host_groups WHERE name = :name
        """), {"name": group_data.name}).fetchone()
        
        if existing:
            raise HTTPException(status_code=400, detail="Group name already exists")
        
        # Create the group
        result = db.execute(text("""
            INSERT INTO host_groups (name, description, color, created_by, created_at, updated_at)
            VALUES (:name, :description, :color, :created_by, :created_at, :updated_at)
            RETURNING id, name, description, color, created_by, created_at, updated_at
        """), {
            "name": group_data.name,
            "description": group_data.description,
            "color": group_data.color,
            "created_by": current_user["id"],
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        })
        
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
            "updated_at": group.updated_at
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
    current_user: dict = Depends(get_current_user)
):
    """Update a host group"""
    try:
        # Check if group exists
        existing = db.execute(text("""
            SELECT id FROM host_groups WHERE id = :group_id
        """), {"group_id": group_id}).fetchone()
        
        if not existing:
            raise HTTPException(status_code=404, detail="Group not found")
        
        # Check if new name conflicts (if name is being updated)
        if group_data.name:
            name_conflict = db.execute(text("""
                SELECT id FROM host_groups WHERE name = :name AND id != :group_id
            """), {"name": group_data.name, "group_id": group_id}).fetchone()
            
            if name_conflict:
                raise HTTPException(status_code=400, detail="Group name already exists")
        
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
        
        update_fields.append("updated_at = :updated_at")
        
        if not update_fields:
            raise HTTPException(status_code=400, detail="No fields to update")
        
        # Update the group
        result = db.execute(text(f"""
            UPDATE host_groups SET {', '.join(update_fields)}
            WHERE id = :group_id
            RETURNING id, name, description, color, created_by, created_at, updated_at
        """), update_params)
        
        group = result.fetchone()
        db.commit()
        
        # Get host count
        count_result = db.execute(text("""
            SELECT COUNT(*) as host_count FROM host_group_memberships WHERE group_id = :group_id
        """), {"group_id": group_id})
        host_count = count_result.fetchone().host_count
        
        return {
            "id": group.id,
            "name": group.name,
            "description": group.description,
            "color": group.color,
            "host_count": host_count,
            "created_by": group.created_by,
            "created_at": group.created_at,
            "updated_at": group.updated_at
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
    current_user: dict = Depends(get_current_user)
):
    """Delete a host group"""
    try:
        # Check if group exists
        existing = db.execute(text("""
            SELECT id FROM host_groups WHERE id = :group_id
        """), {"group_id": group_id}).fetchone()
        
        if not existing:
            raise HTTPException(status_code=404, detail="Group not found")
        
        # Remove all host assignments first
        db.execute(text("""
            DELETE FROM host_group_memberships WHERE group_id = :group_id
        """), {"group_id": group_id})
        
        # Delete the group
        db.execute(text("""
            DELETE FROM host_groups WHERE id = :group_id
        """), {"group_id": group_id})
        
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
    current_user: dict = Depends(get_current_user)
):
    """Assign hosts to a group"""
    try:
        # Check if group exists
        existing = db.execute(text("""
            SELECT id FROM host_groups WHERE id = :group_id
        """), {"group_id": group_id}).fetchone()
        
        if not existing:
            raise HTTPException(status_code=404, detail="Group not found")
        
        # Remove hosts from any existing groups first (each host can only be in one group)
        if request.host_ids:
            placeholders = ','.join([f"'{host_id}'" for host_id in request.host_ids])
            db.execute(text(f"""
                DELETE FROM host_group_memberships WHERE host_id IN ({placeholders})
            """))
        
        # Add hosts to the new group
        for host_id in request.host_ids:
            db.execute(text("""
                INSERT INTO host_group_memberships (host_id, group_id, assigned_by, assigned_at)
                VALUES (:host_id, :group_id, :assigned_by, :assigned_at)
            """), {
                "host_id": host_id,
                "group_id": group_id,
                "assigned_by": current_user["id"],
                "assigned_at": datetime.utcnow()
            })
        
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
    current_user: dict = Depends(get_current_user)
):
    """Remove a host from a group"""
    try:
        # Remove the host from the group
        result = db.execute(text("""
            DELETE FROM host_group_memberships 
            WHERE group_id = :group_id AND host_id = :host_id
        """), {"group_id": group_id, "host_id": host_id})
        
        db.commit()
        
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Host not found in group")
        
        return {"message": "Host removed from group successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing host from group: {e}")
        raise HTTPException(status_code=500, detail="Failed to remove host from group")