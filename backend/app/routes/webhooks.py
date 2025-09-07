"""
Webhook Management API Routes
Handles webhook endpoint registration and delivery tracking for AEGIS integration
"""

import uuid
import hashlib
import hmac
import json
from typing import List, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import text
from pydantic import BaseModel, validator

from ..database import get_db
from ..auth import get_current_user
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])


class WebhookEndpointCreate(BaseModel):
    name: str
    url: str
    event_types: List[str]
    secret: str

    @validator("event_types")
    def validate_event_types(cls, v):
        valid_events = [
            "scan.completed",
            "scan.failed",
            "remediation.completed",
            "remediation.failed",
        ]
        for event in v:
            if event not in valid_events:
                raise ValueError(f"Invalid event type: {event}. Must be one of: {valid_events}")
        return v

    @validator("url")
    def validate_url(cls, v):
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


class WebhookEndpointUpdate(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    event_types: Optional[List[str]] = None
    secret: Optional[str] = None
    is_active: Optional[bool] = None

    @validator("event_types")
    def validate_event_types(cls, v):
        if v is None:
            return v
        valid_events = [
            "scan.completed",
            "scan.failed",
            "remediation.completed",
            "remediation.failed",
        ]
        for event in v:
            if event not in valid_events:
                raise ValueError(f"Invalid event type: {event}. Must be one of: {valid_events}")
        return v

    @validator("url")
    def validate_url(cls, v):
        if v and not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


@router.get("/")
async def list_webhook_endpoints(
    is_active: Optional[bool] = None,
    event_type: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """List webhook endpoints with optional filtering"""
    try:
        # Build query conditions
        where_conditions = []
        params = {"limit": limit, "offset": offset}

        if is_active is not None:
            where_conditions.append("is_active = :is_active")
            params["is_active"] = is_active

        if event_type:
            # Use JSON contains operator for PostgreSQL
            where_conditions.append("event_types::jsonb ? :event_type")
            params["event_type"] = event_type

        where_clause = "WHERE " + " AND ".join(where_conditions) if where_conditions else ""

        query = f"""
            SELECT id, name, url, event_types, is_active, created_by, created_at, updated_at
            FROM webhook_endpoints
            {where_clause}
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset
        """

        result = db.execute(text(query), params)

        webhooks = []
        for row in result:
            webhook_data = {
                "id": str(row.id),
                "name": row.name,
                "url": row.url,
                "event_types": (
                    json.loads(row.event_types)
                    if isinstance(row.event_types, str)
                    else row.event_types
                ),
                "is_active": row.is_active,
                "created_by": row.created_by,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "updated_at": row.updated_at.isoformat() if row.updated_at else None,
            }
            webhooks.append(webhook_data)

        # Get total count
        count_query = f"""
            SELECT COUNT(*) as total
            FROM webhook_endpoints
            {where_clause}
        """
        total_result = db.execute(text(count_query), params).fetchone()

        return {"webhooks": webhooks, "total": total_result.total, "limit": limit, "offset": offset}

    except Exception as e:
        logger.error(f"Error listing webhook endpoints: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve webhook endpoints")


@router.post("/")
async def create_webhook_endpoint(
    webhook_request: WebhookEndpointCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Create a new webhook endpoint"""
    try:
        # Hash the secret for secure storage
        secret_hash = hashlib.sha256(webhook_request.secret.encode()).hexdigest()

        # Create webhook endpoint record
        result = db.execute(
            text(
                """
            INSERT INTO webhook_endpoints 
            (id, name, url, event_types, secret_hash, is_active, created_by, created_at, updated_at)
            VALUES (:id, :name, :url, :event_types, :secret_hash, :is_active, :created_by, :created_at, :updated_at)
            RETURNING id
        """
            ),
            {
                "id": str(uuid.uuid4()),
                "name": webhook_request.name,
                "url": webhook_request.url,
                "event_types": json.dumps(webhook_request.event_types),
                "secret_hash": secret_hash,
                "is_active": True,
                "created_by": current_user["id"],
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
            },
        )

        webhook_id = result.fetchone().id
        db.commit()

        logger.info(f"Webhook endpoint created: {webhook_id}")

        return {
            "id": webhook_id,
            "name": webhook_request.name,
            "url": webhook_request.url,
            "event_types": webhook_request.event_types,
            "is_active": True,
            "message": "Webhook endpoint created successfully",
        }

    except Exception as e:
        logger.error(f"Error creating webhook endpoint: {e}")
        raise HTTPException(status_code=500, detail="Failed to create webhook endpoint")


@router.get("/{webhook_id}")
async def get_webhook_endpoint(
    webhook_id: str, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)
):
    """Get webhook endpoint details"""
    try:
        result = db.execute(
            text(
                """
            SELECT id, name, url, event_types, is_active, created_by, created_at, updated_at
            FROM webhook_endpoints WHERE id = :id
        """
            ),
            {"id": webhook_id},
        ).fetchone()

        if not result:
            raise HTTPException(status_code=404, detail="Webhook endpoint not found")

        return {
            "id": str(result.id),
            "name": result.name,
            "url": result.url,
            "event_types": (
                json.loads(result.event_types)
                if isinstance(result.event_types, str)
                else result.event_types
            ),
            "is_active": result.is_active,
            "created_by": result.created_by,
            "created_at": result.created_at.isoformat() if result.created_at else None,
            "updated_at": result.updated_at.isoformat() if result.updated_at else None,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting webhook endpoint: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve webhook endpoint")


@router.put("/{webhook_id}")
async def update_webhook_endpoint(
    webhook_id: str,
    webhook_update: WebhookEndpointUpdate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Update webhook endpoint"""
    try:
        # Check if webhook exists
        existing = db.execute(
            text(
                """
            SELECT id FROM webhook_endpoints WHERE id = :id
        """
            ),
            {"id": webhook_id},
        ).fetchone()

        if not existing:
            raise HTTPException(status_code=404, detail="Webhook endpoint not found")

        # Build update query with secure column mapping
        updates = []
        params = {"id": webhook_id, "updated_at": datetime.utcnow()}

        # Security Fix: Use explicit column mapping instead of f-string concatenation
        allowed_updates = {
            "name": "name = :name",
            "url": "url = :url",
            "event_types": "event_types = :event_types",
            "is_active": "is_active = :is_active",
            "secret": "secret_hash = :secret_hash",
            "updated_at": "updated_at = :updated_at",
        }

        if webhook_update.name is not None:
            updates.append(allowed_updates["name"])
            params["name"] = webhook_update.name

        if webhook_update.url is not None:
            updates.append(allowed_updates["url"])
            params["url"] = webhook_update.url

        if webhook_update.event_types is not None:
            updates.append(allowed_updates["event_types"])
            params["event_types"] = json.dumps(webhook_update.event_types)

        if webhook_update.is_active is not None:
            updates.append(allowed_updates["is_active"])
            params["is_active"] = webhook_update.is_active

        if webhook_update.secret is not None:
            updates.append(allowed_updates["secret"])
            params["secret_hash"] = hashlib.sha256(webhook_update.secret.encode()).hexdigest()

        updates.append(allowed_updates["updated_at"])

        if updates:
            # Security Fix: Use safe string concatenation instead of f-string
            query = "UPDATE webhook_endpoints SET " + ", ".join(updates) + " WHERE id = :id"
            db.execute(text(query), params)
            db.commit()

        return {"message": "Webhook endpoint updated successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating webhook endpoint: {e}")
        raise HTTPException(status_code=500, detail="Failed to update webhook endpoint")


@router.delete("/{webhook_id}")
async def delete_webhook_endpoint(
    webhook_id: str, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)
):
    """Delete webhook endpoint and its delivery history"""
    try:
        # Check if webhook exists
        result = db.execute(
            text(
                """
            SELECT id FROM webhook_endpoints WHERE id = :id
        """
            ),
            {"id": webhook_id},
        ).fetchone()

        if not result:
            raise HTTPException(status_code=404, detail="Webhook endpoint not found")

        # Delete webhook deliveries first (foreign key constraint)
        db.execute(
            text(
                """
            DELETE FROM webhook_deliveries WHERE webhook_id = :webhook_id
        """
            ),
            {"webhook_id": webhook_id},
        )

        # Delete webhook endpoint
        db.execute(
            text(
                """
            DELETE FROM webhook_endpoints WHERE id = :id
        """
            ),
            {"id": webhook_id},
        )

        db.commit()

        logger.info(f"Webhook endpoint deleted: {webhook_id}")
        return {"message": "Webhook endpoint deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting webhook endpoint: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete webhook endpoint")


@router.get("/{webhook_id}/deliveries")
async def get_webhook_deliveries(
    webhook_id: str,
    delivery_status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get webhook delivery history"""
    try:
        # Verify webhook exists
        webhook_result = db.execute(
            text(
                """
            SELECT id FROM webhook_endpoints WHERE id = :id
        """
            ),
            {"id": webhook_id},
        ).fetchone()

        if not webhook_result:
            raise HTTPException(status_code=404, detail="Webhook endpoint not found")

        # Build query conditions
        where_conditions = ["webhook_id = :webhook_id"]
        params = {"webhook_id": webhook_id, "limit": limit, "offset": offset}

        if delivery_status:
            where_conditions.append("delivery_status = :delivery_status")
            params["delivery_status"] = delivery_status

        where_clause = "WHERE " + " AND ".join(where_conditions)

        query = f"""
            SELECT id, event_type, event_data, delivery_status, http_status_code, 
                   response_body, error_message, created_at, delivered_at
            FROM webhook_deliveries
            {where_clause}
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset
        """

        result = db.execute(text(query), params)

        deliveries = []
        for row in result:
            delivery_data = {
                "id": str(row.id),
                "event_type": row.event_type,
                "event_data": (
                    json.loads(row.event_data)
                    if isinstance(row.event_data, str)
                    else row.event_data
                ),
                "delivery_status": row.delivery_status,
                "http_status_code": row.http_status_code,
                "response_body": row.response_body,
                "error_message": row.error_message,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "delivered_at": row.delivered_at.isoformat() if row.delivered_at else None,
            }
            deliveries.append(delivery_data)

        # Get total count
        count_query = f"""
            SELECT COUNT(*) as total
            FROM webhook_deliveries
            {where_clause}
        """
        total_result = db.execute(text(count_query), params).fetchone()

        return {
            "deliveries": deliveries,
            "total": total_result.total,
            "limit": limit,
            "offset": offset,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting webhook deliveries: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve webhook deliveries")


@router.post("/{webhook_id}/test")
async def test_webhook_endpoint(
    webhook_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Send a test webhook to verify connectivity"""
    try:
        # Get webhook details
        webhook_result = db.execute(
            text(
                """
            SELECT id, name, url, secret_hash FROM webhook_endpoints 
            WHERE id = :id AND is_active = true
        """
            ),
            {"id": webhook_id},
        ).fetchone()

        if not webhook_result:
            raise HTTPException(status_code=404, detail="Webhook endpoint not found or inactive")

        # Create test event data
        test_event = {
            "event_type": "test.webhook",
            "timestamp": datetime.utcnow().isoformat(),
            "webhook_id": webhook_id,
            "test_data": {
                "message": "This is a test webhook delivery",
                "triggered_by": current_user.get("username", "system"),
            },
        }

        # Queue webhook delivery as background task
        from ..tasks.webhook_tasks import deliver_webhook  # Import here to avoid circular imports

        background_tasks.add_task(
            deliver_webhook, webhook_result.url, webhook_result.secret_hash, test_event, webhook_id
        )

        return {
            "message": "Test webhook queued for delivery",
            "webhook_id": webhook_id,
            "url": webhook_result.url,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error testing webhook endpoint: {e}")
        raise HTTPException(status_code=500, detail="Failed to test webhook endpoint")
