"""
Terminal WebSocket Router for OpenWatch

Provides WebSocket endpoints for SSH terminal access to hosts
"""

import logging

from fastapi import APIRouter, Depends, Request, WebSocket, WebSocketDisconnect
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..database import get_db
from ..encryption import EncryptionService
from ..services.terminal_service import terminal_service

# from ..auth import get_current_user  # Optional for future authentication

logger = logging.getLogger(__name__)

router = APIRouter()


def get_client_ip(request: Request) -> str:
    """Extract client IP address from request"""
    # Check X-Forwarded-For header first (for reverse proxy setups)
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        # Take the first IP if there are multiple
        return forwarded_for.split(",")[0].strip()

    # Check X-Real-IP header (nginx)
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()

    # Fallback to direct client IP
    if request.client and request.client.host:
        return request.client.host

    return "unknown"


@router.websocket("/api/hosts/{host_id}/terminal")
async def host_terminal_websocket(websocket: WebSocket, host_id: str, db: Session = Depends(get_db)):
    """
    WebSocket endpoint for SSH terminal access to a specific host

    Args:
        websocket: WebSocket connection
        host_id: UUID of the host to connect to
        db: Database session
    """
    # Get encryption service from app state
    encryption_service: EncryptionService = websocket.app.state.encryption_service

    # Get client IP for audit logging
    client_ip = "unknown"
    try:
        # Extract IP from WebSocket headers
        forwarded_for = websocket.headers.get("x-forwarded-for")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        elif websocket.client and websocket.client.host:
            client_ip = websocket.client.host
    except Exception:
        logger.debug("Ignoring exception during cleanup")

    logger.info(f"Terminal WebSocket connection requested for host {host_id} from {client_ip}")

    # Note: WebSocket connections don't easily support standard HTTP auth middleware
    # For now, we'll accept connections and rely on network-level security
    # In production, consider implementing WebSocket-specific auth

    try:
        await terminal_service.handle_websocket_connection(
            websocket=websocket,
            host_id=host_id,
            db=db,
            client_ip=client_ip,
            encryption_service=encryption_service,
        )
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for host {host_id}")
    except Exception as e:
        logger.error(f"Terminal WebSocket error for host {host_id}: {e}")
        try:
            await websocket.close()
        except Exception:
            logger.debug("Ignoring exception during cleanup")


@router.get("/api/hosts/{host_id}/terminal/status")
async def get_terminal_status(host_id: str, db: Session = Depends(get_db)):
    """
    Get terminal connection status for a host

    Args:
        host_id: UUID of the host
        db: Database session

    Returns:
        Terminal status information
    """
    try:
        # Check if host exists using raw SQL query
        result = db.execute(text("SELECT * FROM hosts WHERE id = :host_id"), {"host_id": host_id})
        host_data = result.fetchone()

        if not host_data:
            return {"error": "Host not found"}

        # Convert row to dict-like object
        host = {
            "id": str(host_data.id),
            "hostname": host_data.hostname,
            "ip_address": host_data.ip_address,
            "auth_method": host_data.auth_method,
        }

        # Check for active sessions
        active_sessions = [key for key in terminal_service.active_sessions.keys() if key.startswith(f"{host_id}_")]

        return {
            "host_id": host_id,
            "hostname": host["hostname"],
            "ip_address": host["ip_address"],
            "active_sessions": len(active_sessions),
            "auth_method": host["auth_method"],
            "terminal_available": True,
        }

    except Exception as e:
        logger.error(f"Error getting terminal status for host {host_id}: {e}")
        return {"error": "Failed to get terminal status", "details": str(e)}
