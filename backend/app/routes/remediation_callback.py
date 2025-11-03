"""
AEGIS Remediation Callback Routes
Handles remediation completion notifications from AEGIS
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import UUID4, BaseModel, Field
from sqlalchemy import and_
from sqlalchemy.orm import Session

from ..audit_db import log_audit_event
from ..config import get_settings
from ..database import Host, Scan, get_db
from ..services.webhook_security import verify_webhook_signature

logger = logging.getLogger(__name__)
settings = get_settings()
router = APIRouter()


class RemediationResult(BaseModel):
    rule_id: str
    rule_name: str
    status: str = Field(..., pattern="^(success|failed|skipped)$")
    error_message: Optional[str] = None


class RemediationCallbackRequest(BaseModel):
    remediation_job_id: UUID4
    scan_id: UUID4
    host_id: UUID4
    openwatch_host_id: UUID4
    status: str = Field(..., pattern="^(completed|failed|partial)$")
    total_rules: int
    successful_rules: int
    failed_rules: int
    skipped_rules: int
    results: List[RemediationResult]
    started_at: datetime
    completed_at: datetime


@router.post("/api/v1/webhooks/remediation-complete")
async def handle_remediation_callback(
    request: Request,
    callback: RemediationCallbackRequest,
    x_openwatch_signature: Optional[str] = Header(None),
    x_hub_signature_256: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """Handle remediation completion callback from AEGIS"""

    # Verify webhook signature
    signature = x_openwatch_signature or x_hub_signature_256
    if not signature:
        logger.warning("Remediation callback received without signature")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing webhook signature")

    # Get webhook secret from environment (AEGIS integration not currently implemented)
    # When AEGIS integration is activated, webhook_secret should be configured in settings
    webhook_secret = getattr(settings, "aegis_webhook_secret", None)

    if not webhook_secret:
        # AEGIS webhooks not configured - this endpoint should not be accessible
        # In production, configure AEGIS_WEBHOOK_SECRET environment variable
        logger.warning("AEGIS webhook callback received but webhook secret not configured")
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="AEGIS webhook integration not configured",
        )

    # Get raw body for signature verification
    body = await request.body()

    if not verify_webhook_signature(body.decode(), webhook_secret, signature):
        logger.error("Invalid webhook signature for remediation callback")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid webhook signature")

    try:
        # Find the original scan
        scan = db.query(Scan).filter(Scan.id == str(callback.scan_id)).first()

        if not scan:
            logger.error(f"Scan not found for remediation callback: {callback.scan_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan {callback.scan_id} not found",
            )

        # Verify host matches
        if str(scan.host_id) != str(callback.openwatch_host_id):
            logger.error(f"Host mismatch in remediation callback: {scan.host_id} != {callback.openwatch_host_id}")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Host ID mismatch")

        # Update scan with remediation information
        scan.aegis_remediation_id = str(callback.remediation_job_id)
        scan.remediation_status = callback.status
        scan.remediation_completed_at = callback.completed_at

        # Store remediation results in scan metadata
        if not scan.metadata:
            scan.metadata = {}

        scan.metadata["remediation"] = {
            "job_id": str(callback.remediation_job_id),
            "status": callback.status,
            "total_rules": callback.total_rules,
            "successful_rules": callback.successful_rules,
            "failed_rules": callback.failed_rules,
            "skipped_rules": callback.skipped_rules,
            "started_at": callback.started_at.isoformat(),
            "completed_at": callback.completed_at.isoformat(),
            "results": [r.dict() for r in callback.results],
        }

        db.commit()

        # Log audit event
        await log_audit_event(
            db=db,
            user_id=None,  # System action
            action="REMEDIATION_COMPLETED",
            resource_type="scan",
            resource_id=str(scan.id),
            details={
                "remediation_job_id": str(callback.remediation_job_id),
                "status": callback.status,
                "successful_rules": callback.successful_rules,
                "failed_rules": callback.failed_rules,
            },
            ip_address="127.0.0.1",  # Internal system
        )

        logger.info(f"Remediation callback processed for scan {scan.id}: {callback.status}")

        # Check if we should trigger a verification scan
        if callback.status == "completed" and callback.successful_rules > 0:
            # TODO: Trigger verification scan
            logger.info(f"Verification scan should be triggered for host {scan.host_id}")

        return {
            "status": "success",
            "message": "Remediation callback processed successfully",
            "scan_id": str(scan.id),
            "verification_scan_needed": callback.successful_rules > 0,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing remediation callback: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process remediation callback",
        )
