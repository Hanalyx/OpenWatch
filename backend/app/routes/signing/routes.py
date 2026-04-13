"""Evidence signing API routes.

Endpoints:
    GET  /api/signing/public-keys            - List all public keys (no auth)
    POST /api/signing/verify                 - Verify a signed bundle (no auth)
    POST /api/transactions/{id}/sign         - Sign a transaction envelope (SECURITY_ADMIN+)

Security Notes:
    - public-keys and verify are unauthenticated so external auditors can
      independently verify evidence bundles without OpenWatch credentials.
    - The sign endpoint requires SECURITY_ADMIN or SUPER_ADMIN role.
    - EncryptionService is loaded from app.state (initialised at startup).
"""

import json
import logging
from typing import Any, Dict
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.rbac import UserRole, require_role
from app.services.signing import SignedBundle, SigningService

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Signing"])


# ---------------------------------------------------------------------------
# Pydantic request/response models
# ---------------------------------------------------------------------------


class VerifyRequest(BaseModel):
    """Request body for POST /api/signing/verify."""

    envelope: Dict[str, Any]
    signature: str
    key_id: str


class VerifyResponse(BaseModel):
    """Response body for POST /api/signing/verify."""

    valid: bool


class SignedBundleResponse(BaseModel):
    """Response body for a signed evidence bundle."""

    envelope: Dict[str, Any]
    signature: str
    key_id: str
    signed_at: str
    signer: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_signing_service(request: Request, db: Session = Depends(get_db)) -> SigningService:
    """Build a SigningService with the app-level EncryptionService."""
    enc = getattr(request.app.state, "encryption_service", None)
    return SigningService(db, encryption_service=enc)


# ---------------------------------------------------------------------------
# Public endpoints (no auth required)
# ---------------------------------------------------------------------------


@router.get("/api/signing/public-keys")
async def list_public_keys(
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """List all signing public keys (active and retired).

    This endpoint is public so that external auditors can fetch keys
    for independent verification of signed evidence bundles.
    """
    service = _get_signing_service(request, db)
    keys = service.get_public_keys()
    return {"keys": keys}


@router.post("/api/signing/verify", response_model=VerifyResponse)
async def verify_bundle(
    body: VerifyRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> VerifyResponse:
    """Verify a signed evidence bundle.

    Accepts an envelope, signature, and key_id; returns whether the
    signature is valid. This endpoint is public for external auditors.
    """
    service = _get_signing_service(request, db)
    bundle = SignedBundle(
        envelope=body.envelope,
        signature=body.signature,
        key_id=body.key_id,
        signed_at="",
        signer="",
    )
    valid = service.verify(bundle)
    return VerifyResponse(valid=valid)


# ---------------------------------------------------------------------------
# Protected endpoints
# ---------------------------------------------------------------------------


@require_role([UserRole.SECURITY_ADMIN, UserRole.SUPER_ADMIN])
@router.post(
    "/api/transactions/{transaction_id}/sign",
    response_model=SignedBundleResponse,
)
async def sign_transaction(
    transaction_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> SignedBundleResponse:
    """Sign a transaction's evidence envelope with the active Ed25519 key.

    Reads the transaction's evidence_envelope from the database and
    produces a SignedBundle. Requires SECURITY_ADMIN or SUPER_ADMIN role.

    Raises:
        HTTPException 404: Transaction not found or has no evidence envelope.
        HTTPException 400: No active signing key configured.
    """
    # Read transaction evidence_envelope
    row = db.execute(
        text("SELECT evidence_envelope " "FROM transactions " "WHERE id = :tid"),
        {"tid": str(transaction_id)},
    ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Transaction not found")

    envelope = row.evidence_envelope
    if envelope is None:
        raise HTTPException(
            status_code=404,
            detail="Transaction has no evidence envelope",
        )

    # Parse JSONB if returned as string
    if isinstance(envelope, str):
        try:
            envelope = json.loads(envelope)
        except (json.JSONDecodeError, ValueError):
            raise HTTPException(
                status_code=500,
                detail="Failed to parse evidence envelope",
            )

    signer = current_user.get("username", "openwatch")

    service = _get_signing_service(request, db)
    try:
        bundle = service.sign_envelope(envelope, signer=signer)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return SignedBundleResponse(
        envelope=bundle.envelope,
        signature=bundle.signature,
        key_id=bundle.key_id,
        signed_at=bundle.signed_at,
        signer=bundle.signer,
    )
