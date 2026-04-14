"""Evidence signing API routes for OpenWatch-originated aggregate artifacts.

Scope narrowed 2026-04-14 per Kensa↔OpenWatch coordination. Per-transaction
envelope signing moved to Kensa (where the evidence originates). OpenWatch's
signing layer now attests only to aggregate artifacts that OpenWatch itself
produces — cross-host audit exports, quarterly posture reports, and the
future State-of-Production report.

Endpoints:
    GET  /api/signing/public-keys   - List all public keys (no auth, for auditors)
    POST /api/signing/verify        - Verify a signed aggregate bundle (no auth)

    (REMOVED) POST /api/transactions/{id}/sign — per-transaction signing
    moves to Kensa per KENSA_GO_DAY1_PLAN.md §8.2 and the Kensa team's
    response §2.2. OpenWatch audit UIs display Kensa-signed envelopes via
    kensa.api.Kensa.VerifyEnvelope() starting at Kensa Week 22.

Security Notes:
    - public-keys and verify are unauthenticated so external auditors can
      independently verify OpenWatch-originated bundles without OpenWatch
      credentials.
    - EncryptionService is loaded from app.state (initialised at startup).

See also:
    - docs/SIGNING_SECURITY_REVIEW_2026-04-14.md (trust-layer boundary)
    - docs/KENSA_OPENWATCH_COORDINATION_2026-04-14.md (§3.2)
    - /home/rracine/hanalyx/kensa/docs/KENSA_OPENWATCH_RESPONSE_2026-04-14.md (§2.2)
"""

import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
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
    """Response body for a signed OpenWatch-originated bundle.

    Used by aggregate audit exports and quarterly posture reports. Not
    used for per-transaction envelopes (those are Kensa-signed).
    """

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
# REMOVED: POST /api/transactions/{transaction_id}/sign
# ---------------------------------------------------------------------------
#
# Per-transaction envelope signing moved to Kensa on 2026-04-14 per the
# Kensa↔OpenWatch coordination (docs/KENSA_OPENWATCH_COORDINATION_2026-04-14.md
# §3.2; Kensa response §2.2). Kensa signs at evidence-capture time — the
# auditor wants the Kensa attestation ("this execution happened on this
# host"), not a later OpenWatch attestation ("OpenWatch stored this").
#
# At Kensa Go Week 22, OpenWatch audit UIs verify per-transaction envelopes
# via kensa.api.Kensa.VerifyEnvelope() (KENSA_GO_DAY1_PLAN.md §3.5.4).
# Until then, Python Kensa produces per-transaction signatures; OpenWatch
# consumes them read-only.
#
# OpenWatch's signing path survives but is narrowed to aggregate artifacts
# OpenWatch itself originates (audit exports, quarterly reports, future
# State-of-Production report). See audit_export._generate_json for the
# remaining legitimate signing call-site.
# ---------------------------------------------------------------------------
