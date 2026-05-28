"""Ed25519 signing for OpenWatch-originated aggregate artifacts.

SCOPE NARROWED 2026-04-14 per Kensa↔OpenWatch coordination
(docs/KENSA_OPENWATCH_COORDINATION_2026-04-14.md §3.2; Kensa response §2.2).

This module signs **aggregate artifacts that OpenWatch itself produces** —
cross-host audit exports, quarterly posture reports, the future State-of-
Production report. It does NOT sign per-transaction evidence envelopes;
those are Kensa-signed at evidence-capture time per
KENSA_GO_DAY1_PLAN.md §8.2. OpenWatch audit UIs display Kensa's
per-transaction signatures via kensa.api.Kensa.VerifyEnvelope() starting
at Kensa Week 22.

Trust-layer boundary::

    +--------------------------------+   +---------------------------------+
    | Kensa (per-transaction)        |   | OpenWatch (aggregate)           |
    |                                |   |                                 |
    | Signs: evidence envelope at    |   | Signs: audit export, quarterly  |
    |   capture/execute time         |   |   posture report, State-of-     |
    |                                |   |   Production release            |
    | Attests: "This execution       |   | Attests: "OpenWatch aggregated  |
    |   happened on this host at     |   |   this data from N hosts and    |
    |   this time"                   |   |   produced this artifact"       |
    +--------------------------------+   +---------------------------------+

Signing keys are stored encrypted at rest via EncryptionService and
support rotation without breaking verification of previously signed
bundles.

Usage (aggregate artifacts only)::

    service = SigningService(db, encryption_service=enc)
    key_id = service.generate_key()  # once per deployment
    bundle = service.sign_envelope(export_data, signer="openwatch")
    valid = service.verify(bundle)
"""

import base64
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.utils.mutation_builders import InsertBuilder

logger = logging.getLogger(__name__)


# SEC-SIGN-01 fix: explicit dev-mode override so production deploys that
# misconfigure EncryptionService surface the error loudly instead of
# silently storing private keys as plain base64. Set via environment for
# tests / local dev only.
_DEV_MODE_ENV = "OPENWATCH_SIGNING_DEV_MODE"


def _dev_mode_enabled() -> bool:
    """True only if the explicit dev-mode env var is set to a truthy value."""
    return os.environ.get(_DEV_MODE_ENV, "").lower() in ("1", "true", "yes")


@dataclass
class SignedBundle:
    """A signed evidence envelope with metadata for independent verification."""

    envelope: Dict[str, Any]
    signature: str  # base64-encoded Ed25519 signature
    key_id: str
    signed_at: str  # ISO 8601
    signer: str


class SigningService:
    """Ed25519 evidence signing and verification service.

    Signs compliance evidence envelopes, producing SignedBundle objects
    that can be independently verified using the public key exposed via
    the /api/signing/public-keys endpoint.

    Private keys are encrypted at rest via EncryptionService. Key rotation
    deactivates the current key and creates a new one; old keys remain
    available for verification.

    Args:
        db: SQLAlchemy database session.
        encryption_service: EncryptionService instance for key-at-rest
            encryption. If None, keys are stored base64-encoded (dev only).
    """

    def __init__(self, db: Session, encryption_service: Optional[Any] = None):
        self.db = db
        self._enc = encryption_service

    def generate_key(self) -> str:
        """Generate a new Ed25519 key pair and activate it.

        Deactivates any currently active key (setting rotated_at) and
        inserts a new active key pair. The private key is encrypted via
        EncryptionService before storage.

        Returns:
            The UUID key_id of the newly created key.
        """
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Serialize to raw bytes
        pub_bytes = public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        priv_bytes = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

        pub_b64 = base64.b64encode(pub_bytes).decode()

        # Encrypt private key at rest via EncryptionService (AC-8).
        # SEC-SIGN-01 fix: hard-fail if EncryptionService is missing in
        # production. Plain-base64 fallback is gated behind an explicit
        # dev-mode env var so misconfiguration surfaces loudly.
        if self._enc:
            priv_encrypted = base64.b64encode(self._enc.encrypt(priv_bytes)).decode()
        elif _dev_mode_enabled():
            logger.warning(
                "EncryptionService not configured; storing signing key as plain "
                "base64 because %s is set. NEVER use this in production.",
                _DEV_MODE_ENV,
            )
            priv_encrypted = base64.b64encode(priv_bytes).decode()
        else:
            raise RuntimeError(
                "Cannot generate signing key: EncryptionService is required for "
                "encryption at rest (spec AC-8). To bypass for development or "
                f"testing, set {_DEV_MODE_ENV}=true."
            )

        # SEC-SIGN-02 fix: wrap deactivate + insert in a single transaction
        # with FOR UPDATE on the previously active row, preventing concurrent
        # generate_key() calls from leaving two rows with active=true.
        self.db.execute(text("SELECT id FROM deployment_signing_keys " "WHERE active = true FOR UPDATE")).fetchall()

        # Deactivate current active key (rotation support, AC-4)
        self.db.execute(
            text("UPDATE deployment_signing_keys " "SET active = false, rotated_at = :now " "WHERE active = true"),
            {"now": datetime.now(timezone.utc)},
        )

        # Insert new active key
        builder = (
            InsertBuilder("deployment_signing_keys")
            .columns("public_key", "private_key_encrypted", "active")
            .values(pub_b64, priv_encrypted, True)
            .returning("id")
        )
        q, p = builder.build()
        row = self.db.execute(text(q), p).fetchone()
        self.db.commit()

        key_id = str(row.id)
        logger.info("Generated new signing key %s", key_id)
        return key_id

    def rotate_key(self) -> str:
        """Rotate the signing key.

        Creates a new active key; the previous key is deactivated but
        remains available for verification of previously signed bundles.

        Returns:
            The UUID key_id of the newly created key.
        """
        return self.generate_key()

    def sign_envelope(self, envelope: Dict[str, Any], signer: str = "openwatch") -> SignedBundle:
        """Sign an evidence envelope with the active Ed25519 key.

        Uses canonical JSON serialisation (sorted keys, compact separators)
        to produce a deterministic byte representation before signing.

        Args:
            envelope: The evidence envelope dictionary to sign.
            signer: Identifier for the signing entity.

        Returns:
            A SignedBundle containing the envelope, signature, and metadata.

        Raises:
            ValueError: If no active signing key exists.
        """
        # Fetch active key
        row = self.db.execute(
            text("SELECT id, private_key_encrypted " "FROM deployment_signing_keys " "WHERE active = true LIMIT 1")
        ).fetchone()

        if not row:
            raise ValueError("No active signing key. Call generate_key() first.")

        # Decrypt private key. SEC-SIGN-01 fix: same dev-mode gate as
        # generate_key — refuse to read plain-base64 keys in production.
        priv_encrypted = base64.b64decode(row.private_key_encrypted)
        if self._enc:
            priv_bytes = self._enc.decrypt(priv_encrypted)
        elif _dev_mode_enabled():
            priv_bytes = priv_encrypted
        else:
            raise RuntimeError(
                "Cannot sign: EncryptionService is required to decrypt the "
                f"signing key. Set {_DEV_MODE_ENV}=true for dev/test only."
            )

        private_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)

        # Canonical JSON serialisation for deterministic signing
        canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()

        # Sign
        signature = private_key.sign(canonical)
        sig_b64 = base64.b64encode(signature).decode()

        now = datetime.now(timezone.utc).isoformat()

        return SignedBundle(
            envelope=envelope,
            signature=sig_b64,
            key_id=str(row.id),
            signed_at=now,
            signer=signer,
        )

    def verify(self, bundle: SignedBundle) -> bool:
        """Verify a signed bundle against the signing key.

        Looks up the public key by key_id and verifies the Ed25519
        signature over the canonical JSON representation.

        Args:
            bundle: The SignedBundle to verify.

        Returns:
            True if the signature is valid, False otherwise.
        """
        row = self.db.execute(
            text("SELECT public_key FROM deployment_signing_keys " "WHERE id = :kid"),
            {"kid": bundle.key_id},
        ).fetchone()

        if not row:
            return False

        pub_bytes = base64.b64decode(row.public_key)
        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)

        canonical = json.dumps(bundle.envelope, sort_keys=True, separators=(",", ":")).encode()
        signature = base64.b64decode(bundle.signature)

        try:
            public_key.verify(signature, canonical)
            return True
        except Exception:
            return False

    def get_public_keys(self) -> List[Dict[str, Any]]:
        """Return all public keys (active and retired).

        Returns:
            List of dicts with key_id, public_key, active, created_at,
            and rotated_at fields.
        """
        rows = self.db.execute(
            text(
                "SELECT id, public_key, active, created_at, rotated_at "
                "FROM deployment_signing_keys "
                "ORDER BY created_at DESC"
            )
        ).fetchall()
        return [
            {
                "key_id": str(r.id),
                "public_key": r.public_key,
                "active": r.active,
                "created_at": (r.created_at.isoformat() if r.created_at else None),
                "rotated_at": (r.rotated_at.isoformat() if r.rotated_at else None),
            }
            for r in rows
        ]
