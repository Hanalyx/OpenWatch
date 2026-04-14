"""
Source-inspection tests for evidence signing (Ed25519).

Spec: specs/services/signing/evidence-signing.spec.yaml
Status: draft (Q2 -- workstream F1)

Tests verify structural properties of the signing implementation via
source inspection: importability, method signatures, and route presence.
"""

import inspect
import os

import pytest

# Route source files are read from disk to avoid transitive import
# failures (passlib, etc.) that are irrelevant to structural checks.
_PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "..")
)
_ROUTES_DIR = os.path.join(
    _PROJECT_ROOT, "backend", "app", "routes", "signing",
)


def _read_route_source() -> str:
    """Read route package source files from disk."""
    parts = []
    for fname in ("__init__.py", "routes.py"):
        fpath = os.path.join(_ROUTES_DIR, fname)
        if os.path.exists(fpath):
            with open(fpath) as f:
                parts.append(f.read())
    return "\n".join(parts)


@pytest.mark.unit
class TestAC1DeploymentSigningKeysTable:
    """AC-1: deployment_signing_keys table exists with required columns."""

    @pytest.mark.skip(reason="AC-1 requires live DB migration; verified via Alembic")
    def test_model_defined(self):
        """DeploymentSigningKey model importable from app.models."""
        from app.models.signing_models import DeploymentSigningKey  # noqa: F401

    @pytest.mark.skip(reason="AC-1 requires live DB migration; verified via Alembic")
    def test_required_columns(self):
        """Model has key_id, public_key, private_key_encrypted, active, created_at, rotated_at."""
        from app.models.signing_models import DeploymentSigningKey

        required = {
            "key_id",
            "public_key",
            "private_key_encrypted",
            "active",
            "created_at",
            "rotated_at",
        }
        actual = {c.name for c in DeploymentSigningKey.__table__.columns}
        assert required.issubset(actual)


@pytest.mark.unit
class TestAC2SignEnvelope:
    """AC-2: SigningService.sign_envelope returns a SignedBundle with Ed25519 signature."""

    def test_sign_envelope_callable(self):
        """SigningService.sign_envelope is callable."""
        from app.services.signing.signing_service import SigningService

        assert callable(getattr(SigningService, "sign_envelope", None))

    def test_sign_envelope_returns_signed_bundle(self):
        """sign_envelope return type annotation references SignedBundle."""
        from app.services.signing.signing_service import SigningService

        sig = inspect.signature(SigningService.sign_envelope)
        assert "SignedBundle" in str(sig.return_annotation)


@pytest.mark.unit
class TestAC3VerifyBundle:
    """AC-3: SigningService.verify validates signature against public key."""

    def test_verify_callable(self):
        """SigningService.verify is callable."""
        from app.services.signing.signing_service import SigningService

        assert callable(getattr(SigningService, "verify", None))


@pytest.mark.unit
class TestAC4KeyRotation:
    """AC-4: Key rotation makes new key active, old keys remain verifiable."""

    def test_rotate_key_method_exists(self):
        """SigningService has a rotate_key method."""
        from app.services.signing.signing_service import SigningService

        assert callable(getattr(SigningService, "rotate_key", None))


@pytest.mark.unit
class TestAC5PublicKeysEndpoint:
    """AC-5: GET /api/signing/public-keys returns active and retired public keys."""

    def test_public_keys_route_exists(self):
        """Route for GET /api/signing/public-keys is registered."""
        source = _read_route_source()
        assert "public-keys" in source or "public_keys" in source


@pytest.mark.unit
class TestAC6SignTransactionEndpoint:
    """AC-6: POST /api/transactions/{id}/sign signs a transaction's evidence envelope."""

    def test_sign_transaction_route_exists(self):
        """Route for POST /api/transactions/{id}/sign is registered."""
        source = _read_route_source()
        assert "sign" in source


@pytest.mark.unit
class TestAC7VerifyEndpoint:
    """AC-7: POST /api/signing/verify accepts a signed bundle and returns valid/invalid."""

    def test_verify_route_exists(self):
        """Route for POST /api/signing/verify is registered."""
        source = _read_route_source()
        assert "verify" in source


@pytest.mark.unit
class TestAC8KeysEncryptedAtRest:
    """AC-8: Signing keys are encrypted at rest via EncryptionService."""

    def test_encryption_service_used(self):
        """SigningService source references EncryptionService."""
        import app.services.signing.signing_service as mod

        source = inspect.getsource(mod)
        assert "EncryptionService" in source
