"""
Source-inspection tests for evidence signing (Ed25519).

Spec: specs/services/signing/evidence-signing.spec.yaml
Status: draft (Q2 — workstream F1)

Tests are skip-marked until the corresponding Q2 implementation lands.
Each PR in the evidence signing workstream removes skip markers from the
tests it makes passing.
"""

import pytest

SKIP_REASON = "Q2: evidence signing not yet implemented"


@pytest.mark.unit
class TestAC1DeploymentSigningKeysTable:
    """AC-1: deployment_signing_keys table exists with required columns."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_model_defined(self):
        """DeploymentSigningKey model importable from app.models."""
        from app.models.signing_models import DeploymentSigningKey  # noqa: F401

    @pytest.mark.skip(reason=SKIP_REASON)
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

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_sign_envelope_callable(self):
        """SigningService.sign_envelope is callable."""
        from app.services.signing.signing_service import SigningService

        assert callable(getattr(SigningService, "sign_envelope", None))

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_sign_envelope_returns_signed_bundle(self):
        """sign_envelope return type annotation references SignedBundle."""
        import inspect

        from app.services.signing.signing_service import SigningService

        sig = inspect.signature(SigningService.sign_envelope)
        assert "SignedBundle" in str(sig.return_annotation)


@pytest.mark.unit
class TestAC3VerifyBundle:
    """AC-3: SigningService.verify validates signature against public key."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_verify_callable(self):
        """SigningService.verify is callable."""
        from app.services.signing.signing_service import SigningService

        assert callable(getattr(SigningService, "verify", None))


@pytest.mark.unit
class TestAC4KeyRotation:
    """AC-4: Key rotation makes new key active, old keys remain verifiable."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_rotate_key_method_exists(self):
        """SigningService has a rotate_key method."""
        from app.services.signing.signing_service import SigningService

        assert callable(getattr(SigningService, "rotate_key", None))


@pytest.mark.unit
class TestAC5PublicKeysEndpoint:
    """AC-5: GET /api/signing/public-keys returns active and retired public keys."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_public_keys_route_exists(self):
        """Route for GET /api/signing/public-keys is registered."""
        import inspect

        import app.routes.signing as mod

        source = inspect.getsource(mod)
        assert "public-keys" in source or "public_keys" in source


@pytest.mark.unit
class TestAC6SignTransactionEndpoint:
    """AC-6: POST /api/transactions/{id}/sign signs a transaction's evidence envelope."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_sign_transaction_route_exists(self):
        """Route for POST /api/transactions/{id}/sign is registered."""
        import inspect

        import app.routes.signing as mod

        source = inspect.getsource(mod)
        assert "sign" in source


@pytest.mark.unit
class TestAC7VerifyEndpoint:
    """AC-7: POST /api/signing/verify accepts a signed bundle and returns valid/invalid."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_verify_route_exists(self):
        """Route for POST /api/signing/verify is registered."""
        import inspect

        import app.routes.signing as mod

        source = inspect.getsource(mod)
        assert "verify" in source


@pytest.mark.unit
class TestAC8KeysEncryptedAtRest:
    """AC-8: Signing keys are encrypted at rest via EncryptionService."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_encryption_service_used(self):
        """SigningService source references EncryptionService."""
        import inspect

        import app.services.signing.signing_service as mod

        source = inspect.getsource(mod)
        assert "EncryptionService" in source
