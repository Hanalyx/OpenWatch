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
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", ".."))
_ROUTES_DIR = os.path.join(
    _PROJECT_ROOT,
    "backend",
    "app",
    "routes",
    "signing",
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
class TestAC6VerifyEndpoint:
    """AC-6: POST /api/signing/verify accepts OpenWatch-signed bundles.

    (Spec v2.0 scope narrow: the former AC-6 per-transaction signing
    endpoint was removed; verification is the relevant public endpoint now.)
    """

    def test_verify_route_exists(self):
        """Route for POST /api/signing/verify is registered."""
        source = _read_route_source()
        assert "verify" in source


@pytest.mark.unit
class TestAC7KeysEncryptedAtRest:
    """AC-7: Signing keys are encrypted at rest via EncryptionService."""

    def test_encryption_service_used(self):
        """SigningService source references EncryptionService."""
        import app.services.signing.signing_service as mod

        source = inspect.getsource(mod)
        assert "EncryptionService" in source

    def test_no_silent_plain_base64_fallback(self):
        """SEC-SIGN-01: production must hard-fail when EncryptionService missing.

        Regression for the security review finding that generate_key() and
        sign_envelope() previously fell back to plain base64 storage when no
        EncryptionService was configured. The fallback is now gated behind
        OPENWATCH_SIGNING_DEV_MODE so production misconfiguration surfaces
        loudly instead of silently producing forgeable bundles.
        """
        import app.services.signing.signing_service as mod

        source = inspect.getsource(mod)
        # The dev-mode env var must be referenced
        assert "OPENWATCH_SIGNING_DEV_MODE" in source
        # And there must be a RuntimeError raised when neither EncryptionService
        # nor dev mode is present.
        assert "RuntimeError" in source
        assert "_dev_mode_enabled" in source


@pytest.mark.unit
class TestAC8AggregateSigningFailureDetectable:
    """AC-8: Aggregate signing failure is machine-detectable in the artifact."""

    def test_audit_export_writes_explicit_null_on_sign_failure(self):
        """audit_export writes signed_bundle=null + signing_error on failure.

        Regression for SEC-SIGN-03 (silent signing failure on export).
        """
        import app.services.compliance.audit_export as mod

        source = inspect.getsource(mod)
        assert 'export_data["signed_bundle"] = None' in source
        assert "signing_error" in source


@pytest.mark.unit
class TestAC9PerTransactionSigningRemoved:
    """AC-9: Per-transaction signing is NOT in OpenWatch's scope.

    Scope narrowed 2026-04-14: per-transaction signing moved to Kensa.
    OpenWatch signs only aggregate artifacts it originates.
    """

    def test_routes_do_not_register_per_transaction_sign_endpoint(self):
        """routes/signing/routes.py must not register POST /api/transactions/{id}/sign."""
        source = _read_route_source()
        # The endpoint must not be registered
        assert "/api/transactions/{transaction_id}/sign" not in source
        # Nor the handler function name
        assert "def sign_transaction" not in source

    def test_module_docstring_documents_kensa_boundary(self):
        """routes/signing/routes.py module docstring must document the boundary."""
        source = _read_route_source()
        # Name the coordination doc that establishes the boundary
        assert "Kensa" in source
        assert "aggregate" in source.lower()
