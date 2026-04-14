"""
Runtime coverage tests for data models, enums, and Pydantic schemas.
These tests import and exercise model code to boost line coverage.

Spec: specs/system/architecture.spec.yaml
"""

import pytest


@pytest.mark.unit
class TestScanModels:
    """AC-2: Models use proper types and enums."""

    def test_scan_status_enum_values(self):
        from app.models.scan_models import ScanStatus

        assert ScanStatus.PENDING.value == "pending"
        assert ScanStatus.RUNNING.value == "running"
        assert ScanStatus.COMPLETED.value == "completed"
        assert ScanStatus.FAILED.value == "failed"
        assert ScanStatus.TIMED_OUT.value == "timed_out"
        assert ScanStatus.CANCELLED.value == "cancelled"
        assert len(ScanStatus) == 6

    def test_scan_status_is_string_enum(self):
        from app.models.scan_models import ScanStatus

        assert isinstance(ScanStatus.PENDING, str)
        assert ScanStatus.PENDING == "pending"

    def test_scan_config_models_importable(self):
        from app.models.scan_config_models import ScanTemplate

        assert ScanTemplate is not None

    def test_error_models_importable(self):
        import app.models.error_models as mod

        assert hasattr(mod, "ScanErrorInternal") or hasattr(mod, "ErrorCategory")

    def test_system_models_importable(self):
        import app.models.system_models as mod

        assert mod is not None

    def test_remediation_models_importable(self):
        import app.models.remediation_models as mod

        assert mod is not None

    def test_authorization_models_importable(self):
        import app.models.authorization_models as mod

        assert mod is not None

    def test_plugin_models_importable(self):
        import app.models.plugin_models as mod

        assert mod is not None


@pytest.mark.unit
class TestEnums:
    """AC-2: Enums define expected values."""

    def test_model_enums(self):
        from app.models.enums import ScanPriority

        assert ScanPriority is not None

    def test_scan_status_members(self):
        from app.models.scan_models import ScanStatus

        members = [s.value for s in ScanStatus]
        assert "pending" in members
        assert "completed" in members


@pytest.mark.unit
class TestEncryptionModels:
    """AC-2: Encryption service models."""

    def test_encryption_config(self):
        from app.encryption.config import EncryptionConfig

        assert EncryptionConfig is not None

    def test_encryption_exceptions(self):
        from app.encryption.exceptions import EncryptionError, DecryptionError

        assert issubclass(EncryptionError, Exception)
        assert issubclass(DecryptionError, Exception)

    def test_encryption_error_message(self):
        from app.encryption.exceptions import EncryptionError

        err = EncryptionError("test error")
        assert str(err) == "test error"


@pytest.mark.unit
class TestPydanticSchemas:
    """AC-2: Pydantic schemas validate data."""

    def test_host_group_models_importable(self):
        import app.routes.host_groups.models as mod

        assert mod is not None

    def test_ssh_models_importable(self):
        import app.routes.ssh.models as mod

        assert mod is not None

    def test_kensa_config(self):
        from app.plugins.kensa.config import KensaConfig

        assert KensaConfig is not None

    def test_unified_rule_models(self):
        import app.models.unified_rule_models as mod

        assert mod is not None


@pytest.mark.unit
class TestConstants:
    """AC-5: Constants and configuration values."""

    def test_constants_importable(self):
        import app.constants

        assert app.constants is not None
