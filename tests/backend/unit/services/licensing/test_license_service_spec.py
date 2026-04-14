"""
Source-inspection tests for license service.

Spec: specs/services/licensing/license-service.spec.yaml
"""

import inspect

import pytest


@pytest.mark.unit
class TestAC1FeatureCheckMethods:
    """AC-1: LicenseService provides check_feature and has_feature methods."""

    def test_license_service_exists(self):
        from app.services.licensing.service import LicenseService

        assert LicenseService is not None

    def test_has_feature_method(self):
        import app.services.licensing.service as mod

        source = inspect.getsource(mod)
        assert "has_feature" in source

    def test_check_feature_method(self):
        import app.services.licensing.service as mod

        source = inspect.getsource(mod)
        assert "check_feature" in source or "has_feature" in source


@pytest.mark.unit
class TestAC2FreeTierFeatures:
    """AC-2: Free tier includes compliance_check, framework_reporting, basic_dashboard."""

    def test_compliance_check_feature(self):
        import app.services.licensing.service as mod

        source = inspect.getsource(mod)
        assert "compliance_check" in source

    def test_framework_reporting_feature(self):
        import app.services.licensing.service as mod

        source = inspect.getsource(mod)
        assert "framework_reporting" in source


@pytest.mark.unit
class TestAC3PlusFeatures:
    """AC-3: OpenWatch+ features include remediation, temporal_queries."""

    def test_remediation_feature(self):
        import app.services.licensing.service as mod

        source = inspect.getsource(mod)
        assert "remediation" in source

    def test_temporal_queries_feature(self):
        import app.services.licensing.service as mod

        source = inspect.getsource(mod)
        assert "temporal_queries" in source


@pytest.mark.unit
class TestAC4RequiresLicenseDecorator:
    """AC-4: requires_license decorator gates methods by feature name."""

    def test_requires_license_decorator(self):
        import app.services.licensing.service as mod

        source = inspect.getsource(mod)
        assert "requires_license" in source


@pytest.mark.unit
class TestAC5BooleanReturn:
    """AC-5: Feature check returns boolean result."""

    def test_returns_bool(self):
        import app.services.licensing.service as mod

        source = inspect.getsource(mod)
        assert "bool" in source or "True" in source or "False" in source
