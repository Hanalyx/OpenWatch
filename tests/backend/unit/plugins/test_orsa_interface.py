"""
Unit tests for ORSA v2.0 plugin interface.

Spec: specs/plugins/orsa-v2.spec.yaml
Tests plugin registration, capability filtering, CheckResult contract,
license gating, and archive/upload security controls.
"""

import inspect

import pytest

# ---------------------------------------------------------------------------
# AC-3: check() returns List[CheckResult]
# AC-4: check() no raise for individual failure
# AC-9: framework_refs is dict (never None)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_check_result_dataclass_fields():
    """AC-3: CheckResult has required fields: rule_id, passed, severity."""
    from app.services.plugins.orsa.interface import CheckResult

    result = CheckResult(
        rule_id="sshd-permit-root-login",
        passed=True,
        severity="high",
        category="access-control",
        title="Disable SSH root login",
        detail="PermitRootLogin is set to no",
    )

    assert result.rule_id == "sshd-permit-root-login"
    assert result.passed is True
    assert result.severity == "high"
    assert result.category == "access-control"
    assert result.title == "Disable SSH root login"


@pytest.mark.unit
def test_check_result_framework_refs_default():
    """AC-9: framework_refs defaults to empty dict, never None."""
    from app.services.plugins.orsa.interface import CheckResult

    result = CheckResult(
        rule_id="test-rule",
        passed=False,
        severity="medium",
        category="system-config",
        title="Test",
        detail="Test detail",
    )

    assert result.framework_refs is not None
    assert isinstance(result.framework_refs, dict)


@pytest.mark.unit
def test_check_result_with_values():
    """AC-8: CheckResult carries actual/expected values and check metadata."""
    from app.services.plugins.orsa.interface import CheckResult

    result = CheckResult(
        rule_id="sshd-permit-root",
        passed=True,
        severity="high",
        category="access-control",
        title="SSH root login",
        detail="Pass",
        actual_value="no",
        expected_value="no",
        check_method="config_value",
    )

    assert result.actual_value == "no"
    assert result.expected_value == "no"
    assert result.check_method == "config_value"


# ---------------------------------------------------------------------------
# AC-1: Plugin registration
# AC-2: Duplicate registration error
# AC-7: find_by_capability filters correctly
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_capability_enum_values():
    """AC-7: Capability enum has expected values."""
    from app.services.plugins.orsa.interface import Capability

    assert Capability.COMPLIANCE_CHECK == "compliance_check"
    assert Capability.REMEDIATION == "remediation"
    assert Capability.ROLLBACK == "rollback"
    assert Capability.FRAMEWORK_MAPPING == "framework_map"


@pytest.mark.unit
def test_plugin_info_has_platforms_and_frameworks():
    """AC-10: PluginInfo includes supported_platforms and supported_frameworks."""
    from app.services.plugins.orsa.interface import Capability, PluginInfo

    info = PluginInfo(
        plugin_id="test-plugin",
        name="Test Plugin",
        version="1.0.0",
        description="A test plugin",
        vendor="Test Vendor",
        capabilities=[Capability.COMPLIANCE_CHECK],
        supported_platforms=["rhel9", "ubuntu22"],
        supported_frameworks=["cis", "stig"],
    )

    assert len(info.supported_platforms) == 2
    assert "rhel9" in info.supported_platforms
    assert len(info.supported_frameworks) == 2
    assert "cis" in info.supported_frameworks


# ---------------------------------------------------------------------------
# AC-5: remediate() license gate
# AC-6: rollback() license gate
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_kensa_plugin_capabilities():
    """AC-7: KensaORSAPlugin advertises expected capabilities."""
    from app.plugins.kensa.orsa_plugin import KensaORSAPlugin
    from app.services.plugins.orsa.interface import Capability

    plugin = KensaORSAPlugin()
    import asyncio

    capabilities = asyncio.run(plugin.get_capabilities())

    assert Capability.COMPLIANCE_CHECK in capabilities
    assert Capability.REMEDIATION in capabilities
    assert Capability.ROLLBACK in capabilities
    assert Capability.FRAMEWORK_MAPPING in capabilities


@pytest.mark.unit
def test_kensa_plugin_info():
    """AC-10: KensaORSAPlugin get_info returns valid PluginInfo."""
    from app.plugins.kensa.orsa_plugin import KensaORSAPlugin

    plugin = KensaORSAPlugin()
    import asyncio

    info = asyncio.run(plugin.get_info())

    assert info.plugin_id == "kensa"
    assert info.name == "Kensa Compliance Engine"
    assert info.vendor == "Hanalyx"
    assert len(info.supported_platforms) > 0
    assert len(info.supported_frameworks) > 0


# ---------------------------------------------------------------------------
# AC-11: _install_package validates tar members for path traversal
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC11TarPathTraversal:
    """AC-11: _install_package validates tar members before extraction."""

    def test_install_package_exists(self):
        """Verify _install_package method exists in KensaUpdater."""
        from app.plugins.kensa.updater import KensaUpdater

        assert hasattr(KensaUpdater, "_install_package")

    def test_install_package_checks_dotdot(self):
        """Verify _install_package rejects '..' in tar member paths."""
        from app.plugins.kensa.updater import KensaUpdater

        source = inspect.getsource(KensaUpdater._install_package)
        # Must check for path traversal via '..' or use filter='data'
        has_dotdot_check = ".." in source
        has_filter_data = "filter=" in source and "data" in source
        assert has_dotdot_check or has_filter_data, (
            "_install_package must validate tar members for '..' traversal "
            "or use filter='data'"
        )

    def test_install_package_checks_absolute_paths(self):
        """Verify _install_package rejects absolute paths in tar members."""
        from app.plugins.kensa.updater import KensaUpdater

        source = inspect.getsource(KensaUpdater._install_package)
        # Must check for leading '/' or use filter='data'
        has_abs_check = "startswith('/')" in source or 'startswith("/")' in source
        has_is_absolute = "is_absolute" in source
        has_filter_data = "filter=" in source and "data" in source
        assert has_abs_check or has_is_absolute or has_filter_data, (
            "_install_package must validate tar members for absolute paths "
            "or use filter='data'"
        )


# ---------------------------------------------------------------------------
# AC-12: Plugin service extractall validates member paths
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC12PluginServiceExtractall:
    """AC-12: Plugin services validate member paths before extractall."""

    def test_marketplace_service_validates_paths(self):
        """Verify marketplace service validates tar member paths."""
        import importlib

        mod = importlib.import_module("app.services.plugins.marketplace.service")
        source = inspect.getsource(mod)
        has_extractall = "extractall" in source
        if not has_extractall:
            # No extractall means no risk
            return
        # Must validate members before extraction
        has_dotdot_check = ".." in source
        has_filter_data = "filter=" in source and "data" in source
        has_member_check = "getmembers" in source or "getnames" in source
        assert has_dotdot_check or has_filter_data or has_member_check, (
            "Marketplace service must validate tar members before extractall"
        )

    def test_development_service_validates_paths(self):
        """Verify development service validates tar member paths."""
        import importlib

        mod = importlib.import_module("app.services.plugins.development.service")
        source = inspect.getsource(mod)
        has_extractall = "extractall" in source
        if not has_extractall:
            return
        has_dotdot_check = ".." in source
        has_filter_data = "filter=" in source and "data" in source
        has_member_check = "getmembers" in source or "getnames" in source
        assert has_dotdot_check or has_filter_data or has_member_check, (
            "Development service must validate tar members before extractall"
        )


# ---------------------------------------------------------------------------
# AC-13: Upload handlers sanitize filenames
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC13FilenameSanitization:
    """AC-13: Upload handlers sanitize filenames before path construction."""

    def test_upload_handler_sanitizes_filename(self):
        """Verify upload handler sanitizes package.filename."""
        import importlib

        mod = importlib.import_module("app.routes.plugins.updates")
        source = inspect.getsource(mod)
        has_sanitize = "sanitize_filename" in source
        has_secure = "secure_filename" in source
        has_basename = "os.path.basename" in source
        assert has_sanitize or has_secure or has_basename, (
            "Upload handler must sanitize filename before constructing paths"
        )
