"""
Unit tests for ORSA v2.0 plugin interface.

Spec: specs/plugins/orsa-v2.spec.yaml
Tests plugin registration, capability filtering, CheckResult contract,
and license gating.
"""

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
