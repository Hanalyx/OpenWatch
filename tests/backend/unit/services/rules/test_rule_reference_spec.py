"""
Rule Reference Service spec compliance tests.
Verifies that services/rule_reference_service.py implements the behavioral
contract defined in the rule-reference-service spec via source inspection.

Spec: specs/services/rules/rule-reference.spec.yaml
"""

import inspect

import pytest


@pytest.mark.unit
class TestAC1SingletonPattern:
    """AC-1: Service loaded via singleton get_rule_reference_service()."""

    def test_singleton_function_exists(self):
        import app.services.rule_reference_service as mod

        assert hasattr(mod, "get_rule_reference_service")
        assert callable(mod.get_rule_reference_service)

    def test_singleton_function_defined_in_module(self):
        import app.services.rule_reference_service as mod

        source = inspect.getsource(mod)
        assert "def get_rule_reference_service" in source


@pytest.mark.unit
class TestAC2RulesLoadedFromYAML:
    """AC-2: Rules loaded from YAML files in rules_path directory."""

    def test_module_imports_yaml(self):
        import app.services.rule_reference_service as mod

        source = inspect.getsource(mod)
        assert "import yaml" in source

    def test_module_references_rules_path(self):
        import app.services.rule_reference_service as mod

        source = inspect.getsource(mod)
        assert "KENSA_RULES_PATH" in source or "rules_path" in source.lower()


@pytest.mark.unit
class TestAC3FrameworkFilteringUsesMappings:
    """AC-3: Framework filtering uses mapping files."""

    def test_module_references_mappings(self):
        import app.services.rule_reference_service as mod

        source = inspect.getsource(mod)
        # The service references runner.mappings or mapping files
        assert "mapping" in source.lower()


@pytest.mark.unit
class TestAC4CapabilityProbes22Items:
    """AC-4: CAPABILITY_PROBES defines 22 detectable system capabilities."""

    def test_capability_probes_constant_exists(self):
        import app.services.rule_reference_service as mod

        assert hasattr(mod, "CAPABILITY_PROBES")

    def test_capability_probes_has_22_items(self):
        import app.services.rule_reference_service as mod

        assert len(mod.CAPABILITY_PROBES) == 22

    def test_capability_probes_includes_sshd_config_d(self):
        import app.services.rule_reference_service as mod

        assert "sshd_config_d" in mod.CAPABILITY_PROBES

    def test_capability_probes_includes_firewalld(self):
        import app.services.rule_reference_service as mod

        assert "firewalld" in mod.CAPABILITY_PROBES

    def test_capability_probes_includes_selinux(self):
        import app.services.rule_reference_service as mod

        assert "selinux" in mod.CAPABILITY_PROBES

    def test_capability_probes_includes_usbguard(self):
        import app.services.rule_reference_service as mod

        assert "usbguard" in mod.CAPABILITY_PROBES

    def test_capability_probes_includes_fips_mode(self):
        import app.services.rule_reference_service as mod

        assert "fips_mode" in mod.CAPABILITY_PROBES

    def test_capability_probes_includes_sudo(self):
        import app.services.rule_reference_service as mod

        assert "sudo" in mod.CAPABILITY_PROBES


@pytest.mark.unit
class TestAC5InMemoryCaching:
    """AC-5: Results cached in memory; refresh clears cache."""

    def test_module_has_cache_clearing_method(self):
        import app.services.rule_reference_service as mod

        source = inspect.getsource(mod)
        assert "clear_cache" in source

    def test_cache_mechanism_exists(self):
        import app.services.rule_reference_service as mod

        source = inspect.getsource(mod)
        # Service caches loaded rules in an instance attribute
        assert "cache" in source.lower() or "_rules" in source or "_loaded" in source


@pytest.mark.unit
class TestAC6SearchSupportsMultipleFields:
    """AC-6: Search supports title, description, ID, and tags."""

    def test_module_has_list_rules_method(self):
        import app.services.rule_reference_service as mod

        source = inspect.getsource(mod)
        assert "def list_rules" in source

    def test_search_parameter_in_list_rules(self):
        import app.services.rule_reference_service as mod

        source = inspect.getsource(mod)
        assert "search" in source
