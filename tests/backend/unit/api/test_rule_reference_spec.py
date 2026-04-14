"""
Rule Reference API spec compliance tests.
Verifies that routes/rules/reference.py implements the behavioral contract
defined in the rule-reference spec via source inspection.

Spec: specs/api/rules/rule-reference.spec.yaml
"""

import inspect

import pytest


@pytest.mark.unit
class TestAC1ListRulesFilters:
    """AC-1: List rules supports framework, severity, capability, tags filters."""

    def test_list_rules_has_framework_param(self):
        import app.routes.rules.reference as mod

        source = inspect.getsource(mod.list_rules)
        assert "framework" in source

    def test_list_rules_has_severity_param(self):
        import app.routes.rules.reference as mod

        source = inspect.getsource(mod.list_rules)
        assert "severity" in source

    def test_list_rules_has_capability_param(self):
        import app.routes.rules.reference as mod

        source = inspect.getsource(mod.list_rules)
        assert "capability" in source

    def test_list_rules_has_tags_param(self):
        import app.routes.rules.reference as mod

        source = inspect.getsource(mod.list_rules)
        assert "tags" in source


@pytest.mark.unit
class TestAC2ListRulesPagination:
    """AC-2: List rules supports pagination (page/per_page, max 200 per page)."""

    def test_list_rules_has_page_param(self):
        import app.routes.rules.reference as mod

        source = inspect.getsource(mod.list_rules)
        assert "page" in source

    def test_list_rules_has_per_page_param(self):
        import app.routes.rules.reference as mod

        source = inspect.getsource(mod.list_rules)
        assert "per_page" in source

    def test_list_rules_max_200_per_page(self):
        import app.routes.rules.reference as mod

        source = inspect.getsource(mod.list_rules)
        assert "le=200" in source


@pytest.mark.unit
class TestAC3GetRuleByIdReturnsDetail:
    """AC-3: Get rule by ID returns RuleDetailResponse."""

    def test_get_rule_returns_detail_response(self):
        import app.routes.rules.reference as mod

        source = inspect.getsource(mod.get_rule)
        assert "RuleDetailResponse" in source

    def test_get_rule_returns_404_if_missing(self):
        import app.routes.rules.reference as mod

        source = inspect.getsource(mod.get_rule)
        assert "404" in source or "HTTP_404_NOT_FOUND" in source


@pytest.mark.unit
class TestAC4StatisticsEndpoint:
    """AC-4: Statistics endpoint returns rule/framework/category/capability counts."""

    def test_stats_calls_get_statistics(self):
        import app.routes.rules.reference as mod

        source = inspect.getsource(mod.get_rule_statistics)
        assert "get_statistics" in source


@pytest.mark.unit
class TestAC5FrameworksEndpoint:
    """AC-5: Frameworks endpoint lists available compliance frameworks."""

    def test_frameworks_calls_list_frameworks(self):
        import app.routes.rules.reference as mod

        source = inspect.getsource(mod.list_frameworks)
        assert "list_frameworks" in source

    def test_frameworks_returns_framework_list_response(self):
        import app.routes.rules.reference as mod

        source = inspect.getsource(mod.list_frameworks)
        assert "FrameworkListResponse" in source


@pytest.mark.unit
class TestAC6VariablesEndpoint:
    """AC-6: Variables endpoint lists configurable Kensa variables."""

    def test_variables_calls_list_variables(self):
        import app.routes.rules.reference as mod

        source = inspect.getsource(mod.list_variables)
        assert "list_variables" in source

    def test_variables_returns_variable_list_response(self):
        import app.routes.rules.reference as mod

        source = inspect.getsource(mod.list_variables)
        assert "VariableListResponse" in source


@pytest.mark.unit
class TestAC7RefreshEndpoint:
    """AC-7: Refresh endpoint clears rules cache."""

    def test_refresh_calls_clear_cache(self):
        import app.routes.rules.reference as mod

        source = inspect.getsource(mod.refresh_rules_cache)
        assert "clear_cache" in source


@pytest.mark.unit
class TestAC8AllEndpointsUseSingleton:
    """AC-8: All endpoints use RuleReferenceService singleton."""

    def test_list_rules_uses_singleton(self):
        import app.routes.rules.reference as mod

        source = inspect.getsource(mod.list_rules)
        assert "get_rule_reference_service()" in source

    def test_get_rule_uses_singleton(self):
        import app.routes.rules.reference as mod

        source = inspect.getsource(mod.get_rule)
        assert "get_rule_reference_service()" in source

    def test_stats_uses_singleton(self):
        import app.routes.rules.reference as mod

        source = inspect.getsource(mod.get_rule_statistics)
        assert "get_rule_reference_service()" in source

    def test_frameworks_uses_singleton(self):
        import app.routes.rules.reference as mod

        source = inspect.getsource(mod.list_frameworks)
        assert "get_rule_reference_service()" in source

    def test_variables_uses_singleton(self):
        import app.routes.rules.reference as mod

        source = inspect.getsource(mod.list_variables)
        assert "get_rule_reference_service()" in source

    def test_refresh_uses_singleton(self):
        import app.routes.rules.reference as mod

        source = inspect.getsource(mod.refresh_rules_cache)
        assert "get_rule_reference_service()" in source

    def test_module_imports_singleton_function(self):
        import app.routes.rules.reference as mod

        source = inspect.getsource(mod)
        assert "from ...services.rule_reference_service import get_rule_reference_service" in source
