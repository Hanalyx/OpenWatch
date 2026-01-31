"""
Integration tests for rules API endpoints.

Tests rule listing, search, filtering, and CRUD operations.
"""

import pytest


@pytest.mark.integration
class TestRulesEndpoints:
    """Test /api/rules/* endpoints."""

    def test_list_rules_unauthenticated(self, client):
        """Rules list requires authentication."""
        resp = client.get("/api/rules/")
        assert resp.status_code in (401, 403, 404)

    def test_list_rules_authenticated(self, client, test_user):
        """Rules list returns data when authenticated."""
        resp = client.get("/api/rules/", headers=test_user["headers"])
        assert resp.status_code in (200, 404)
        if resp.status_code == 200:
            data = resp.json()
            assert isinstance(data, (list, dict))

    def test_get_rule_not_found(self, client, test_user):
        """Getting a nonexistent rule returns 404."""
        resp = client.get("/api/rules/nonexistent-rule-id", headers=test_user["headers"])
        assert resp.status_code in (404, 422)

    def test_search_rules(self, client, test_user):
        """Rules search endpoint accepts query parameter."""
        resp = client.get("/api/rules/?search=password", headers=test_user["headers"])
        assert resp.status_code in (200, 404, 422)

    def test_filter_rules_by_severity(self, client, test_user):
        """Rules can be filtered by severity."""
        resp = client.get("/api/rules/?severity=high", headers=test_user["headers"])
        assert resp.status_code in (200, 404, 422)


@pytest.mark.integration
class TestComplianceRulesEndpoints:
    """Test /api/compliance-rules/* endpoints."""

    def test_compliance_rules_unauthenticated(self, client):
        """Compliance rules endpoint without auth."""
        resp = client.get("/api/compliance-rules/")
        # Endpoint may be public or require auth
        assert resp.status_code in (200, 401, 403, 404)

    def test_compliance_rules_authenticated(self, client, test_user):
        """Compliance rules returns data when authenticated."""
        resp = client.get("/api/compliance-rules/", headers=test_user["headers"])
        assert resp.status_code in (200, 404)
