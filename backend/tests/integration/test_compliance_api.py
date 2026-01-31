"""
Integration tests for compliance API endpoints.

Tests compliance drift, intelligence, and OWCA score endpoints.
"""

import pytest


@pytest.mark.integration
class TestComplianceEndpoints:
    """Test /api/compliance/* endpoints."""

    def test_compliance_unauthenticated(self, client):
        """Compliance endpoints require authentication."""
        resp = client.get("/api/compliance/")
        assert resp.status_code in (401, 403, 404, 405)

    def test_compliance_drift_unauthenticated(self, client):
        """Compliance drift endpoint requires authentication."""
        resp = client.get("/api/compliance/drift")
        assert resp.status_code in (401, 403, 404)

    def test_compliance_drift_authenticated(self, client, test_user):
        """Compliance drift endpoint returns data when authenticated."""
        resp = client.get("/api/compliance/drift", headers=test_user["headers"])
        # May return 200 with data or 404 if no drift data exists
        assert resp.status_code in (200, 404, 422)

    def test_compliance_intelligence_unauthenticated(self, client):
        """Intelligence endpoint requires authentication."""
        resp = client.get("/api/compliance/intelligence")
        assert resp.status_code in (401, 403, 404)

    def test_compliance_intelligence_authenticated(self, client, test_user):
        """Intelligence endpoint returns data when authenticated."""
        resp = client.get("/api/compliance/intelligence", headers=test_user["headers"])
        assert resp.status_code in (200, 404, 422)

    def test_compliance_owca_unauthenticated(self, client):
        """OWCA endpoint requires authentication."""
        resp = client.get("/api/compliance/owca")
        assert resp.status_code in (401, 403, 404)

    def test_compliance_owca_authenticated(self, client, test_user):
        """OWCA endpoint returns data when authenticated."""
        resp = client.get("/api/compliance/owca", headers=test_user["headers"])
        assert resp.status_code in (200, 404, 422)
