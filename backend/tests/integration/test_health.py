"""
Integration tests for the health check endpoint.

Tests:
- Health check returns 200
- Health check response structure
"""

import pytest


@pytest.mark.integration
class TestHealthCheck:
    def test_health_returns_200(self, client):
        """Health endpoint should return 200 when app is running."""
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_response_has_status(self, client):
        """Health response should include a status field."""
        resp = client.get("/health")
        data = resp.json()
        assert "status" in data
        assert data["status"] in ("healthy", "degraded", "unhealthy")
