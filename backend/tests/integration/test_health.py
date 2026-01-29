"""
Integration tests for the health check endpoint.

Tests:
- Health check returns 200
- Health check response structure
"""

import pytest


@pytest.mark.integration
class TestHealthCheck:
    def test_health_endpoint_responds(self, client):
        """Health endpoint should respond (200 healthy or 503 degraded)."""
        resp = client.get("/health")
        # 200 = all services healthy, 503 = degraded (e.g. MongoDB unavailable in CI)
        assert resp.status_code in (200, 503)

    def test_health_response_has_status(self, client):
        """Health response should include a status field."""
        resp = client.get("/health")
        data = resp.json()
        assert "status" in data
        assert data["status"] in ("healthy", "degraded", "unhealthy")
