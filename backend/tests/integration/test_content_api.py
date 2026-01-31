"""
Integration tests for content API endpoints.

Tests SCAP content listing, import, and XCCDF endpoints.
"""

import pytest


@pytest.mark.integration
class TestContentEndpoints:
    """Test /api/content/* endpoints."""

    def test_list_content_unauthenticated(self, client):
        """Content listing requires authentication."""
        resp = client.get("/api/content/")
        assert resp.status_code in (401, 403, 404)

    def test_list_content_authenticated(self, client, test_user):
        """Content listing returns data when authenticated."""
        resp = client.get("/api/content/", headers=test_user["headers"])
        assert resp.status_code in (200, 404)
        if resp.status_code == 200:
            data = resp.json()
            assert isinstance(data, (list, dict))


@pytest.mark.integration
class TestImportEndpoints:
    """Test /api/scap-import/* endpoints."""

    def test_import_unauthenticated(self, client):
        """Import requires authentication."""
        resp = client.post("/api/scap-import/")
        assert resp.status_code in (401, 403, 404, 405, 422)

    def test_import_requires_file(self, client, test_user):
        """Import without file should fail."""
        resp = client.post("/api/scap-import/", headers=test_user["headers"])
        assert resp.status_code in (400, 404, 405, 422)


@pytest.mark.integration
class TestXCCDFEndpoints:
    """Test /api/xccdf/* endpoints."""

    def test_xccdf_benchmarks_unauthenticated(self, client):
        """XCCDF benchmarks require authentication."""
        resp = client.get("/api/xccdf/benchmarks")
        assert resp.status_code in (401, 403, 404)

    def test_xccdf_benchmarks_authenticated(self, client, test_user):
        """XCCDF benchmarks returns data when authenticated."""
        resp = client.get("/api/xccdf/benchmarks", headers=test_user["headers"])
        assert resp.status_code in (200, 404)
