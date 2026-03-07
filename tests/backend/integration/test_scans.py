"""
Integration tests for scan endpoints.

Tests:
- List scans (authenticated)
- Get scan by ID
- Unauthenticated access rejected
"""

import pytest


@pytest.mark.integration
class TestScanList:
    def test_list_scans_authenticated(self, client, test_user):
        """Listing scans with valid auth should return 200."""
        resp = client.get("/api/scans/", headers=test_user["headers"])
        assert resp.status_code == 200
        data = resp.json()
        # Response is a dict with scans list or a list directly
        assert isinstance(data, (list, dict))

    def test_list_scans_unauthenticated(self, client):
        """Listing scans without auth should fail."""
        resp = client.get("/api/scans/")
        assert resp.status_code in (401, 403)

    def test_list_scans_with_filters(self, client, test_user):
        """Listing scans with filter params should return 200."""
        resp = client.get(
            "/api/scans/",
            params={"status": "completed", "limit": 10},
            headers=test_user["headers"],
        )
        assert resp.status_code == 200


@pytest.mark.integration
class TestScanGet:
    def test_get_scan_not_found(self, client, test_user):
        """Getting a nonexistent scan should return 404."""
        fake_id = "00000000-0000-0000-0000-000000000000"
        resp = client.get(f"/api/scans/{fake_id}", headers=test_user["headers"])
        assert resp.status_code == 404

    def test_get_scan_unauthenticated(self, client):
        """Getting a scan without auth should fail."""
        fake_id = "00000000-0000-0000-0000-000000000000"
        resp = client.get(f"/api/scans/{fake_id}")
        assert resp.status_code in (401, 403)
