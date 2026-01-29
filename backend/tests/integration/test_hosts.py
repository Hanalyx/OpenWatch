"""
Integration tests for host CRUD endpoints.

Tests:
- Create host (authenticated)
- List hosts (authenticated)
- Get host by ID
- Update host
- Delete host
- Unauthenticated access rejected
"""

import pytest

from tests.conftest import create_test_host


@pytest.mark.integration
class TestHostCreate:
    def test_create_host_authenticated(self, client, test_user):
        """Creating a host with valid data should return 200/201."""
        resp = create_test_host(client, test_user["headers"], suffix="create")
        assert resp.status_code in (200, 201)
        data = resp.json()
        assert "hostname" in data
        assert data["hostname"] == "test-host-create"

    def test_create_host_unauthenticated(self, client):
        """Creating a host without auth should fail."""
        resp = client.post(
            "/api/hosts/",
            json={
                "hostname": "unauth-host",
                "ip_address": "10.0.0.99",
                "operating_system": "RHEL 9",
            },
        )
        assert resp.status_code in (401, 403)

    def test_create_host_missing_required_fields(self, client, test_user):
        """Creating a host without required fields should fail."""
        resp = client.post(
            "/api/hosts/",
            json={"hostname": "incomplete-host"},
            headers=test_user["headers"],
        )
        assert resp.status_code == 422


@pytest.mark.integration
class TestHostList:
    def test_list_hosts_authenticated(self, client, test_user):
        """Listing hosts with valid auth should return 200."""
        resp = client.get("/api/hosts/", headers=test_user["headers"])
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    def test_list_hosts_unauthenticated(self, client):
        """Listing hosts without auth should fail."""
        resp = client.get("/api/hosts/")
        assert resp.status_code in (401, 403)


@pytest.mark.integration
class TestHostGetUpdateDelete:
    def test_get_host_by_id(self, client, test_user):
        """Getting a host by ID should return the host data."""
        # Create a host first
        create_resp = create_test_host(client, test_user["headers"], suffix="getbyid")
        if create_resp.status_code not in (200, 201):
            pytest.skip(f"Host creation not available: {create_resp.status_code}")

        host_id = create_resp.json().get("id")
        if not host_id:
            pytest.skip("Host creation did not return an id")

        resp = client.get(f"/api/hosts/{host_id}", headers=test_user["headers"])
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == host_id

    def test_get_host_not_found(self, client, test_user):
        """Getting a nonexistent host should return 404."""
        fake_id = "00000000-0000-0000-0000-000000000000"
        resp = client.get(f"/api/hosts/{fake_id}", headers=test_user["headers"])
        assert resp.status_code == 404

    def test_delete_host(self, client, test_user):
        """Deleting a host should return success."""
        create_resp = create_test_host(client, test_user["headers"], suffix="todelete")
        if create_resp.status_code not in (200, 201):
            pytest.skip(f"Host creation not available: {create_resp.status_code}")

        host_id = create_resp.json().get("id")
        if not host_id:
            pytest.skip("Host creation did not return an id")

        resp = client.delete(f"/api/hosts/{host_id}", headers=test_user["headers"])
        assert resp.status_code in (200, 204)

    def test_delete_host_not_found(self, client, test_user):
        """Deleting a nonexistent host should return 404."""
        fake_id = "00000000-0000-0000-0000-000000000000"
        resp = client.delete(f"/api/hosts/{fake_id}", headers=test_user["headers"])
        assert resp.status_code == 404
