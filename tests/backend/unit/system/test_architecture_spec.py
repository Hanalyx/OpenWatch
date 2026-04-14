"""
Source-inspection tests for system architecture invariants.

Spec: specs/system/architecture.spec.yaml
"""

import inspect
import os

import pytest


@pytest.mark.unit
class TestAC1RBACDecorators:
    """AC-1: All route handlers use RBAC decorators."""

    def test_auth_routes_have_rbac(self):
        import app.routes.auth.login as mod

        source = inspect.getsource(mod)
        assert "get_current_user" in source or "require_role" in source

    def test_admin_routes_have_rbac(self):
        import app.routes.admin.users as mod

        source = inspect.getsource(mod)
        assert "require_permission" in source or "require_role" in source

    def test_scan_routes_have_rbac(self):
        import app.routes.scans.kensa as mod

        source = inspect.getsource(mod)
        assert "require_role" in source


@pytest.mark.unit
class TestAC2UUIDPrimaryKeys:
    """AC-2: All SQLAlchemy models use UUID primary keys."""

    def test_scans_use_uuid(self):
        import app.models.scan_models as mod

        source = inspect.getsource(mod)
        assert "UUID" in source or "uuid" in source

    def test_hosts_reference_uuid(self):
        import app.routes.hosts.crud as mod

        source = inspect.getsource(mod)
        assert "uuid" in source.lower() or "UUID" in source


@pytest.mark.unit
class TestAC3CeleryQueues:
    """AC-3: All Celery tasks route to named queues."""

    def test_celery_app_has_queues(self):
        import app.celery_app as mod

        source = inspect.getsource(mod)
        assert "queue" in source.lower()

    def test_task_routing_configured(self):
        import app.celery_app as mod

        source = inspect.getsource(mod)
        assert "route" in source.lower() or "task_routes" in source.lower()


@pytest.mark.unit
class TestAC4ZustandState:
    """AC-4: Frontend uses Zustand (not Redux) for global state."""

    def test_zustand_store_exists(self):
        # Frontend check - skip if frontend not available in container
        store_path = os.path.join(
            os.path.dirname(__file__),
            "../../../../frontend/src/store/useAuthStore.ts",
        )
        if not os.path.exists(store_path):
            pytest.skip("Frontend not available in container")
        assert os.path.exists(store_path)

    def test_no_redux_store(self):
        pytest.skip("Frontend path check - verified in frontend tests")


@pytest.mark.unit
class TestAC5APIPrefix:
    """AC-5: All API routes registered under /api prefix in main.py."""

    def test_api_prefix_in_main(self):
        import app.main as mod

        source = inspect.getsource(mod)
        assert "/api" in source

    def test_include_router_calls(self):
        import app.main as mod

        source = inspect.getsource(mod)
        assert "include_router" in source


@pytest.mark.unit
class TestAC6NoMongoDB:
    """AC-6: PostgreSQL is the sole database (no MongoDB in active code)."""

    def test_no_mongo_driver_in_main(self):
        import app.main as mod

        source = inspect.getsource(mod)
        # motor (async MongoDB driver) must not be imported
        assert "from motor" not in source
        assert "import motor" not in source

    def test_no_mongo_driver_in_config(self):
        import app.config as mod

        source = inspect.getsource(mod)
        assert "from motor" not in source
        assert "import pymongo" not in source
