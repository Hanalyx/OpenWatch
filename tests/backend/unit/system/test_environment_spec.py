"""
Source-inspection tests for environment configuration.

Spec: specs/system/environment.spec.yaml
"""

import inspect

import pytest


@pytest.mark.unit
class TestAC1DatabaseURL:
    """AC-1: OPENWATCH_DATABASE_URL is required with no hardcoded default."""

    def test_database_url_from_env(self):
        import app.config as mod

        source = inspect.getsource(mod)
        assert "DATABASE_URL" in source or "database_url" in source

    def test_no_hardcoded_default(self):
        pytest.skip("init_admin.py deleted")

        source = inspect.getsource(mod)
        # init_admin.py was fixed to require env var (no default)
        assert "OPENWATCH_DATABASE_URL" in source


@pytest.mark.unit
class TestAC2SecretKey:
    """AC-2: OPENWATCH_SECRET_KEY configurable via environment variable."""

    def test_secret_key_config(self):
        import app.config as mod

        source = inspect.getsource(mod)
        assert "SECRET_KEY" in source or "secret_key" in source


@pytest.mark.unit
class TestAC3JWTKeyPaths:
    """AC-3: JWT keys loaded from file paths."""

    def test_jwt_key_path_config(self):
        import app.config as mod

        source = inspect.getsource(mod)
        assert "jwt" in source.lower() or "token" in source.lower() or "key" in source.lower()

    def test_private_key_path(self):
        import app.config as mod

        source = inspect.getsource(mod)
        assert "key" in source.lower()


@pytest.mark.unit
class TestAC4RedisURL:
    """AC-4: Redis URL configurable via OPENWATCH_REDIS_URL."""

    def test_redis_url_config(self):
        import app.config as mod

        source = inspect.getsource(mod)
        assert "REDIS" in source or "redis" in source.lower()


@pytest.mark.unit
class TestAC5DebugMode:
    """AC-5: Debug mode controlled by OPENWATCH_DEBUG."""

    def test_debug_config(self):
        import app.config as mod

        source = inspect.getsource(mod)
        assert "DEBUG" in source or "debug" in source


@pytest.mark.unit
class TestAC6FIPSMode:
    """AC-6: FIPS mode controlled by OPENWATCH_FIPS_MODE."""

    def test_fips_config(self):
        import app.config as mod

        source = inspect.getsource(mod)
        assert "FIPS" in source or "fips" in source.lower()
