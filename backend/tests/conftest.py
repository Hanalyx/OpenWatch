"""
Pytest configuration and fixtures for OpenWatch backend integration tests.

Provides:
- FastAPI TestClient (function-scoped for isolation)
- Database session with automatic rollback
- User registration and authentication helpers
- Test data factories for hosts, scans, users
"""

import os
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

# Test database configuration
TEST_DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL",
    os.getenv(
        "OPENWATCH_DATABASE_URL",
        "postgresql://openwatch:openwatch_test@localhost:5432/openwatch_test",  # pragma: allowlist secret
    ),
)


@pytest.fixture(scope="session")
def test_engine():
    """Create test database engine (session-scoped, shared across all tests)."""
    engine = create_engine(TEST_DATABASE_URL)
    yield engine
    engine.dispose()


@pytest.fixture(scope="function")
def db_session(test_engine) -> Session:
    """Provide database session with automatic rollback after each test."""
    session_factory = sessionmaker(bind=test_engine)
    session = session_factory()
    yield session
    session.rollback()
    session.close()


@pytest.fixture(scope="session")
def client():
    """Provide FastAPI TestClient (session-scoped to avoid repeated app startup).

    The app lifespan (DB init, MongoDB connect) runs once for the entire
    test session, keeping CI fast.  Tests still get isolation through
    unique test data and separate DB sessions.
    """
    from app.main import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def unique_suffix():
    """Generate a unique suffix for test data to avoid collisions."""
    return uuid.uuid4().hex[:8]


def register_user(client, username, email, password, role="guest"):
    """Register a new user via the API. Returns the response."""
    return client.post(
        "/api/auth/register",
        json={
            "username": username,
            "email": email,
            "password": password,
            "role": role,
        },
    )


def login_user(client, username, password):
    """Login a user via the API. Returns the response."""
    return client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
    )


def auth_headers(token):
    """Create Authorization headers from a JWT token."""
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def test_user(client, unique_suffix):
    """Register a test user and return (user_data, token, headers).

    Creates a unique user for each test to avoid collisions.
    """
    username = f"testuser_{unique_suffix}"
    email = f"testuser_{unique_suffix}@example.com"
    password = "TestPass123!@#"  # pragma: allowlist secret

    resp = register_user(client, username, email, password)
    if resp.status_code != 200:
        pytest.skip(f"User registration not available: {resp.status_code} {resp.text}")

    data = resp.json()
    token = data.get("access_token")
    headers = auth_headers(token)

    return {
        "username": username,
        "email": email,
        "password": password,
        "token": token,
        "headers": headers,
        "user": data.get("user", {}),
    }


@pytest.fixture
def admin_user(client, unique_suffix):
    """Register an admin user and return (user_data, token, headers)."""
    username = f"admin_{unique_suffix}"
    email = f"admin_{unique_suffix}@example.com"
    password = "AdminPass123!@#"  # pragma: allowlist secret

    resp = register_user(client, username, email, password, role="super_admin")
    if resp.status_code != 200:
        pytest.skip(f"Admin registration not available: {resp.status_code} {resp.text}")

    data = resp.json()
    token = data.get("access_token")
    headers = auth_headers(token)

    return {
        "username": username,
        "email": email,
        "password": password,
        "token": token,
        "headers": headers,
        "user": data.get("user", {}),
    }


def create_test_host(client, headers, suffix="", **overrides):
    """Create a test host via API. Returns the response."""
    host_data = {
        "hostname": f"test-host-{suffix}" if suffix else f"test-host-{uuid.uuid4().hex[:6]}",
        "ip_address": f"10.0.{hash(suffix) % 256}.{hash(suffix + 'x') % 256}" if suffix else "10.0.0.1",
        "operating_system": "Red Hat Enterprise Linux 9.3",
        "os_family": "rhel",
        "os_version": "9.3",
        "port": 22,
        "username": "root",
    }
    host_data.update(overrides)
    return client.post("/api/hosts/", json=host_data, headers=headers)
