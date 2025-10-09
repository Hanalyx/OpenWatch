"""
Pytest configuration and fixtures for OpenWatch backend tests.
"""
import pytest
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from fastapi.testclient import TestClient

# Test database configuration
# Uses the same PostgreSQL instance as dev, but separate database
TEST_DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL",
    "postgresql://openwatch:openwatch_secure_db_2025@localhost:5432/openwatch_test"
)


@pytest.fixture(scope="session")
def test_engine():
    """Create test database engine"""
    engine = create_engine(TEST_DATABASE_URL)
    yield engine
    engine.dispose()


@pytest.fixture(scope="function")
def db_session(test_engine) -> Session:
    """Provide database session for tests with automatic rollback"""
    SessionLocal = sessionmaker(bind=test_engine)
    session = SessionLocal()

    yield session

    session.rollback()
    session.close()


@pytest.fixture(scope="module")
def client():
    """Provide FastAPI test client"""
    from app.main import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def admin_token(client):
    """Get admin JWT token for authenticated requests"""
    response = client.post("/api/auth/login", json={
        "username": "admin",
        "password": "admin"
    })

    if response.status_code != 200:
        pytest.skip("Admin login not available in test environment")

    return response.json().get("access_token")
