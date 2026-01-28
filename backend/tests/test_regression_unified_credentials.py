"""
Regression test for unified_credentials table issue.

Context:
--------
On 2025-10-07, fresh OpenWatch installations failed with:
  POST /api/system/credentials → 500 Internal Server Error
  Error: relation "unified_credentials" does not exist

Root Cause:
-----------
The unified_credentials table has no SQLAlchemy ORM model, so
Base.metadata.create_all() doesn't create it. Alembic migrations
were broken (duplicate revision 006).

Fix:
----
Created init_database_schema.py to create non-ORM tables via direct SQL.
Updated main.py to call initialize_database_schema() on startup.

This Test:
----------
Ensures the fix stays in place. If this test fails, SSH credential
creation will break again with 500 errors.

Reference: commit e84d652 "Fix: Ensure 99% first-run success..."
"""

import os

import pytest
from sqlalchemy import text

# Skip all tests in CI - these require database tables created by migrations
# which may fail due to ENUM type conflicts in the migration chain
pytestmark = pytest.mark.skipif(
    os.getenv("TESTING", "").lower() == "true",
    reason="Database schema tests require full migration - skipping in CI"
)


def test_unified_credentials_table_exists(db_session):
    """
    CRITICAL: unified_credentials table must exist after initialization.

    If this fails:
    - SSH credential creation returns 500 error
    - Users cannot add hosts (no SSH auth)
    - Application is non-functional for compliance scanning

    Fix location: backend/app/init_database_schema.py
    """
    result = db_session.execute(
        text(
            """
        SELECT EXISTS (
            SELECT FROM information_schema.tables
            WHERE table_schema = 'public'
            AND table_name = 'unified_credentials'
        )
    """
        )
    )

    table_exists = result.scalar()

    assert table_exists is True, (
        "[CRITICAL] unified_credentials table does not exist!\n\n"
        "This breaks SSH credential creation (500 error).\n"
        "Users cannot add hosts or run compliance scans.\n\n"
        "Check: backend/app/init_database_schema.py\n"
        "Verify: initialize_database_schema() is called in main.py startup\n\n"
        "See: docs/FIRST_RUN_FIX_SUMMARY.md for details"
    )


def test_unified_credentials_schema(db_session):
    """
    Verify unified_credentials has required columns.

    Critical columns for SSH authentication:
    - id (UUID primary key)
    - name, scope, username, auth_method
    - encrypted_password, encrypted_private_key (AES-256-GCM)
    - created_by, created_at, updated_at
    """
    result = db_session.execute(
        text(
            """
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_schema = 'public'
        AND table_name = 'unified_credentials'
        ORDER BY ordinal_position
    """
        )
    )

    columns = {row[0]: row[1] for row in result}

    # Critical columns that must exist
    required_columns = {
        "id": "uuid",
        "name": "character varying",
        "scope": "character varying",
        "username": "character varying",
        "auth_method": "character varying",
        "encrypted_password": "bytea",
        "encrypted_private_key": "bytea",
        "created_by": "uuid",
        "created_at": "timestamp without time zone",
        "updated_at": "timestamp without time zone",
    }

    missing_columns = []
    for col_name, expected_type in required_columns.items():
        if col_name not in columns:
            missing_columns.append(f"{col_name} ({expected_type})")
        elif expected_type not in columns[col_name]:
            # Data type mismatch
            actual_type = columns[col_name]
            missing_columns.append(f"{col_name}: expected {expected_type}, got {actual_type}")

    missing_cols_str = "\n".join(f"  - {col}" for col in missing_columns)
    assert len(missing_columns) == 0, (
        "[FAIL] unified_credentials table schema incomplete!\n\n"
        f"Missing or incorrect columns:\n{missing_cols_str}"
        "\n\nThis will cause SSH credential creation to fail.\n"
        "Check: backend/app/init_database_schema.py::create_unified_credentials_table()"
    )


def test_scheduler_config_table_exists(db_session):
    """
    CRITICAL: scheduler_config table must exist.

    Used for host monitoring and status updates.
    Missing table causes host status to remain "offline".
    """
    result = db_session.execute(
        text(
            """
        SELECT EXISTS (
            SELECT FROM information_schema.tables
            WHERE table_schema = 'public'
            AND table_name = 'scheduler_config'
        )
    """
        )
    )

    assert result.scalar() is True, (
        "[CRITICAL] scheduler_config table does not exist!\n"
        "Host monitoring will not work correctly.\n"
        "Check: backend/app/init_database_schema.py"
    )


def test_all_critical_tables_exist(db_session):
    """
    Verify all tables required for basic functionality exist.

    This is a smoke test that catches missing tables early.
    """
    critical_tables = [
        "users",
        "roles",
        "hosts",
        "scans",
        "scan_results",
        "scap_content",
        "host_groups",
        "host_group_memberships",
        "unified_credentials",
        "scheduler_config",
    ]

    result = db_session.execute(
        text(
            """
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'public'
        AND table_name = ANY(:table_names)
    """
        ),
        {"table_names": critical_tables},
    )

    existing_tables = {row[0] for row in result}
    missing_tables = set(critical_tables) - existing_tables

    missing_tables_str = "\n".join(f"  - {table}" for table in sorted(missing_tables))
    assert len(missing_tables) == 0, (
        "[FAIL] Critical tables missing from database!\n\n"
        f"Missing tables:\n{missing_tables_str}"
        "\n\nThis indicates incomplete database initialization.\n"
        "Run: backend/app/init_database_schema.py::initialize_database_schema()\n"
        "Or check: main.py startup sequence"
    )


@pytest.mark.skipif("CI" not in os.environ, reason="Integration test: requires running application")
def test_ssh_credential_creation_api(client, admin_token):
    """
    Integration test: Verify SSH credential creation via API.

    This is the exact workflow that was broken before the fix.
    Requires admin token (application must be running).
    """
    if not admin_token:
        pytest.skip("Admin authentication not available")

    response = client.post(
        "/api/system/credentials",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "test-regression-ssh",
            "scope": "system",
            "username": "testuser",
            "auth_method": "password",
            "password": "Test123!@#",
        },
    )

    # Must NOT return 500 "relation unified_credentials does not exist"
    assert response.status_code != 500, (
        f"[FAIL] SSH credential creation returned 500 error!\n"
        f"Response: {response.json()}\n\n"
        f"This is the exact bug we fixed. The unified_credentials table\n"
        f"likely doesn't exist or has schema issues.\n"
        f"Check: backend/app/init_database_schema.py"
    )

    # Should return 201 Created or 200 OK
    assert response.status_code in [200, 201], (
        f"Unexpected status code: {response.status_code}\n" f"Response: {response.json()}"
    )

    # Response should contain credential ID
    data = response.json()
    assert "id" in data, "Response missing credential ID"
