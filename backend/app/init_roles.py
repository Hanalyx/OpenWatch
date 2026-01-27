"""
Initialize roles and permissions in the database
"""

import asyncio
import json
import logging

from sqlalchemy import text
from sqlalchemy.orm import Session

from .database import SessionLocal, create_tables
from .rbac import ROLE_PERMISSIONS, UserRole

logger = logging.getLogger(__name__)


def init_roles(db: Session):
    """Initialize roles in the database"""

    role_definitions = {
        UserRole.SUPER_ADMIN: {
            "display_name": "Super Administrator",
            "description": "Full system access with user management capabilities",
        },
        UserRole.SECURITY_ADMIN: {
            "display_name": "Security Administrator",
            "description": "Security-focused administration without user management",
        },
        UserRole.SECURITY_ANALYST: {
            "display_name": "Security Analyst",
            "description": "Day-to-day security operations and scan execution",
        },
        UserRole.COMPLIANCE_OFFICER: {
            "display_name": "Compliance Officer",
            "description": "Compliance reporting and read-only access to results",
        },
        UserRole.AUDITOR: {
            "display_name": "Auditor",
            "description": "External audit support with read-only access",
        },
        UserRole.GUEST: {
            "display_name": "Guest",
            "description": "Limited read-only access to assigned resources",
        },
    }

    try:
        for role_name, role_info in role_definitions.items():
            # Check if role already exists
            result = db.execute(
                text("""
                SELECT id FROM roles WHERE name = :name
            """),
                {"name": role_name.value},
            )

            if result.fetchone():
                logger.info(f"Role {role_name.value} already exists, updating permissions...")
                # Update existing role permissions
                permissions_json = json.dumps([p.value for p in ROLE_PERMISSIONS[role_name]])
                db.execute(
                    text("""
                    UPDATE roles
                    SET permissions = :permissions,
                        display_name = :display_name,
                        description = :description,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE name = :name
                """),
                    {
                        "name": role_name.value,
                        "permissions": permissions_json,
                        "display_name": role_info["display_name"],
                        "description": role_info["description"],
                    },
                )
            else:
                logger.info(f"Creating role {role_name.value}...")
                # Create new role
                permissions_json = json.dumps([p.value for p in ROLE_PERMISSIONS[role_name]])
                db.execute(
                    text("""
                    INSERT INTO roles (
                        name, display_name, description, permissions, is_active, created_at, updated_at  # noqa: E501
                    )
                    VALUES (:name, :display_name, :description, :permissions, true, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """),
                    {
                        "name": role_name.value,
                        "display_name": role_info["display_name"],
                        "description": role_info["description"],
                        "permissions": permissions_json,
                    },
                )

        db.commit()
        logger.info("Roles initialized successfully")

    except Exception as e:
        logger.error(f"Error initializing roles: {e}")
        db.rollback()
        raise


def create_default_super_admin(db: Session):
    """Create default super admin user"""
    try:
        # Check if there's already a user with ID 1
        result = db.execute(text("SELECT id, role FROM users WHERE id = 1"))
        existing_user = result.fetchone()

        if existing_user:
            # Update existing user to super_admin role
            if existing_user.role != "super_admin":
                db.execute(text("UPDATE users SET role = 'super_admin' WHERE id = 1"))
                logger.info("Updated existing user (ID=1) to super_admin role")
            else:
                logger.info("User with ID=1 already has super_admin role")
        else:
            # Create new super admin user
            from .auth import pwd_context

            hashed_password = pwd_context.hash("admin123")  # Default password - should be changed

            db.execute(  # noqa: E501
                text("""
                INSERT INTO users (
                    id, username, email, hashed_password, role, is_active,
                    created_at, failed_login_attempts, mfa_enabled
                )
                VALUES (1, 'admin', 'admin@example.com', :password, 'super_admin', true, CURRENT_TIMESTAMP, 0, false)
            """),
                {"password": hashed_password},
            )
            logger.info("Created new super admin user (username: admin, password: admin123)")

        db.commit()

    except Exception as e:
        logger.error(f"Error creating default super admin: {e}")
        db.rollback()
        raise


def init_default_system_credentials(db: Session):
    """
    Check for system credentials existence (no longer creates placeholder)

    System credentials are optional - hosts can have their own credentials.
    Users should create system credentials via Settings UI if they want
    a default credential set for all hosts.

    Updated 2025-11-04: Removed placeholder credential creation for cleaner UX
    """
    try:
        # Check if system-level credentials exist in unified_credentials
        result = db.execute(text("""
            SELECT COUNT(*) as count
            FROM unified_credentials
            WHERE scope = 'system' AND is_active = true
        """))

        existing_count = result.fetchone().count

        if existing_count > 0:
            logger.info(f"Found {existing_count} existing system credentials")
        else:
            logger.info(
                "No system credentials configured - users can create them in Settings if needed. "
                "Hosts can use individual credentials without system defaults."
            )

    except Exception as e:
        logger.error(f"Error checking system credentials: {e}")
        db.rollback()
        raise


async def initialize_rbac_system() -> None:
    """Initialize the complete RBAC system including default credentials."""
    try:
        # Ensure tables exist
        create_tables()

        # Initialize roles and system components
        db = SessionLocal()
        try:
            init_roles(db)
            create_default_super_admin(db)
            init_default_system_credentials(db)
            logger.info("RBAC system and default credentials initialized successfully")
        finally:
            db.close()

    except Exception as e:
        logger.error(f"Failed to initialize RBAC system: {e}")
        raise


if __name__ == "__main__":
    # Run initialization
    asyncio.run(initialize_rbac_system())
