"""
Initialize roles and permissions in the database
"""

import asyncio
import base64
from sqlalchemy.orm import Session
from sqlalchemy import text
from .database import SessionLocal, create_tables
from .rbac import UserRole, ROLE_PERMISSIONS
from .encryption import create_encryption_service
from .config import get_settings
import logging
import json
from datetime import datetime

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
                text(
                    """
                SELECT id FROM roles WHERE name = :name
            """
                ),
                {"name": role_name.value},
            )

            if result.fetchone():
                logger.info(f"Role {role_name.value} already exists, updating permissions...")
                # Update existing role permissions
                permissions_json = json.dumps([p.value for p in ROLE_PERMISSIONS[role_name]])
                db.execute(
                    text(
                        """
                    UPDATE roles 
                    SET permissions = :permissions, 
                        display_name = :display_name,
                        description = :description,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE name = :name
                """
                    ),
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
                    text(
                        """
                    INSERT INTO roles (name, display_name, description, permissions, is_active, created_at, updated_at)
                    VALUES (:name, :display_name, :description, :permissions, true, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """
                    ),
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

            db.execute(
                text(
                    """
                INSERT INTO users (id, username, email, hashed_password, role, is_active, created_at, failed_login_attempts, mfa_enabled)
                VALUES (1, 'admin', 'admin@example.com', :password, 'super_admin', true, CURRENT_TIMESTAMP, 0, false)
            """
                ),
                {"password": hashed_password},
            )
            logger.info("Created new super admin user (username: admin, password: admin123)")

        db.commit()

    except Exception as e:
        logger.error(f"Error creating default super admin: {e}")
        db.rollback()
        raise


def init_default_system_credentials(db: Session):
    """Initialize default system SSH credentials for frictionless onboarding"""
    try:
        # Check if any system credentials already exist
        result = db.execute(
            text(
                """
            SELECT COUNT(*) as count FROM system_credentials WHERE is_active = true
        """
            )
        )

        existing_count = result.fetchone().count

        if existing_count > 0:
            logger.info(
                f"Found {existing_count} existing system credentials, skipping initialization"
            )
            return

        logger.info("No system credentials found - creating placeholder credentials for easy setup")

        # Create placeholder credentials that guide users to configure actual credentials
        placeholder_description = (
            "Default placeholder credentials - PLEASE UPDATE with your actual SSH credentials. "
            "This entry provides a starting point for SSH-based scanning and monitoring. "
            "Update the username, password, or SSH key to match your environment."
        )

        current_time = datetime.utcnow()

        # Encrypt placeholder password using new encryption service
        settings = get_settings()
        encryption_service = create_encryption_service(master_key=settings.master_key)
        encrypted_bytes = encryption_service.encrypt(b"CHANGE_ME_PLEASE")
        encrypted_password = base64.b64encode(encrypted_bytes).decode("ascii")

        # Insert placeholder credentials (no actual sensitive data)
        db.execute(
            text(
                """
            INSERT INTO system_credentials
            (name, description, username, auth_method, encrypted_password,
             encrypted_private_key, private_key_passphrase, is_default, is_active,
             created_by, created_at, updated_at)
            VALUES (:name, :description, :username, :auth_method, :encrypted_password,
                    :encrypted_private_key, :private_key_passphrase, :is_default, :is_active,
                    :created_by, :created_at, :updated_at)
        """
            ),
            {
                "name": "Setup Required - Default SSH Credentials",
                "description": placeholder_description,
                "username": "root",
                "auth_method": "password",
                "encrypted_password": encrypted_password,  # Obvious placeholder
                "encrypted_private_key": None,
                "private_key_passphrase": None,
                "is_default": True,
                "is_active": True,
                "created_by": 1,  # Created by default admin user
                "created_at": current_time,
                "updated_at": current_time,
            },
        )

        db.commit()

        logger.info(
            "Created placeholder system credentials - users should update these in Settings"
        )
        logger.warning(
            "SECURITY NOTICE: Default SSH credentials created with placeholder password. Users must update these credentials in Settings before performing SSH operations."
        )

    except Exception as e:
        logger.error(f"Error creating default system credentials: {e}")
        db.rollback()
        raise


async def initialize_rbac_system():
    """Initialize the complete RBAC system including default credentials"""
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
