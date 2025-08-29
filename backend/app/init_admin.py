#!/usr/bin/env python3.9
"""
Simple admin user initialization script
"""
import os
import sys
from sqlalchemy import create_engine, text
from passlib.context import CryptContext
from rbac import UserRole

# Database URL
DATABASE_URL = os.getenv("OPENWATCH_DATABASE_URL", "postgresql://openwatch:OpenWatch2025@localhost:5432/openwatch")

# Password hasher
pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__memory_cost=65536,
    argon2__time_cost=3,
    argon2__parallelism=1,
)

def create_admin_user():
    """Create default admin user if it doesn't exist"""
    engine = create_engine(DATABASE_URL)
    
    with engine.connect() as conn:
        # Check if admin user exists
        result = conn.execute(text("SELECT id FROM users WHERE username = 'admin'"))
        if result.fetchone():
            print("Admin user already exists")
            return
        
        # Create admin user
        hashed_password = pwd_context.hash("admin123")
        conn.execute(text("""
            INSERT INTO users (username, email, hashed_password, role, is_active, created_at, failed_login_attempts, mfa_enabled)
            VALUES ('admin', 'admin@example.com', :password, :role, true, CURRENT_TIMESTAMP, 0, false)
        """), {"password": hashed_password, "role": UserRole.SUPER_ADMIN.value})
        conn.commit()
        
        print("Admin user created successfully")
        print("Username: admin")
        print("Password: admin123")

if __name__ == "__main__":
    try:
        create_admin_user()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)