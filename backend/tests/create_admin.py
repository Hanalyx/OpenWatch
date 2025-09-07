#!/usr/bin/env python3
"""Create admin user for OpenWatch"""
import os
import sys
from app.database import SessionLocal
from app.auth import pwd_context
from sqlalchemy import text
import uuid

import secrets
import string

# Generate secure admin credentials (should be changed after first login)
username = os.getenv("ADMIN_USERNAME", "admin")
email = os.getenv("ADMIN_EMAIL", "admin@openwatch.local")
# Generate a secure random password if not provided via environment
default_password = ''.join(secrets.choice(string.ascii_letters + string.digits + '!@#$%^&*') for _ in range(16))
password = os.getenv("ADMIN_PASSWORD", default_password)

db = SessionLocal()

try:
    # Check if user exists
    result = db.execute(text("SELECT id FROM users WHERE username = :username"), {"username": username})
    if result.first():
        print(f"User {username} already exists")
        sys.exit(0)
    
    # Create admin user with all required fields
    hashed_password = pwd_context.hash(password)
    
    db.execute(text("""
        INSERT INTO users (username, email, hashed_password, role, is_active, mfa_enabled, 
                         created_at, failed_login_attempts)
        VALUES (:username, :email, :password, 'super_admin', true, false, 
                CURRENT_TIMESTAMP, 0)
    """), {
        "username": username,
        "email": email,
        "password": hashed_password
    })
    
    db.commit()
    print(f"Admin user '{username}' created successfully!")
    print(f"Username: {username}")
    if os.getenv("ADMIN_PASSWORD"):
        print("Password: [Set via ADMIN_PASSWORD environment variable]")
    else:
        print(f"Generated Password: {password}")
        print("⚠️  IMPORTANT: Save this password securely and change it after first login!")
    
except Exception as e:
    print(f"Error creating user: {e}")
    db.rollback()
    sys.exit(1)
finally:
    db.close()