#!/usr/bin/env python3
"""Create admin user for OpenWatch"""
import sys
from app.database import SessionLocal
from app.auth import pwd_context
from sqlalchemy import text
import uuid

# Default admin credentials
username = "admin"
email = "admin@openwatch.local"
password = "admin123"

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
    print(f"Password: {password}")
    
except Exception as e:
    print(f"Error creating user: {e}")
    db.rollback()
    sys.exit(1)
finally:
    db.close()