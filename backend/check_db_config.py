#!/usr/bin/env python3
"""Check database configuration and create admin user with correct URL"""
import os
import sys
from app.config import get_settings
from app.database import SessionLocal, DATABASE_URL
from app.auth import pwd_context
from sqlalchemy import text

def check_and_create_admin():
    """Check database config and create admin user"""
    settings = get_settings()
    print(f"Database URL from config: {DATABASE_URL}")
    print(f"Debug mode: {settings.debug}")
    
    # Try to connect with current configuration
    try:
        db = SessionLocal()
        
        # Check if admin user exists
        result = db.execute(text("SELECT id, username FROM users WHERE username = 'admin'"))
        admin_user = result.fetchone()
        
        if admin_user:
            print(f"Admin user already exists with ID: {admin_user.id}")
            print("Testing login...")
            
            # Test login by checking password hash
            result = db.execute(text("SELECT hashed_password FROM users WHERE username = 'admin'"))
            user_data = result.fetchone()
            if user_data:
                # Try to verify the default password
                if pwd_context.verify("admin123", user_data.hashed_password):
                    print("✅ Admin user 'admin' exists with password 'admin123'")
                else:
                    print("❌ Admin user exists but password doesn't match 'admin123'")
            return True
        
        # Create admin user
        print("Creating admin user...")
        hashed_password = pwd_context.hash("admin123")
        
        db.execute(text("""
            INSERT INTO users (username, email, hashed_password, role, is_active, 
                             created_at, failed_login_attempts)
            VALUES (:username, :email, :password, 'super_admin', true, 
                    CURRENT_TIMESTAMP, 0)
        """), {
            "username": "admin",
            "email": "admin@openwatch.local",
            "password": hashed_password
        })
        
        db.commit()
        print("✅ Admin user created successfully!")
        print("Username: admin")
        print("Password: admin123")
        return True
        
    except Exception as e:
        print(f"❌ Database error: {e}")
        return False
    finally:
        try:
            db.close()
        except:
            pass

if __name__ == "__main__":
    success = check_and_create_admin()
    sys.exit(0 if success else 1)