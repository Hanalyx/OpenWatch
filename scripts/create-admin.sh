#!/bin/bash

# Script to create initial admin user for OpenWatch

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if backend container is running
if ! docker ps | grep -q "openwatch-backend"; then
    print_error "Backend container is not running. Please run ./scripts/setup.sh first."
    exit 1
fi

print_info "Creating admin user for OpenWatch"
echo ""

# Get user input
read -p "Enter admin username: " USERNAME
read -p "Enter admin email: " EMAIL
read -s -p "Enter admin password (min 12 chars): " PASSWORD
echo ""
read -s -p "Confirm password: " PASSWORD_CONFIRM
echo ""

# Validate password match
if [ "$PASSWORD" != "$PASSWORD_CONFIRM" ]; then
    print_error "Passwords do not match"
    exit 1
fi

# Create Python script to add admin user
cat > /tmp/create_admin.py << 'EOF'
import sys
import os
sys.path.append('/app')

from backend.app.database import SessionLocal, engine
from backend.app.auth import get_password_hash
from sqlalchemy import text
import uuid

username = os.environ.get('ADMIN_USERNAME')
email = os.environ.get('ADMIN_EMAIL')
password = os.environ.get('ADMIN_PASSWORD')

db = SessionLocal()

try:
    # Check if user exists
    result = db.execute(text("SELECT id FROM users WHERE username = :username"), {"username": username})
    if result.first():
        print(f"User {username} already exists")
        sys.exit(1)
    
    # Create admin user
    user_id = str(uuid.uuid4())
    hashed_password = get_password_hash(password)
    
    db.execute(text("""
        INSERT INTO users (id, username, email, hashed_password, role, is_active, mfa_enabled, created_at, updated_at)
        VALUES (:id, :username, :email, :password, 'admin', true, false, NOW(), NOW())
    """), {
        "id": user_id,
        "username": username,
        "email": email,
        "password": hashed_password
    })
    
    db.commit()
    print(f"Admin user '{username}' created successfully!")
    
except Exception as e:
    print(f"Error creating user: {e}")
    db.rollback()
    sys.exit(1)
finally:
    db.close()
EOF

# Run the script in the backend container
docker exec -e ADMIN_USERNAME="$USERNAME" -e ADMIN_EMAIL="$EMAIL" -e ADMIN_PASSWORD="$PASSWORD" \
    openwatch-backend python3.9 /tmp/create_admin.py

# Clean up
docker exec openwatch-backend rm -f /tmp/create_admin.py

print_info "You can now log in at https://localhost with username: $USERNAME"