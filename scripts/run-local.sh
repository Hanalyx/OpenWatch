#!/bin/bash

# Script to run OpenWatch locally without Docker for testing

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to generate secure random string
generate_secret() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-32
}

print_info "OpenWatch Local Development Setup"
echo ""

# Check dependencies
print_info "Checking dependencies..."

if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is required but not installed"
    exit 1
fi

if ! command -v npm &> /dev/null; then
    print_error "Node.js/npm is required but not installed"
    exit 1
fi

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    print_info "Creating .env file..."
    cp .env.example .env
    
    # Generate secure passwords
    POSTGRES_PASS=$(generate_secret)
    REDIS_PASS=$(generate_secret)
    SECRET_KEY=$(generate_secret)
    MASTER_KEY=$(generate_secret)
    
    # Update .env file with generated values
    sed -i "s/your_secure_database_password_here_32_chars_minimum/$POSTGRES_PASS/g" .env
    sed -i "s/your_secure_redis_password_here_32_chars_minimum/$REDIS_PASS/g" .env
    sed -i "s/your_jwt_secret_key_here_must_be_at_least_32_characters_long/$SECRET_KEY/g" .env
    sed -i "s/your_master_encryption_key_here_must_be_at_least_32_characters_long/$MASTER_KEY/g" .env
    
    print_info "Generated secure passwords and keys in .env file"
fi

# Load environment variables (skip comments and empty lines)
while IFS= read -r line; do
    if [[ $line && $line != \#* ]]; then
        export "$line"
    fi
done < <(grep -v '^#' .env | grep -v '^$')

# Create necessary directories
print_info "Creating directories..."
mkdir -p backend/app/data/{scap,results,uploads}
mkdir -p backend/app/logs
mkdir -p security/{certs,keys}

# Install Python dependencies
print_info "Installing Python dependencies..."
pip3 install --user -r requirements.txt

# Install frontend dependencies if needed
if [ ! -d "frontend/node_modules" ]; then
    print_info "Installing frontend dependencies..."
    cd frontend
    npm install
    cd ..
fi

# Build frontend if needed
if [ ! -d "frontend/build" ]; then
    print_info "Building frontend..."
    cd frontend
    npm run build
    cd ..
fi

# Set up environment variables for backend
export PYTHONPATH=$(pwd)
export OPENWATCH_DATABASE_URL="sqlite:///./backend/app/data/openwatch.db"
export OPENWATCH_REDIS_URL="redis://localhost:6379"
export OPENWATCH_SECRET_KEY=$SECRET_KEY
export OPENWATCH_MASTER_KEY=$MASTER_KEY
export OPENWATCH_FIPS_MODE="false"
export OPENWATCH_REQUIRE_HTTPS="false"
export OPENWATCH_DEBUG="true"

# Create a simple Python script to initialize the database
cat > /tmp/init_db.py << 'EOF'
import sys
sys.path.append('.')

from backend.app.database import engine, Base
from backend.app import models

print("Creating database tables...")
Base.metadata.create_all(bind=engine)
print("Database initialized!")
EOF

# Initialize database
print_info "Initializing database..."
python3 /tmp/init_db.py
rm /tmp/init_db.py

# Start services
print_info "Starting services..."
echo ""
print_info "Services will run in the foreground. Press Ctrl+C to stop."
echo ""

# Function to cleanup on exit
cleanup() {
    print_info "Stopping services..."
    kill $(jobs -p) 2>/dev/null
    exit 0
}

trap cleanup INT TERM

# Start backend API
print_info "Starting backend API on http://localhost:8000..."
cd backend
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!
cd ..

# Wait for backend to start
sleep 5

# Start frontend dev server
print_info "Starting frontend on http://localhost:3000..."
cd frontend
npm run dev &
FRONTEND_PID=$!
cd ..

echo ""
print_info "OpenWatch is running!"
echo ""
echo "Access the application at:"
echo "  - Frontend: http://localhost:3000"
echo "  - Backend API: http://localhost:8000"
echo "  - API Docs: http://localhost:8000/docs"
echo ""
print_warning "Note: This is a simplified setup for local testing only."
print_warning "Some features like Redis/Celery tasks won't work without those services."
echo ""
print_info "Press Ctrl+C to stop all services"

# Wait for services
wait