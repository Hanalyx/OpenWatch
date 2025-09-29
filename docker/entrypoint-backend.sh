#!/bin/bash
# Backend entrypoint script to fix permissions

# Ensure logs directory has proper permissions
if [ -d "/app/logs" ]; then
    # Create audit.log if it doesn't exist
    touch /app/logs/audit.log 2>/dev/null || true
    
    # Try to fix permissions as the current user
    chmod -R 755 /app/logs 2>/dev/null || true
    chmod 644 /app/logs/audit.log 2>/dev/null || true
fi

# Ensure security directories have proper permissions
if [ -d "/app/security" ]; then
    chmod -R 700 /app/security 2>/dev/null || true
    
    # Create keys directory if it doesn't exist
    mkdir -p /app/security/keys 2>/dev/null || true
    chmod 700 /app/security/keys 2>/dev/null || true
    
    # Create certs directory if it doesn't exist
    mkdir -p /app/security/certs 2>/dev/null || true
    chmod 700 /app/security/certs 2>/dev/null || true
fi

# Start the application
exec "$@"