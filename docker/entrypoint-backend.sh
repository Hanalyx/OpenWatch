#!/bin/bash
# Backend entrypoint script to fix permissions

# Ensure logs directory has proper permissions
if [ -d "/openwatch/logs" ]; then
    # Create audit.log if it doesn't exist
    touch /openwatch/logs/audit.log 2>/dev/null || true

    # Try to fix permissions as the current user
    chmod -R 755 /openwatch/logs 2>/dev/null || true
    chmod 644 /openwatch/logs/audit.log 2>/dev/null || true
fi

# Ensure security directories have proper permissions
if [ -d "/openwatch/security" ]; then
    chmod -R 700 /openwatch/security 2>/dev/null || true

    # Create keys directory if it doesn't exist
    mkdir -p /openwatch/security/keys 2>/dev/null || true
    chmod 700 /openwatch/security/keys 2>/dev/null || true

    # Create certs directory if it doesn't exist
    mkdir -p /openwatch/security/certs 2>/dev/null || true
    chmod 700 /openwatch/security/certs 2>/dev/null || true
fi

# Start the application
exec "$@"
