"""
Authentication Routes Package

This package provides all authentication-related REST API endpoints.
Consolidates auth, MFA, and API key management into a single organized package.

Package Structure:
    auth/
    ├── __init__.py      # This file - router aggregation
    ├── login.py         # Login/logout/register/refresh endpoints
    ├── mfa.py           # Multi-factor authentication endpoints
    └── api_keys.py      # API key CRUD endpoints

Migration Status (E1-S4 - Route Consolidation):
    - auth.py → auth/login.py
    - mfa.py → auth/mfa.py
    - api_keys.py → auth/api_keys.py

Usage:
    # Import the aggregated router in main.py
    from app.routes.auth import router
    app.include_router(router, prefix="/api/auth")

Router Organization:
    The main router aggregates all sub-routers:

    Login Router (login.py):
        POST /auth/login           - Authenticate user with username/password
        POST /auth/register        - Register new user account
        POST /auth/refresh         - Refresh access token
        POST /auth/logout          - Logout and invalidate token
        GET  /auth/me              - Get current user info

    MFA Router (mfa.py):
        GET  /auth/mfa/status                - Get MFA enrollment status
        POST /auth/mfa/enroll                - Enroll in MFA
        POST /auth/mfa/validate              - Validate MFA code
        POST /auth/mfa/enable                - Enable MFA
        POST /auth/mfa/regenerate-backup-codes - Regenerate backup codes
        POST /auth/mfa/disable               - Disable MFA

    API Keys Router (api_keys.py):
        POST   /auth/api-keys                - Create new API key
        GET    /auth/api-keys                - List user's API keys
        DELETE /auth/api-keys/{api_key_id}   - Revoke API key
        PUT    /auth/api-keys/{api_key_id}/permissions - Update key permissions
"""

from fastapi import APIRouter

# Create main router that aggregates all sub-routers
router = APIRouter(tags=["Authentication"])

# Import sub-routers from modular files
try:
    from .login import router as login_router
    from .mfa import router as mfa_router
    from .api_keys import router as api_keys_router

    # Include all sub-routers into main router
    # Login endpoints (no prefix - /auth/login, /auth/logout, etc.)
    router.include_router(login_router)

    # MFA endpoints (/auth/mfa/*)
    router.include_router(mfa_router, prefix="/mfa")

    # API Keys endpoints (/auth/api-keys/*)
    router.include_router(api_keys_router, prefix="/api-keys")

except ImportError as e:
    import logging

    logger = logging.getLogger(__name__)
    logger.error(f"Failed to load auth sub-routers: {e}")
    # In production, this should not happen
    # If it does, the /auth endpoints will be unavailable

__all__ = [
    "router",
]
