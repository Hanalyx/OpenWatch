"""
Remediation API Package

Provides endpoints for automated fix management, remediation provider
interfaces, and Kensa webhook callbacks.

Usage:
    from app.routes.remediation import router
    app.include_router(router, prefix="/api")
"""

from fastapi import APIRouter

# Create main router that aggregates all sub-routers
router = APIRouter()

# Import and include sub-routers
from .callback import router as callback_router  # noqa: E402
from .fixes import router as fixes_router  # noqa: E402
from .provider import router as provider_router  # noqa: E402

# fixes.py already has prefix="/automated-fixes" in its router definition
router.include_router(fixes_router, tags=["Secure Automated Fixes"])

# provider.py has no prefix; was registered with prefix="/api/remediation" in main.py
# Since this package is included with prefix="/api", we add /remediation here
router.include_router(provider_router, prefix="/remediation", tags=["Remediation Provider"])

# callback.py has no prefix; endpoint is /webhooks/remediation-complete
# Was registered with prefix="/api" in main.py, so no additional prefix needed
router.include_router(callback_router, tags=["Kensa Integration"])

__all__ = ["router"]
