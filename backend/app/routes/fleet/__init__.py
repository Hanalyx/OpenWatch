"""
Fleet-level API routes.

Provides fleet-wide health and status summaries for dashboard widgets.
"""

from .health import router

__all__ = ["router"]
