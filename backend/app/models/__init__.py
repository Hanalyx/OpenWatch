"""
OpenWatch Models Package
"""

# Import Host from database module to make it available at package level
from ..database import Host  # noqa: E402
from .health_models import ContentHealthDocument, HealthSummaryDocument, ServiceHealthDocument  # noqa: E402

__all__ = [
    # Database models
    "Host",
    # Health models
    "ServiceHealthDocument",
    "ContentHealthDocument",
    "HealthSummaryDocument",
]
