"""
OpenWatch Licensing Service

Provides license validation and feature gating for OpenWatch and OpenWatch+.

Free Tier (Core):
- Compliance checking (always free)
- Framework reporting
- Basic dashboard

OpenWatch+ (Licensed):
- Automated remediation
- Rollback support
- Priority updates
- Advanced analytics

Usage:
    from app.services.licensing import LicenseService, requires_license

    # Check feature availability
    license_service = LicenseService()
    if await license_service.has_feature("remediation"):
        # Execute remediation
        pass

    # Decorator usage
    class MyPlugin:
        @requires_license("remediation")
        async def remediate(self, host_id: str, rule_ids: List[str]):
            # This method requires OpenWatch+ license
            pass
"""

from .service import LicenseRequiredError, LicenseService, requires_license

__all__ = [
    "LicenseService",
    "LicenseRequiredError",
    "requires_license",
]
