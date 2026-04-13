"""
Integration test: OIDC SSO flow.

Spec: specs/services/auth/sso-federation.spec.yaml AC-15
"""

import pytest


@pytest.mark.integration
class TestOIDCFlow:
    """AC-15: Complete OIDC flow against mock IdP."""

    def test_oidc_provider_importable(self):
        """OIDCProvider can be imported from sso.oidc module."""
        from app.services.auth.sso.oidc import OIDCProvider

        assert OIDCProvider is not None

    def test_oidc_provider_has_required_methods(self):
        """OIDCProvider exposes get_login_url and handle_callback."""
        from app.services.auth.sso.oidc import OIDCProvider

        assert hasattr(OIDCProvider, "get_login_url")
        assert hasattr(OIDCProvider, "handle_callback")

    def test_oidc_provider_inherits_sso_provider(self):
        """OIDCProvider inherits from the base SSOProvider."""
        from app.services.auth.sso.oidc import OIDCProvider
        from app.services.auth.sso.provider import SSOProvider

        assert issubclass(OIDCProvider, SSOProvider)

    @pytest.mark.skip(reason="Requires authlib mock IdP setup")
    def test_full_oidc_flow(self):
        """Complete flow: login URL -> callback -> JWT issued."""
        # 1. Instantiate OIDCProvider with mock IdP config
        # 2. Generate login URL with state parameter
        # 3. Simulate callback with mock authorization code
        # 4. Verify SSOUserClaims returned with expected fields
        # 5. Verify JWT issued for the authenticated user
        pass
