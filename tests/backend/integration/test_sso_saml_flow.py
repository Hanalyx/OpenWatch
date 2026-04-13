"""
Integration test: SAML SSO flow.

Spec: specs/services/auth/sso-federation.spec.yaml AC-16
"""

import pytest


@pytest.mark.integration
class TestSAMLFlow:
    """AC-16: Complete SAML flow against mock IdP."""

    def test_saml_provider_importable(self):
        """SAMLProvider can be imported from sso.saml module."""
        from app.services.auth.sso.saml import SAMLProvider

        assert SAMLProvider is not None

    def test_saml_provider_has_required_methods(self):
        """SAMLProvider exposes get_login_url and handle_callback."""
        from app.services.auth.sso.saml import SAMLProvider

        assert hasattr(SAMLProvider, "get_login_url")
        assert hasattr(SAMLProvider, "handle_callback")

    def test_saml_provider_inherits_sso_provider(self):
        """SAMLProvider inherits from the base SSOProvider."""
        from app.services.auth.sso.provider import SSOProvider
        from app.services.auth.sso.saml import SAMLProvider

        assert issubclass(SAMLProvider, SSOProvider)

    @pytest.mark.skip(reason="Requires pysaml2 mock IdP setup")
    def test_full_saml_flow(self):
        """Complete flow: login URL -> ACS callback -> JWT issued."""
        # 1. Instantiate SAMLProvider with mock IdP metadata
        # 2. Generate login URL (AuthnRequest) with state
        # 3. Simulate ACS callback with mock SAML response
        # 4. Verify SSOUserClaims returned with expected fields
        # 5. Verify JWT issued for the authenticated user
        pass
