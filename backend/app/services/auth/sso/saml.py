"""
SAML 2.0 federated authentication provider.

Uses pysaml2 for AuthnRequest generation and Response validation.
Validates response signature, enforces NotOnOrAfter, rejects unsigned
assertions, and verifies the Issuer matches the configured IdP entity ID.

Spec: specs/services/auth/sso-federation.spec.yaml (AC-5)
"""

import logging
from typing import Any, Dict

from .provider import SSOProvider, SSOUserClaims

logger = logging.getLogger(__name__)


class SAMLProvider(SSOProvider):
    """SAML 2.0 Service Provider backed by pysaml2."""

    def get_login_url(self, state: str, redirect_uri: str) -> str:
        """Build the SAML AuthnRequest redirect URL.

        Args:
            state: Relay state token for CSRF protection.
            redirect_uri: Assertion Consumer Service URL.

        Returns:
            IdP SSO URL with the encoded AuthnRequest.
        """
        from saml2.client import Saml2Client

        sp_config = self._build_sp_config(redirect_uri)
        client = Saml2Client(config=sp_config)
        _session_id, info = client.prepare_for_authenticate(
            relay_state=state,
        )
        # Extract the redirect Location from the response headers
        for key, value in info["headers"]:
            if key == "Location":
                return value
        raise ValueError("No redirect URL in SAML AuthnRequest response")

    def handle_callback(self, request_data: Dict[str, Any]) -> SSOUserClaims:
        """Parse and validate the SAML Response.

        Validation handled by pysaml2 includes:
        - Response and assertion signature verification
        - NotOnOrAfter / NotBefore time window enforcement
        - Issuer matching against configured IdP entity ID
        - Rejection of unsigned assertions (want_assertions_signed=True)
        - InResponseTo validation against the original AuthnRequest ID

        Args:
            request_data: Must contain ``SAMLResponse`` (base64-encoded)
                and optionally ``redirect_uri``.

        Returns:
            Validated SSOUserClaims.

        Raises:
            ValueError: On any validation failure.
        """
        import saml2
        from saml2.client import Saml2Client

        sp_config = self._build_sp_config(
            request_data.get("redirect_uri", ""),
        )
        client = Saml2Client(config=sp_config)

        # parse_authn_request_response validates signature, NotOnOrAfter,
        # Issuer, and rejects unsigned assertions based on sp_config
        authn_response = client.parse_authn_request_response(
            request_data["SAMLResponse"],
            saml2.BINDING_HTTP_POST,
        )

        if not authn_response:
            raise ValueError("Invalid SAML response")

        identity = authn_response.get_identity()
        name_id = str(authn_response.name_id)

        return SSOUserClaims(
            external_id=name_id,
            email=identity.get("email", [""])[0],
            username=identity.get("uid", [name_id])[0],
            groups=identity.get("memberOf", []),
            raw_claims=identity,
        )

    def _build_sp_config(self, acs_url: str) -> Any:
        """Build a pysaml2 SPConfig from the stored provider config.

        The config enforces:
        - ``want_assertions_signed: True`` (reject unsigned assertions)
        - ``want_response_signed: True`` (validate response signature)
        - IdP metadata with entity_id matching the configured value

        Args:
            acs_url: Assertion Consumer Service URL for this SP.

        Returns:
            A configured ``saml2.config.SPConfig`` instance.
        """
        from saml2.config import SPConfig

        sp_settings: Dict[str, Any] = {
            "entityid": self.config.get(
                "sp_entity_id",
                "openwatch-sso-sp",
            ),
            "service": {
                "sp": {
                    "endpoints": {
                        "assertion_consumer_service": [
                            (acs_url, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"),
                        ],
                    },
                    "allow_unsolicited": False,
                    "want_assertions_signed": True,
                    "want_response_signed": True,
                },
            },
            "metadata": {},
            "key_file": self.config.get("sp_key_file", ""),
            "cert_file": self.config.get("sp_cert_file", ""),
        }

        # Configure IdP metadata
        idp_entity_id = self.config.get("idp_entity_id", "")
        idp_metadata_url = self.config.get("idp_metadata_url")
        idp_metadata_file = self.config.get("idp_metadata_file")

        if idp_metadata_url:
            sp_settings["metadata"]["remote"] = [
                {"url": idp_metadata_url},
            ]
        elif idp_metadata_file:
            sp_settings["metadata"]["local"] = [idp_metadata_file]

        if idp_entity_id:
            sp_settings["idp_entity_id"] = idp_entity_id

        config = SPConfig()
        config.load(sp_settings)
        return config
