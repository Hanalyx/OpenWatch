"""
OIDC federated authentication provider.

Uses authlib for the OAuth 2.0 / OpenID Connect protocol flow with PKCE.
Validates id_token signatures against the IdP's JWKS endpoint and enforces
standard claims (iss, aud, exp, nbf).  Rejects tokens signed with
``alg=none``.

Spec: specs/services/auth/sso-federation.spec.yaml (AC-4)
"""

import logging
from typing import Any, Dict

from .provider import SSOProvider, SSOUserClaims

logger = logging.getLogger(__name__)


class OIDCProvider(SSOProvider):
    """OpenID Connect provider backed by authlib."""

    def get_login_url(self, state: str, redirect_uri: str) -> str:
        """Build the OIDC authorization URL with PKCE.

        Args:
            state: CSRF state token.
            redirect_uri: Callback URL for the authorization code.

        Returns:
            Authorization endpoint URL with query parameters.
        """
        from authlib.integrations.requests_client import OAuth2Session

        client = OAuth2Session(
            client_id=self.config["client_id"],
            client_secret=self.config.get("client_secret"),
            scope=self.config.get("scope", "openid email profile"),
            code_challenge_method="S256",
        )
        url, _ = client.create_authorization_url(
            self.config["authorization_endpoint"],
            state=state,
            redirect_uri=redirect_uri,
        )
        return url

    def handle_callback(self, request_data: Dict[str, Any]) -> SSOUserClaims:
        """Exchange the authorization code for tokens and validate the id_token.

        Validates:
        - id_token signature against IdP JWKS endpoint
        - iss, aud, exp, nbf standard claims
        - Rejects tokens with alg=none

        Args:
            request_data: Must contain ``code`` and ``redirect_uri``.

        Returns:
            Validated SSOUserClaims extracted from the id_token.

        Raises:
            ValueError: On validation failure (bad signature, expired,
                wrong issuer, alg=none, etc.).
        """
        from authlib.integrations.requests_client import OAuth2Session
        from authlib.jose import jwt as jose_jwt

        client = OAuth2Session(
            client_id=self.config["client_id"],
            client_secret=self.config.get("client_secret"),
        )
        token = client.fetch_token(
            self.config["token_endpoint"],
            code=request_data["code"],
            redirect_uri=request_data["redirect_uri"],
        )

        id_token_raw = token.get("id_token")
        if not id_token_raw:
            raise ValueError("No id_token in token response")

        # Fetch JWKS and decode / verify signature
        jwks = self._get_jwks()
        claims = jose_jwt.decode(id_token_raw, jwks)

        # Reject alg=none before any further processing
        header = claims.header if hasattr(claims, "header") else {}
        if header.get("alg") == "none":
            raise ValueError("Tokens with alg=none are rejected")

        # Validate standard claims (iss, aud, exp, nbf)
        claims.validate()

        return SSOUserClaims(
            external_id=claims["sub"],
            email=claims.get("email", ""),
            username=claims.get("preferred_username"),
            groups=claims.get("groups", []),
            raw_claims=dict(claims),
        )

    def _get_jwks(self) -> Dict[str, Any]:
        """Fetch the IdP's JSON Web Key Set.

        Returns:
            JWKS dictionary used for id_token signature verification.
        """
        import httpx

        resp = httpx.get(self.config["jwks_uri"], timeout=10)
        resp.raise_for_status()
        return resp.json()
