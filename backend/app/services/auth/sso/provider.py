"""
Abstract base class for SSO providers (SAML 2.0 and OIDC).

Defines the common interface that concrete providers must implement,
plus shared utilities for claim-to-role mapping and cryptographic
state generation.

Spec: specs/services/auth/sso-federation.spec.yaml
"""

import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SSOUserClaims:
    """Claims extracted from an IdP assertion or id_token.

    Attributes:
        external_id: The unique subject identifier from the IdP (SAML NameID
            or OIDC ``sub`` claim).
        email: Email address from IdP claims.
        username: Optional preferred username.
        groups: IdP group memberships used for role mapping.
        raw_claims: The full, unprocessed claim set for audit logging.
    """

    external_id: str
    email: str
    username: Optional[str] = None
    groups: Optional[List[str]] = None
    raw_claims: Optional[Dict[str, Any]] = field(default_factory=dict)


class SSOProvider(ABC):
    """Abstract base for federated identity providers.

    Concrete subclasses (OIDCProvider, SAMLProvider) handle protocol-specific
    logic while this class provides the shared contract and helper methods.
    """

    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config

    @abstractmethod
    def get_login_url(self, state: str, redirect_uri: str) -> str:
        """Build the IdP redirect URL for initiating authentication.

        Args:
            state: Opaque, cryptographically random state token for CSRF
                protection.  Must be validated on callback.
            redirect_uri: The callback URL the IdP should redirect to after
                authentication.

        Returns:
            Absolute URL to redirect the user's browser to.
        """
        ...

    @abstractmethod
    def handle_callback(self, request_data: Dict[str, Any]) -> SSOUserClaims:
        """Process the IdP callback and return validated user claims.

        Args:
            request_data: Protocol-specific callback data (e.g. ``code`` and
                ``redirect_uri`` for OIDC, ``SAMLResponse`` for SAML).

        Returns:
            Validated and extracted user claims.

        Raises:
            ValueError: If the callback data is invalid, the signature
                cannot be verified, or required claims are missing.
        """
        ...

    def map_claims_to_role(self, claims: SSOUserClaims) -> str:
        """Map IdP groups to an OpenWatch role via ``group_role_map`` config.

        The mapping is evaluated in the order the groups appear in
        ``claims.groups``.  The first match wins.  If no group matches,
        ``default_role`` from the provider config is returned (defaults
        to ``"GUEST"``).

        Args:
            claims: Validated user claims from handle_callback.

        Returns:
            OpenWatch role string (e.g. ``"super_admin"``, ``"guest"``).
        """
        group_role_map: Dict[str, str] = self.config.get("group_role_map", {})
        default_role: str = self.config.get("default_role", "guest")
        if claims.groups:
            for group in claims.groups:
                if group in group_role_map:
                    return group_role_map[group]
        return default_role

    @staticmethod
    def generate_state() -> str:
        """Generate a cryptographically random state token.

        Uses ``secrets.token_urlsafe(32)`` which produces 256 bits of
        entropy (well above the 128-bit minimum required by the spec).

        Returns:
            URL-safe base64-encoded random string.
        """
        return secrets.token_urlsafe(32)
