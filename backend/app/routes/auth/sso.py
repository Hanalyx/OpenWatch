"""
Public SSO authentication routes.

Provides endpoints for listing enabled SSO providers, initiating SSO login
flows, and handling IdP callbacks for both OIDC and SAML protocols.

Login and callback endpoints are PUBLIC (no auth required) since the user
is not yet authenticated.

Spec: specs/services/auth/sso-federation.spec.yaml
"""

import base64
import json
import logging
from typing import Any, Dict
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from ...audit_db import log_login_event
from ...auth import audit_logger, jwt_manager
from ...config import get_settings
from ...database import get_db
from ...services.auth.sso.provider import SSOProvider, SSOUserClaims
from ...services.auth.sso_state import SSOStateStore
from ...utils.mutation_builders import InsertBuilder, UpdateBuilder
from ...utils.query_builder import QueryBuilder

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter(tags=["SSO Authentication"])


def _get_client_ip(request: Request) -> str:
    """Extract client IP address from request."""
    from ...utils.trusted_proxies import get_client_ip

    return get_client_ip(request)


def _get_sso_state_store(db: Session) -> SSOStateStore:
    """Get an SSOStateStore backed by PostgreSQL."""
    return SSOStateStore(db)


def _get_encryption_service(request: Request) -> Any:
    """Retrieve EncryptionService from app state."""
    if hasattr(request.app.state, "encryption_service"):
        return request.app.state.encryption_service
    from ...encryption import EncryptionConfig, create_encryption_service

    return create_encryption_service(settings.master_key, EncryptionConfig())


def _decrypt_config(encryption_service: Any, encrypted_b64: str) -> Dict[str, Any]:
    """Decrypt a base64-encoded encrypted config back to a dict."""
    encrypted_bytes = base64.b64decode(encrypted_b64)
    plaintext = encryption_service.decrypt(encrypted_bytes)
    return json.loads(plaintext.decode("utf-8"))


def _build_provider(provider_type: str, config: Dict[str, Any]) -> SSOProvider:
    """Instantiate the correct SSOProvider subclass."""
    if provider_type == "oidc":
        from ...services.auth.sso.oidc import OIDCProvider

        return OIDCProvider(config)
    elif provider_type == "saml":
        from ...services.auth.sso.saml import SAMLProvider

        return SAMLProvider(config)
    else:
        raise ValueError(f"Unknown provider type: {provider_type}")


def _find_or_create_user(
    db: Session,
    claims: SSOUserClaims,
    provider_id: str,
    role: str,
) -> Dict[str, Any]:
    """Find existing SSO user or create a new one.

    First login creates a local user row with sso_provider_id and external_id.
    Subsequent logins update email, username, role, and last_sso_login_at.
    SSO-provisioned users have no password_hash.
    """
    # Look up existing user by (sso_provider_id, external_id)
    builder = (
        QueryBuilder("users")
        .select("id", "username", "email", "role", "is_active")
        .where("sso_provider_id = :sso_pid", provider_id, "sso_pid")
        .where("external_id = :ext_id", claims.external_id, "ext_id")
    )
    query, params = builder.build()
    result = db.execute(text(query), params)
    user = result.fetchone()

    if user:
        # AC-7: Subsequent login - refresh claims
        username = claims.username or claims.email.split("@")[0]
        update_builder = (
            UpdateBuilder("users")
            .set("email", claims.email)
            .set("username", username)
            .set("role", role)
            .set_raw("last_sso_login_at", "CURRENT_TIMESTAMP")
            .set_raw("updated_at", "CURRENT_TIMESTAMP")
            .where("id = :id", str(user.id), "id")
            .returning("id", "username", "email", "role", "is_active")
        )
        uq, up = update_builder.build()
        result = db.execute(text(uq), up)
        db.commit()
        updated = result.fetchone()
        return {
            "id": str(updated.id),
            "username": updated.username,
            "email": updated.email,
            "role": updated.role,
            "is_active": updated.is_active,
        }
    else:
        # AC-6: First login - create user with no password_hash
        username = claims.username or claims.email.split("@")[0]
        insert_builder = (
            InsertBuilder("users")
            .columns(
                "username",
                "email",
                "role",
                "is_active",
                "sso_provider_id",
                "external_id",
                "last_sso_login_at",
            )
            .values(
                username,
                claims.email,
                role,
                True,
                provider_id,
                claims.external_id,
                "NOW()",
            )
            .returning("id", "username", "email", "role", "is_active")
        )
        iq, ip = insert_builder.build()
        result = db.execute(text(iq), ip)
        db.commit()
        created = result.fetchone()
        return {
            "id": str(created.id),
            "username": created.username,
            "email": created.email,
            "role": created.role,
            "is_active": created.is_active,
        }


def _issue_tokens(user: Dict[str, Any]) -> Dict[str, Any]:
    """Issue JWT access + refresh token pair for the authenticated user."""
    token_data = {
        "sub": user["id"],
        "username": user["username"],
        "role": user["role"],
    }
    access_token = jwt_manager.create_access_token(token_data)
    refresh_token = jwt_manager.create_refresh_token(token_data)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": settings.access_token_expire_minutes * 60,
        "user": user,
    }


# ---------------------------------------------------------------------------
# Public endpoints
# ---------------------------------------------------------------------------


@router.get("/sso/providers")
async def list_sso_providers(
    db: Session = Depends(get_db),
) -> list:
    """List enabled SSO providers (public, no auth required).

    Returns minimal information (id, name, provider_type) so the frontend
    can render SSO login buttons.
    """
    builder = (
        QueryBuilder("sso_providers")
        .select("id", "name", "provider_type")
        .where("enabled = :enabled", True, "enabled")
        .order_by("name", "ASC")
    )
    query, params = builder.build()
    result = db.execute(text(query), params)
    rows = result.fetchall()
    return [
        {
            "id": str(row.id),
            "name": row.name,
            "provider_type": row.provider_type,
        }
        for row in rows
    ]


@router.get("/sso/login")
async def sso_login(
    request: Request,
    provider_id: UUID = Query(..., description="SSO provider ID"),
    redirect_uri: str = Query(..., description="Callback URL"),
    db: Session = Depends(get_db),
) -> Dict[str, str]:
    """Initiate SSO login by redirecting to the IdP.

    Generates a cryptographic state token, stores it in Redis with a
    5-minute TTL, and returns the IdP authorization URL.
    """
    encryption_service = _get_encryption_service(request)

    # Fetch provider
    builder = (
        QueryBuilder("sso_providers")
        .where("id = :id", str(provider_id), "id")
        .where("enabled = :enabled", True, "enabled")
    )
    query, params = builder.build()
    result = db.execute(text(query), params)
    row = result.fetchone()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SSO provider not found or disabled",
        )

    config = _decrypt_config(encryption_service, row.config_encrypted)
    provider = _build_provider(row.provider_type, config)

    # Generate and store state (AC-12: 128+ bits, single-use)
    state = SSOProvider.generate_state()
    store = _get_sso_state_store(db)
    store.store(state, str(provider_id), ttl_seconds=300)

    login_url = provider.get_login_url(state, redirect_uri)
    return {"login_url": login_url}


@router.get("/sso/callback/oidc/{provider_id}")
async def oidc_callback(
    provider_id: UUID,
    request: Request,
    code: str = Query(...),
    state: str = Query(...),
    redirect_uri: str = Query(""),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Handle OIDC authorization code callback.

    Validates the state token, exchanges the code for tokens, validates
    the id_token, provisions or updates the user, and issues JWT tokens.
    """
    client_ip = _get_client_ip(request)
    user_agent = request.headers.get("user-agent")

    # AC-12: Validate and consume single-use state
    store = _get_sso_state_store(db)
    stored_provider_id = store.validate_and_consume(state)
    if not stored_provider_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired state parameter",
        )

    # Verify state maps to this provider
    if stored_provider_id != str(provider_id):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="State parameter does not match provider",
        )

    encryption_service = _get_encryption_service(request)

    # Fetch provider config
    builder = (
        QueryBuilder("sso_providers")
        .where("id = :id", str(provider_id), "id")
        .where("enabled = :enabled", True, "enabled")
    )
    query, params = builder.build()
    result = db.execute(text(query), params)
    row = result.fetchone()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SSO provider not found",
        )

    config = _decrypt_config(encryption_service, row.config_encrypted)
    provider = _build_provider("oidc", config)

    try:
        claims = provider.handle_callback(
            {
                "code": code,
                "redirect_uri": redirect_uri,
            }
        )
    except Exception as exc:
        logger.error("OIDC callback failed for provider %s: %s", provider_id, exc)
        audit_logger.log_security_event(
            "SSO_AUTH_FAILURE",
            f"OIDC callback failed: provider={provider_id}, error={exc}",
            client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SSO authentication failed",
        )

    role = provider.map_claims_to_role(claims)
    user = _find_or_create_user(db, claims, str(provider_id), role)

    # AC-11: Audit log
    audit_logger.log_security_event(
        "SSO_AUTH_SUCCESS",
        (f"OIDC login: provider_id={provider_id}, " f"external_id={claims.external_id}, " f"user_agent={user_agent}"),
        client_ip,
    )
    log_login_event(
        db=db,
        username=user["username"],
        user_id=user["id"],
        success=True,
        ip_address=client_ip,
        user_agent=user_agent,
    )

    return _issue_tokens(user)


@router.post("/sso/callback/saml/{provider_id}")
async def saml_callback(
    provider_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Handle SAML Assertion Consumer Service (ACS) POST callback.

    Validates the SAML response signature, extracts claims, provisions
    or updates the user, and issues JWT tokens.
    """
    client_ip = _get_client_ip(request)
    user_agent = request.headers.get("user-agent")

    form_data = await request.form()
    saml_response = form_data.get("SAMLResponse", "")
    relay_state = form_data.get("RelayState", "")

    # AC-12: Validate and consume single-use state
    store = _get_sso_state_store(db)
    stored_provider_id = store.validate_and_consume(relay_state)
    if not stored_provider_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired state parameter",
        )

    if stored_provider_id != str(provider_id):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="State parameter does not match provider",
        )

    encryption_service = _get_encryption_service(request)

    # Fetch provider config
    builder = (
        QueryBuilder("sso_providers")
        .where("id = :id", str(provider_id), "id")
        .where("enabled = :enabled", True, "enabled")
    )
    query, params = builder.build()
    result = db.execute(text(query), params)
    row = result.fetchone()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SSO provider not found",
        )

    config = _decrypt_config(encryption_service, row.config_encrypted)
    provider = _build_provider("saml", config)

    try:
        claims = provider.handle_callback(
            {
                "SAMLResponse": saml_response,
                "redirect_uri": config.get("acs_url", ""),
            }
        )
    except Exception as exc:
        logger.error("SAML callback failed for provider %s: %s", provider_id, exc)
        audit_logger.log_security_event(
            "SSO_AUTH_FAILURE",
            f"SAML callback failed: provider={provider_id}, error={exc}",
            client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SSO authentication failed",
        )

    role = provider.map_claims_to_role(claims)
    user = _find_or_create_user(db, claims, str(provider_id), role)

    # AC-11: Audit log
    audit_logger.log_security_event(
        "SSO_AUTH_SUCCESS",
        (f"SAML login: provider_id={provider_id}, " f"external_id={claims.external_id}, " f"user_agent={user_agent}"),
        client_ip,
    )
    log_login_event(
        db=db,
        username=user["username"],
        user_id=user["id"],
        success=True,
        ip_address=client_ip,
        user_agent=user_agent,
    )

    return _issue_tokens(user)
