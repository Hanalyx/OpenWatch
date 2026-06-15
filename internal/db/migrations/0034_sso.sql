-- 0034_sso.sql
--
-- Single sign-on via OpenID Connect. Three tables:
--
--   sso_providers   — admin-configured OIDC providers. The client secret is
--                     stored AES-256-GCM encrypted (same DEK as notification
--                     channels + API tokens); only the non-secret fields are
--                     ever returned by the read path.
--   sso_identities  — the federation link: (provider, subject) -> local user.
--                     The OIDC `sub` claim is the stable identifier; email can
--                     change, sub does not. A local user is provisioned on
--                     first successful sign-in.
--   sso_auth_states — short-lived per-login state carrying the CSRF `state`,
--                     replay-guard `nonce`, and PKCE `code_verifier` across
--                     the redirect to the IdP and back. Consumed once at
--                     callback; a sweeper deletes expired rows.

-- +goose Up
CREATE TABLE sso_providers (
    id                   UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Display name shown on the login button ("Acme SSO").
    name                 TEXT         NOT NULL,
    -- Protocol. Only 'oidc' for now; SAML is a later slice. CHECK keeps the
    -- column honest so a typo can't smuggle in an unhandled type.
    type                 TEXT         NOT NULL DEFAULT 'oidc' CHECK (type IN ('oidc')),
    -- OIDC issuer URL. Discovery fetches {issuer}/.well-known/openid-configuration.
    issuer               TEXT         NOT NULL,
    client_id            TEXT         NOT NULL,
    -- AES-256-GCM ciphertext of the client secret. Never returned by the API.
    client_secret_enc    BYTEA        NOT NULL,
    -- Space-delimited scopes; "openid" is always requested regardless.
    scopes               TEXT         NOT NULL DEFAULT 'openid email profile',
    -- Role granted to users provisioned through this provider. RESTRICT so a
    -- role can't be deleted out from under a live provider.
    default_role         TEXT         NOT NULL DEFAULT 'viewer' REFERENCES roles(id) ON DELETE RESTRICT,
    enabled              BOOLEAN      NOT NULL DEFAULT false,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    created_by           UUID         REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX idx_sso_providers_enabled ON sso_providers (enabled) WHERE enabled;

CREATE TABLE sso_identities (
    provider_id   UUID         NOT NULL REFERENCES sso_providers(id) ON DELETE CASCADE,
    -- The OIDC `sub` claim — opaque, stable, unique within the provider.
    subject       TEXT         NOT NULL,
    user_id       UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ,
    PRIMARY KEY (provider_id, subject)
);

CREATE INDEX idx_sso_identities_user ON sso_identities (user_id);

CREATE TABLE sso_auth_states (
    -- High-entropy random value echoed back by the IdP as `state` (CSRF guard).
    state         TEXT         PRIMARY KEY,
    provider_id   UUID         NOT NULL REFERENCES sso_providers(id) ON DELETE CASCADE,
    -- Replay guard: echoed in the ID token's `nonce` claim, checked at callback.
    nonce         TEXT         NOT NULL,
    -- PKCE (RFC 7636) verifier; its S256 challenge went to the IdP.
    code_verifier TEXT         NOT NULL,
    -- Open-redirect-safe post-login destination (validated server-side).
    redirect_to   TEXT         NOT NULL DEFAULT '/dashboard',
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ  NOT NULL
);

CREATE INDEX idx_sso_auth_states_expiry ON sso_auth_states (expires_at);

-- +goose Down
DROP TABLE IF EXISTS sso_auth_states;
DROP TABLE IF EXISTS sso_identities;
DROP TABLE IF EXISTS sso_providers;
