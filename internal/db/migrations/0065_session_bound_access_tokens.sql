-- +goose Up
-- Session-bound access tokens (bugs/OW-069, system-auth-identity C-38).
--
-- An access token used to be an independent bearer credential: once
-- signed it authenticated until it expired, whatever happened to the
-- session it came from. That is why an administrative password reset
-- left a working token behind. The account stays enabled after a reset,
-- so an account-state check cannot reach it; only binding it to the
-- session that issued it can.
--
-- Two halves:
--   1. refresh_tokens.session_id ties a refresh lineage to its session,
--      so revoking the session ends the lineage.
--   2. the JWT carries the same session id as a `sid` claim, checked by
--      the binder (application side).

ALTER TABLE refresh_tokens
    ADD COLUMN session_id UUID REFERENCES sessions(id) ON DELETE CASCADE;

CREATE INDEX idx_refresh_tokens_session_id ON refresh_tokens (session_id);

-- Every credential minted before this migration has no session link and
-- no `sid` claim, so nothing can decide whether its session is still
-- alive. Leaving them live would mean the guarantee this migration adds
-- is false for every existing credential, silently, for up to seven
-- days. Revoke them: everyone signs in again once.
--
-- Interactive credentials only. api_tokens is a separate lifecycle and
-- is deliberately untouched.
UPDATE sessions       SET revoked_at = now() WHERE revoked_at IS NULL;
UPDATE refresh_tokens SET revoked_at = now() WHERE revoked_at IS NULL;

-- +goose Down
-- Dropping the column removes the binding. The sign-out above is not
-- undone: re-minting credentials that were deliberately revoked is not
-- something a schema rollback should do silently.
DROP INDEX IF EXISTS idx_refresh_tokens_session_id;
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS session_id;
