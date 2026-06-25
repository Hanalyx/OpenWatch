-- 0047_refresh_absolute_deadline.sql
--
-- AUTH-1 (b): make the session ABSOLUTE timeout a real ceiling.
--
-- The cookie-refresh path (PostAuthRefreshCookie) re-mints a session on the
-- 7-day refresh token and, before this change, gave the new session a FRESH
-- absolute window — so the absolute timeout (default 12h) never actually bit:
-- a browser could be kept alive for the full 7-day refresh-token life.
--
-- Carry the original login's absolute deadline through the refresh-token
-- lineage: it is stamped at login and copied UNCHANGED on every rotation. Once
-- now > absolute_expires_at, refresh is refused and the chain ends.
--
-- Nullable: refresh tokens minted before this migration (in-flight, up to 7
-- days) carry NULL and are treated as legacy (no absolute ceiling) until they
-- naturally expire — no forced logout on upgrade.
--
-- Spec: system-auth-identity.

-- +goose Up
ALTER TABLE refresh_tokens ADD COLUMN absolute_expires_at TIMESTAMPTZ;

-- +goose Down
ALTER TABLE refresh_tokens DROP COLUMN absolute_expires_at;
