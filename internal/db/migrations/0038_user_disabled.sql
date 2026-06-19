-- 0038_user_disabled.sql
--
-- Account disable for admin user-management. A disabled user cannot
-- authenticate: the login path rejects them and the session binder rejects
-- their cookie. Disabling also revokes the user's active sessions so the
-- cutoff is immediate (not deferred to session expiry).
--
-- Modeled on the existing deleted_at soft-delete column (0005_identity): a
-- nullable timestamp, where NOT NULL means "disabled since". Distinct from
-- deleted_at — a disabled account is recoverable (enable) and keeps its
-- username/email; a deleted account is gone.
--
-- Spec: api-users (admin reset-password + disable/enable).

-- +goose Up
ALTER TABLE users ADD COLUMN disabled_at TIMESTAMPTZ;

-- +goose Down
ALTER TABLE users DROP COLUMN IF EXISTS disabled_at;
