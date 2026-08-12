-- +goose Up
-- Scope the idempotency cache to the caller who created the entry.
--
-- A cache hit answers at internal/idempotency/middleware.go with
-- replayCached and returns without calling next.ServeHTTP, so the handler
-- never runs and no authorization check inside it ever executes. The cached
-- row carried no caller identity: the primary key was the client-supplied
-- header value alone, one global namespace with a 24 hour life. Any caller
-- who knew another caller's key and the exact body that produced its hash
-- was served that caller's stored response. See CP
-- bugs/OW-012-idempotency-replay-bypasses-authorization.
--
-- Moving the permission check above the middleware was considered and is not
-- enough. It stops an anonymous replay, but caller B, who legitimately holds
-- the permission, is still served caller A's cached response. The cache key
-- itself has to carry the actor, which is what this migration adds.
--
-- Dropping the existing rows is required, not merely tolerated. ADD COLUMN
-- with NOT NULL and no default fails on a non-empty table, and there is no
-- honest actor value to backfill: the rows never recorded who made the call,
-- so any default would invent one. Dropping them is also correct on its own
-- terms. This table is a response cache with a 24 hour life, an upgrade
-- restarts the process anyway, and the worst case is one client re-executing
-- a retry once. That is the same outcome as the TTL expiring a second
-- earlier, which the design already accepts.
DELETE FROM idempotency_keys;
ALTER TABLE idempotency_keys DROP CONSTRAINT idempotency_keys_pkey;
ALTER TABLE idempotency_keys ADD COLUMN actor_id TEXT NOT NULL;
ALTER TABLE idempotency_keys ADD CONSTRAINT idempotency_keys_pkey PRIMARY KEY (actor_id, key);

COMMENT ON COLUMN idempotency_keys.actor_id IS
    'auth.Identity.ID of the caller that created this entry. Part of the primary key: a replay from a different actor must miss the cache so the handler runs and that caller''s own authorization applies. See CP bugs/OW-012-idempotency-replay-bypasses-authorization.';

-- +goose Down
-- Same reasoning in reverse. The rows cannot survive the narrower key
-- collapsing back to a wider one: two actors may hold the same key, and
-- key alone can only keep one of them.
DELETE FROM idempotency_keys;
ALTER TABLE idempotency_keys DROP CONSTRAINT idempotency_keys_pkey;
ALTER TABLE idempotency_keys DROP COLUMN actor_id;
ALTER TABLE idempotency_keys ADD CONSTRAINT idempotency_keys_pkey PRIMARY KEY (key);
