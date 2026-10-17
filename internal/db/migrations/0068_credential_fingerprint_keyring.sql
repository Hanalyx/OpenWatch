-- +goose Up
-- The fingerprint keyring (features/OW-122 slice 2; spec
-- system-credential-protection C-15 to C-17; slice 2 proposal r3).
--
-- A password's identifier is HMAC-SHA256(fingerprint key, normalized
-- username || 0x00 || password). Each fingerprint key is 32 random bytes,
-- stored wrapped (AES-256-GCM) by the credential encryption key. Rotating the
-- encryption key re-wraps these rows (openwatch credential-key rewrap); it
-- never changes a key, so recorded protection state keeps matching. A
-- password is identified under every key here, and a key is never removed
-- while protection history may use it.
--
-- credprotect_keyring is a single row that every keyring change locks FOR
-- UPDATE and every reservation reads FOR SHARE. This migration creates it, so
-- even the first initialization locks a row that exists. generation changes
-- whenever the set of keys or the current key changes; wrap_epoch on every
-- re-wrap.
--
-- Nothing here is swept: losing a key loses the protection history it
-- identifies.

CREATE TABLE credprotect_keyring (
    singleton       BOOLEAN      PRIMARY KEY DEFAULT true,
    initialized_at  TIMESTAMPTZ,
    generation      BIGINT       NOT NULL DEFAULT 0,
    wrap_epoch      BIGINT       NOT NULL DEFAULT 0,
    CONSTRAINT credprotect_keyring_one_row CHECK (singleton),
    CONSTRAINT credprotect_keyring_counters CHECK (generation >= 0 AND wrap_epoch >= 0)
);

INSERT INTO credprotect_keyring (singleton) VALUES (true);

CREATE TABLE credprotect_fingerprint_keys (
    id          UUID         PRIMARY KEY,
    wrapped     BYTEA        NOT NULL,
    is_current  BOOLEAN      NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ  NOT NULL
);

-- At most one current key. "Exactly one" is checked by the code that reads
-- the keyring, which refuses a keyring with none.
CREATE UNIQUE INDEX credprotect_fingerprint_keys_one_current
    ON credprotect_fingerprint_keys ((true)) WHERE is_current;

-- +goose Down
DROP TABLE credprotect_fingerprint_keys;
DROP TABLE credprotect_keyring;
