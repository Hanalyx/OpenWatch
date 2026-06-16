-- 0035_host_connection_profile.sql
--
-- Per-host "last known good" SSH connection profile. OpenWatch talks to a
-- managed host from four code paths (liveness privilege probe, OS
-- discovery, OS intelligence collection, and the compliance scan). Each
-- has to decide, every time it connects, (a) which SSH auth method to
-- offer first and (b) how to escalate to root. Without memory, every
-- connection re-discovers this: it offers the public key even to a host
-- that only accepts the password (a failed publickey attempt that counts
-- against MaxAuthTries and can trip fail2ban), and it runs `sudo -n` even
-- on a host known to need a sudo password (a wasted round-trip before the
-- `sudo -S` retry).
--
-- This table records what actually worked last time so each path can lead
-- with the known-good choice. It is a hint, never a lock: callers still
-- fall back to the other methods if the recorded one fails (keys rotate,
-- sudoers change) and rewrite the row when the working choice changes, so
-- a stale hint self-heals on the next connection.
--
-- One row per host, UPSERTed by whichever path last connected. Columns are
-- nullable: a value is absent until that dimension has been observed once.

-- +goose Up
CREATE TABLE host_connection_profile (
    host_id          UUID PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,

    -- The SSH auth method that last authenticated successfully. Drives the
    -- order auth methods are offered to crypto/ssh on the next dial.
    ssh_auth_method  TEXT CHECK (ssh_auth_method IN ('key', 'password')),

    -- The privilege mode that last reached root successfully:
    --   'root'     — the login user is already root; no sudo wrapping.
    --   'nopasswd' — `sudo -n` succeeded (NOPASSWD sudoers).
    --   'password' — `sudo -S` with the credential password succeeded.
    sudo_mode        TEXT CHECK (sudo_mode IN ('root', 'nopasswd', 'password')),

    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS host_connection_profile;
