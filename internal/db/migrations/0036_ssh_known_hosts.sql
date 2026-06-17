-- 0036_ssh_known_hosts.sql
--
-- Persistent SSH known-hosts store. OpenWatch dials managed hosts from the
-- scan, discovery, intelligence, and liveness paths. Host-key verification
-- runs in TOFU mode (trust-on-first-use, then strict against the stored
-- key). Before this table the store was in-memory and per-process, so the
-- "trust" was forgotten on every daemon restart — re-TOFU meant a
-- network-positioned attacker could MITM the first scan after each restart
-- and harvest the credentials presented to the host.
--
-- This table makes TOFU durable: the first key seen for a hostname is
-- recorded once and verified on every later connection, including across
-- restarts. A changed key (MITM or legitimate rekey) surfaces as a
-- mismatch the dial layer rejects.
--
-- Keyed by hostname (the dial layer's lookup key). public_key is the
-- wire-marshalled ssh.PublicKey bytes.

-- +goose Up
CREATE TABLE ssh_known_hosts (
    hostname    TEXT PRIMARY KEY,
    public_key  BYTEA NOT NULL,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE ssh_known_hosts;
