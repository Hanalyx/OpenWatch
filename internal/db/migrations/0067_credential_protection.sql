-- +goose Up
-- Credential protection state and reservations (features/OW-122, slice 3).
-- Spec system-credential-protection. internal/credprotect is the only code
-- that reads or writes these tables.
--
-- A secret is identified by its kind and its aliases: (key id, 32-byte keyed
-- identifier) pairs, stored as the parallel arrays alias_key_ids and
-- alias_ids. Every row that records a secret stores every alias the writer
-- presented, and two secrets are the same when their kinds match and their
-- alias sets overlap. So a row written under [new, old] during a key
-- rotation is seen by a reservation that knows only old, and the reverse.
-- An identifier is a sensitive equality value: it is never returned by the
-- API, logged or audited.
--
-- Nothing here is swept. Protection history must outlive the credentials and
-- hosts it was recorded for, so the foreign keys to them set NULL rather
-- than cascade, except a credential's classification, which describes the
-- credential itself.

CREATE TABLE credprotect_identities (
    id              UUID         PRIMARY KEY,
    scope           TEXT         NOT NULL,
    username        TEXT         NOT NULL,
    host_id         UUID         REFERENCES hosts(id) ON DELETE SET NULL,
    directory_name  TEXT,
    depth           INTEGER      NOT NULL,
    created_at      TIMESTAMPTZ  NOT NULL,
    CONSTRAINT credprotect_identities_scope_known
        CHECK (scope IN ('unconfirmed', 'local', 'directory')),
    CONSTRAINT credprotect_identities_depth_bounded
        CHECK (depth BETWEEN 1 AND 3),
    CONSTRAINT credprotect_identities_root_depth
        CHECK ((scope = 'unconfirmed') = (depth = 1)),
    CONSTRAINT credprotect_identities_directory_named
        CHECK ((scope = 'directory') = (directory_name IS NOT NULL))
);

-- One root per username, one local identity per account on a host, one
-- directory identity per name.
CREATE UNIQUE INDEX uq_credprotect_identities_root
    ON credprotect_identities (username) WHERE scope = 'unconfirmed';
CREATE UNIQUE INDEX uq_credprotect_identities_local
    ON credprotect_identities (host_id, username) WHERE scope = 'local';
CREATE UNIQUE INDEX uq_credprotect_identities_directory
    ON credprotect_identities (directory_name) WHERE scope = 'directory';

CREATE TABLE credprotect_identity_edges (
    child_id   UUID  NOT NULL REFERENCES credprotect_identities(id),
    parent_id  UUID  NOT NULL REFERENCES credprotect_identities(id),
    PRIMARY KEY (child_id, parent_id),
    CONSTRAINT credprotect_identity_edges_not_self CHECK (child_id <> parent_id)
);
CREATE INDEX idx_credprotect_identity_edges_parent ON credprotect_identity_edges (parent_id);

-- A credential with no row here is unconfirmed. parent_identity_id is the
-- identity the credential resolved to before it was classified; new
-- identities it resolves to get a lineage edge to it.
CREATE TABLE credprotect_credential_classes (
    credential_id          UUID         PRIMARY KEY REFERENCES credentials(id) ON DELETE CASCADE,
    scope                  TEXT         NOT NULL,
    directory_identity_id  UUID         REFERENCES credprotect_identities(id),
    parent_identity_id     UUID         NOT NULL REFERENCES credprotect_identities(id),
    classified_at          TIMESTAMPTZ  NOT NULL,
    CONSTRAINT credprotect_credential_classes_scope_known
        CHECK (scope IN ('local', 'directory')),
    CONSTRAINT credprotect_credential_classes_directory_named
        CHECK ((scope = 'directory') = (directory_identity_id IS NOT NULL))
);

CREATE TABLE credprotect_restrictions (
    id             UUID         PRIMARY KEY,
    identity_id    UUID         NOT NULL REFERENCES credprotect_identities(id),
    kind           TEXT         NOT NULL,
    -- NULL secret: every secret of the identity (a pause, or a block from an
    -- ambiguous outcome).
    secret_kind    TEXT,
    alias_key_ids  TEXT[],
    alias_ids      BYTEA[],
    reason         TEXT         NOT NULL,
    submission_id  UUID,
    created_at     TIMESTAMPTZ  NOT NULL,
    -- A cooldown's end.
    expires_at     TIMESTAMPTZ,
    -- A pause's end, set on the identity where it was created.
    ended_at       TIMESTAMPTZ,
    CONSTRAINT credprotect_restrictions_kind_known
        CHECK (kind IN ('block', 'pause', 'cooldown', 'allowance_used')),
    CONSTRAINT credprotect_restrictions_secret_whole
        CHECK ((secret_kind IS NULL) = (alias_ids IS NULL)
           AND (secret_kind IS NULL) = (alias_key_ids IS NULL)
           AND (secret_kind IS NULL OR (cardinality(alias_ids) = cardinality(alias_key_ids)
                                        AND cardinality(alias_ids) >= 1))),
    CONSTRAINT credprotect_restrictions_secret_kind_known
        CHECK (secret_kind IS NULL OR secret_kind IN ('password', 'key')),
    CONSTRAINT credprotect_restrictions_pause_every_secret
        CHECK (kind <> 'pause' OR secret_kind IS NULL),
    CONSTRAINT credprotect_restrictions_one_secret
        CHECK (kind NOT IN ('cooldown', 'allowance_used') OR secret_kind IS NOT NULL),
    CONSTRAINT credprotect_restrictions_cooldown_expires
        CHECK ((kind = 'cooldown') = (expires_at IS NOT NULL)),
    CONSTRAINT credprotect_restrictions_only_pause_ends
        CHECK (kind = 'pause' OR ended_at IS NULL)
);
CREATE INDEX idx_credprotect_restrictions_identity ON credprotect_restrictions (identity_id);

CREATE TABLE credprotect_submissions (
    id               UUID         PRIMARY KEY,
    identity_id      UUID         NOT NULL REFERENCES credprotect_identities(id),
    credential_id    UUID         REFERENCES credentials(id) ON DELETE SET NULL,
    host_id          UUID         REFERENCES hosts(id) ON DELETE SET NULL,
    kind             TEXT         NOT NULL,
    stage            TEXT         NOT NULL,
    -- Every alias the submission was reserved with. The restrictions it
    -- creates record all of them.
    secret_kind      TEXT         NOT NULL,
    alias_key_ids    TEXT[]       NOT NULL,
    alias_ids        BYTEA[]      NOT NULL,
    owner_machine    TEXT         NOT NULL,
    owner_pid        INTEGER      NOT NULL,
    owner_start      TEXT         NOT NULL,
    reserved_at      TIMESTAMPTZ  NOT NULL,
    deadline         TIMESTAMPTZ  NOT NULL,
    -- The ids of every restriction that applied when this was reserved.
    snapshot         UUID[]       NOT NULL,
    slot_held        BOOLEAN      NOT NULL,
    -- Known to have ended: the owner reported, or its process was verified
    -- gone. Until then an overridden submission counts in o.
    ended_at         TIMESTAMPTZ,
    overridden_at    TIMESTAMPTZ,
    override_by      UUID,
    override_reason  TEXT,
    outcome          TEXT,
    outcome_by       TEXT,
    outcome_at       TIMESTAMPTZ,
    late             BOOLEAN      NOT NULL DEFAULT false,
    late_outcome     TEXT,
    late_outcome_at  TIMESTAMPTZ,
    CONSTRAINT credprotect_submissions_kind_known
        CHECK (kind IN ('ordinary', 'verification')),
    CONSTRAINT credprotect_submissions_secret_kind_known
        CHECK (secret_kind IN ('password', 'key')),
    CONSTRAINT credprotect_submissions_outcome_by_known
        CHECK (outcome_by IS NULL OR outcome_by IN ('owner', 'expiry', 'termination')),
    CONSTRAINT credprotect_submissions_outcome_whole
        CHECK ((outcome IS NULL) = (outcome_by IS NULL) AND (outcome IS NULL) = (outcome_at IS NULL)),
    CONSTRAINT credprotect_submissions_override_whole
        CHECK ((overridden_at IS NULL) = (override_reason IS NULL)),
    CONSTRAINT credprotect_submissions_overridden_slot_free
        CHECK (overridden_at IS NULL OR NOT slot_held),
    CONSTRAINT credprotect_submissions_aliases_paired
        CHECK (cardinality(alias_key_ids) = cardinality(alias_ids) AND cardinality(alias_ids) >= 1),
    CONSTRAINT credprotect_submissions_owner_whole
        CHECK (owner_machine <> '' AND owner_pid > 0 AND owner_start <> ''),
    CONSTRAINT credprotect_submissions_late_follows_unknown
        CHECK (late_outcome IS NULL OR (outcome = 'unknown' AND outcome_by = 'expiry'))
);
-- K = 1: at most one submission per identity holds a slot. The reservation
-- also checks this under the username's lock; the index makes it a
-- database invariant too.
CREATE UNIQUE INDEX uq_credprotect_submissions_slot
    ON credprotect_submissions (identity_id) WHERE slot_held;
CREATE INDEX idx_credprotect_submissions_open
    ON credprotect_submissions (deadline) WHERE outcome IS NULL;

CREATE TABLE credprotect_recoveries (
    id             UUID         PRIMARY KEY,
    identity_id    UUID         NOT NULL REFERENCES credprotect_identities(id),
    submission_id  UUID         NOT NULL UNIQUE REFERENCES credprotect_submissions(id),
    -- The block ids this recovery lifts, for this identity only.
    lifted         UUID[]       NOT NULL,
    created_at     TIMESTAMPTZ  NOT NULL
);
CREATE INDEX idx_credprotect_recoveries_identity ON credprotect_recoveries (identity_id);

CREATE TABLE credprotect_verification_requests (
    id              UUID         PRIMARY KEY,
    identity_id     UUID         NOT NULL REFERENCES credprotect_identities(id),
    secret_kind     TEXT         NOT NULL,
    alias_key_ids   TEXT[]       NOT NULL,
    alias_ids       BYTEA[]      NOT NULL,
    requested_by    UUID         NOT NULL,
    requested_at    TIMESTAMPTZ  NOT NULL,
    ended_at        TIMESTAMPTZ,
    ended_by_submission UUID     REFERENCES credprotect_submissions(id)
);
-- At most one pending request per identity and secret is enforced under the
-- username's lock: alias sets match by overlap, which an index cannot test.
CREATE INDEX idx_credprotect_verification_requests_pending
    ON credprotect_verification_requests (identity_id) WHERE ended_at IS NULL;

CREATE TABLE credprotect_verified_secrets (
    recovery_id    UUID         PRIMARY KEY REFERENCES credprotect_recoveries(id),
    identity_id    UUID         NOT NULL REFERENCES credprotect_identities(id),
    secret_kind    TEXT         NOT NULL,
    alias_key_ids  TEXT[]       NOT NULL,
    alias_ids      BYTEA[]      NOT NULL,
    verified_at    TIMESTAMPTZ  NOT NULL
);
CREATE INDEX idx_credprotect_verified_secrets_identity ON credprotect_verified_secrets (identity_id);

-- +goose Down
DROP TABLE IF EXISTS credprotect_verified_secrets;
DROP TABLE IF EXISTS credprotect_verification_requests;
DROP TABLE IF EXISTS credprotect_recoveries;
DROP TABLE IF EXISTS credprotect_submissions;
DROP TABLE IF EXISTS credprotect_restrictions;
DROP TABLE IF EXISTS credprotect_credential_classes;
DROP TABLE IF EXISTS credprotect_identity_edges;
DROP TABLE IF EXISTS credprotect_identities;
