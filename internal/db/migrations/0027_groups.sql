-- 0027_groups.sql
--
-- Host groups. A host can belong to many groups. Two kinds:
--
--   site         - an operator-curated grouping by environment or
--                  topology role (Production, Development, DR). Membership
--                  is MANUAL: hosts are assigned explicitly via
--                  group_members.
--   os_category  - a platform/workload grouping. An os_category may be
--                  AUTO (membership computed live from hosts.os_family ==
--                  match_family, e.g. an "RHEL" group of every RHEL host)
--                  or MANUAL (a curated workload group like "Database").
--
-- Auto membership is NOT materialised into group_members: it is derived
-- at query time from hosts.os_family so a newly-discovered host joins its
-- OS group with no backfill. Manual membership lives in group_members.
--
-- maintenance pauses scanning/alerting for a group's hosts (surfaced in
-- the UI; enforcement is a follow-up). The check below enforces
-- auto <=> a match_family is set.
--
-- Spec: api-groups v1.0.0.

-- +goose Up
CREATE TABLE groups (
    id           UUID PRIMARY KEY,
    name         TEXT NOT NULL,
    kind         TEXT NOT NULL CHECK (kind IN ('site', 'os_category')),
    -- display label under the name (Environment, Disaster recovery, OS
    -- family, Workload). Free text; the UI does not enum it.
    subtype      TEXT NOT NULL DEFAULT '',
    -- swatch token name (an --ow-* accent the card renders).
    color        TEXT NOT NULL DEFAULT 'info',
    membership   TEXT NOT NULL CHECK (membership IN ('manual', 'auto')),
    -- auto groups: the hosts.os_family value whose hosts are members.
    -- NULL for manual groups. The CHECK ties them together.
    match_family TEXT,
    maintenance  BOOLEAN NOT NULL DEFAULT false,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT groups_auto_has_match
        CHECK ((membership = 'auto') = (match_family IS NOT NULL))
);

-- One auto group per OS family (two "RHEL" auto groups would double-count).
CREATE UNIQUE INDEX groups_one_auto_per_family
    ON groups (match_family) WHERE membership = 'auto';

CREATE TABLE group_members (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    host_id  UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, host_id)
);

CREATE INDEX group_members_host ON group_members (host_id);

-- +goose Down
DROP TABLE IF EXISTS group_members;
DROP TABLE IF EXISTS groups;
