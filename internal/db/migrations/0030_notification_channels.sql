-- 0030_notification_channels.sql
--
-- Operator-managed notification channels for alert delivery.
--
-- The alertrouter dispatch layer (internal/alertrouter) already fans
-- fired alerts out to registered Channel implementations, but the only
-- channel shipped to date is stdout (journal logging). This table makes
-- channels operator-configurable: a row per Slack/webhook endpoint, its
-- routing tag filter, and its target secret.
--
-- The target (Slack incoming-webhook URL, generic webhook URL + optional
-- bearer token) is a SECRET. It is stored encrypted at rest in
-- config_ciphertext via the same AES-256-GCM data-encryption key the
-- credential store uses (internal/secretkey); the plaintext config never
-- touches a column and is never returned by the API.

-- +goose Up
CREATE TABLE notification_channels (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    type              TEXT         NOT NULL CHECK (type IN ('slack', 'webhook')),
    name              TEXT         NOT NULL,
    enabled           BOOLEAN      NOT NULL DEFAULT true,
    -- AES-256-GCM ciphertext of the channel config JSON {url, token?}.
    config_ciphertext BYTEA        NOT NULL,
    -- Non-secret display hint (the target URL host, e.g. hooks.slack.com)
    -- so the list/read path never decrypts the secret just to render a
    -- recognizable label.
    target_hint       TEXT         NOT NULL DEFAULT '',
    -- Routing filter: alert tags this channel matches. Empty = wildcard
    -- (receives every alert), mirroring alertrouter.ChannelRegistration.
    tag_filter        JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_notification_channels_enabled ON notification_channels (enabled);

-- +goose Down
DROP TABLE IF EXISTS notification_channels;
