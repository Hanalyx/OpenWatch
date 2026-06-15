-- 0031_notification_channels_email.sql
--
-- Phase 2b: add the email/SMTP channel type. The 0030 CHECK constraint
-- only allowed slack + webhook; widen it to include email. The SMTP
-- target (host/port/username/password/from/to) rides in the same
-- AES-256-GCM config_ciphertext blob as the HTTP channels' url/token —
-- no schema change beyond the CHECK.

-- +goose Up
ALTER TABLE notification_channels DROP CONSTRAINT notification_channels_type_check;
ALTER TABLE notification_channels
    ADD CONSTRAINT notification_channels_type_check
    CHECK (type IN ('slack', 'webhook', 'email'));

-- +goose Down
ALTER TABLE notification_channels DROP CONSTRAINT notification_channels_type_check;
ALTER TABLE notification_channels
    ADD CONSTRAINT notification_channels_type_check
    CHECK (type IN ('slack', 'webhook'));
