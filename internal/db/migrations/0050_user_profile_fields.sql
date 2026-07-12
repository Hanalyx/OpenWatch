-- 0050_user_profile_fields.sql
--
-- Self-service profile fields on the users table. The Settings -> Profile
-- page renders full name, display name, job title, timezone, and phone, but
-- until now had nowhere to store them (the users table held only the
-- sign-in identity + auth material), so the "Save changes" button was a
-- no-op. These columns back the new PATCH /api/v1/auth/me endpoint.
--
-- All are non-secret free text, nullable-by-default via an empty-string
-- default (keeps the columns NOT NULL so reads never see NULL). Email stays
-- where it is (it is the sign-in identity with its own unique index); the
-- PATCH endpoint updates users.email directly with a uniqueness check.
--
-- Spec: api-auth (patchAuthMe) + system-user-management.

-- +goose Up
ALTER TABLE users
    ADD COLUMN full_name    TEXT NOT NULL DEFAULT '',
    ADD COLUMN display_name TEXT NOT NULL DEFAULT '',
    ADD COLUMN job_title    TEXT NOT NULL DEFAULT '',
    ADD COLUMN timezone     TEXT NOT NULL DEFAULT '',
    ADD COLUMN phone        TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE users
    DROP COLUMN full_name,
    DROP COLUMN display_name,
    DROP COLUMN job_title,
    DROP COLUMN timezone,
    DROP COLUMN phone;
