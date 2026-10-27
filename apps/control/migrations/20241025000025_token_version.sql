-- Session epoch / token version. Incrementing this column invalidates every
-- JWT issued with the previous value.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS token_version BIGINT NOT NULL DEFAULT 0;
