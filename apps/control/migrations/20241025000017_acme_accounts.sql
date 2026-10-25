-- ACME (Let's Encrypt) account credentials, shared by control instances.

CREATE TABLE IF NOT EXISTS acme_accounts (
    directory   TEXT PRIMARY KEY,
    key_pem     TEXT NOT NULL,
    kid         TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
