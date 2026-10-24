CREATE TABLE IF NOT EXISTS acme_challenges (
    token           TEXT PRIMARY KEY,
    key_authorization TEXT NOT NULL,
    domain_name     TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '1 hour')
);
