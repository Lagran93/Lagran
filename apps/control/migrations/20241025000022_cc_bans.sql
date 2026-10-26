-- Cross-node CC bans. Edges report auto-bans here; every edge polls the
-- active list and enforces it locally. Rows expire automatically by time and
-- are also cleaned opportunistically.
CREATE TABLE IF NOT EXISTS cc_bans (
    id BIGSERIAL PRIMARY KEY,
    domain TEXT NOT NULL,
    ip TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'edge',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    UNIQUE (domain, ip)
);

CREATE INDEX IF NOT EXISTS idx_cc_bans_expires_at ON cc_bans (expires_at);
