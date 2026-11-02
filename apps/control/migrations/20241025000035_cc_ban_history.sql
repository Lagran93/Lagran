-- Preserve CC ban history instead of deleting rows on manual unban.
ALTER TABLE cc_bans
    ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS revoked_by TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_cc_bans_created_at
    ON cc_bans (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_cc_bans_domain_created
    ON cc_bans (domain, created_at DESC);
