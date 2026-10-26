-- Per-domain CC (L7 flood) protection. Counters and bans live in edge
-- memory; these columns configure the policy and are pushed with the domain
-- config.
ALTER TABLE domains
    ADD COLUMN IF NOT EXISTS cc_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS cc_rps INTEGER NOT NULL DEFAULT 20,
    ADD COLUMN IF NOT EXISTS cc_burst INTEGER NOT NULL DEFAULT 40,
    ADD COLUMN IF NOT EXISTS cc_ban_after INTEGER NOT NULL DEFAULT 5,
    ADD COLUMN IF NOT EXISTS cc_ban_seconds INTEGER NOT NULL DEFAULT 300,
    ADD COLUMN IF NOT EXISTS cc_mode TEXT NOT NULL DEFAULT 'block',
    ADD COLUMN IF NOT EXISTS cc_allow_ips TEXT NOT NULL DEFAULT '';
