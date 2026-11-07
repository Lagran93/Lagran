-- Signed managed WAF rulepack versions.
CREATE TABLE IF NOT EXISTS waf_rulepack_versions (
    version TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    signature TEXT NOT NULL,
    checksum TEXT NOT NULL,
    slot TEXT NOT NULL DEFAULT 'retired',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by TEXT NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX IF NOT EXISTS waf_rulepack_one_active
    ON waf_rulepack_versions ((slot = 'active')) WHERE slot = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS waf_rulepack_one_previous
    ON waf_rulepack_versions ((slot = 'previous')) WHERE slot = 'previous';

-- Per-domain version pin and gray rollout percentage.
ALTER TABLE waf_settings
    ADD COLUMN IF NOT EXISTS waf_rulepack_version TEXT NOT NULL DEFAULT '';
ALTER TABLE waf_settings
    ADD COLUMN IF NOT EXISTS waf_gray_percent INT NOT NULL DEFAULT 0;
