-- WAF browser challenge settings (per domain)

ALTER TABLE waf_settings
    ADD COLUMN IF NOT EXISTS challenge_difficulty INT NOT NULL DEFAULT 4;
ALTER TABLE waf_settings
    ADD COLUMN IF NOT EXISTS challenge_ttl_secs INT NOT NULL DEFAULT 1800;

COMMENT ON COLUMN waf_settings.challenge_difficulty IS 'Number of leading hex zeroes for the JS challenge (1-6)';
COMMENT ON COLUMN waf_settings.challenge_ttl_secs IS 'Clearance cookie lifetime in seconds';
