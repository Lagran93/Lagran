-- Cache rule enhancements: conditions, browser TTL, per-rule toggles

ALTER TABLE cache_rules ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE cache_rules ADD COLUMN IF NOT EXISTS match_methods TEXT NOT NULL DEFAULT '';
ALTER TABLE cache_rules ADD COLUMN IF NOT EXISTS match_query TEXT NOT NULL DEFAULT '';
ALTER TABLE cache_rules ADD COLUMN IF NOT EXISTS browser_ttl_seconds BIGINT NOT NULL DEFAULT 0;
-- NULL means "inherit the domain's ignore_query_string setting"
ALTER TABLE cache_rules ADD COLUMN IF NOT EXISTS ignore_query BOOLEAN;
ALTER TABLE cache_rules ADD COLUMN IF NOT EXISTS note TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN cache_rules.match_methods IS 'Comma separated methods; empty matches all';
COMMENT ON COLUMN cache_rules.match_query IS 'Case-insensitive substring of the raw query string; empty matches all';
COMMENT ON COLUMN cache_rules.browser_ttl_seconds IS 'Override Cache-Control max-age sent to clients; 0 keeps origin headers';
