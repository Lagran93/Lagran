ALTER TABLE cache_rules
    ADD COLUMN IF NOT EXISTS match_content_type TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN cache_rules.match_content_type IS
    'Optional case-insensitive Content-Type substring; empty matches any response type';
