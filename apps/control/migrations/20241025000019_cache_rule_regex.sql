-- Cache rule matching mode: glob (existing behavior) or regex.
ALTER TABLE cache_rules
    ADD COLUMN IF NOT EXISTS match_type TEXT NOT NULL DEFAULT 'glob';
