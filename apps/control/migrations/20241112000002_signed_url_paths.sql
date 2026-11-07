-- Path-level signed URL policy.
ALTER TABLE domains ADD COLUMN IF NOT EXISTS signed_url_mode TEXT NOT NULL DEFAULT 'off';
ALTER TABLE domains ADD COLUMN IF NOT EXISTS signed_url_paths TEXT NOT NULL DEFAULT '';
-- Preserve the existing domain-wide behavior for domains already enabled.
UPDATE domains SET signed_url_mode = 'all' WHERE signed_url_enabled = TRUE;
