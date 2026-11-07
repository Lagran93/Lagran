-- Signed URL protection for a domain.
ALTER TABLE domains ADD COLUMN IF NOT EXISTS signed_url_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS signed_url_secret TEXT NOT NULL DEFAULT '';
ALTER TABLE domains ADD COLUMN IF NOT EXISTS signed_url_previous_secret TEXT NOT NULL DEFAULT '';
ALTER TABLE domains ADD COLUMN IF NOT EXISTS signed_url_ttl_secs INT NOT NULL DEFAULT 3600;
