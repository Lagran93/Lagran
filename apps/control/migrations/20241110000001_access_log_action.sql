-- Separate edge/security action from the cache outcome in visitor logs.
ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS action TEXT NOT NULL DEFAULT '';
