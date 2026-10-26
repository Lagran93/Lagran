-- Allow a cache rule to cache static assets even when the browser sends
-- cookies (analytics/session cookies often make otherwise-cacheable assets
-- bypass the shared cache).
ALTER TABLE cache_rules
    ADD COLUMN IF NOT EXISTS ignore_cookie BOOLEAN NOT NULL DEFAULT FALSE;
