-- Per-prefetch cache-key request headers. These are sent on the internal
-- warmup GET so Accept-Language/Origin/CORS variants can be selected by the
-- operator and match real browser cache keys.
ALTER TABLE prefetch_tasks
    ADD COLUMN IF NOT EXISTS headers JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE prefetch_schedules
    ADD COLUMN IF NOT EXISTS headers JSONB NOT NULL DEFAULT '{}'::jsonb;
