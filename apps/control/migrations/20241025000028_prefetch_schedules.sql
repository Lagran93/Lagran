-- Scheduled cache warming.
CREATE TABLE IF NOT EXISTS prefetch_schedules (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain           TEXT NOT NULL,
    paths            JSONB NOT NULL DEFAULT '[]'::jsonb,
    interval_minutes INT NOT NULL DEFAULT 60,
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    last_run_at      TIMESTAMPTZ,
    next_run_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_prefetch_schedules_due
    ON prefetch_schedules (next_run_at)
    WHERE enabled = TRUE;

ALTER TABLE prefetch_tasks
    ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'manual';
