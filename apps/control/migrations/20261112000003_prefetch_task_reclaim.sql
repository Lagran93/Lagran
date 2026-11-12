-- Reclaim prefetch tasks that were claimed but never finished.
--
-- `claim_prefetch_tasks` flips a row to `running` and nothing ever moved it back.
-- A worker that dies mid-task (panic, deploy, killed pod), or a dispatch that
-- outlives every timeout, left the row `running` forever: it was never retried,
-- never reported, and the console showed a stuck entry. There was no column to
-- tell how long a task had been running, so staleness could not even be measured.
--
-- `started_at` records the claim time. The worker uses it to return abandoned
-- tasks to `pending` (or mark them `failed` once they have been retried too
-- often) instead of leaving them in limbo.

ALTER TABLE prefetch_tasks
    ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS attempts INT NOT NULL DEFAULT 0;

-- Existing `running` rows have no start time. Treat them as started now, so the
-- reclaim threshold applies from this upgrade rather than instantly expiring
-- tasks that a live worker may still be processing.
UPDATE prefetch_tasks
SET started_at = NOW()
WHERE status = 'running' AND started_at IS NULL;

-- The reclaim query scans by status and start time.
CREATE INDEX IF NOT EXISTS idx_prefetch_tasks_running
    ON prefetch_tasks (status, started_at)
    WHERE status = 'running';
