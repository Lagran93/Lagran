-- SEC-NEW-05: prefetch listings are tenant-filtered in SQL, not in memory.
--
-- The console queries are `WHERE domain = ANY($visible) ORDER BY created_at
-- DESC LIMIT n`. Neither table had an index on `domain`, so the database still
-- had to read and sort the whole table to produce one tenant's window — the
-- cost the pushdown was supposed to remove. A composite index lets Postgres
-- walk the (domain, newest-first) order directly and stop at the limit.
CREATE INDEX IF NOT EXISTS idx_prefetch_tasks_domain_created
    ON prefetch_tasks (domain, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_prefetch_schedules_domain_created
    ON prefetch_schedules (domain, created_at DESC);