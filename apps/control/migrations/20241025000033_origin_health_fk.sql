-- Origin health rows must follow the current domain set. Before adding the
-- foreign key, remove rows left behind by older deletes or stale edge reports.
DELETE FROM origin_health oh
WHERE NOT EXISTS (
    SELECT 1 FROM domains d WHERE d.name = oh.domain_name
);

-- Deleting a domain must atomically remove its health rows; an edge with a
-- stale config can no longer recreate them because the FK rejects the insert.
ALTER TABLE origin_health
    DROP CONSTRAINT IF EXISTS origin_health_domain_fk;

ALTER TABLE origin_health
    ADD CONSTRAINT origin_health_domain_fk
    FOREIGN KEY (domain_name) REFERENCES domains(name) ON DELETE CASCADE;
