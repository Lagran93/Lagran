-- Make the "one firing event per (rule, fingerprint)" guarantee hold when
-- `rule_id` is NULL.
--
-- `idx_alert_events_firing` is `(rule_id, fingerprint) WHERE status = 'firing'`.
-- Postgres treats NULLs as distinct in a unique index, so the constraint stopped
-- applying exactly when `alert_events.rule_id` became NULL - which happens for
-- every event of a deleted rule, because the column is `ON DELETE SET NULL`.
-- Deleting a rule therefore left a growing set of duplicate firing events, each
-- of which fires its own notification.
--
-- Indexing `COALESCE(rule_id, ...)` gives the orphaned rows a real key value, so
-- duplicates are rejected again. A fixed all-zero UUID is used as the sentinel
-- because it can never be a real `alert_rules.id` (those come from
-- `gen_random_uuid()`); the point is uniqueness, not identity.

-- 1) Drop the old index first: the rebuild below would otherwise fail on rows
--    that already violate the new expression.
DROP INDEX IF EXISTS idx_alert_events_firing;

-- 2) Remove duplicates the broken constraint allowed. Keep the oldest event of
--    each group: it carries the real `started_at` operators care about, and the
--    newer rows are the ones that leaked through.
DELETE FROM alert_events a
USING alert_events b
WHERE a.status = 'firing'
  AND b.status = 'firing'
  AND a.id > b.id
  AND a.fingerprint = b.fingerprint
  AND COALESCE(a.rule_id, '00000000-0000-0000-0000-000000000000'::uuid)
    = COALESCE(b.rule_id, '00000000-0000-0000-0000-000000000000'::uuid);

-- 3) Rebuild with the NULL-safe key.
CREATE UNIQUE INDEX IF NOT EXISTS idx_alert_events_firing
    ON alert_events (COALESCE(rule_id, '00000000-0000-0000-0000-000000000000'::uuid), fingerprint)
    WHERE status = 'firing';
