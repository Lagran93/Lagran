CREATE TABLE IF NOT EXISTS audit_logs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor       TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL,
    resource    TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT '',
    ip          TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at DESC);

-- optional domain notes
ALTER TABLE domains ADD COLUMN IF NOT EXISTS remark TEXT NOT NULL DEFAULT '';
