-- Scope alert channels, rules and events to a project.
-- Existing rows (project_id IS NULL) remain global and are visible only to admins.

ALTER TABLE alert_channels
    ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id) ON DELETE CASCADE;
ALTER TABLE alert_rules
    ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id) ON DELETE CASCADE;
ALTER TABLE alert_events
    ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_alert_channels_project ON alert_channels(project_id);
CREATE INDEX IF NOT EXISTS idx_alert_rules_project ON alert_rules(project_id);
CREATE INDEX IF NOT EXISTS idx_alert_events_project ON alert_events(project_id, started_at DESC);
