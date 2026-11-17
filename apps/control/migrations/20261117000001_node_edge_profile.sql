-- Hardware profile captured by the console's "add edge" wizard.
--
-- Stored as JSON text: the console owns the shape (see
-- apps/frontend/utils/edgeSizing.ts), the control plane only round-trips it,
-- and rows created before the wizard existed keep the empty default. TEXT
-- instead of JSONB keeps this migration independent of sqlx's JSON feature and
-- makes the column trivially forward/backward compatible.
ALTER TABLE edge_nodes
    ADD COLUMN IF NOT EXISTS edge_profile TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN edge_nodes.edge_profile IS
    'Console-generated edge.env sizing inputs (hardware profile), JSON text';
