-- Authentication attempt history for security review.
CREATE TABLE IF NOT EXISTS login_logs (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    email TEXT NOT NULL,
    client_ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    success BOOLEAN NOT NULL,
    reason TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_login_logs_created_at
    ON login_logs (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_login_logs_email_created_at
    ON login_logs (email, created_at DESC);
