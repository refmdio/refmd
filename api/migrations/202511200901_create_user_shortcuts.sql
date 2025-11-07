CREATE TABLE IF NOT EXISTS user_shortcuts (
  user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  bindings JSONB NOT NULL DEFAULT '{}'::jsonb,
  leader_key TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_user_shortcuts_updated_at ON user_shortcuts(updated_at);
