CREATE TABLE IF NOT EXISTS git_pull_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending', -- pending | resolving | merged | stale
  conflicts JSONB NOT NULL DEFAULT '[]'::jsonb,
  resolutions JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  base_commit BYTEA NULL,
  remote_commit BYTEA NULL
);

CREATE INDEX IF NOT EXISTS idx_git_pull_sessions_workspace ON git_pull_sessions(workspace_id, updated_at DESC);
