-- Create table for Git integration configuration (single-row minimal config)
CREATE TABLE IF NOT EXISTS git_configs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  root_path TEXT NOT NULL,
  remote_url TEXT NULL,
  branch TEXT NOT NULL DEFAULT 'main',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Ensure at most one row by adding a dummy uniqueness via boolean column if needed later.
-- For now, API will treat the first row as the active config.

-- Helpful index
CREATE INDEX IF NOT EXISTS idx_git_configs_updated_at ON git_configs(updated_at);
