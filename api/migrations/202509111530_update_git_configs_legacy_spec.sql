-- Align git_configs table closer to legacy spec (per-user)
ALTER TABLE git_configs
    ADD COLUMN IF NOT EXISTS user_id UUID NULL,
    ADD COLUMN IF NOT EXISTS repository_url TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS branch_name TEXT NOT NULL DEFAULT 'main',
    ADD COLUMN IF NOT EXISTS auth_type TEXT NULL,
    ADD COLUMN IF NOT EXISTS auth_data JSONB NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS auto_sync BOOLEAN NOT NULL DEFAULT true;

-- Optional backfill from previous columns if present
UPDATE git_configs SET repository_url = COALESCE(repository_url, remote_url) WHERE TRUE;
UPDATE git_configs SET branch_name = COALESCE(branch_name, branch) WHERE TRUE;

-- Indexes and partial unique constraint (user-scoped config)
CREATE INDEX IF NOT EXISTS idx_git_configs_user_id ON git_configs(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_git_configs_user_id ON git_configs(user_id) WHERE user_id IS NOT NULL;

-- Sync logs (minimal)
CREATE TABLE IF NOT EXISTS git_sync_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  operation TEXT NOT NULL CHECK (operation IN ('push','pull','commit','init')),
  status TEXT NOT NULL CHECK (status IN ('success','error')),
  message TEXT NULL,
  commit_hash TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_git_sync_logs_user_id ON git_sync_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_git_sync_logs_created_at ON git_sync_logs(created_at DESC);
