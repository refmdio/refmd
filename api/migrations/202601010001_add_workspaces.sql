-- Workspace core tables and data backfill

CREATE TABLE IF NOT EXISTS workspaces (
  id UUID PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  icon TEXT NULL,
  description TEXT NULL,
  created_by UUID NULL REFERENCES users(id) ON DELETE SET NULL,
  is_personal BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS workspace_members (
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_kind TEXT NOT NULL CHECK (role_kind IN ('system','custom')),
  system_role TEXT NULL CHECK (system_role IN ('owner','admin','editor','viewer')),
  custom_role_id UUID NULL,
  invited_by UUID NULL REFERENCES users(id) ON DELETE SET NULL,
  joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_active_at TIMESTAMPTZ NULL,
  is_default BOOLEAN NOT NULL DEFAULT false,
  PRIMARY KEY(workspace_id, user_id)
);

CREATE TABLE IF NOT EXISTS workspace_roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT NULL,
  base_role TEXT NOT NULL CHECK (base_role IN ('viewer','editor','admin')),
  priority INT NOT NULL DEFAULT 0,
  created_by UUID NULL REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(workspace_id, name)
);

CREATE TABLE IF NOT EXISTS workspace_role_permissions (
  id BIGSERIAL PRIMARY KEY,
  workspace_role_id UUID NOT NULL REFERENCES workspace_roles(id) ON DELETE CASCADE,
  permission TEXT NOT NULL,
  allowed BOOLEAN NOT NULL,
  UNIQUE(workspace_role_id, permission)
);

CREATE TABLE IF NOT EXISTS workspace_invitations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  role_kind TEXT NOT NULL CHECK (role_kind IN ('system','custom')),
  system_role TEXT NULL CHECK (system_role IN ('owner','admin','editor','viewer')),
  custom_role_id UUID NULL REFERENCES workspace_roles(id) ON DELETE SET NULL,
  invited_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NULL,
  accepted_by UUID NULL REFERENCES users(id) ON DELETE SET NULL,
  accepted_at TIMESTAMPTZ NULL,
  revoked_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS default_workspace_id UUID NULL;

-- Seed personal workspaces for existing users
INSERT INTO workspaces (id, name, slug, icon, description, created_by, is_personal, created_at, updated_at)
SELECT
  u.id,
  COALESCE(NULLIF(u.name, ''), 'Workspace'),
  concat_ws(
    '-',
    NULLIF(
      trim('-' FROM left(regexp_replace(lower(COALESCE(NULLIF(u.name, ''), u.id::text)), '[^a-z0-9]+', '-', 'g'), 40)),
      ''
    ),
    substr(u.id::text, 1, 8)
  ),
  NULL,
  NULL,
  u.id,
  true,
  now(),
  now()
FROM users u
ON CONFLICT (id) DO NOTHING;

INSERT INTO workspace_members (workspace_id, user_id, role_kind, system_role, custom_role_id, invited_by, joined_at, is_default)
SELECT
  u.id,
  u.id,
  'system',
  'owner',
  NULL,
  u.id,
  now(),
  true
FROM users u
ON CONFLICT (workspace_id, user_id) DO NOTHING;

UPDATE users
SET default_workspace_id = COALESCE(default_workspace_id, id);

ALTER TABLE users
  ALTER COLUMN default_workspace_id SET NOT NULL,
  ADD CONSTRAINT users_default_workspace_fk FOREIGN KEY (default_workspace_id) REFERENCES workspaces(id) ON DELETE RESTRICT;

ALTER TABLE documents
  ADD COLUMN IF NOT EXISTS workspace_id UUID,
  ADD COLUMN IF NOT EXISTS created_by UUID NULL REFERENCES users(id) ON DELETE SET NULL;

UPDATE documents SET workspace_id = COALESCE(workspace_id, owner_id);
UPDATE documents SET created_by = COALESCE(created_by, owner_id);

ALTER TABLE documents
  ALTER COLUMN workspace_id SET NOT NULL,
  ADD CONSTRAINT documents_workspace_fk FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;

-- For now keep owner_id to maintain backward compatibility. Future migration will drop it once application fully migrates.

CREATE INDEX IF NOT EXISTS idx_documents_workspace ON documents(workspace_id);
CREATE INDEX IF NOT EXISTS idx_workspace_members_default ON workspace_members(user_id, is_default) WHERE is_default;
CREATE INDEX IF NOT EXISTS idx_workspace_members_role ON workspace_members(workspace_id, role_kind, system_role);

-- Ensure personal workspace slugs are stable and enforce single default membership
WITH sanitized AS (
    SELECT
        id,
        concat_ws(
            '-',
            NULLIF(
                trim(
                    BOTH '-'
                    FROM left(
                        regexp_replace(lower(COALESCE(NULLIF(name, ''), id::text)), '[^a-z0-9]+', '-', 'g'),
                        40
                    )
                ),
                ''
            ),
            substr(id::text, 1, 8)
        ) AS desired_slug
    FROM workspaces
    WHERE is_personal
)
UPDATE workspaces w
SET slug = s.desired_slug
FROM sanitized s
WHERE w.id = s.id
  AND w.slug <> s.desired_slug;

WITH ranked_defaults AS (
    SELECT
        workspace_id,
        user_id,
        ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY joined_at, workspace_id) AS rn
    FROM workspace_members
    WHERE is_default
)
UPDATE workspace_members wm
SET is_default = false
FROM ranked_defaults rd
WHERE wm.workspace_id = rd.workspace_id
  AND wm.user_id = rd.user_id
  AND rd.rn > 1;

DROP INDEX IF EXISTS idx_workspace_members_default;
CREATE UNIQUE INDEX IF NOT EXISTS uq_workspace_members_default ON workspace_members(user_id) WHERE is_default;

-- Documents.owner_id -> workspaces and owner_user_id preservation
ALTER TABLE documents
    ADD COLUMN IF NOT EXISTS owner_user_id UUID;

UPDATE documents
SET owner_user_id = owner_id
WHERE owner_user_id IS NULL;

ALTER TABLE documents
    ADD CONSTRAINT documents_owner_user_id_fk FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE SET NULL;

DO $$
BEGIN
    ALTER TABLE documents DROP CONSTRAINT IF EXISTS documents_owner_id_fkey;
END $$;

UPDATE documents
SET owner_id = workspace_id;

ALTER TABLE documents
    ADD CONSTRAINT documents_owner_id_fk FOREIGN KEY (owner_id) REFERENCES workspaces(id) ON DELETE CASCADE;

-- Git rebuild jobs switch to workspace scope
ALTER TABLE git_rebuild_jobs
    DROP CONSTRAINT IF EXISTS git_rebuild_jobs_user_id_fkey;

ALTER TABLE git_rebuild_jobs
    RENAME COLUMN user_id TO workspace_id;

ALTER TABLE git_rebuild_jobs
    ADD CONSTRAINT git_rebuild_jobs_workspace_id_fkey
        FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;

ALTER TABLE git_rebuild_jobs
    DROP CONSTRAINT IF EXISTS git_rebuild_jobs_user_id_key;

ALTER TABLE git_rebuild_jobs
    ADD CONSTRAINT git_rebuild_jobs_workspace_unique
        UNIQUE (workspace_id);

ALTER TABLE git_rebuild_jobs
    ADD COLUMN actor_id UUID NULL,
    ADD COLUMN permission_snapshot JSONB NOT NULL DEFAULT '[]'::jsonb;

-- Storage ingest queue
ALTER TABLE storage_ingest_queue
    ADD COLUMN IF NOT EXISTS workspace_id UUID NULL,
    ADD COLUMN IF NOT EXISTS actor_id UUID NULL,
    ADD COLUMN IF NOT EXISTS permission_snapshot JSONB NULL;

UPDATE storage_ingest_queue
SET workspace_id = user_id,
    actor_id = user_id,
    permission_snapshot = '[]'::jsonb
WHERE workspace_id IS NULL;

ALTER TABLE storage_ingest_queue
    ALTER COLUMN workspace_id SET NOT NULL,
    ALTER COLUMN permission_snapshot SET NOT NULL,
    ALTER COLUMN permission_snapshot SET DEFAULT '[]'::jsonb;

DO $$
BEGIN
    ALTER TABLE storage_ingest_queue
        ADD CONSTRAINT storage_ingest_queue_workspace_id_fkey
            FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

ALTER TABLE storage_ingest_queue
    DROP CONSTRAINT IF EXISTS storage_ingest_queue_user_repo_backend_unique;

DO $$
BEGIN
    ALTER TABLE storage_ingest_queue
        ADD CONSTRAINT storage_ingest_queue_workspace_repo_backend_unique
            UNIQUE (workspace_id, repo_path, backend);
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

-- Plugin installations
ALTER TABLE plugin_installations
    ADD COLUMN IF NOT EXISTS workspace_id UUID NULL;

UPDATE plugin_installations
SET workspace_id = user_id
WHERE workspace_id IS NULL;

ALTER TABLE plugin_installations
    ALTER COLUMN workspace_id SET NOT NULL;

DO $$
BEGIN
    ALTER TABLE plugin_installations
        ADD CONSTRAINT plugin_installations_workspace_fk
            FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

ALTER TABLE plugin_installations
    DROP CONSTRAINT IF EXISTS plugin_installations_pkey;

ALTER TABLE plugin_installations
    ADD CONSTRAINT plugin_installations_pkey PRIMARY KEY (workspace_id, plugin_id);

ALTER TABLE plugin_installations
    DROP COLUMN IF EXISTS user_id;

-- Git config / state tables
ALTER TABLE git_configs
    ADD COLUMN IF NOT EXISTS workspace_id UUID NULL;

UPDATE git_configs
SET workspace_id = user_id
WHERE workspace_id IS NULL;

ALTER TABLE git_configs
    ALTER COLUMN workspace_id SET NOT NULL;

DO $$
BEGIN
    ALTER TABLE git_configs
        ADD CONSTRAINT git_configs_workspace_fk
            FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

ALTER TABLE git_configs
    DROP CONSTRAINT IF EXISTS git_configs_user_id_unique;

ALTER TABLE git_configs
    ADD CONSTRAINT git_configs_workspace_unique UNIQUE (workspace_id);

ALTER TABLE git_configs
    DROP COLUMN IF EXISTS user_id;

ALTER TABLE git_sync_logs
    ADD COLUMN IF NOT EXISTS workspace_id UUID NULL;

UPDATE git_sync_logs
SET workspace_id = user_id
WHERE workspace_id IS NULL;

ALTER TABLE git_sync_logs
    ALTER COLUMN workspace_id SET NOT NULL;

DO $$
BEGIN
    ALTER TABLE git_sync_logs
        ADD CONSTRAINT git_sync_logs_workspace_fk
            FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

ALTER TABLE git_sync_logs
    DROP COLUMN IF EXISTS user_id;

ALTER TABLE git_repository_state
    ADD COLUMN IF NOT EXISTS workspace_id UUID NULL;

UPDATE git_repository_state
SET workspace_id = user_id
WHERE workspace_id IS NULL;

ALTER TABLE git_repository_state
    ALTER COLUMN workspace_id SET NOT NULL;

DO $$
BEGIN
    ALTER TABLE git_repository_state
        ADD CONSTRAINT git_repository_state_workspace_fk
            FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

ALTER TABLE git_repository_state
    DROP COLUMN IF EXISTS user_id;

ALTER TABLE git_commits
    ADD COLUMN IF NOT EXISTS workspace_id UUID NULL;

UPDATE git_commits
SET workspace_id = user_id
WHERE workspace_id IS NULL;

ALTER TABLE git_commits
    ALTER COLUMN workspace_id SET NOT NULL;

DO $$
BEGIN
    ALTER TABLE git_commits
        ADD CONSTRAINT git_commits_workspace_fk
            FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

ALTER TABLE git_commits
    DROP COLUMN IF EXISTS user_id;

DROP INDEX IF EXISTS idx_git_commits_user;
CREATE INDEX IF NOT EXISTS idx_git_commits_workspace ON git_commits(workspace_id, committed_at DESC);

ALTER TABLE git_dirty_files
    ADD COLUMN IF NOT EXISTS workspace_id UUID NULL;

UPDATE git_dirty_files
SET workspace_id = user_id
WHERE workspace_id IS NULL;

ALTER TABLE git_dirty_files
    ALTER COLUMN workspace_id SET NOT NULL;

ALTER TABLE git_dirty_files
    DROP CONSTRAINT IF EXISTS git_dirty_files_pkey;

ALTER TABLE git_dirty_files
    ADD CONSTRAINT git_dirty_files_pkey PRIMARY KEY (workspace_id, path);

DO $$
BEGIN
    ALTER TABLE git_dirty_files
        ADD CONSTRAINT git_dirty_files_workspace_fk
            FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DROP INDEX IF EXISTS idx_git_dirty_files_user_created;
CREATE INDEX IF NOT EXISTS idx_git_dirty_files_workspace_created
    ON git_dirty_files(workspace_id, created_at DESC);

ALTER TABLE git_dirty_files
    DROP COLUMN IF EXISTS user_id;

-- API tokens
ALTER TABLE api_tokens
    ADD COLUMN IF NOT EXISTS workspace_id UUID NULL,
    ADD COLUMN IF NOT EXISTS owner_id UUID NULL;

UPDATE api_tokens
SET workspace_id = user_id,
    owner_id = user_id
WHERE workspace_id IS NULL;

ALTER TABLE api_tokens
    ALTER COLUMN workspace_id SET NOT NULL;

ALTER TABLE api_tokens
    ALTER COLUMN owner_id SET NOT NULL;

DO $$
BEGIN
    ALTER TABLE api_tokens
        ADD CONSTRAINT api_tokens_workspace_fk
            FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
    ALTER TABLE api_tokens
        ADD CONSTRAINT api_tokens_owner_fk
            FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

ALTER TABLE api_tokens
    DROP COLUMN IF EXISTS user_id;

CREATE INDEX IF NOT EXISTS idx_api_tokens_workspace ON api_tokens(workspace_id);

ALTER TABLE api_tokens
    ADD COLUMN IF NOT EXISTS lookup_digest TEXT NULL;

UPDATE api_tokens
SET lookup_digest = encode(sha256(decode(token_digest, 'hex')), 'hex')
WHERE lookup_digest IS NULL;

ALTER TABLE api_tokens
    ADD CONSTRAINT uq_api_tokens_lookup_digest UNIQUE (lookup_digest);

-- Doc events
ALTER TABLE doc_events
    ADD COLUMN IF NOT EXISTS workspace_id UUID NULL;

UPDATE doc_events de
SET workspace_id = d.workspace_id
FROM documents d
WHERE de.doc_id = d.id
  AND de.workspace_id IS NULL;

ALTER TABLE doc_events
    ALTER COLUMN workspace_id SET NOT NULL;

DO $$
BEGIN
    ALTER TABLE doc_events
        ADD CONSTRAINT doc_events_workspace_fk
            FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

-- Storage projection jobs
ALTER TABLE storage_projection_jobs
    ADD COLUMN IF NOT EXISTS workspace_id UUID NULL;

UPDATE storage_projection_jobs j
SET workspace_id = d.workspace_id
FROM documents d
WHERE j.doc_id IS NOT NULL
  AND j.doc_id = d.id
  AND j.workspace_id IS NULL;

UPDATE storage_projection_jobs j
SET workspace_id = d.workspace_id
FROM documents d
WHERE j.doc_id IS NULL
  AND j.folder_id = d.id
  AND j.workspace_id IS NULL;

ALTER TABLE storage_projection_jobs
    ALTER COLUMN workspace_id SET NOT NULL;

DO $$
BEGIN
    ALTER TABLE storage_projection_jobs
        ADD CONSTRAINT storage_projection_jobs_workspace_fk
            FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

CREATE INDEX IF NOT EXISTS idx_storage_projection_jobs_workspace
    ON storage_projection_jobs(workspace_id);

-- Storage reconcile jobs move to workspace scope
DO $$
BEGIN
    ALTER TABLE storage_reconcile_jobs DROP CONSTRAINT IF EXISTS storage_reconcile_jobs_user_id_fkey;
EXCEPTION
    WHEN undefined_object THEN NULL;
END $$;

ALTER TABLE storage_reconcile_jobs
    RENAME COLUMN user_id TO workspace_id;

DO $$
BEGIN
    ALTER TABLE storage_reconcile_jobs
        ADD CONSTRAINT storage_reconcile_jobs_workspace_fk
            FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

ALTER TABLE storage_reconcile_jobs
    DROP CONSTRAINT IF EXISTS storage_reconcile_jobs_user_scope_unique;

ALTER TABLE storage_reconcile_jobs
    ADD CONSTRAINT storage_reconcile_jobs_workspace_scope_unique
        UNIQUE (workspace_id, scope);

DROP INDEX IF EXISTS idx_storage_reconcile_jobs_unique;
CREATE UNIQUE INDEX IF NOT EXISTS idx_storage_reconcile_jobs_workspace_scope
    ON storage_reconcile_jobs(workspace_id, scope)
    WHERE locked_at IS NULL;

DROP INDEX IF EXISTS idx_storage_reconcile_jobs_pending;
CREATE INDEX IF NOT EXISTS idx_storage_reconcile_jobs_pending
    ON storage_reconcile_jobs (locked_at, created_at)
    WHERE locked_at IS NULL;
