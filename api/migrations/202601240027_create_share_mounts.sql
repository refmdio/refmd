CREATE TABLE IF NOT EXISTS share_mounts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  created_by uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  share_token TEXT NOT NULL,
  target_document_id uuid NOT NULL,
  target_document_type TEXT NOT NULL CHECK (target_document_type IN ('document','folder')),
  target_title TEXT NOT NULL,
  permission TEXT NOT NULL CHECK (permission IN ('view','edit')),
  parent_folder_id uuid NULL REFERENCES documents(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_share_mounts_workspace_target
  ON share_mounts(workspace_id, share_token, target_document_id);

CREATE INDEX IF NOT EXISTS idx_share_mounts_workspace
  ON share_mounts(workspace_id);
