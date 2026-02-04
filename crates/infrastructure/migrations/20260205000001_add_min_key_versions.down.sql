-- Remove indexes
DROP INDEX IF EXISTS idx_documents_min_dek_version;
DROP INDEX IF EXISTS idx_workspaces_min_kek_version;
DROP INDEX IF EXISTS idx_workspaces_needs_kek_rotation;

-- Remove columns
ALTER TABLE documents DROP COLUMN min_dek_version;
ALTER TABLE workspaces DROP COLUMN needs_kek_rotation;
ALTER TABLE workspaces DROP COLUMN min_kek_version;
