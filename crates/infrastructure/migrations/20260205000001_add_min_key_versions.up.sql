-- Add min_kek_version to workspaces for KEK version floor enforcement
ALTER TABLE workspaces ADD COLUMN min_kek_version INTEGER NOT NULL DEFAULT 1;

-- Add needs_kek_rotation flag for tracking when KEK rotation is required (e.g., after device revocation)
ALTER TABLE workspaces ADD COLUMN needs_kek_rotation BOOLEAN NOT NULL DEFAULT FALSE;

-- Add min_dek_version to documents for DEK version floor enforcement
ALTER TABLE documents ADD COLUMN min_dek_version INTEGER NOT NULL DEFAULT 1;

-- Add index for efficient version checks
CREATE INDEX idx_workspaces_min_kek_version ON workspaces(id, min_kek_version);
CREATE INDEX idx_documents_min_dek_version ON documents(id, min_dek_version);

-- Add index for finding workspaces needing key rotation
CREATE INDEX idx_workspaces_needs_kek_rotation ON workspaces(needs_kek_rotation) WHERE needs_kek_rotation = TRUE;
