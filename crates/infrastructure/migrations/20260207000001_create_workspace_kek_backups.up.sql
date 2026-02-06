-- Workspace KEK backups: KEK encrypted with UMK for recovery
-- Unlike workspace_encrypted_keys which are per-device (ECDH), these are per-user (UMK)
CREATE TABLE workspace_kek_backups (
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_version INT NOT NULL CHECK (key_version > 0),
    encrypted_kek BYTEA NOT NULL,
    nonce BYTEA NOT NULL CHECK (length(nonce) = 24),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (workspace_id, user_id, key_version)
);

-- Ensure only one active backup per workspace+user
CREATE UNIQUE INDEX idx_workspace_kek_backups_single_active
    ON workspace_kek_backups(workspace_id, user_id) WHERE is_active = TRUE;
