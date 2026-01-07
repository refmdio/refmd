-- E2EE (End-to-End Encryption) Schema Migration
-- Phase 0: Database schema changes for E2EE support

--------------------------------------------------------------------------------
-- Part 1: New tables for key management
--------------------------------------------------------------------------------

-- User public keys (ECDH P-256)
CREATE TABLE IF NOT EXISTS user_public_keys (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    public_key BYTEA NOT NULL,
    key_type TEXT NOT NULL DEFAULT 'ecdh-p256',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- User encrypted master keys (for recovery)
CREATE TABLE IF NOT EXISTS user_encrypted_master_keys (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    encrypted_key BYTEA NOT NULL,
    salt BYTEA NOT NULL,
    kdf_type TEXT NOT NULL DEFAULT 'argon2id',
    kdf_params JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- User encrypted private keys (encrypted with UMK)
CREATE TABLE IF NOT EXISTS user_encrypted_private_keys (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    encrypted_private_key BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Workspace encrypted keys (KEK encrypted with each member's public key)
CREATE TABLE IF NOT EXISTS workspace_encrypted_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_kek BYTEA NOT NULL,
    key_version INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, user_id, key_version)
);

-- Document encrypted keys (DEK encrypted with workspace KEK)
CREATE TABLE IF NOT EXISTS document_encrypted_keys (
    document_id UUID PRIMARY KEY REFERENCES documents(id) ON DELETE CASCADE,
    encrypted_dek BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    key_version INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Share encrypted keys (DEK encrypted with share key)
CREATE TABLE IF NOT EXISTS share_encrypted_keys (
    share_id UUID PRIMARY KEY REFERENCES shares(id) ON DELETE CASCADE,
    encrypted_dek BYTEA NOT NULL,
    salt BYTEA,
    kdf_params JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Public document contents (plaintext for published documents)
CREATE TABLE IF NOT EXISTS public_document_contents (
    document_id UUID PRIMARY KEY REFERENCES documents(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    title TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Encrypted tag index (deterministic encryption for searchable tags)
CREATE TABLE IF NOT EXISTS encrypted_tag_index (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    encrypted_tag BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

--------------------------------------------------------------------------------
-- Part 2: Add columns to existing tables
--------------------------------------------------------------------------------

-- Users: E2EE setup tracking
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS e2ee_setup_completed_at TIMESTAMPTZ;

-- Documents: encrypted title
ALTER TABLE documents
    ADD COLUMN IF NOT EXISTS encrypted_title BYTEA,
    ADD COLUMN IF NOT EXISTS encrypted_title_nonce BYTEA;

-- Document updates: encryption metadata and signature
ALTER TABLE document_updates
    ADD COLUMN IF NOT EXISTS nonce BYTEA,
    ADD COLUMN IF NOT EXISTS signature BYTEA,
    ADD COLUMN IF NOT EXISTS public_key BYTEA;

-- Document snapshots: encryption metadata, signature, and seq tracking
ALTER TABLE document_snapshots
    ADD COLUMN IF NOT EXISTS nonce BYTEA,
    ADD COLUMN IF NOT EXISTS signature BYTEA,
    ADD COLUMN IF NOT EXISTS seq_at_snapshot BIGINT;

-- Files: encrypted metadata
ALTER TABLE files
    ADD COLUMN IF NOT EXISTS encrypted_metadata BYTEA,
    ADD COLUMN IF NOT EXISTS encrypted_metadata_nonce BYTEA,
    ADD COLUMN IF NOT EXISTS encrypted_hash TEXT;

-- Git configs: encrypted auth data
ALTER TABLE git_configs
    ADD COLUMN IF NOT EXISTS encrypted_auth_data BYTEA,
    ADD COLUMN IF NOT EXISTS encrypted_auth_nonce BYTEA;

-- Plugin KV: encrypted value
ALTER TABLE plugin_kv
    ADD COLUMN IF NOT EXISTS encrypted_value BYTEA,
    ADD COLUMN IF NOT EXISTS nonce BYTEA;

-- Plugin records: encrypted data
ALTER TABLE plugin_records
    ADD COLUMN IF NOT EXISTS encrypted_data BYTEA,
    ADD COLUMN IF NOT EXISTS nonce BYTEA;

--------------------------------------------------------------------------------
-- Part 3: Indexes
--------------------------------------------------------------------------------

-- Workspace encrypted keys lookup
CREATE INDEX IF NOT EXISTS idx_workspace_encrypted_keys_workspace
    ON workspace_encrypted_keys(workspace_id);

CREATE INDEX IF NOT EXISTS idx_workspace_encrypted_keys_user
    ON workspace_encrypted_keys(user_id);

-- Encrypted tag index lookup (for deterministic encryption search)
CREATE INDEX IF NOT EXISTS idx_encrypted_tag_index_workspace_tag
    ON encrypted_tag_index(workspace_id, encrypted_tag);

CREATE INDEX IF NOT EXISTS idx_encrypted_tag_index_document
    ON encrypted_tag_index(document_id);

-- E2EE setup status lookup
CREATE INDEX IF NOT EXISTS idx_users_e2ee_setup
    ON users(e2ee_setup_completed_at)
    WHERE e2ee_setup_completed_at IS NOT NULL;
