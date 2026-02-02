-- Document domain tables

-- Documents
CREATE TABLE documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    parent_id UUID REFERENCES documents(id) ON DELETE SET NULL,
    title VARCHAR(500) NOT NULL,
    encrypted_title BYTEA,
    encrypted_title_nonce BYTEA,
    slug VARCHAR(255) NOT NULL,
    path TEXT,
    doc_type VARCHAR(20) NOT NULL DEFAULT 'document',  -- 'document' or 'folder'
    is_encrypted BOOLEAN NOT NULL DEFAULT FALSE,
    needs_dek_rotation BOOLEAN NOT NULL DEFAULT FALSE,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    archived_at TIMESTAMPTZ
);

CREATE INDEX idx_documents_workspace_id ON documents(workspace_id);
CREATE INDEX idx_documents_parent_id ON documents(parent_id);
CREATE UNIQUE INDEX idx_documents_workspace_slug ON documents(workspace_id, slug);
CREATE INDEX idx_documents_needs_dek_rotation ON documents(workspace_id) WHERE needs_dek_rotation = TRUE;

-- Document updates (CRDT update log)
CREATE TABLE document_updates (
    id BIGSERIAL PRIMARY KEY,
    document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    seq BIGINT NOT NULL,
    update_data BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    key_version INT NOT NULL,
    update_hash VARCHAR(64) NOT NULL UNIQUE,
    prev_update_hash VARCHAR(64),
    signature BYTEA NOT NULL,
    author_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    timestamp BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_document_updates_document_id ON document_updates(document_id);
CREATE INDEX idx_document_updates_document_seq ON document_updates(document_id, seq);

-- Document snapshots
CREATE TABLE document_snapshots (
    id BIGSERIAL PRIMARY KEY,
    document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    version BIGINT NOT NULL,
    snapshot_data BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    key_version INT NOT NULL,
    signature BYTEA NOT NULL,
    author_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    seq_at_snapshot BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_document_snapshots_document_id ON document_snapshots(document_id);
CREATE UNIQUE INDEX idx_document_snapshots_document_version ON document_snapshots(document_id, version);

-- Document snapshot archives (labeled snapshots)
CREATE TABLE document_snapshot_archives (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    snapshot_id BIGINT NOT NULL REFERENCES document_snapshots(id) ON DELETE CASCADE,
    label VARCHAR(255) NOT NULL,
    notes TEXT,
    kind VARCHAR(20) NOT NULL DEFAULT 'manual',  -- 'manual' or 'auto'
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_document_snapshot_archives_document_id ON document_snapshot_archives(document_id);

-- Tags (workspace scoped)
CREATE TABLE tags (
    id BIGSERIAL PRIMARY KEY,
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    UNIQUE (workspace_id, name)
);

CREATE INDEX idx_tags_workspace_id ON tags(workspace_id);

-- Document tags
CREATE TABLE document_tags (
    document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    tag_id BIGINT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    encrypted_tag BYTEA,
    PRIMARY KEY (document_id, tag_id)
);

CREATE INDEX idx_document_tags_tag_id ON document_tags(tag_id);

-- Document links (for backlinks)
CREATE TABLE document_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    target_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    link_type VARCHAR(50) NOT NULL,
    link_text TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_document_links_source_id ON document_links(source_id);
CREATE INDEX idx_document_links_target_id ON document_links(target_id);

-- Add FK constraint to document_encrypted_keys
ALTER TABLE document_encrypted_keys
    ADD CONSTRAINT fk_document_encrypted_keys_document
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE;
