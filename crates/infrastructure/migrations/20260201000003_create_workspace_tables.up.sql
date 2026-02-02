-- Workspace domain tables

-- Workspaces
CREATE TABLE workspaces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    icon VARCHAR(255),
    is_personal BOOLEAN NOT NULL DEFAULT FALSE,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_workspaces_owner_id ON workspaces(owner_id);
CREATE INDEX idx_workspaces_slug ON workspaces(slug);

-- Workspace roles
CREATE TABLE workspace_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    base_role VARCHAR(20) NOT NULL,        -- 'owner', 'admin', 'editor', 'viewer'
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_workspace_roles_workspace_id ON workspace_roles(workspace_id);

-- Workspace role permissions
CREATE TABLE workspace_role_permissions (
    role_id UUID NOT NULL REFERENCES workspace_roles(id) ON DELETE CASCADE,
    permission VARCHAR(100) NOT NULL,
    granted BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (role_id, permission)
);

-- Workspace members
CREATE TABLE workspace_members (
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES workspace_roles(id) ON DELETE RESTRICT,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (workspace_id, user_id)
);

CREATE INDEX idx_workspace_members_user_id ON workspace_members(user_id);
CREATE INDEX idx_workspace_members_user_default ON workspace_members(user_id) WHERE is_default = TRUE;

-- Workspace invitations
CREATE TABLE workspace_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    token_prefix VARCHAR(20) NOT NULL,
    role_id UUID NOT NULL REFERENCES workspace_roles(id) ON DELETE CASCADE,
    invited_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    invited_email VARCHAR(255),
    max_uses INT,
    use_count INT NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_workspace_invitations_workspace_id ON workspace_invitations(workspace_id);
CREATE INDEX idx_workspace_invitations_token_hash ON workspace_invitations(token_hash);

-- Add FK constraint to workspace_encrypted_keys
ALTER TABLE workspace_encrypted_keys
    ADD CONSTRAINT fk_workspace_encrypted_keys_workspace
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;
