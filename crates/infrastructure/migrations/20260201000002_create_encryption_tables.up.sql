-- Encryption domain tables

-- User Identity public key (long-term user identification)
CREATE TABLE user_identity_public_keys (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    ecdh_public_key BYTEA NOT NULL,        -- X25519 ECDH public key (32 bytes)
    signing_public_key BYTEA NOT NULL,     -- Ed25519 signing public key (32 bytes)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- User Encrypted Master Key (UMK)
CREATE TABLE user_encrypted_master_keys (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    auth_type VARCHAR(20) NOT NULL,        -- 'password' or 'oauth'

    -- Password user fields (nullable for OAuth users)
    encrypted_umk BYTEA,                   -- Encrypted UMK (encrypted with PUK)
    umk_nonce BYTEA,                       -- Nonce for UMK encryption
    salt BYTEA,                            -- Salt for KDF (PUK derivation)
    kdf_type VARCHAR(20),                  -- KDF type (e.g., 'argon2id')
    kdf_params JSONB,                      -- KDF parameters
    auth_key_hash VARCHAR(255),            -- bcrypt hash of authKey

    -- Recovery fields (required for all users)
    recovery_encrypted_umk BYTEA NOT NULL, -- UMK encrypted with recovery key
    recovery_nonce BYTEA NOT NULL,         -- Nonce for recovery encryption

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints for password users (PUK fields required)
    CONSTRAINT password_user_fields CHECK (
        auth_type != 'password' OR (
            encrypted_umk IS NOT NULL AND
            umk_nonce IS NOT NULL AND
            salt IS NOT NULL AND
            kdf_type IS NOT NULL AND
            kdf_params IS NOT NULL AND
            auth_key_hash IS NOT NULL
        )
    ),

    -- Constraints for OAuth users (PUK fields must be NULL)
    CONSTRAINT oauth_user_fields CHECK (
        auth_type != 'oauth' OR (
            encrypted_umk IS NULL AND
            umk_nonce IS NULL AND
            salt IS NULL AND
            kdf_type IS NULL AND
            kdf_params IS NULL AND
            auth_key_hash IS NULL
        )
    )
);

-- User Encrypted Identity Key (private keys encrypted with UMK)
CREATE TABLE user_encrypted_identity_keys (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    encrypted_ecdh_private BYTEA NOT NULL,
    encrypted_ecdh_private_nonce BYTEA NOT NULL,
    encrypted_signing_private BYTEA NOT NULL,
    encrypted_signing_private_nonce BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Devices (verified user devices with cryptographic keys)
CREATE TABLE devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    device_type VARCHAR(20) NOT NULL,      -- 'browser', 'desktop', 'mobile'
    ecdh_public_key BYTEA NOT NULL,        -- X25519 ECDH public key (32 bytes)
    signing_public_key BYTEA NOT NULL,     -- Ed25519 signing public key (32 bytes)
    identity_signature BYTEA NOT NULL,     -- Signature from Identity key
    client_nonce BYTEA NOT NULL,           -- SAS verification nonce (16 bytes)
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_devices_user_id ON devices(user_id);
CREATE INDEX idx_devices_user_active ON devices(user_id) WHERE revoked_at IS NULL;

-- Pending devices (awaiting SAS verification)
CREATE TABLE pending_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    device_type VARCHAR(20) NOT NULL,
    ecdh_public_key BYTEA NOT NULL,
    signing_public_key BYTEA NOT NULL,
    client_nonce BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_pending_devices_user_id ON pending_devices(user_id);
CREATE INDEX idx_pending_devices_expires_at ON pending_devices(expires_at);

-- Device Revocation Events (signed by Identity key)
CREATE TABLE device_revocation_events (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID NOT NULL,
    revoked_at BIGINT NOT NULL,            -- Unix milliseconds
    revoked_by_device_id UUID NOT NULL,
    signature BYTEA NOT NULL,              -- Signature by Identity signing key
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, device_id)
);

-- Device Encrypted UMK (UMK distributed to approved devices)
CREATE TABLE device_encrypted_umks (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    sender_device_id UUID NOT NULL,
    encrypted_umk BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, device_id)
);

-- Workspace Encrypted Keys (KEK per workspace per device)
CREATE TABLE workspace_encrypted_keys (
    workspace_id UUID NOT NULL,            -- FK added when workspaces table is created
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    sender_device_id UUID NOT NULL,
    key_version INT NOT NULL,
    encrypted_kek BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (workspace_id, user_id, device_id, key_version)
);

CREATE INDEX idx_workspace_keys_workspace ON workspace_encrypted_keys(workspace_id);
CREATE INDEX idx_workspace_keys_active ON workspace_encrypted_keys(workspace_id, user_id, device_id) WHERE is_active = TRUE;

-- Document Encrypted Keys (DEK per document)
CREATE TABLE document_encrypted_keys (
    document_id UUID NOT NULL,             -- FK added when documents table is created
    key_version INT NOT NULL,
    encrypted_dek BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (document_id, key_version)
);

CREATE INDEX idx_document_keys_active ON document_encrypted_keys(document_id) WHERE is_active = TRUE;
