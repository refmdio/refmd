-- Make device_id and sender_device_id nullable for workspace_encrypted_keys

-- Drop the old primary key (includes device_id)
ALTER TABLE workspace_encrypted_keys
    DROP CONSTRAINT workspace_encrypted_keys_pkey;

-- Drop the foreign key constraint
ALTER TABLE workspace_encrypted_keys
    DROP CONSTRAINT workspace_encrypted_keys_device_id_fkey;

-- Make device_id nullable
ALTER TABLE workspace_encrypted_keys
    ALTER COLUMN device_id DROP NOT NULL;

-- Make sender_device_id nullable
ALTER TABLE workspace_encrypted_keys
    ALTER COLUMN sender_device_id DROP NOT NULL;

-- Add new primary key without device_id
ALTER TABLE workspace_encrypted_keys
    ADD CONSTRAINT workspace_encrypted_keys_pkey
    PRIMARY KEY (workspace_id, user_id, key_version);

-- Drop old indexes that reference device_id
DROP INDEX IF EXISTS idx_workspace_keys_active;

-- Create new index for active keys (without device_id requirement)
CREATE INDEX idx_workspace_keys_active ON workspace_encrypted_keys(workspace_id, user_id) WHERE is_active = TRUE;
