-- Revert: Make device_id and sender_device_id required again
-- Note: This will fail if there are rows with NULL device_id

-- Drop the new primary key
ALTER TABLE workspace_encrypted_keys
    DROP CONSTRAINT workspace_encrypted_keys_pkey;

-- Make device_id required
ALTER TABLE workspace_encrypted_keys
    ALTER COLUMN device_id SET NOT NULL;

-- Make sender_device_id required
ALTER TABLE workspace_encrypted_keys
    ALTER COLUMN sender_device_id SET NOT NULL;

-- Add the original primary key (includes device_id)
ALTER TABLE workspace_encrypted_keys
    ADD CONSTRAINT workspace_encrypted_keys_pkey
    PRIMARY KEY (workspace_id, user_id, device_id, key_version);

-- Re-add the foreign key constraint
ALTER TABLE workspace_encrypted_keys
    ADD CONSTRAINT workspace_encrypted_keys_device_id_fkey
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE;

-- Drop new index
DROP INDEX IF EXISTS idx_workspace_keys_active;

-- Recreate original index
CREATE INDEX idx_workspace_keys_active ON workspace_encrypted_keys(workspace_id, user_id, device_id) WHERE is_active = TRUE;
