-- Restore workspace_encrypted_keys: device_id is required
-- This migration reverts changes from 20260201000008 and 20260204000001

-- Step 1: Drop the surrogate primary key added by 20260204000001
ALTER TABLE workspace_encrypted_keys
    DROP CONSTRAINT workspace_encrypted_keys_pkey;

-- Step 2: Drop the unique index with COALESCE
DROP INDEX IF EXISTS workspace_encrypted_keys_unique_key;

-- Step 3: Drop the id column (surrogate key) added by 20260204000001
ALTER TABLE workspace_encrypted_keys
    DROP COLUMN IF EXISTS id;

-- Step 4: Delete any records with NULL device_id (invalid data)
DELETE FROM workspace_encrypted_keys WHERE device_id IS NULL;

-- Step 5: Make device_id NOT NULLALTER TABLE workspace_encrypted_keys
    ALTER COLUMN device_id SET NOT NULL;

-- Step 6: Make sender_device_id NOT NULLALTER TABLE workspace_encrypted_keys
    ALTER COLUMN sender_device_id SET NOT NULL;

-- Step 7: Re-add foreign key constraint on device_id
ALTER TABLE workspace_encrypted_keys
    ADD CONSTRAINT workspace_encrypted_keys_device_id_fkey
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE;

-- Step 8: Create composite primary key: (workspace_id, user_id, device_id, key_version)
ALTER TABLE workspace_encrypted_keys
    ADD CONSTRAINT workspace_encrypted_keys_pkey
    PRIMARY KEY (workspace_id, user_id, device_id, key_version);

-- Step 9: Recreate active key index (per device)
DROP INDEX IF EXISTS idx_workspace_keys_active;
CREATE INDEX idx_workspace_keys_active
    ON workspace_encrypted_keys(workspace_id, user_id, device_id)
    WHERE is_active = TRUE;
