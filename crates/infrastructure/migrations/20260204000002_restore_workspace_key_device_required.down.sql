-- Revert to state after 20260204000001 (device_id nullable with surrogate key)

-- Drop primary key
ALTER TABLE workspace_encrypted_keys
    DROP CONSTRAINT workspace_encrypted_keys_pkey;

-- Drop active index
DROP INDEX IF EXISTS idx_workspace_keys_active;

-- Drop foreign key
ALTER TABLE workspace_encrypted_keys
    DROP CONSTRAINT workspace_encrypted_keys_device_id_fkey;

-- Make device_id nullable
ALTER TABLE workspace_encrypted_keys
    ALTER COLUMN device_id DROP NOT NULL;

-- Make sender_device_id nullable
ALTER TABLE workspace_encrypted_keys
    ALTER COLUMN sender_device_id DROP NOT NULL;

-- Re-add id column with surrogate key
ALTER TABLE workspace_encrypted_keys
    ADD COLUMN IF NOT EXISTS id UUID DEFAULT gen_random_uuid();

UPDATE workspace_encrypted_keys SET id = gen_random_uuid() WHERE id IS NULL;

ALTER TABLE workspace_encrypted_keys
    ALTER COLUMN id SET NOT NULL;

-- Add surrogate primary key
ALTER TABLE workspace_encrypted_keys
    ADD CONSTRAINT workspace_encrypted_keys_pkey PRIMARY KEY (id);

-- Re-add unique index with COALESCE
CREATE UNIQUE INDEX workspace_encrypted_keys_unique_key
    ON workspace_encrypted_keys(workspace_id, user_id, COALESCE(device_id, '00000000-0000-0000-0000-000000000000'::uuid), key_version);

-- Recreate active key index
CREATE INDEX idx_workspace_keys_active
    ON workspace_encrypted_keys(workspace_id, user_id, device_id)
    WHERE is_active = TRUE;
