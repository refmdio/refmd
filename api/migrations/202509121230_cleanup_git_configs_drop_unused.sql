-- Clean up legacy columns not used by the current implementation
-- Drop columns that cause NOT NULL violations and duplication with new fields
ALTER TABLE git_configs
    DROP COLUMN IF EXISTS root_path,
    DROP COLUMN IF EXISTS remote_url,
    DROP COLUMN IF EXISTS branch;

