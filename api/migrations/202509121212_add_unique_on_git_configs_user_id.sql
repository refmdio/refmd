-- Ensure ON CONFLICT (user_id) works by adding a proper unique constraint
-- 1) Guarantee user_id column exists
ALTER TABLE git_configs
    ADD COLUMN IF NOT EXISTS user_id UUID;

-- 2) Drop partial unique index if it exists (it doesn't satisfy ON CONFLICT inference)
DROP INDEX IF EXISTS uniq_git_configs_user_id;

-- 3) Add UNIQUE constraint on user_id (allows multiple NULLs, enforces uniqueness for non-NULL)
DO $$ BEGIN
    ALTER TABLE git_configs
        ADD CONSTRAINT git_configs_user_id_unique UNIQUE (user_id);
EXCEPTION WHEN duplicate_object THEN
    NULL;
END $$;
