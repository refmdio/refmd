-- Remove device_id from sessions table
DROP INDEX IF EXISTS idx_sessions_device_id;
ALTER TABLE sessions DROP COLUMN IF EXISTS device_id;
