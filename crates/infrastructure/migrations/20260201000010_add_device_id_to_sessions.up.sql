-- Add device_id to sessions table for is_current device detection
ALTER TABLE sessions ADD COLUMN device_id UUID REFERENCES devices(id) ON DELETE SET NULL;

CREATE INDEX idx_sessions_device_id ON sessions(device_id);
