-- Remove IP address from pending devices
ALTER TABLE pending_devices DROP COLUMN ip_address;
