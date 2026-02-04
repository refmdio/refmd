-- Add IP address to pending devices for security verification
ALTER TABLE pending_devices ADD COLUMN ip_address VARCHAR(45);
