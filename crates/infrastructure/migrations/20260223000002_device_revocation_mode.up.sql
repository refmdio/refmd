ALTER TABLE device_revocation_events
  ADD COLUMN revocation_mode VARCHAR(20) NOT NULL DEFAULT 'security';
