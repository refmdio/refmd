ALTER TABLE device_revocation_events
  ADD CONSTRAINT chk_revocation_mode CHECK (revocation_mode IN ('security', 'retire'));
