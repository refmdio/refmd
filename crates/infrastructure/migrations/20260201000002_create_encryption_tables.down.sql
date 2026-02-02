-- Drop encryption domain tables

DROP TABLE IF EXISTS document_encrypted_keys;
DROP TABLE IF EXISTS workspace_encrypted_keys;
DROP TABLE IF EXISTS device_encrypted_umks;
DROP TABLE IF EXISTS device_revocation_events;
DROP TABLE IF EXISTS pending_devices;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS user_encrypted_identity_keys;
DROP TABLE IF EXISTS user_encrypted_master_keys;
DROP TABLE IF EXISTS user_identity_public_keys;
