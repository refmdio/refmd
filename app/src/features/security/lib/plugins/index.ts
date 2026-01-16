/**
 * Plugin E2EE Module
 *
 * Provides transparent encryption for plugin KV and Records storage.
 * Plugins do not need to handle encryption themselves - the runtime
 * layer encrypts data before sending to the server and decrypts
 * when receiving.
 */

// Plugin DEK derivation
export { derivePluginDEK } from './plugin-dek'

// KV encryption
export {
  encryptKV,
  decryptKV,
  isEncryptedKVValue,
  isLegacyKVValue,
  type EncryptedKVValue,
  type LegacyKVValue,
} from './plugin-kv'

// Records encryption
export {
  encryptRecordData,
  decryptRecordData,
  decryptRecords,
  isEncryptedRecordData,
  type EncryptedRecordData,
  type EncryptedRecord,
  type PlaintextRecord,
} from './plugin-records'
