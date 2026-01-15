/**
 * Plugin KV encryption/decryption module
 *
 * Provides transparent encryption for plugin key-value storage.
 * Values are encrypted with the plugin-specific DEK before storage,
 * and decrypted when retrieved.
 */

import { encrypt, decrypt } from '../crypto/xchacha20'
import { toBase64, fromBase64 } from '../crypto/canonicalize'
import { derivePluginDEK } from './plugin-dek'

/** Encrypted KV value format */
export interface EncryptedKVValue {
  /** Base64-encoded ciphertext */
  ciphertext: string
  /** Base64-encoded nonce */
  nonce: string
  /** Encryption version for future compatibility */
  _v: 1
  /** Marker to distinguish from legacy plaintext values */
  _encrypted: true
}

/** Legacy plaintext value format (for backward compatibility) */
export interface LegacyKVValue {
  value: unknown
  _encrypted: false
}

/**
 * Check if a stored value is encrypted.
 */
export function isEncryptedKVValue(value: unknown): value is EncryptedKVValue {
  return (
    value !== null &&
    typeof value === 'object' &&
    '_encrypted' in value &&
    (value as any)._encrypted === true &&
    '_v' in value &&
    (value as any)._v === 1 &&
    'ciphertext' in value &&
    'nonce' in value
  )
}

/**
 * Check if a stored value is a legacy plaintext value.
 */
export function isLegacyKVValue(value: unknown): value is LegacyKVValue {
  return (
    value !== null &&
    typeof value === 'object' &&
    '_encrypted' in value &&
    (value as any)._encrypted === false &&
    'value' in value
  )
}

/**
 * Encrypt a KV value for storage.
 *
 * @param value - Value to encrypt (will be JSON serialized)
 * @param documentDEK - Document DEK
 * @param pluginId - Plugin identifier for key derivation
 * @returns Encrypted value object ready for storage
 */
export async function encryptKV(
  value: unknown,
  documentDEK: Uint8Array,
  pluginId: string
): Promise<EncryptedKVValue> {
  const pluginDEK = await derivePluginDEK(documentDEK, pluginId)

  const plaintext = new TextEncoder().encode(JSON.stringify(value))
  const { ciphertext, nonce } = await encrypt(pluginDEK, plaintext)

  return {
    ciphertext: await toBase64(ciphertext),
    nonce: await toBase64(nonce),
    _v: 1,
    _encrypted: true,
  }
}

/**
 * Decrypt a KV value from storage.
 *
 * Handles both encrypted and legacy plaintext values.
 *
 * @param stored - Stored value (may be encrypted or legacy)
 * @param documentDEK - Document DEK
 * @param pluginId - Plugin identifier for key derivation
 * @returns Decrypted value
 */
export async function decryptKV(
  stored: unknown,
  documentDEK: Uint8Array,
  pluginId: string
): Promise<unknown> {
  // Handle null/undefined
  if (stored === null || stored === undefined) {
    return stored
  }

  // Handle legacy plaintext values
  if (isLegacyKVValue(stored)) {
    return stored.value
  }

  // Handle encrypted values
  if (isEncryptedKVValue(stored)) {
    const pluginDEK = await derivePluginDEK(documentDEK, pluginId)
    const ciphertext = await fromBase64(stored.ciphertext)
    const nonce = await fromBase64(stored.nonce)

    const plaintext = await decrypt(pluginDEK, ciphertext, nonce)
    return JSON.parse(new TextDecoder().decode(plaintext))
  }

  // Unknown format - return as-is for backward compatibility
  // This handles cases where the value was stored before encryption was enabled
  return stored
}
