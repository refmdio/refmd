/**
 * Plugin Records encryption/decryption module
 *
 * Provides transparent encryption for plugin records storage.
 * Record data is encrypted with the plugin-specific DEK before storage,
 * and decrypted when retrieved.
 *
 * Note: Only the `data` field is encrypted. Metadata fields (id, kind,
 * createdAt, updatedAt) remain in plaintext for routing and sorting.
 */

import { encrypt, decrypt } from '../crypto/xchacha20'
import { toBase64, fromBase64 } from '../crypto/canonicalize'
import { derivePluginDEK } from './plugin-dek'

/** Encrypted record data format */
export interface EncryptedRecordData {
  /** Base64-encoded ciphertext */
  ciphertext: string
  /** Base64-encoded nonce */
  nonce: string
  /** Encryption version for future compatibility */
  _v: 1
  /** Marker to distinguish from legacy plaintext values */
  _encrypted: true
}

/** Record with encrypted data field */
export interface EncryptedRecord {
  id: string
  data: EncryptedRecordData
  createdAt?: string
  updatedAt?: string
  [key: string]: unknown
}

/** Record with plaintext data field (legacy or decrypted) */
export interface PlaintextRecord {
  id: string
  data: unknown
  createdAt?: string
  updatedAt?: string
  [key: string]: unknown
}

/**
 * Check if a record's data is encrypted.
 */
export function isEncryptedRecordData(data: unknown): data is EncryptedRecordData {
  return (
    data !== null &&
    typeof data === 'object' &&
    '_encrypted' in data &&
    (data as any)._encrypted === true &&
    '_v' in data &&
    (data as any)._v === 1 &&
    'ciphertext' in data &&
    'nonce' in data
  )
}

/**
 * Encrypt record data for storage.
 *
 * @param data - Record data to encrypt (will be JSON serialized)
 * @param documentDEK - Document DEK
 * @param pluginId - Plugin identifier for key derivation
 * @returns Encrypted data object ready for storage
 */
export async function encryptRecordData(
  data: unknown,
  documentDEK: Uint8Array,
  pluginId: string
): Promise<EncryptedRecordData> {
  const pluginDEK = await derivePluginDEK(documentDEK, pluginId)

  const plaintext = new TextEncoder().encode(JSON.stringify(data))
  const { ciphertext, nonce } = await encrypt(pluginDEK, plaintext)

  return {
    ciphertext: await toBase64(ciphertext),
    nonce: await toBase64(nonce),
    _v: 1,
    _encrypted: true,
  }
}

/**
 * Decrypt record data from storage.
 *
 * Handles both encrypted and legacy plaintext data.
 *
 * @param data - Stored data (may be encrypted or legacy)
 * @param documentDEK - Document DEK
 * @param pluginId - Plugin identifier for key derivation
 * @returns Decrypted data
 */
export async function decryptRecordData(
  data: unknown,
  documentDEK: Uint8Array,
  pluginId: string
): Promise<unknown> {
  // Handle null/undefined
  if (data === null || data === undefined) {
    return data
  }

  // Handle encrypted data
  if (isEncryptedRecordData(data)) {
    const pluginDEK = await derivePluginDEK(documentDEK, pluginId)
    const ciphertext = await fromBase64(data.ciphertext)
    const nonce = await fromBase64(data.nonce)

    const plaintext = await decrypt(pluginDEK, ciphertext, nonce)
    return JSON.parse(new TextDecoder().decode(plaintext))
  }

  // Unknown format - return as-is for backward compatibility
  return data
}

/**
 * Decrypt multiple records from storage.
 *
 * @param records - Array of records with potentially encrypted data
 * @param documentDEK - Document DEK
 * @param pluginId - Plugin identifier for key derivation
 * @returns Array of records with decrypted data
 */
export async function decryptRecords(
  records: unknown[],
  documentDEK: Uint8Array,
  pluginId: string
): Promise<PlaintextRecord[]> {
  return Promise.all(
    records.map(async (record) => {
      if (!record || typeof record !== 'object') {
        return record as PlaintextRecord
      }

      const rec = record as Record<string, unknown>
      if (!('data' in rec)) {
        return rec as PlaintextRecord
      }

      const decryptedData = await decryptRecordData(rec.data, documentDEK, pluginId)
      return {
        ...rec,
        data: decryptedData,
      } as PlaintextRecord
    })
  )
}
