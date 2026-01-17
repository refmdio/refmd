/**
 * Document DEK (Data Encryption Key) Management
 *
 * DEKs are used to encrypt document content.
 * Each document has its own DEK, encrypted with the workspace KEK.
 */

import {
  generateKey,
  encrypt,
  decrypt,
  getSodium,
} from '../crypto'

import { getDekCache } from './key-cache'

/** DEK size (32 bytes) */
export const DEK_SIZE = 32

/** Document DEK with metadata */
export interface DocumentDek {
  /** Document ID */
  documentId: string
  /** 32-byte DEK */
  key: Uint8Array
  /** Key version for rotation */
  version: number
}

/** Encrypted DEK from API response */
export interface EncryptedDekFromApi {
  /** Encrypted DEK (Base64) */
  encryptedDek: string
  /** Nonce (Base64) */
  nonce: string
  /** Key version */
  keyVersion: number
  /** Document ID */
  documentId: string
}

/**
 * Generate a new Document DEK.
 *
 * @returns 32-byte random DEK
 */
export async function generateDocumentDek(): Promise<Uint8Array> {
  return generateKey()
}

/**
 * Encrypt a DEK with a workspace KEK.
 *
 * @param dek - The DEK to encrypt
 * @param kek - Workspace KEK
 * @returns Encrypted DEK with nonce
 */
export async function encryptDekWithKek(
  dek: Uint8Array,
  kek: Uint8Array
): Promise<{
  encryptedDek: Uint8Array
  nonce: Uint8Array
}> {
  const result = await encrypt(kek, dek)
  return {
    encryptedDek: result.ciphertext,
    nonce: result.nonce,
  }
}

/**
 * Decrypt a DEK with a workspace KEK.
 *
 * @param encryptedDek - Encrypted DEK
 * @param nonce - Nonce used for encryption
 * @param kek - Workspace KEK
 * @returns Decrypted DEK
 */
export async function decryptDekWithKek(
  encryptedDek: Uint8Array,
  nonce: Uint8Array,
  kek: Uint8Array
): Promise<Uint8Array> {
  return decrypt(kek, encryptedDek, nonce)
}

/**
 * Decrypt a DEK from API response format.
 *
 * @param encryptedDekBase64 - Base64-encoded encrypted DEK
 * @param nonceBase64 - Base64-encoded nonce
 * @param kek - Workspace KEK
 * @returns Decrypted DEK
 */
export async function decryptDekFromApiResponse(
  encryptedDekBase64: string,
  nonceBase64: string,
  kek: Uint8Array
): Promise<Uint8Array> {
  const sodium = await getSodium()

  const encryptedDek = sodium.from_base64(encryptedDekBase64, sodium.base64_variants.ORIGINAL)
  const nonce = sodium.from_base64(nonceBase64, sodium.base64_variants.ORIGINAL)

  return decryptDekWithKek(encryptedDek, nonce, kek)
}

/**
 * Encode DEK for API request.
 *
 * @param encryptedDek - Encrypted DEK
 * @param nonce - Nonce
 * @returns Base64-encoded values
 */
export async function encodeDekForApi(
  encryptedDek: Uint8Array,
  nonce: Uint8Array
): Promise<{
  encryptedDek: string
  nonce: string
}> {
  const sodium = await getSodium()

  return {
    encryptedDek: sodium.to_base64(encryptedDek, sodium.base64_variants.ORIGINAL),
    nonce: sodium.to_base64(nonce, sodium.base64_variants.ORIGINAL),
  }
}

/**
 * Create encrypted DEK ready for API request.
 *
 * @param dek - The DEK to encrypt
 * @param kek - Workspace KEK
 * @returns Base64-encoded encrypted DEK and nonce
 */
export async function createEncryptedDekForApi(
  dek: Uint8Array,
  kek: Uint8Array
): Promise<{
  encryptedDek: string
  nonce: string
}> {
  const { encryptedDek, nonce } = await encryptDekWithKek(dek, kek)
  return encodeDekForApi(encryptedDek, nonce)
}

/**
 * Get DEK from cache or fetch from API.
 *
 * @param documentId - Document ID
 * @param kek - Workspace KEK for decryption
 * @param fetchDekFn - Function to fetch encrypted DEK from API
 * @returns Decrypted DEK
 */
export async function getOrFetchDek(
  documentId: string,
  kek: Uint8Array,
  fetchDekFn: () => Promise<{ encryptedDek: string; nonce: string }>
): Promise<Uint8Array> {
  const cache = getDekCache()

  // Check cache first
  const cached = cache.getDek(documentId)
  if (cached) {
    return cached
  }

  // Fetch from API
  const { encryptedDek, nonce } = await fetchDekFn()

  // Decrypt
  const dek = await decryptDekFromApiResponse(encryptedDek, nonce, kek)

  // Cache the result
  cache.setDek(documentId, dek)

  return dek
}

/**
 * Invalidate cached DEK (e.g., after rotation).
 *
 * @param documentId - Document ID
 */
export function invalidateCachedDek(documentId: string): void {
  const cache = getDekCache()
  cache.deleteDek(documentId)
}

/**
 * Invalidate all DEKs for documents in a workspace.
 * Call this when workspace KEK is rotated.
 *
 * @param documentIds - Document IDs to invalidate
 */
export function invalidateWorkspaceDeks(documentIds: string[]): void {
  const cache = getDekCache()
  cache.deleteByWorkspace(documentIds)
}

/**
 * Re-encrypt a DEK with a new KEK (for KEK rotation).
 *
 * @param dek - The DEK to re-encrypt
 * @param newKek - New workspace KEK
 * @returns Encrypted DEK with new KEK
 */
export async function reEncryptDek(
  dek: Uint8Array,
  newKek: Uint8Array
): Promise<{
  encryptedDek: string
  nonce: string
}> {
  return createEncryptedDekForApi(dek, newKek)
}
