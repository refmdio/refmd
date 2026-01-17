/**
 * Workspace KEK (Key Encryption Key) Management
 *
 * KEKs are used to encrypt Document DEKs within a workspace.
 * Each workspace has its own KEK, encrypted for each member.
 */

import {
  generateKey,
  getSodium,
  encryptKeyForRecipient,
  decryptKeyFromSender,
} from '../crypto'

import { getKekCache } from './key-cache'

/** HKDF context for KEK derivation */
const KEK_HKDF_INFO = 'refmd_workspace_kek'

/** KEK size (32 bytes) */
export const KEK_SIZE = 32

/** Workspace KEK with metadata */
export interface WorkspaceKek {
  /** Workspace ID */
  workspaceId: string
  /** 32-byte KEK */
  key: Uint8Array
  /** Key version for rotation */
  version: number
}

/** Encrypted KEK from API response */
export interface EncryptedKekFromApi {
  /** Encrypted KEK (Base64) */
  encryptedKek: string
  /** Key version */
  keyVersion: number
  /** Workspace ID */
  workspaceId: string
}

/**
 * Generate a new Workspace KEK.
 *
 * @returns 32-byte random KEK
 */
export async function generateWorkspaceKek(): Promise<Uint8Array> {
  return generateKey()
}

/**
 * Encrypt a KEK for a recipient using their public key.
 *
 * @param kek - The KEK to encrypt
 * @param recipientPublicKey - Recipient's ECDH public key
 * @returns Encrypted KEK with ephemeral public key and nonce
 */
export async function encryptKekForRecipient(
  kek: Uint8Array,
  recipientPublicKey: Uint8Array
): Promise<{
  encryptedKek: Uint8Array
  ephemeralPublicKey: Uint8Array
  nonce: Uint8Array
}> {
  const result = await encryptKeyForRecipient(recipientPublicKey, kek, KEK_HKDF_INFO)

  return {
    encryptedKek: result.encryptedKey,
    ephemeralPublicKey: result.ephemeralPublicKey,
    nonce: result.nonce,
  }
}

/**
 * Decrypt a KEK that was encrypted for us.
 *
 * @param ourPrivateKey - Our ECDH private key
 * @param encryptedKek - Encrypted KEK
 * @param ephemeralPublicKey - Sender's ephemeral public key
 * @param nonce - Nonce used for encryption
 * @returns Decrypted KEK
 */
export async function decryptKek(
  ourPrivateKey: Uint8Array,
  encryptedKek: Uint8Array,
  ephemeralPublicKey: Uint8Array,
  nonce: Uint8Array
): Promise<Uint8Array> {
  return decryptKeyFromSender(ourPrivateKey, ephemeralPublicKey, encryptedKek, nonce, KEK_HKDF_INFO)
}

/**
 * Decrypt a KEK from API response format.
 * The API returns the encrypted KEK as: ephemeralPublicKey || nonce || ciphertext (all Base64 encoded together)
 *
 * @param ourPrivateKey - Our ECDH private key
 * @param encryptedKekBase64 - Base64-encoded encrypted KEK from API
 * @returns Decrypted KEK
 */
export async function decryptKekFromApiResponse(
  ourPrivateKey: Uint8Array,
  encryptedKekBase64: string
): Promise<Uint8Array> {
  const sodium = await getSodium()
  const combined = sodium.from_base64(encryptedKekBase64, sodium.base64_variants.ORIGINAL)

  // Format: ephemeralPublicKey (65 bytes) || nonce (24 bytes) || ciphertext (remaining)
  const EPHEMERAL_KEY_SIZE = 65
  const NONCE_SIZE = 24

  if (combined.length < EPHEMERAL_KEY_SIZE + NONCE_SIZE + 1) {
    throw new Error('Invalid encrypted KEK format: too short')
  }

  const ephemeralPublicKey = combined.slice(0, EPHEMERAL_KEY_SIZE)
  const nonce = combined.slice(EPHEMERAL_KEY_SIZE, EPHEMERAL_KEY_SIZE + NONCE_SIZE)
  const encryptedKek = combined.slice(EPHEMERAL_KEY_SIZE + NONCE_SIZE)

  return decryptKek(ourPrivateKey, encryptedKek, ephemeralPublicKey, nonce)
}

/**
 * Encode a KEK for API request.
 * Format: ephemeralPublicKey || nonce || ciphertext (all Base64 encoded together)
 *
 * @param encryptedKek - Encrypted KEK
 * @param ephemeralPublicKey - Ephemeral public key
 * @param nonce - Nonce
 * @returns Base64-encoded combined data
 */
export async function encodeKekForApi(
  encryptedKek: Uint8Array,
  ephemeralPublicKey: Uint8Array,
  nonce: Uint8Array
): Promise<string> {
  const sodium = await getSodium()

  // Combine: ephemeralPublicKey || nonce || ciphertext
  const combined = new Uint8Array(
    ephemeralPublicKey.length + nonce.length + encryptedKek.length
  )
  combined.set(ephemeralPublicKey, 0)
  combined.set(nonce, ephemeralPublicKey.length)
  combined.set(encryptedKek, ephemeralPublicKey.length + nonce.length)

  return sodium.to_base64(combined, sodium.base64_variants.ORIGINAL)
}

/**
 * Get KEK from cache or fetch from API.
 *
 * @param workspaceId - Workspace ID
 * @param ecdhPrivateKey - Our ECDH private key
 * @param fetchKekFn - Function to fetch encrypted KEK from API
 * @returns Decrypted KEK
 */
export async function getOrFetchKek(
  workspaceId: string,
  ecdhPrivateKey: Uint8Array,
  fetchKekFn: () => Promise<string> // Returns Base64-encoded encrypted KEK
): Promise<Uint8Array> {
  const cache = getKekCache()

  // Check cache first
  const cached = cache.getKek(workspaceId)
  if (cached) {
    return cached
  }

  // Fetch from API
  const encryptedKekBase64 = await fetchKekFn()

  // Decrypt
  const kek = await decryptKekFromApiResponse(ecdhPrivateKey, encryptedKekBase64)

  // Cache the result
  cache.setKek(workspaceId, kek)

  return kek
}

/**
 * Invalidate cached KEK (e.g., after rotation).
 *
 * @param workspaceId - Workspace ID
 */
export function invalidateCachedKek(workspaceId: string): void {
  const cache = getKekCache()
  cache.deleteKek(workspaceId)
}

/**
 * Create a KEK for a new workspace member.
 *
 * @param kek - The workspace KEK
 * @param memberPublicKey - New member's ECDH public key
 * @returns Encrypted KEK for the new member (Base64)
 */
export async function createKekForMember(
  kek: Uint8Array,
  memberPublicKey: Uint8Array
): Promise<string> {
  const { encryptedKek, ephemeralPublicKey, nonce } = await encryptKekForRecipient(
    kek,
    memberPublicKey
  )

  return encodeKekForApi(encryptedKek, ephemeralPublicKey, nonce)
}
