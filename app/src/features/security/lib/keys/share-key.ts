/**
 * Share Key Management
 *
 * Handles key generation and management for shared document links.
 * Supports two modes:
 * 1. URL fragment mode: key is in the URL hash (never sent to server)
 * 2. Password mode: key is derived from a password using PBKDF2
 */

import {
  generateKey,
  encrypt,
  decrypt,
  pbkdf2DeriveKey,
  pbkdf2GenerateSalt,
  getSodium,
  PBKDF2_DEFAULT_ITERATIONS,
} from '../crypto'

/** Share key size (32 bytes) */
export const SHARE_KEY_SIZE = 32

/** URL fragment prefix for share keys */
export const URL_FRAGMENT_PREFIX = 'key='

/** Share key with metadata */
export interface ShareKey {
  /** 32-byte share key */
  key: Uint8Array
  /** Whether this is password-derived */
  isPasswordProtected: boolean
}

/** Encrypted share key for API */
export interface EncryptedShareKeyForApi {
  /** Encrypted DEK (Base64) */
  encryptedDek: string
  /** Nonce (Base64) */
  nonce: string
  /** Salt for password-protected shares (Base64), if applicable */
  salt?: string
}

/**
 * Generate a new share key for URL fragment mode.
 *
 * @returns Share key and URL fragment
 */
export async function generateShareKey(): Promise<{
  key: Uint8Array
  fragment: string
}> {
  const sodium = await getSodium()
  const key = await generateKey()
  const keyBase64 = sodium.to_base64(key, sodium.base64_variants.URLSAFE_NO_PADDING)

  return {
    key,
    fragment: `${URL_FRAGMENT_PREFIX}${keyBase64}`,
  }
}

/**
 * Extract share key from URL fragment.
 *
 * @param fragment - URL fragment (with or without leading #)
 * @returns Decoded share key, or null if not found/invalid
 */
export async function extractShareKeyFromFragment(
  fragment: string
): Promise<Uint8Array | null> {
  const sodium = await getSodium()

  // Remove leading # if present
  const cleanFragment = fragment.startsWith('#') ? fragment.slice(1) : fragment

  // Check for key prefix
  if (!cleanFragment.startsWith(URL_FRAGMENT_PREFIX)) {
    return null
  }

  const keyBase64 = cleanFragment.slice(URL_FRAGMENT_PREFIX.length)

  try {
    return sodium.from_base64(keyBase64, sodium.base64_variants.URLSAFE_NO_PADDING)
  } catch {
    return null
  }
}

/**
 * Derive a share key from a password.
 *
 * @param password - User-provided password
 * @param salt - Salt (generate new for creation, use existing for access)
 * @returns Derived share key
 */
export async function deriveShareKeyFromPassword(
  password: string,
  salt: Uint8Array
): Promise<Uint8Array> {
  return pbkdf2DeriveKey(password, salt, PBKDF2_DEFAULT_ITERATIONS)
}

/**
 * Create a password-protected share key.
 *
 * @param password - User-provided password
 * @returns Derived share key and salt
 */
export async function createPasswordProtectedShareKey(
  password: string
): Promise<{
  key: Uint8Array
  salt: Uint8Array
}> {
  const salt = await pbkdf2GenerateSalt()
  const key = await deriveShareKeyFromPassword(password, salt)

  return { key, salt }
}

/**
 * Encrypt a DEK with a share key for storage.
 *
 * @param dek - Document DEK to encrypt
 * @param shareKey - Share key
 * @returns Encrypted DEK and nonce (Base64)
 */
export async function encryptDekWithShareKey(
  dek: Uint8Array,
  shareKey: Uint8Array
): Promise<{
  encryptedDek: string
  nonce: string
}> {
  const sodium = await getSodium()
  const { ciphertext, nonce } = await encrypt(shareKey, dek)

  return {
    encryptedDek: sodium.to_base64(ciphertext, sodium.base64_variants.ORIGINAL),
    nonce: sodium.to_base64(nonce, sodium.base64_variants.ORIGINAL),
  }
}

/**
 * Decrypt a DEK with a share key.
 *
 * @param encryptedDekBase64 - Encrypted DEK (Base64)
 * @param nonceBase64 - Nonce (Base64)
 * @param shareKey - Share key
 * @returns Decrypted DEK
 */
export async function decryptDekWithShareKey(
  encryptedDekBase64: string,
  nonceBase64: string,
  shareKey: Uint8Array
): Promise<Uint8Array> {
  const sodium = await getSodium()

  const encryptedDek = sodium.from_base64(encryptedDekBase64, sodium.base64_variants.ORIGINAL)
  const nonce = sodium.from_base64(nonceBase64, sodium.base64_variants.ORIGINAL)

  return decrypt(shareKey, encryptedDek, nonce)
}

/**
 * Build a complete share URL with the key in the fragment.
 *
 * @param baseUrl - Base share URL (e.g., "https://refmd.io/share/abc123")
 * @param fragment - Key fragment (e.g., "key=...")
 * @returns Complete URL with fragment
 */
export function buildShareUrl(baseUrl: string, fragment: string): string {
  // Remove any existing fragment from baseUrl
  const cleanBaseUrl = baseUrl.split('#')[0]
  return `${cleanBaseUrl}#${fragment}`
}

/**
 * Parse salt from API response.
 *
 * @param saltBase64 - Base64-encoded salt
 * @returns Decoded salt
 */
export async function parseSaltFromApi(saltBase64: string): Promise<Uint8Array> {
  const sodium = await getSodium()
  return sodium.from_base64(saltBase64, sodium.base64_variants.ORIGINAL)
}

/**
 * Encode salt for API request.
 *
 * @param salt - Salt bytes
 * @returns Base64-encoded salt
 */
export async function encodeSaltForApi(salt: Uint8Array): Promise<string> {
  const sodium = await getSodium()
  return sodium.to_base64(salt, sodium.base64_variants.ORIGINAL)
}

/**
 * Check if a URL fragment contains a share key.
 *
 * @param fragment - URL fragment
 * @returns true if contains key fragment
 */
export function hasShareKeyFragment(fragment: string): boolean {
  const cleanFragment = fragment.startsWith('#') ? fragment.slice(1) : fragment
  return cleanFragment.startsWith(URL_FRAGMENT_PREFIX)
}
