/**
 * XChaCha20-Poly1305 AEAD encryption module
 *
 * Compatible with backend implementation (api/crates/infrastructure/src/core/crypto/xchacha20.rs)
 * Note: This does NOT include robustnessTag (differs from secsync)
 */

import { getSodium } from './sodium'

/** XChaCha20-Poly1305 nonce size (24 bytes) */
export const NONCE_SIZE = 24

/** XChaCha20-Poly1305 key size (32 bytes / 256 bits) */
export const KEY_SIZE = 32

/** Poly1305 authentication tag size (16 bytes) */
export const TAG_SIZE = 16

export interface EncryptResult {
  /** Encrypted data including authentication tag */
  ciphertext: Uint8Array
  /** 24-byte nonce used for encryption */
  nonce: Uint8Array
}

/**
 * Generate a random 24-byte nonce for XChaCha20-Poly1305.
 *
 * Each encryption operation MUST use a unique nonce.
 * Using the same nonce twice with the same key is catastrophic.
 */
export async function generateNonce(): Promise<Uint8Array> {
  const sodium = await getSodium()
  return sodium.randombytes_buf(NONCE_SIZE)
}

/**
 * Generate a random 32-byte key for XChaCha20-Poly1305.
 */
export async function generateKey(): Promise<Uint8Array> {
  const sodium = await getSodium()
  return sodium.randombytes_buf(KEY_SIZE)
}

/**
 * Encrypt plaintext using XChaCha20-Poly1305.
 *
 * @param key - 32-byte encryption key
 * @param plaintext - Data to encrypt
 * @returns Ciphertext (including auth tag) and nonce
 * @throws Error if key length is invalid
 */
export async function encrypt(
  key: Uint8Array,
  plaintext: Uint8Array
): Promise<EncryptResult> {
  if (key.length !== KEY_SIZE) {
    throw new Error(`Invalid key length: expected ${KEY_SIZE}, got ${key.length}`)
  }

  const sodium = await getSodium()
  const nonce = await generateNonce()

  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    null, // no additional data
    null, // secret nonce (not used)
    nonce,
    key
  )

  return { ciphertext, nonce }
}

/**
 * Decrypt ciphertext using XChaCha20-Poly1305.
 *
 * @param key - 32-byte encryption key
 * @param ciphertext - Encrypted data (including auth tag)
 * @param nonce - 24-byte nonce used during encryption
 * @returns Decrypted plaintext
 * @throws Error if decryption fails (wrong key, corrupted data, or tampered)
 */
export async function decrypt(
  key: Uint8Array,
  ciphertext: Uint8Array,
  nonce: Uint8Array
): Promise<Uint8Array> {
  if (key.length !== KEY_SIZE) {
    throw new Error(`Invalid key length: expected ${KEY_SIZE}, got ${key.length}`)
  }
  if (nonce.length !== NONCE_SIZE) {
    throw new Error(`Invalid nonce length: expected ${NONCE_SIZE}, got ${nonce.length}`)
  }

  const sodium = await getSodium()

  try {
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null, // secret nonce (not used)
      ciphertext,
      null, // no additional data
      nonce,
      key
    )
  } catch {
    throw new Error('Decryption failed: authentication tag mismatch or corrupted data')
  }
}

/**
 * Encrypt a DEK (Data Encryption Key) with a KEK (Key Encryption Key).
 *
 * @param kek - 32-byte Key Encryption Key
 * @param dek - 32-byte Data Encryption Key to encrypt
 * @returns Encrypted DEK and nonce
 */
export async function encryptDek(
  kek: Uint8Array,
  dek: Uint8Array
): Promise<EncryptResult> {
  if (dek.length !== KEY_SIZE) {
    throw new Error(`Invalid DEK length: expected ${KEY_SIZE}, got ${dek.length}`)
  }
  return encrypt(kek, dek)
}

/**
 * Decrypt a DEK (Data Encryption Key) with a KEK (Key Encryption Key).
 *
 * @param kek - 32-byte Key Encryption Key
 * @param encryptedDek - Encrypted DEK (including auth tag)
 * @param nonce - 24-byte nonce used during encryption
 * @returns Decrypted 32-byte DEK
 */
export async function decryptDek(
  kek: Uint8Array,
  encryptedDek: Uint8Array,
  nonce: Uint8Array
): Promise<Uint8Array> {
  const decrypted = await decrypt(kek, encryptedDek, nonce)
  if (decrypted.length !== KEY_SIZE) {
    throw new Error(`Invalid decrypted DEK length: expected ${KEY_SIZE}, got ${decrypted.length}`)
  }
  return decrypted
}

/**
 * Encrypt string data using XChaCha20-Poly1305.
 *
 * @param key - 32-byte encryption key
 * @param plaintext - String to encrypt (UTF-8 encoded)
 * @returns Ciphertext and nonce
 */
export async function encryptString(
  key: Uint8Array,
  plaintext: string
): Promise<EncryptResult> {
  const encoder = new TextEncoder()
  return encrypt(key, encoder.encode(plaintext))
}

/**
 * Decrypt to string using XChaCha20-Poly1305.
 *
 * @param key - 32-byte encryption key
 * @param ciphertext - Encrypted data
 * @param nonce - 24-byte nonce
 * @returns Decrypted string (UTF-8 decoded)
 */
export async function decryptString(
  key: Uint8Array,
  ciphertext: Uint8Array,
  nonce: Uint8Array
): Promise<string> {
  const decrypted = await decrypt(key, ciphertext, nonce)
  const decoder = new TextDecoder()
  return decoder.decode(decrypted)
}
