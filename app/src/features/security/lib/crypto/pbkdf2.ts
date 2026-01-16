/**
 * PBKDF2-SHA256 Key Derivation Function (Fallback)
 *
 * Used as a fallback when Argon2id is not available.
 * Uses Web Crypto API for PBKDF2.
 *
 * Parameters:
 * - iterations: 1,000,000 (high iteration count to compensate for lack of memory-hardness)
 * - hash: SHA-256
 */

import { getSodium } from './sodium'

/** Salt size for PBKDF2 (16 bytes) */
export const SALT_SIZE = 16

/** Output key size (32 bytes) */
export const KEY_SIZE = 32

/** Default iteration count (1,000,000) */
export const DEFAULT_ITERATIONS = 1_000_000

/**
 * Generate a random salt for PBKDF2.
 *
 * @returns 16-byte random salt
 */
export async function generateSalt(): Promise<Uint8Array> {
  const sodium = await getSodium()
  return sodium.randombytes_buf(SALT_SIZE)
}

/**
 * Derive a key from a passphrase using PBKDF2-SHA256.
 *
 * @param passphrase - User's passphrase
 * @param salt - 16-byte random salt
 * @param iterations - Number of iterations (default: 1,000,000)
 * @returns 32-byte derived key
 */
export async function deriveKey(
  passphrase: string,
  salt: Uint8Array,
  iterations: number = DEFAULT_ITERATIONS
): Promise<Uint8Array> {
  if (salt.length !== SALT_SIZE) {
    throw new Error(`Invalid salt length: expected ${SALT_SIZE}, got ${salt.length}`)
  }

  const encoder = new TextEncoder()
  const passphraseBytes = encoder.encode(passphrase)

  // Import the passphrase as a key
  const baseKey = await crypto.subtle.importKey(
    'raw',
    passphraseBytes,
    'PBKDF2',
    false,
    ['deriveBits']
  )

  // Derive the key using PBKDF2
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt as BufferSource,
      iterations,
      hash: 'SHA-256',
    },
    baseKey,
    KEY_SIZE * 8 // bits
  )

  return new Uint8Array(derivedBits)
}

/**
 * Derive a key from a passphrase with a new random salt.
 *
 * @param passphrase - User's passphrase
 * @param iterations - Number of iterations (optional)
 * @returns Derived key and the salt used
 */
export async function deriveKeyWithNewSalt(
  passphrase: string,
  iterations: number = DEFAULT_ITERATIONS
): Promise<{ key: Uint8Array; salt: Uint8Array }> {
  const salt = await generateSalt()
  const key = await deriveKey(passphrase, salt, iterations)
  return { key, salt }
}
