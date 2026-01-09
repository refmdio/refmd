/**
 * Argon2id Key Derivation Function
 *
 * Used for deriving encryption keys from user passphrases.
 * Argon2id is the recommended KDF for password hashing.
 *
 * Parameters follow OWASP recommendations:
 * - memory: 64 MB (65536 KB)
 * - iterations: 3
 * - parallelism: 4
 */

import { argon2id } from 'hash-wasm'
import { getSodium } from './sodium'

/** Salt size for Argon2id (16 bytes) */
export const SALT_SIZE = 16

/** Output key size (32 bytes for XChaCha20-Poly1305) */
export const KEY_SIZE = 32

/** Argon2id parameters */
export interface Argon2Params {
  /** Memory cost in KB (default: 65536 = 64 MB) */
  memory: number
  /** Time cost / iterations (default: 3) */
  iterations: number
  /** Parallelism / lanes (default: 4) */
  parallelism: number
}

/** Default Argon2id parameters (OWASP recommended) */
export const DEFAULT_ARGON2_PARAMS: Argon2Params = {
  memory: 65536, // 64 MB
  iterations: 3,
  parallelism: 4,
}

/**
 * Generate a random salt for Argon2id.
 *
 * @returns 16-byte random salt
 */
export async function generateSalt(): Promise<Uint8Array> {
  const sodium = await getSodium()
  return sodium.randombytes_buf(SALT_SIZE)
}

/**
 * Derive a key from a passphrase using Argon2id.
 *
 * @param passphrase - User's passphrase
 * @param salt - 16-byte random salt
 * @param params - Argon2id parameters (optional, defaults to OWASP recommended)
 * @returns 32-byte derived key
 */
export async function deriveKey(
  passphrase: string,
  salt: Uint8Array,
  params: Argon2Params = DEFAULT_ARGON2_PARAMS
): Promise<Uint8Array> {
  if (salt.length !== SALT_SIZE) {
    throw new Error(`Invalid salt length: expected ${SALT_SIZE}, got ${salt.length}`)
  }

  const hashHex = await argon2id({
    password: passphrase,
    salt,
    iterations: params.iterations,
    memorySize: params.memory,
    parallelism: params.parallelism,
    hashLength: KEY_SIZE,
    outputType: 'hex',
  })

  // Convert hex string to Uint8Array
  const bytes = new Uint8Array(KEY_SIZE)
  for (let i = 0; i < KEY_SIZE; i++) {
    bytes[i] = parseInt(hashHex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

/**
 * Derive a key from a passphrase with a new random salt.
 *
 * @param passphrase - User's passphrase
 * @param params - Argon2id parameters (optional)
 * @returns Derived key and the salt used
 */
export async function deriveKeyWithNewSalt(
  passphrase: string,
  params: Argon2Params = DEFAULT_ARGON2_PARAMS
): Promise<{ key: Uint8Array; salt: Uint8Array }> {
  const salt = await generateSalt()
  const key = await deriveKey(passphrase, salt, params)
  return { key, salt }
}

/**
 * Check if Argon2id is supported in the current environment.
 * Falls back to PBKDF2 if not supported.
 *
 * @returns true if Argon2id is supported
 */
export async function isArgon2Supported(): Promise<boolean> {
  try {
    // Try a minimal hash to check if Argon2 WASM is working
    await argon2id({
      password: 'test',
      salt: new Uint8Array(16),
      iterations: 1,
      memorySize: 1024,
      parallelism: 1,
      hashLength: 32,
      outputType: 'hex',
    })
    return true
  } catch {
    return false
  }
}
