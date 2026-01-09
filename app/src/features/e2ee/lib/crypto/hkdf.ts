/**
 * HKDF-SHA256 key derivation module
 *
 * Used for deriving multiple keys from a single master key.
 * Uses libsodium's crypto_kdf functions.
 */

import { getSodium } from './sodium'

/** Minimum context length for HKDF */
export const MIN_CONTEXT_LENGTH = 8

/** Maximum context length for HKDF */
export const MAX_CONTEXT_LENGTH = 8

/** Master key size (32 bytes) */
export const MASTER_KEY_SIZE = 32

/** Minimum derived key size */
export const MIN_KEY_SIZE = 16

/** Maximum derived key size */
export const MAX_KEY_SIZE = 64

/**
 * Derive a subkey from a master key using HKDF-SHA256.
 *
 * @param masterKey - 32-byte master key (IKM)
 * @param subkeyId - Numeric ID for the subkey (used for domain separation)
 * @param context - 8-byte context string (for domain separation)
 * @param length - Desired output key length (16-64 bytes)
 * @returns Derived key
 */
export async function deriveKey(
  masterKey: Uint8Array,
  subkeyId: number,
  context: string,
  length: number = 32
): Promise<Uint8Array> {
  if (masterKey.length !== MASTER_KEY_SIZE) {
    throw new Error(`Invalid master key length: expected ${MASTER_KEY_SIZE}, got ${masterKey.length}`)
  }
  if (length < MIN_KEY_SIZE || length > MAX_KEY_SIZE) {
    throw new Error(`Invalid key length: must be between ${MIN_KEY_SIZE} and ${MAX_KEY_SIZE}`)
  }

  // Pad or truncate context to exactly 8 bytes
  const contextBytes = new TextEncoder().encode(context.padEnd(8, '\0').slice(0, 8))

  const sodium = await getSodium()

  return sodium.crypto_kdf_derive_from_key(
    length,
    subkeyId,
    new TextDecoder().decode(contextBytes),
    masterKey
  )
}

/**
 * Generate a random master key for HKDF.
 *
 * @returns 32-byte random master key
 */
export async function generateMasterKey(): Promise<Uint8Array> {
  const sodium = await getSodium()
  return sodium.crypto_kdf_keygen()
}

/** Context strings for different key derivations */
export const HKDF_CONTEXTS = {
  /** Derive encryption key from UMK */
  ENCRYPTION: 'refmd_ek',
  /** Derive signing key from UMK */
  SIGNING: 'refmd_sk',
  /** Derive workspace KEK */
  WORKSPACE: 'refmd_ws',
  /** Derive document DEK */
  DOCUMENT: 'refmd_dc',
  /** Derive plugin key */
  PLUGIN: 'refmd_pl',
} as const

/** Subkey IDs for different purposes */
export const SUBKEY_IDS = {
  /** Main encryption key */
  MAIN: 1,
  /** Backup encryption key */
  BACKUP: 2,
  /** Authentication key */
  AUTH: 3,
} as const
