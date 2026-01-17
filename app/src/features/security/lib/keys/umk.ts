/**
 * User Master Key (UMK) Management
 *
 * The UMK is the root of the key hierarchy:
 * - Generated from random entropy or derived from passphrase
 * - Never stored in IndexedDB, only in session memory
 * - Can be recovered from BIP39 mnemonic (recovery key)
 */

import {
  argon2DeriveKey,
  argon2DeriveKeyWithNewSalt,
  isArgon2Supported,
  pbkdf2DeriveKey,
  pbkdf2DeriveKeyWithNewSalt,
  DEFAULT_ARGON2_PARAMS,
  PBKDF2_DEFAULT_ITERATIONS,
  type Argon2Params,
  generateRecoveryKey,
  validateRecoveryKey,
  recoveryKeyToUmk,
  umkToRecoveryKey,
  getSodium,
} from '../crypto'

import type { StoredKeys } from './key-store'

/** UMK size in bytes (256 bits) */
export const UMK_SIZE = 32

/** Result of UMK generation */
export interface UmkGenerationResult {
  /** The generated UMK (32 bytes) */
  umk: Uint8Array
  /** BIP39 recovery key (24 words) */
  recoveryKey: string
  /** Salt used for passphrase derivation */
  salt: Uint8Array
  /** KDF type used */
  kdf: 'argon2id' | 'pbkdf2'
  /** KDF parameters */
  kdfParams: Argon2Params | { iterations: number }
}

/** KDF parameters for storage */
export type KdfParams = Argon2Params | { type: 'pbkdf2'; iterations: number }

/**
 * Generate a new UMK with recovery key.
 *
 * The UMK is derived from a passphrase using Argon2id (or PBKDF2 fallback).
 * A recovery key (BIP39 mnemonic) is also generated for backup.
 *
 * @param passphrase - User's passphrase (min 12 characters recommended)
 * @returns UMK generation result
 */
export async function generateUmk(passphrase: string): Promise<UmkGenerationResult> {
  // Validate passphrase
  if (!passphrase || passphrase.length < 8) {
    throw new Error('Passphrase must be at least 8 characters')
  }

  // Check if Argon2id is supported
  const useArgon2 = await isArgon2Supported()

  let umk: Uint8Array
  let salt: Uint8Array
  let kdf: 'argon2id' | 'pbkdf2'
  let kdfParams: Argon2Params | { iterations: number }

  if (useArgon2) {
    const result = await argon2DeriveKeyWithNewSalt(passphrase, DEFAULT_ARGON2_PARAMS)
    umk = result.key
    salt = result.salt
    kdf = 'argon2id'
    kdfParams = DEFAULT_ARGON2_PARAMS
  } else {
    const result = await pbkdf2DeriveKeyWithNewSalt(passphrase, PBKDF2_DEFAULT_ITERATIONS)
    umk = result.key
    salt = result.salt
    kdf = 'pbkdf2'
    kdfParams = { iterations: PBKDF2_DEFAULT_ITERATIONS }
  }

  // Generate recovery key from the UMK
  const recoveryKey = umkToRecoveryKey(umk)

  return {
    umk,
    recoveryKey,
    salt,
    kdf,
    kdfParams,
  }
}

/**
 * Derive UMK from passphrase using stored parameters.
 *
 * @param passphrase - User's passphrase
 * @param salt - Salt from key store
 * @param kdf - KDF type ('argon2id' or 'pbkdf2')
 * @param kdfParams - KDF parameters
 * @returns Derived UMK
 */
export async function deriveUmkFromPassphrase(
  passphrase: string,
  salt: Uint8Array,
  kdf: 'argon2id' | 'pbkdf2',
  kdfParams: Argon2Params | { iterations: number }
): Promise<Uint8Array> {
  if (kdf === 'argon2id') {
    return argon2DeriveKey(passphrase, salt, kdfParams as Argon2Params)
  } else {
    return pbkdf2DeriveKey(
      passphrase,
      salt,
      (kdfParams as { iterations: number }).iterations
    )
  }
}

/**
 * Restore UMK from recovery key (BIP39 mnemonic).
 *
 * @param recoveryKey - 24-word BIP39 mnemonic
 * @returns The restored UMK
 * @throws Error if recovery key is invalid
 */
export function restoreUmkFromRecoveryKey(recoveryKey: string): Uint8Array {
  if (!validateRecoveryKey(recoveryKey)) {
    throw new Error('Invalid recovery key')
  }

  return recoveryKeyToUmk(recoveryKey)
}

/**
 * Re-encrypt UMK with a new passphrase.
 * Used when user changes their passphrase.
 *
 * @param umk - Current UMK
 * @param newPassphrase - New passphrase
 * @returns New salt and KDF parameters
 */
export async function reEncryptUmk(
  _umk: Uint8Array,
  newPassphrase: string
): Promise<{
  salt: Uint8Array
  kdf: 'argon2id' | 'pbkdf2'
  kdfParams: Argon2Params | { iterations: number }
}> {
  if (!newPassphrase || newPassphrase.length < 8) {
    throw new Error('Passphrase must be at least 8 characters')
  }

  const useArgon2 = await isArgon2Supported()

  if (useArgon2) {
    const { salt } = await argon2DeriveKeyWithNewSalt(newPassphrase, DEFAULT_ARGON2_PARAMS)
    return {
      salt,
      kdf: 'argon2id',
      kdfParams: DEFAULT_ARGON2_PARAMS,
    }
  } else {
    const { salt } = await pbkdf2DeriveKeyWithNewSalt(newPassphrase, PBKDF2_DEFAULT_ITERATIONS)
    return {
      salt,
      kdf: 'pbkdf2',
      kdfParams: { iterations: PBKDF2_DEFAULT_ITERATIONS },
    }
  }
}

/**
 * Verify if a passphrase matches the stored keys.
 * Derives UMK and attempts to decrypt the stored private key.
 *
 * @param passphrase - Passphrase to verify
 * @param storedKeys - Stored keys from IndexedDB
 * @returns true if passphrase is correct
 */
export async function verifyPassphrase(
  passphrase: string,
  storedKeys: StoredKeys
): Promise<boolean> {
  try {
    const umk = await deriveUmkFromPassphrase(
      passphrase,
      storedKeys.salt,
      storedKeys.kdf,
      storedKeys.kdfParams
    )

    // Try to decrypt the stored private key
    const sodium = await getSodium()

    // Try ECDH key decryption
    const decrypted = sodium.crypto_secretbox_open_easy(
      storedKeys.encryptedEcdhPrivateKey,
      storedKeys.encryptedEcdhPrivateKeyNonce,
      umk
    )

    // If we get here, the passphrase is correct
    // Zero out the decrypted key
    decrypted.fill(0)
    umk.fill(0)

    return true
  } catch {
    return false
  }
}

/**
 * Generate a new recovery key for an existing UMK.
 * The UMK must already be unlocked.
 *
 * @param umk - Current UMK
 * @returns New recovery key (24 words)
 */
export function generateNewRecoveryKey(umk: Uint8Array): string {
  if (umk.length !== UMK_SIZE) {
    throw new Error(`Invalid UMK size: expected ${UMK_SIZE}, got ${umk.length}`)
  }

  return umkToRecoveryKey(umk)
}

/**
 * Validate a recovery key without restoring.
 *
 * @param recoveryKey - Recovery key to validate
 * @returns true if valid BIP39 mnemonic
 */
export { validateRecoveryKey }

/**
 * Export recovery key generation for new UMKs.
 */
export { generateRecoveryKey }

/**
 * Zero out UMK from memory (call when locking session).
 *
 * @param umk - UMK to zero out
 */
export function zeroUmk(umk: Uint8Array): void {
  umk.fill(0)
}
