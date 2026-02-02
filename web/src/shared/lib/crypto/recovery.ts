/**
 * Recovery Key operations using BIP39
 *
 * BIP39 24-word mnemonic → seed → HKDF → RUK (Recovery Unlock Key)
 * RUK is used to wrap UMK as a backup
 */

import { generateMnemonic, mnemonicToSeed, validateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { randomBytes } from '@noble/ciphers/utils.js'
import { buildRecoveryUmkWrapAad } from './aad'

/** HKDF salt: 32 bytes of zeros (per spec) */
const HKDF_ZERO_SALT = new Uint8Array(32)

/** HKDF info constant (per spec) */
const HKDF_INFO_RUK = 'ruk'

/**
 * Recovery key data returned to user
 */
export interface RecoveryKeyData {
  /** 24-word mnemonic (user must save this) */
  mnemonic: string
  /** RUK derived from mnemonic (32 bytes) */
  ruk: Uint8Array
}

/**
 * Encrypted UMK with recovery key
 */
export interface RecoveryWrappedUmk {
  /** Encrypted UMK */
  encryptedUmk: Uint8Array
  /** Nonce for encryption */
  nonce: Uint8Array
}

/**
 * Generate a new recovery key (BIP39 24-word mnemonic)
 *
 * @returns Recovery key data with mnemonic and derived RUK
 */
export async function generateRecoveryKey(): Promise<RecoveryKeyData> {
  // Generate 256-bit entropy → 24 words
  const mnemonic = generateMnemonic(wordlist, 256)

  // Derive RUK from mnemonic
  const ruk = await deriveRukFromMnemonic(mnemonic)

  return {
    mnemonic,
    ruk,
  }
}

/**
 * Derive RUK from mnemonic
 *
 * Flow: mnemonic → BIP39 seed (empty passphrase) → HKDF → RUK
 *
 * @param mnemonic 24-word BIP39 mnemonic
 * @returns RUK (32 bytes)
 */
export async function deriveRukFromMnemonic(mnemonic: string): Promise<Uint8Array> {
  // Validate mnemonic
  if (!validateMnemonic(mnemonic, wordlist)) {
    throw new Error('Invalid mnemonic')
  }

  // BIP39: mnemonic → seed (with empty passphrase per ADR-005)
  const seed = await mnemonicToSeed(mnemonic, '')

  // HKDF: seed → RUK (using 32-byte zero salt per spec)
  const rukInfo = new TextEncoder().encode(HKDF_INFO_RUK)
  const ruk = hkdf(sha256, seed, HKDF_ZERO_SALT, rukInfo, 32)

  return ruk
}

/**
 * Wrap UMK with RUK using XChaCha20-Poly1305
 *
 * @param umk User Master Key (32 bytes)
 * @param ruk Recovery Unlock Key (32 bytes)
 * @param userId User ID for AAD binding
 * @returns Encrypted UMK and nonce
 */
export function wrapUmkWithRuk(umk: Uint8Array, ruk: Uint8Array, userId: string): RecoveryWrappedUmk {
  // Build AAD for context binding (per spec)
  const aad = buildRecoveryUmkWrapAad(userId)

  const nonce = randomBytes(24)
  const cipher = xchacha20poly1305(ruk, nonce, aad)
  const encryptedUmk = cipher.encrypt(umk)

  return {
    encryptedUmk,
    nonce,
  }
}

/**
 * Unwrap UMK with RUK
 *
 * @param wrapped Encrypted UMK from server
 * @param ruk Recovery Unlock Key (32 bytes)
 * @param userId User ID for AAD binding
 * @returns Decrypted UMK
 * @throws Error if decryption fails (wrong mnemonic)
 */
export function unwrapUmkWithRuk(wrapped: RecoveryWrappedUmk, ruk: Uint8Array, userId: string): Uint8Array {
  // Reconstruct AAD for verification (per spec)
  const aad = buildRecoveryUmkWrapAad(userId)

  const cipher = xchacha20poly1305(ruk, wrapped.nonce, aad)
  return cipher.decrypt(wrapped.encryptedUmk)
}

/**
 * Validate a mnemonic
 *
 * @param mnemonic Mnemonic to validate
 * @returns true if valid BIP39 mnemonic
 */
export function isValidMnemonic(mnemonic: string): boolean {
  return validateMnemonic(mnemonic, wordlist)
}
