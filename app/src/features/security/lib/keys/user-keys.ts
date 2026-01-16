/**
 * User Key Pair Management
 *
 * Manages ECDH key pairs (for key exchange) and Ed25519 key pairs (for signing).
 * Private keys are encrypted with UMK before storage.
 */

import {
  generateEcdhKeyPair,
  generateSigningKeyPair,
  encrypt,
  decrypt,
  getSodium,
  type EcdhKeyPair,
  type Ed25519KeyPair,
} from '../crypto'
import type { StoredKeys } from './key-store'

/** Complete user key set */
export interface UserKeySet {
  /** ECDH key pair for key exchange */
  ecdh: EcdhKeyPair
  /** Ed25519 key pair for signing */
  signing: Ed25519KeyPair
}

/** Encrypted private keys for storage */
export interface EncryptedUserKeys {
  /** ECDH private key encrypted with UMK */
  encryptedEcdhPrivateKey: Uint8Array
  /** Nonce for ECDH private key encryption */
  encryptedEcdhPrivateKeyNonce: Uint8Array
  /** Ed25519 signing private key encrypted with UMK */
  encryptedSigningPrivateKey: Uint8Array
  /** Nonce for signing private key encryption */
  encryptedSigningPrivateKeyNonce: Uint8Array
  /** ECDH public key (unencrypted) */
  ecdhPublicKey: Uint8Array
  /** Ed25519 signing public key (unencrypted) */
  signingPublicKey: Uint8Array
}

/**
 * Generate a new set of user key pairs.
 *
 * @returns New ECDH and Ed25519 key pairs
 */
export async function generateUserKeys(): Promise<UserKeySet> {
  // Generate ECDH key pair for key exchange
  const ecdh = generateEcdhKeyPair()

  // Generate Ed25519 key pair for signing
  const signing = await generateSigningKeyPair()

  return { ecdh, signing }
}

/**
 * Encrypt user private keys with UMK for storage.
 *
 * @param keys - User key set
 * @param umk - User Master Key
 * @returns Encrypted keys ready for storage
 */
export async function encryptUserKeys(
  keys: UserKeySet,
  umk: Uint8Array
): Promise<EncryptedUserKeys> {
  // Encrypt ECDH private key
  const ecdhResult = await encrypt(umk, keys.ecdh.privateKey)

  // Encrypt Ed25519 signing private key
  const signingResult = await encrypt(umk, keys.signing.privateKey)

  return {
    encryptedEcdhPrivateKey: ecdhResult.ciphertext,
    encryptedEcdhPrivateKeyNonce: ecdhResult.nonce,
    encryptedSigningPrivateKey: signingResult.ciphertext,
    encryptedSigningPrivateKeyNonce: signingResult.nonce,
    ecdhPublicKey: keys.ecdh.publicKey,
    signingPublicKey: keys.signing.publicKey,
  }
}

/**
 * Decrypt user private keys from storage.
 *
 * @param storedKeys - Stored encrypted keys
 * @param umk - User Master Key
 * @returns Decrypted user key set
 */
export async function decryptUserKeys(
  storedKeys: StoredKeys,
  umk: Uint8Array
): Promise<UserKeySet> {
  // Decrypt ECDH private key
  const ecdhPrivateKey = await decrypt(
    umk,
    storedKeys.encryptedEcdhPrivateKey,
    storedKeys.encryptedEcdhPrivateKeyNonce
  )

  // Decrypt Ed25519 signing private key
  const signingPrivateKey = await decrypt(
    umk,
    storedKeys.encryptedSigningPrivateKey,
    storedKeys.encryptedSigningPrivateKeyNonce
  )

  return {
    ecdh: {
      privateKey: ecdhPrivateKey,
      publicKey: storedKeys.ecdhPublicKey,
    },
    signing: {
      privateKey: signingPrivateKey,
      publicKey: storedKeys.signingPublicKey,
    },
  }
}

/**
 * Re-encrypt user keys with a new UMK (for passphrase change).
 *
 * @param keys - Current user key set
 * @param newUmk - New User Master Key
 * @returns Newly encrypted keys
 */
export async function reEncryptUserKeys(
  keys: UserKeySet,
  newUmk: Uint8Array
): Promise<EncryptedUserKeys> {
  return encryptUserKeys(keys, newUmk)
}

/**
 * Zero out user keys from memory (call when locking session).
 *
 * @param keys - User key set to zero out
 */
export function zeroUserKeys(keys: UserKeySet): void {
  keys.ecdh.privateKey.fill(0)
  keys.signing.privateKey.fill(0)
}

/**
 * Convert public keys to Base64 for API transmission.
 *
 * @param keys - User key set
 * @returns Base64-encoded public keys
 */
export async function getPublicKeysBase64(keys: UserKeySet): Promise<{
  ecdhPublicKey: string
  signingPublicKey: string
}> {
  const sodium = await getSodium()

  return {
    ecdhPublicKey: sodium.to_base64(keys.ecdh.publicKey, sodium.base64_variants.ORIGINAL),
    signingPublicKey: sodium.to_base64(keys.signing.publicKey, sodium.base64_variants.ORIGINAL),
  }
}

/**
 * Parse public keys from Base64 (from API).
 *
 * @param ecdhPublicKey - Base64-encoded ECDH public key
 * @param signingPublicKey - Base64-encoded signing public key
 * @returns Decoded public keys
 */
export async function parsePublicKeysFromBase64(
  ecdhPublicKey: string,
  signingPublicKey: string
): Promise<{
  ecdhPublicKey: Uint8Array
  signingPublicKey: Uint8Array
}> {
  const sodium = await getSodium()

  return {
    ecdhPublicKey: sodium.from_base64(ecdhPublicKey, sodium.base64_variants.ORIGINAL),
    signingPublicKey: sodium.from_base64(signingPublicKey, sodium.base64_variants.ORIGINAL),
  }
}
