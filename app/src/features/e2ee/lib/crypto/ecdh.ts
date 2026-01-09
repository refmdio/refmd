/**
 * ECDH P-256 Key Exchange module
 *
 * Used for key sharing between users.
 * Uses @noble/curves for elliptic curve operations.
 */

import { p256 } from '@noble/curves/nist.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'

/** P-256 private key size (32 bytes) */
export const PRIVATE_KEY_SIZE = 32

/** P-256 public key size (uncompressed: 65 bytes, compressed: 33 bytes) */
export const PUBLIC_KEY_SIZE_UNCOMPRESSED = 65
export const PUBLIC_KEY_SIZE_COMPRESSED = 33

/** Derived shared secret size (32 bytes after HKDF) */
export const SHARED_SECRET_SIZE = 32

/** ECDH P-256 key pair */
export interface EcdhKeyPair {
  /** 32-byte private key */
  privateKey: Uint8Array
  /** 65-byte uncompressed public key (04 || x || y) */
  publicKey: Uint8Array
}

/**
 * Generate an ECDH P-256 key pair.
 *
 * @returns New ECDH key pair
 */
export function generateKeyPair(): EcdhKeyPair {
  const privateKey = p256.utils.randomSecretKey()
  const publicKey = p256.getPublicKey(privateKey, false) // uncompressed

  return { privateKey, publicKey }
}

/**
 * Get the public key from a private key.
 *
 * @param privateKey - 32-byte private key
 * @param compressed - Whether to return compressed format (default: false)
 * @returns Public key
 */
export function getPublicKey(privateKey: Uint8Array, compressed = false): Uint8Array {
  return p256.getPublicKey(privateKey, compressed)
}

/**
 * Compute shared secret using ECDH.
 *
 * @param privateKey - Our 32-byte private key
 * @param publicKey - Their public key (33 or 65 bytes)
 * @returns Raw shared point x-coordinate (32 bytes)
 */
export function computeSharedSecret(
  privateKey: Uint8Array,
  publicKey: Uint8Array
): Uint8Array {
  const sharedPoint = p256.getSharedSecret(privateKey, publicKey)
  // getSharedSecret returns the full point, we only need the x-coordinate
  // The first byte is 0x04 for uncompressed, then 32 bytes x, 32 bytes y
  // For compressed, first byte is 0x02 or 0x03, then 32 bytes x
  // We return the x-coordinate (bytes 1-33 for uncompressed)
  return sharedPoint.slice(1, 33)
}

/**
 * Derive a symmetric key from ECDH shared secret using HKDF-SHA256.
 *
 * @param privateKey - Our 32-byte private key
 * @param publicKey - Their public key
 * @param info - Context info for HKDF (e.g., "refmd_kek")
 * @param length - Desired output key length (default: 32)
 * @returns Derived symmetric key
 */
export function deriveSharedKey(
  privateKey: Uint8Array,
  publicKey: Uint8Array,
  info: string,
  length = SHARED_SECRET_SIZE
): Uint8Array {
  const sharedSecret = computeSharedSecret(privateKey, publicKey)

  // Use HKDF to derive a key from the shared secret
  const encoder = new TextEncoder()
  return hkdf(sha256, sharedSecret, undefined, encoder.encode(info), length)
}

/**
 * Encrypt a key for a recipient using ECDH.
 * This creates an ephemeral key pair, derives a shared key, and encrypts.
 *
 * @param recipientPublicKey - Recipient's public key
 * @param keyToEncrypt - The key to encrypt (e.g., KEK)
 * @param info - Context info for HKDF
 * @returns Ephemeral public key and encrypted key
 */
export async function encryptKeyForRecipient(
  recipientPublicKey: Uint8Array,
  keyToEncrypt: Uint8Array,
  info: string
): Promise<{ ephemeralPublicKey: Uint8Array; encryptedKey: Uint8Array; nonce: Uint8Array }> {
  // Import xchacha20 dynamically to avoid circular dependency
  const { encrypt } = await import('./xchacha20')

  // Generate ephemeral key pair
  const ephemeral = generateKeyPair()

  // Derive shared key
  const sharedKey = deriveSharedKey(ephemeral.privateKey, recipientPublicKey, info)

  // Encrypt the key
  const { ciphertext, nonce } = await encrypt(sharedKey, keyToEncrypt)

  return {
    ephemeralPublicKey: ephemeral.publicKey,
    encryptedKey: ciphertext,
    nonce,
  }
}

/**
 * Decrypt a key that was encrypted for us using ECDH.
 *
 * @param ourPrivateKey - Our private key
 * @param ephemeralPublicKey - Sender's ephemeral public key
 * @param encryptedKey - The encrypted key
 * @param nonce - The nonce used for encryption
 * @param info - Context info for HKDF
 * @returns Decrypted key
 */
export async function decryptKeyFromSender(
  ourPrivateKey: Uint8Array,
  ephemeralPublicKey: Uint8Array,
  encryptedKey: Uint8Array,
  nonce: Uint8Array,
  info: string
): Promise<Uint8Array> {
  // Import xchacha20 dynamically to avoid circular dependency
  const { decrypt } = await import('./xchacha20')

  // Derive shared key
  const sharedKey = deriveSharedKey(ourPrivateKey, ephemeralPublicKey, info)

  // Decrypt the key
  return decrypt(sharedKey, encryptedKey, nonce)
}

/**
 * Validate a P-256 public key.
 *
 * @param publicKey - Public key to validate
 * @returns true if valid, false otherwise
 */
export function isValidPublicKey(publicKey: Uint8Array): boolean {
  try {
    // Try to validate the public key
    return p256.utils.isValidPublicKey(publicKey)
  } catch {
    return false
  }
}
