/**
 * User Master Key (UMK) operations
 *
 * UMK is wrapped with PUK using XChaCha20-Poly1305 with AAD
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { randomBytes } from '@noble/ciphers/utils.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { buildUmkWrapAad, buildDeviceUmkDistributionAad } from './aad'
import { ecdhSharedSecret } from './identity'
import { HKDF_ZERO_SALT } from './kdf'

/**
 * Generate a random User Master Key (256 bits)
 */
export function generateUmk(): Uint8Array {
  return randomBytes(32)
}

/**
 * Wrap (encrypt) UMK with PUK using XChaCha20-Poly1305
 *
 * @param umk User Master Key (32 bytes)
 * @param puk Password Unlock Key (32 bytes)
 * @param userId User ID for AAD binding
 * @returns { encryptedUmk, nonce } - encrypted UMK and nonce for decryption
 */
export function wrapUmk(
  umk: Uint8Array,
  puk: Uint8Array,
  userId: string
): { encryptedUmk: Uint8Array; nonce: Uint8Array } {
  // XChaCha20-Poly1305 uses 24-byte nonce
  const nonce = randomBytes(24)

  // Build AAD for context binding (per spec)
  const aad = buildUmkWrapAad(userId)

  const cipher = xchacha20poly1305(puk, nonce, aad)
  const encryptedUmk = cipher.encrypt(umk)

  return { encryptedUmk, nonce }
}

/**
 * Unwrap (decrypt) UMK with PUK using XChaCha20-Poly1305
 *
 * @param encryptedUmk Encrypted UMK
 * @param nonce Nonce used for encryption
 * @param puk Password Unlock Key (32 bytes)
 * @param userId User ID for AAD binding
 * @returns Decrypted UMK (32 bytes)
 * @throws Error if decryption fails (wrong PUK or tampered data)
 */
export function unwrapUmk(
  encryptedUmk: Uint8Array,
  nonce: Uint8Array,
  puk: Uint8Array,
  userId: string
): Uint8Array {
  // Reconstruct AAD for verification (per spec)
  const aad = buildUmkWrapAad(userId)

  const cipher = xchacha20poly1305(puk, nonce, aad)
  return cipher.decrypt(encryptedUmk)
}

/**
 * Derive UMK distribution key from ECDH shared secret using HKDF
 *
 * Per spec: Uses 32-byte zero salt (safe for high-entropy IKM like ECDH shared secret)
 * Info string "device_umk_wrap" provides domain separation from other ECDH-derived keys.
 */
function deriveUmkDistributionKey(sharedSecret: Uint8Array): Uint8Array {
  const info = new TextEncoder().encode('device_umk_wrap')
  return hkdf(sha256, sharedSecret, HKDF_ZERO_SALT, info, 32)
}

/**
 * Encrypt UMK for distribution to another device using ECDH + HKDF
 *
 * Uses X25519 ECDH to derive a shared secret, HKDF for key derivation,
 * then encrypts UMK with XChaCha20-Poly1305.
 *
 * @param umk User Master Key (32 bytes)
 * @param senderEcdhPrivate Sender's X25519 private key (32 bytes)
 * @param targetEcdhPublic Target device's X25519 public key (32 bytes)
 * @param userId User ID for AAD binding
 * @param senderDeviceId Sender device ID for AAD binding
 * @param targetDeviceId Target device ID for AAD binding
 * @returns { encryptedUmk, nonce } - encrypted UMK and nonce for decryption
 */
export function encryptUmkForDevice(
  umk: Uint8Array,
  senderEcdhPrivate: Uint8Array,
  targetEcdhPublic: Uint8Array,
  userId: string,
  senderDeviceId: string,
  targetDeviceId: string
): { encryptedUmk: Uint8Array; nonce: Uint8Array } {
  // Derive shared secret using ECDH, then derive encryption key via HKDF
  const sharedSecret = ecdhSharedSecret(senderEcdhPrivate, targetEcdhPublic)
  const encryptionKey = deriveUmkDistributionKey(sharedSecret)

  // XChaCha20-Poly1305 uses 24-byte nonce
  const nonce = randomBytes(24)

  // Build AAD for context binding
  const aad = buildDeviceUmkDistributionAad(userId, senderDeviceId, targetDeviceId)

  const cipher = xchacha20poly1305(encryptionKey, nonce, aad)
  const encryptedUmk = cipher.encrypt(umk)

  return { encryptedUmk, nonce }
}

/**
 * Decrypt UMK received from another device using ECDH
 *
 * Uses X25519 ECDH to derive a shared secret, then decrypts UMK with XChaCha20-Poly1305.
 *
 * @param encryptedUmk Encrypted UMK
 * @param nonce Nonce used for encryption
 * @param receiverEcdhPrivate Receiver's X25519 private key (32 bytes)
 * @param senderEcdhPublic Sender's X25519 public key (32 bytes)
 * @param userId User ID for AAD binding
 * @param senderDeviceId Sender device ID for AAD binding
 * @param targetDeviceId Target (receiver) device ID for AAD binding
 * @returns Decrypted UMK (32 bytes)
 * @throws Error if decryption fails
 */
export function decryptUmkFromDevice(
  encryptedUmk: Uint8Array,
  nonce: Uint8Array,
  receiverEcdhPrivate: Uint8Array,
  senderEcdhPublic: Uint8Array,
  userId: string,
  senderDeviceId: string,
  targetDeviceId: string
): Uint8Array {
  // Derive shared secret using ECDH, then derive encryption key via HKDF
  const sharedSecret = ecdhSharedSecret(receiverEcdhPrivate, senderEcdhPublic)
  const encryptionKey = deriveUmkDistributionKey(sharedSecret)

  // Reconstruct AAD for verification
  const aad = buildDeviceUmkDistributionAad(userId, senderDeviceId, targetDeviceId)

  const cipher = xchacha20poly1305(encryptionKey, nonce, aad)
  return cipher.decrypt(encryptedUmk)
}
