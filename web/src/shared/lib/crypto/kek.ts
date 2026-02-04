/**
 * KEK (Key Encryption Key) operations
 *
 * KEK is wrapped per-device using ECDH, not with UMK directly.
 * This provides per-device isolation - revoking a device doesn't require
 * re-encrypting KEK for all other devices.
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { randomBytes } from '@noble/ciphers/utils.js'
import { buildDeviceKekDistributionAad } from './aad'
import { ecdhSharedSecret } from './identity'

/**
 * Generate a random KEK (256 bits)
 */
export function generateKek(): Uint8Array {
  return randomBytes(32)
}

/**
 * Encrypt KEK for distribution to a device using ECDH
 *
 * Uses X25519 ECDH to derive a shared secret, then encrypts KEK with XChaCha20-Poly1305.
 *
 * @param kek Key Encryption Key (32 bytes)
 * @param senderEcdhPrivate Sender's X25519 private key (32 bytes)
 * @param targetEcdhPublic Target device's X25519 public key (32 bytes)
 * @param workspaceId Workspace ID for AAD binding
 * @param userId User ID for AAD binding
 * @param senderDeviceId Sender device ID for AAD binding
 * @param targetDeviceId Target device ID for AAD binding
 * @returns { encryptedKek, nonce } - encrypted KEK and nonce for decryption
 */
export function encryptKekForDevice(
  kek: Uint8Array,
  senderEcdhPrivate: Uint8Array,
  targetEcdhPublic: Uint8Array,
  workspaceId: string,
  userId: string,
  senderDeviceId: string,
  targetDeviceId: string
): { encryptedKek: Uint8Array; nonce: Uint8Array } {
  // Derive shared secret using ECDH
  const sharedSecret = ecdhSharedSecret(senderEcdhPrivate, targetEcdhPublic)

  // XChaCha20-Poly1305 uses 24-byte nonce
  const nonce = randomBytes(24)

  // Build AAD for context binding
  const aad = buildDeviceKekDistributionAad(workspaceId, userId, senderDeviceId, targetDeviceId)

  const cipher = xchacha20poly1305(sharedSecret, nonce, aad)
  const encryptedKek = cipher.encrypt(kek)

  return { encryptedKek, nonce }
}

/**
 * Decrypt KEK received from another device using ECDH
 *
 * Uses X25519 ECDH to derive a shared secret, then decrypts KEK with XChaCha20-Poly1305.
 *
 * @param encryptedKek Encrypted KEK
 * @param nonce Nonce used for encryption
 * @param receiverEcdhPrivate Receiver's X25519 private key (32 bytes)
 * @param senderEcdhPublic Sender's X25519 public key (32 bytes)
 * @param workspaceId Workspace ID for AAD binding
 * @param userId User ID for AAD binding
 * @param senderDeviceId Sender device ID for AAD binding
 * @param targetDeviceId Target (receiver) device ID for AAD binding
 * @returns Decrypted KEK (32 bytes)
 * @throws Error if decryption fails
 */
export function decryptKekFromDevice(
  encryptedKek: Uint8Array,
  nonce: Uint8Array,
  receiverEcdhPrivate: Uint8Array,
  senderEcdhPublic: Uint8Array,
  workspaceId: string,
  userId: string,
  senderDeviceId: string,
  targetDeviceId: string
): Uint8Array {
  // Derive shared secret using ECDH (same secret as sender computed)
  const sharedSecret = ecdhSharedSecret(receiverEcdhPrivate, senderEcdhPublic)

  // Reconstruct AAD for verification
  const aad = buildDeviceKekDistributionAad(workspaceId, userId, senderDeviceId, targetDeviceId)

  const cipher = xchacha20poly1305(sharedSecret, nonce, aad)
  return cipher.decrypt(encryptedKek)
}
