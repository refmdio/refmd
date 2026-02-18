/**
 * KEK (Key Encryption Key) operations
 *
 * KEK is wrapped per-device using ECDH, not with UMK directly.
 * This provides per-device isolation - revoking a device doesn't require
 * re-encrypting KEK for all other devices.
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { randomBytes } from '@noble/ciphers/utils.js'
import { buildDeviceKekDistributionAad, buildUmkKekBackupAad } from './aad'
import { ecdhEncrypt, ecdhDecrypt } from './ecdh-cipher'

/**
 * Generate a random KEK (256 bits)
 */
export function generateKek(): Uint8Array {
  return randomBytes(32)
}

/** HKDF info string for KEK distribution domain separation */
const KEK_HKDF_INFO = 'kek_wrap'

/**
 * Encrypt KEK for distribution to a device using ECDH + HKDF
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
  const aad = buildDeviceKekDistributionAad(workspaceId, userId, senderDeviceId, targetDeviceId)
  const { ciphertext, nonce } = ecdhEncrypt(kek, senderEcdhPrivate, targetEcdhPublic, KEK_HKDF_INFO, aad)
  return { encryptedKek: ciphertext, nonce }
}

/**
 * Wrap KEK with UMK for backup (direct XChaCha20-Poly1305, no HKDF)
 *
 * @param kek Key Encryption Key (32 bytes)
 * @param umk User Master Key (32 bytes)
 * @param workspaceId Workspace ID for AAD binding
 * @param userId User ID for AAD binding
 * @param keyVersion KEK version for AAD binding (prevents version mixup)
 * @returns { encryptedKek, nonce } - encrypted KEK and nonce
 */
export function wrapKekWithUmk(
  kek: Uint8Array,
  umk: Uint8Array,
  workspaceId: string,
  userId: string,
  keyVersion: number
): { encryptedKek: Uint8Array; nonce: Uint8Array } {
  const nonce = randomBytes(24)
  const aad = buildUmkKekBackupAad(workspaceId, userId, keyVersion)
  const cipher = xchacha20poly1305(umk, nonce, aad)
  const encryptedKek = cipher.encrypt(kek)
  return { encryptedKek, nonce }
}

/**
 * Unwrap KEK from UMK backup (direct XChaCha20-Poly1305, no HKDF)
 *
 * @param encryptedKek Encrypted KEK
 * @param nonce Nonce used for encryption
 * @param umk User Master Key (32 bytes)
 * @param workspaceId Workspace ID for AAD binding
 * @param userId User ID for AAD binding
 * @param keyVersion KEK version for AAD binding
 * @returns Decrypted KEK (32 bytes)
 * @throws Error if decryption fails
 */
export function unwrapKekWithUmk(
  encryptedKek: Uint8Array,
  nonce: Uint8Array,
  umk: Uint8Array,
  workspaceId: string,
  userId: string,
  keyVersion: number
): Uint8Array {
  const aad = buildUmkKekBackupAad(workspaceId, userId, keyVersion)
  const cipher = xchacha20poly1305(umk, nonce, aad)
  return cipher.decrypt(encryptedKek)
}

/**
 * Decrypt KEK received from another device using ECDH
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
  const aad = buildDeviceKekDistributionAad(workspaceId, userId, senderDeviceId, targetDeviceId)
  return ecdhDecrypt(encryptedKek, nonce, receiverEcdhPrivate, senderEcdhPublic, KEK_HKDF_INFO, aad)
}
