/**
 * User Master Key (UMK) operations
 *
 * UMK is wrapped with PUK using XChaCha20-Poly1305 with AAD
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { randomBytes } from '@noble/ciphers/utils.js'
import { buildUmkWrapAad } from './aad'

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
