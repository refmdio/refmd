/**
 * ECDH + HKDF + XChaCha20-Poly1305 cipher helpers
 *
 * Shared pipeline for encrypting/decrypting data using X25519 ECDH
 * key agreement, HKDF domain-separated key derivation, and
 * XChaCha20-Poly1305 authenticated encryption.
 *
 * Used by both KEK distribution (info="kek_wrap") and
 * UMK distribution (info="device_umk_wrap").
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { randomBytes } from '@noble/ciphers/utils.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { ecdhSharedSecret } from './identity'
import { HKDF_ZERO_SALT } from './kdf'

function deriveKey(sharedSecret: Uint8Array, info: string): Uint8Array {
  return hkdf(sha256, sharedSecret, HKDF_ZERO_SALT, new TextEncoder().encode(info), 32)
}

/**
 * Encrypt data for a target device using ECDH + HKDF + XChaCha20-Poly1305
 */
export function ecdhEncrypt(
  plaintext: Uint8Array,
  senderEcdhPrivate: Uint8Array,
  targetEcdhPublic: Uint8Array,
  hkdfInfo: string,
  aad: Uint8Array,
): { ciphertext: Uint8Array; nonce: Uint8Array } {
  const sharedSecret = ecdhSharedSecret(senderEcdhPrivate, targetEcdhPublic)
  const encryptionKey = deriveKey(sharedSecret, hkdfInfo)
  const nonce = randomBytes(24)
  const cipher = xchacha20poly1305(encryptionKey, nonce, aad)
  return { ciphertext: cipher.encrypt(plaintext), nonce }
}

/**
 * Decrypt data from another device using ECDH + HKDF + XChaCha20-Poly1305
 */
export function ecdhDecrypt(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  receiverEcdhPrivate: Uint8Array,
  senderEcdhPublic: Uint8Array,
  hkdfInfo: string,
  aad: Uint8Array,
): Uint8Array {
  const sharedSecret = ecdhSharedSecret(receiverEcdhPrivate, senderEcdhPublic)
  const encryptionKey = deriveKey(sharedSecret, hkdfInfo)
  const cipher = xchacha20poly1305(encryptionKey, nonce, aad)
  return cipher.decrypt(ciphertext)
}
