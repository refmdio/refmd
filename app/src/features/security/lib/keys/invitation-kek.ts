/**
 * Invitation KEK Encryption
 *
 * Encrypts workspace KEK using a key derived from the invitation token.
 * This allows invited users to decrypt the KEK without requiring
 * the inviter to be online at acceptance time.
 *
 * Security model:
 * - Token is a UUID (122 bits entropy) generated server-side
 * - Token is transmitted to invitee via any secure channel
 * - Token is single-use and expires
 * - Key derivation uses BLAKE2b (via crypto_generichash)
 */

import { getSodium } from '../crypto'

/** Domain separation context for invitation KEK derivation */
const INVITATION_KEK_CONTEXT = 'refmd_invitation_kek_v1'

/** Key size for XChaCha20-Poly1305 (32 bytes) */
const KEY_SIZE = 32

/** Nonce size for XChaCha20-Poly1305 (24 bytes) */
const NONCE_SIZE = 24

/**
 * Derive a symmetric key from an invitation token.
 *
 * Uses BLAKE2b hash with domain separation to derive a 32-byte key
 * from the invitation token.
 *
 * @param token - Invitation token (UUID string)
 * @returns 32-byte derived key
 */
export async function deriveKeyFromInvitationToken(token: string): Promise<Uint8Array> {
  const sodium = await getSodium()

  // Combine token with context for domain separation
  const input = `${INVITATION_KEK_CONTEXT}:${token}`
  const inputBytes = sodium.from_string(input)

  // Use BLAKE2b to derive a 32-byte key
  return sodium.crypto_generichash(KEY_SIZE, inputBytes)
}

/**
 * Encrypt a KEK for an invitation.
 *
 * @param kek - The workspace KEK to encrypt
 * @param invitationToken - The invitation token
 * @returns Encrypted KEK with nonce
 */
export async function encryptKekForInvitation(
  kek: Uint8Array,
  invitationToken: string
): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }> {
  if (kek.length !== KEY_SIZE) {
    throw new Error(`Invalid KEK length: expected ${KEY_SIZE}, got ${kek.length}`)
  }

  const sodium = await getSodium()
  const derivedKey = await deriveKeyFromInvitationToken(invitationToken)

  const nonce = sodium.randombytes_buf(NONCE_SIZE)
  const ciphertext = sodium.crypto_secretbox_easy(kek, nonce, derivedKey)

  return { ciphertext, nonce }
}

/**
 * Decrypt a KEK from an invitation.
 *
 * @param ciphertext - Encrypted KEK
 * @param nonce - Nonce used during encryption
 * @param invitationToken - The invitation token
 * @returns Decrypted KEK
 * @throws Error if decryption fails (wrong token or corrupted data)
 */
export async function decryptKekFromInvitation(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  invitationToken: string
): Promise<Uint8Array> {
  if (nonce.length !== NONCE_SIZE) {
    throw new Error(`Invalid nonce length: expected ${NONCE_SIZE}, got ${nonce.length}`)
  }

  const sodium = await getSodium()
  const derivedKey = await deriveKeyFromInvitationToken(invitationToken)

  try {
    const decrypted = sodium.crypto_secretbox_open_easy(ciphertext, nonce, derivedKey)

    if (decrypted.length !== KEY_SIZE) {
      throw new Error(`Invalid decrypted KEK length: expected ${KEY_SIZE}, got ${decrypted.length}`)
    }

    return decrypted
  } catch {
    throw new Error('Failed to decrypt invitation KEK: invalid token or corrupted data')
  }
}

/**
 * Encode invitation-encrypted KEK for API storage.
 *
 * Format: nonce (24 bytes) || ciphertext
 *
 * @param ciphertext - Encrypted KEK
 * @param nonce - Nonce used during encryption
 * @returns Base64-encoded combined data
 */
export async function encodeInvitationKekForApi(
  ciphertext: Uint8Array,
  nonce: Uint8Array
): Promise<string> {
  const sodium = await getSodium()

  const combined = new Uint8Array(nonce.length + ciphertext.length)
  combined.set(nonce, 0)
  combined.set(ciphertext, nonce.length)

  return sodium.to_base64(combined, sodium.base64_variants.ORIGINAL)
}

/**
 * Decode invitation-encrypted KEK from API response.
 *
 * @param encryptedKekBase64 - Base64-encoded encrypted KEK from API
 * @returns Nonce and ciphertext
 */
export async function decodeInvitationKekFromApi(encryptedKekBase64: string): Promise<{
  nonce: Uint8Array
  ciphertext: Uint8Array
}> {
  const sodium = await getSodium()
  const combined = sodium.from_base64(encryptedKekBase64, sodium.base64_variants.ORIGINAL)

  if (combined.length < NONCE_SIZE + 1) {
    throw new Error('Invalid invitation KEK format: too short')
  }

  const nonce = combined.slice(0, NONCE_SIZE)
  const ciphertext = combined.slice(NONCE_SIZE)

  return { nonce, ciphertext }
}
