/**
 * Invitation KEK Operations
 *
 * Token generation, KEK encryption/decryption for workspace invitations.
 * Uses HKDF to derive encryption key from invitation token, then
 * XChaCha20-Poly1305 to encrypt/decrypt KEK.
 */

import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { randomBytes } from '@noble/ciphers/utils.js'
import { HKDF_ZERO_SALT, buildInvitationKekWrapAad, base64UrlEncode } from '@/shared/lib/crypto'

const INVITATION_HKDF_INFO = 'invitation_kek_wrap'

/** Derive encryption key from invitation token via HKDF */
function deriveTokenKey(token: Uint8Array): Uint8Array {
  const info = new TextEncoder().encode(INVITATION_HKDF_INFO)
  return hkdf(sha256, token, HKDF_ZERO_SALT, info, 32)
}

/** Generate a new invitation token */
export function generateInvitationToken(): {
  token: Uint8Array
  tokenHash: string
  tokenPrefix: string
} {
  const token = randomBytes(32)
  const hashBytes = sha256(token)
  const tokenHash = base64UrlEncode(hashBytes)
  const tokenPrefix = base64UrlEncode(token).slice(0, 4)
  return { token, tokenHash, tokenPrefix }
}

/** Encrypt KEK for an invitation using token-derived key */
export function encryptKekForInvitation(
  kek: Uint8Array,
  token: Uint8Array,
  workspaceId: string,
  invitationId: string,
  keyVersion: number
): { encryptedKek: Uint8Array; nonce: Uint8Array } {
  const tokenKey = deriveTokenKey(token)
  const nonce = randomBytes(24)
  const aad = buildInvitationKekWrapAad(workspaceId, invitationId, keyVersion)
  const cipher = xchacha20poly1305(tokenKey, nonce, aad)
  const encryptedKek = cipher.encrypt(kek)
  return { encryptedKek, nonce }
}

/** Decrypt KEK from an invitation using token-derived key */
export function decryptKekFromInvitation(
  encryptedKek: Uint8Array,
  nonce: Uint8Array,
  token: Uint8Array,
  workspaceId: string,
  invitationId: string,
  keyVersion: number
): Uint8Array {
  const tokenKey = deriveTokenKey(token)
  const aad = buildInvitationKekWrapAad(workspaceId, invitationId, keyVersion)
  const cipher = xchacha20poly1305(tokenKey, nonce, aad)
  return cipher.decrypt(encryptedKek)
}
