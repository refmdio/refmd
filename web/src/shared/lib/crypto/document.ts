/**
 * Document Encryption Module
 *
 * Implements DEK/content encryption for document CRDT updates:
 * - DEK generation (32 bytes random)
 * - DEK wrapping with KEK using XChaCha20-Poly1305
 * - Content (Yjs updates) encryption with DEK using XChaCha20-Poly1305
 *
 * Per spec:
 * - Key hierarchy: KEK → DEK
 * - All AEAD operations use AAD with protocol/version/purpose/context
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { randomBytes } from '@noble/ciphers/utils.js'
import { buildDekWrapAad, buildDocumentContentAad } from './aad'

/**
 * Generate a random Document Encryption Key (256 bits)
 */
export function generateDek(): Uint8Array {
  return randomBytes(32)
}

/**
 * Wrap (encrypt) DEK with KEK using XChaCha20-Poly1305
 *
 * @param dek Document Encryption Key (32 bytes)
 * @param kek Key Encryption Key (32 bytes)
 * @param documentId Document ID for AAD binding
 * @param workspaceId Workspace ID for AAD binding
 * @returns { encryptedDek, nonce } - encrypted DEK and 24-byte nonce
 */
export function wrapDek(
  dek: Uint8Array,
  kek: Uint8Array,
  documentId: string,
  workspaceId: string
): { encryptedDek: Uint8Array; nonce: Uint8Array } {
  // XChaCha20-Poly1305 uses 24-byte nonce
  const nonce = randomBytes(24)

  // Build AAD for context binding (per spec)
  const aad = buildDekWrapAad(documentId, workspaceId)

  const cipher = xchacha20poly1305(kek, nonce, aad)
  const encryptedDek = cipher.encrypt(dek)

  return { encryptedDek, nonce }
}

/**
 * Unwrap (decrypt) DEK with KEK using XChaCha20-Poly1305
 *
 * @param encryptedDek Encrypted DEK
 * @param nonce Nonce used for encryption (24 bytes)
 * @param kek Key Encryption Key (32 bytes)
 * @param documentId Document ID for AAD binding
 * @param workspaceId Workspace ID for AAD binding
 * @returns Decrypted DEK (32 bytes)
 * @throws Error if decryption fails (wrong KEK or tampered data)
 */
export function unwrapDek(
  encryptedDek: Uint8Array,
  nonce: Uint8Array,
  kek: Uint8Array,
  documentId: string,
  workspaceId: string
): Uint8Array {
  // Reconstruct AAD for verification (per spec)
  const aad = buildDekWrapAad(documentId, workspaceId)

  const cipher = xchacha20poly1305(kek, nonce, aad)
  return cipher.decrypt(encryptedDek)
}

/**
 * Encrypt content (Yjs update) with DEK using XChaCha20-Poly1305
 *
 * @param content Plaintext content (Yjs update binary)
 * @param dek Document Encryption Key (32 bytes)
 * @param documentId Document ID for AAD binding
 * @returns { encrypted, nonce } - encrypted content and 24-byte nonce
 */
export function encryptContent(
  content: Uint8Array,
  dek: Uint8Array,
  documentId: string
): { encrypted: Uint8Array; nonce: Uint8Array } {
  // XChaCha20-Poly1305 uses 24-byte nonce
  const nonce = randomBytes(24)

  // Build AAD for context binding (per spec)
  const aad = buildDocumentContentAad(documentId)

  const cipher = xchacha20poly1305(dek, nonce, aad)
  const encrypted = cipher.encrypt(content)

  return { encrypted, nonce }
}

/**
 * Decrypt content (Yjs update) with DEK using XChaCha20-Poly1305
 *
 * @param encrypted Encrypted content
 * @param nonce Nonce used for encryption (24 bytes)
 * @param dek Document Encryption Key (32 bytes)
 * @param documentId Document ID for AAD binding
 * @returns Decrypted content (Yjs update binary)
 * @throws Error if decryption fails (wrong DEK or tampered data)
 */
export function decryptContent(
  encrypted: Uint8Array,
  nonce: Uint8Array,
  dek: Uint8Array,
  documentId: string
): Uint8Array {
  // Reconstruct AAD for verification (per spec)
  const aad = buildDocumentContentAad(documentId)

  const cipher = xchacha20poly1305(dek, nonce, aad)
  return cipher.decrypt(encrypted)
}
