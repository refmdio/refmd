/**
 * Document Encryption Module
 *
 * Implements DEK/content encryption for document CRDT updates:
 * - DEK generation (32 bytes random)
 * - DEK wrapping with KEK using XChaCha20-Poly1305
 * - Content (Yjs updates) encryption with DEK using XChaCha20-Poly1305
 * - Snapshot encryption/decryption and proof chain
 *
 * Key hierarchy: KEK → DEK
 * All AEAD operations use AAD with protocol/version/purpose/context
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { randomBytes } from '@noble/ciphers/utils.js'
import { blake3 } from '@noble/hashes/blake3.js'
import { buildDekWrapAad, buildDocumentContentAad } from './aad'
import { canonicalizeBytes } from './signature'
import { base64UrlEncode } from './encoding'

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

  // Build AAD for context binding
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
  // Reconstruct AAD for verification
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
 * @param keyVersion DEK version for AAD binding (prevents cross-version replay)
 * @returns { encrypted, nonce } - encrypted content and 24-byte nonce
 */
export function encryptContent(
  content: Uint8Array,
  dek: Uint8Array,
  documentId: string,
  keyVersion: number
): { encrypted: Uint8Array; nonce: Uint8Array } {
  // XChaCha20-Poly1305 uses 24-byte nonce
  const nonce = randomBytes(24)

  // Build AAD for context binding
  const aad = buildDocumentContentAad(documentId, keyVersion)

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
 * @param keyVersion DEK version for AAD binding (prevents cross-version replay)
 * @returns Decrypted content (Yjs update binary)
 * @throws Error if decryption fails (wrong DEK or tampered data)
 */
export function decryptContent(
  encrypted: Uint8Array,
  nonce: Uint8Array,
  dek: Uint8Array,
  documentId: string,
  keyVersion: number
): Uint8Array {
  // Reconstruct AAD for verification
  const aad = buildDocumentContentAad(documentId, keyVersion)

  const cipher = xchacha20poly1305(dek, nonce, aad)
  return cipher.decrypt(encrypted)
}

// =============================================================================
// Snapshot encryption/decryption and proof chain
// =============================================================================

/**
 * Encrypt a Yjs full state (snapshot) with DEK using XChaCha20-Poly1305
 *
 * @param yjsState Full Yjs state binary
 * @param dek Document Encryption Key (32 bytes)
 * @param documentId Document ID for AAD binding
 * @param keyVersion DEK version for AAD binding
 * @returns { ciphertext, nonce } - encrypted snapshot and 24-byte nonce
 */
export function encryptSnapshot(
  yjsState: Uint8Array,
  dek: Uint8Array,
  documentId: string,
  keyVersion: number
): { ciphertext: Uint8Array; nonce: Uint8Array } {
  const { encrypted, nonce } = encryptContent(yjsState, dek, documentId, keyVersion)
  return { ciphertext: encrypted, nonce }
}

/**
 * Decrypt a snapshot ciphertext with DEK using XChaCha20-Poly1305
 *
 * @param ciphertext Encrypted snapshot
 * @param nonce Nonce used for encryption (24 bytes)
 * @param dek Document Encryption Key (32 bytes)
 * @param documentId Document ID for AAD binding
 * @param keyVersion DEK version for AAD binding
 * @returns Decrypted Yjs state binary
 * @throws Error if decryption fails
 */
export function decryptSnapshot(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  dek: Uint8Array,
  documentId: string,
  keyVersion: number
): Uint8Array {
  return decryptContent(ciphertext, nonce, dek, documentId, keyVersion)
}

/**
 * Compute BLAKE3 hash of snapshot ciphertext (content-addressable)
 *
 * @param ciphertext Encrypted snapshot bytes
 * @returns Base64url-encoded BLAKE3 hash
 */
export function computeSnapshotCiphertextHash(ciphertext: Uint8Array): string {
  const hash = blake3(ciphertext)
  return base64UrlEncode(hash)
}

/**
 * Compute parent snapshot proof (chain hash)
 *
 * proof = BLAKE3(JCS({ ciphertext_hash, parent_proof, snapshot_id }))
 *
 * JCS key names follow the codebase snake_case convention (same as update_hash).
 * For the first snapshot (no grandparent), parent_proof is empty string.
 *
 * @param grandParentProof Base64url-encoded proof from grandparent (or empty string)
 * @param parentSnapshotId UUID of the parent snapshot
 * @param parentCiphertextHash Base64url-encoded BLAKE3 hash of parent's ciphertext
 * @returns Base64url-encoded BLAKE3 hash (the proof)
 */
export function computeParentSnapshotProof(
  grandParentProof: string,
  parentSnapshotId: string,
  parentCiphertextHash: string
): string {
  const canonical = canonicalizeBytes({
    ciphertext_hash: parentCiphertextHash,
    parent_proof: grandParentProof,
    snapshot_id: parentSnapshotId,
  })
  const hash = blake3(canonical)
  return base64UrlEncode(hash)
}

/**
 * Compute update_hash per update-hash.md specification.
 *
 * update_hash = BLAKE3(JCS({
 *   clock, device_signing_pub_key, document_id,
 *   encrypted_content, key_version, nonce,
 *   ref_snapshot_id, timestamp
 * }))
 *
 * @param params All fields required for the hash computation
 * @returns Base64url-encoded BLAKE3 hash
 */
export function computeUpdateHash(params: {
  clock: number
  deviceSigningPubKey: string
  documentId: string
  encryptedContent: string
  keyVersion: number
  nonce: string
  refSnapshotId: string
  timestamp: number
}): string {
  const canonical = canonicalizeBytes({
    clock: params.clock,
    device_signing_pub_key: params.deviceSigningPubKey,
    document_id: params.documentId,
    encrypted_content: params.encryptedContent,
    key_version: params.keyVersion,
    nonce: params.nonce,
    ref_snapshot_id: params.refSnapshotId,
    timestamp: params.timestamp,
  })
  const hash = blake3(canonical)
  return base64UrlEncode(hash)
}

