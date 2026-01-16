/**
 * File decryption for .rme format
 */

import { decrypt } from '../crypto/xchacha20'
import { CryptoError, ERROR_CODES } from '../types/errors'
import {
  isRmeFile,
  type DecryptedRmeFile,
  type RmeMetadata,
} from '../types/file-format'
import { parseRme } from './format'
import { computeSha256 } from './hash'

/**
 * Decrypt a .rme file
 *
 * @param rmeBytes - Encrypted .rme file bytes
 * @param dek - Document Encryption Key (32 bytes)
 * @param options - Decryption options
 * @returns Decrypted file content and metadata
 * @throws CryptoError if decryption fails
 */
export async function decryptFile(
  rmeBytes: Uint8Array,
  dek: Uint8Array,
  options?: { skipHashCheck?: boolean }
): Promise<DecryptedRmeFile> {
  // 1. Validate magic bytes
  if (!isRmeFile(rmeBytes)) {
    throw new CryptoError(
      ERROR_CODES.FILE_FORMAT_INVALID,
      'Invalid RME file: magic bytes mismatch'
    )
  }

  // 2. Parse header and structure
  let rmeFile
  try {
    rmeFile = parseRme(rmeBytes)
  } catch (err) {
    throw new CryptoError(
      ERROR_CODES.FILE_FORMAT_INVALID,
      `Invalid RME file: ${err instanceof Error ? err.message : 'parse error'}`,
      { cause: err instanceof Error ? err : undefined }
    )
  }

  // 3. Decrypt metadata
  let metadataBytes: Uint8Array
  try {
    metadataBytes = await decrypt(
      dek,
      rmeFile.encryptedMetadata,
      rmeFile.metadataNonce
    )
  } catch (err) {
    throw new CryptoError(
      ERROR_CODES.DECRYPTION_FAILED,
      'Failed to decrypt metadata',
      { cause: err instanceof Error ? err : undefined }
    )
  }

  let metadata: RmeMetadata
  try {
    const metadataJson = new TextDecoder().decode(metadataBytes)
    metadata = JSON.parse(metadataJson)
  } catch (err) {
    throw new CryptoError(ERROR_CODES.FILE_CORRUPTED, 'Invalid metadata format', {
      cause: err instanceof Error ? err : undefined,
    })
  }

  // 4. Decrypt content
  let content: Uint8Array
  try {
    content = await decrypt(dek, rmeFile.encryptedContent, rmeFile.contentNonce)
  } catch (err) {
    throw new CryptoError(
      ERROR_CODES.DECRYPTION_FAILED,
      'Failed to decrypt content',
      { cause: err instanceof Error ? err : undefined }
    )
  }

  // 5. Validate size
  if (content.length !== metadata.originalSize) {
    throw new CryptoError(
      ERROR_CODES.FILE_CORRUPTED,
      `Content size mismatch: expected ${metadata.originalSize}, got ${content.length}`
    )
  }

  // 6. Validate hash (optional, can skip for performance)
  if (!options?.skipHashCheck) {
    const computedHash = await computeSha256(content)
    if (computedHash !== metadata.originalHash) {
      throw new CryptoError(
        ERROR_CODES.FILE_CORRUPTED,
        'Content hash mismatch - file may be corrupted'
      )
    }
  }

  return { metadata, content }
}

/**
 * Decrypt file metadata only (without full file content)
 *
 * Used for building file maps from API responses where only
 * encrypted metadata and nonce are available.
 *
 * @param encryptedMetadata - Encrypted metadata bytes
 * @param nonce - Nonce used for encryption
 * @param dek - Document Encryption Key (32 bytes)
 * @returns Decrypted metadata
 */
export async function decryptMetadata(
  encryptedMetadata: Uint8Array,
  nonce: Uint8Array,
  dek: Uint8Array
): Promise<RmeMetadata> {
  let metadataBytes: Uint8Array
  try {
    metadataBytes = await decrypt(dek, encryptedMetadata, nonce)
  } catch (err) {
    throw new CryptoError(
      ERROR_CODES.DECRYPTION_FAILED,
      'Failed to decrypt metadata',
      { cause: err instanceof Error ? err : undefined }
    )
  }

  try {
    const metadataJson = new TextDecoder().decode(metadataBytes)
    return JSON.parse(metadataJson)
  } catch (err) {
    throw new CryptoError(ERROR_CODES.FILE_CORRUPTED, 'Invalid metadata format', {
      cause: err instanceof Error ? err : undefined,
    })
  }
}
