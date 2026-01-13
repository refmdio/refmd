/**
 * File decryption for .rme format
 */

import { decrypt } from '../crypto/xchacha20'
import {
  isRmeFile,
  type DecryptedRmeFile,
  type RmeMetadata,
} from '../types/file-format'
import { parseRme } from './format'
import { computeSha256 } from './hash'

/**
 * E2EE file error codes
 */
export const E2EE_FILE_ERROR = {
  FORMAT_INVALID: 'E2EE_FILE_FORMAT_INVALID',
  CORRUPTED: 'E2EE_FILE_CORRUPTED',
  DECRYPTION_FAILED: 'E2EE_FILE_DECRYPTION_FAILED',
} as const

/**
 * E2EE file error
 */
export class E2EEFileError extends Error {
  constructor(
    public readonly code: string,
    message: string
  ) {
    super(message)
    this.name = 'E2EEFileError'
  }
}

/**
 * Decrypt a .rme file
 *
 * @param rmeBytes - Encrypted .rme file bytes
 * @param dek - Document Encryption Key (32 bytes)
 * @param options - Decryption options
 * @returns Decrypted file content and metadata
 * @throws E2EEFileError if decryption fails
 */
export async function decryptFile(
  rmeBytes: Uint8Array,
  dek: Uint8Array,
  options?: { skipHashCheck?: boolean }
): Promise<DecryptedRmeFile> {
  // 1. Validate magic bytes
  if (!isRmeFile(rmeBytes)) {
    throw new E2EEFileError(
      E2EE_FILE_ERROR.FORMAT_INVALID,
      'Invalid RME file: magic bytes mismatch'
    )
  }

  // 2. Parse header and structure
  let rmeFile
  try {
    rmeFile = parseRme(rmeBytes)
  } catch (err) {
    throw new E2EEFileError(
      E2EE_FILE_ERROR.FORMAT_INVALID,
      `Invalid RME file: ${err instanceof Error ? err.message : 'parse error'}`
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
    throw new E2EEFileError(
      E2EE_FILE_ERROR.DECRYPTION_FAILED,
      'Failed to decrypt metadata'
    )
  }

  let metadata: RmeMetadata
  try {
    const metadataJson = new TextDecoder().decode(metadataBytes)
    metadata = JSON.parse(metadataJson)
  } catch (err) {
    throw new E2EEFileError(
      E2EE_FILE_ERROR.CORRUPTED,
      'Invalid metadata format'
    )
  }

  // 4. Decrypt content
  let content: Uint8Array
  try {
    content = await decrypt(dek, rmeFile.encryptedContent, rmeFile.contentNonce)
  } catch (err) {
    throw new E2EEFileError(
      E2EE_FILE_ERROR.DECRYPTION_FAILED,
      'Failed to decrypt content'
    )
  }

  // 5. Validate size
  if (content.length !== metadata.originalSize) {
    throw new E2EEFileError(
      E2EE_FILE_ERROR.CORRUPTED,
      `Content size mismatch: expected ${metadata.originalSize}, got ${content.length}`
    )
  }

  // 6. Validate hash (optional, can skip for performance)
  if (!options?.skipHashCheck) {
    const computedHash = await computeSha256(content)
    if (computedHash !== metadata.originalHash) {
      throw new E2EEFileError(
        E2EE_FILE_ERROR.CORRUPTED,
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
    throw new E2EEFileError(
      E2EE_FILE_ERROR.DECRYPTION_FAILED,
      'Failed to decrypt metadata'
    )
  }

  try {
    const metadataJson = new TextDecoder().decode(metadataBytes)
    return JSON.parse(metadataJson)
  } catch (err) {
    throw new E2EEFileError(
      E2EE_FILE_ERROR.CORRUPTED,
      'Invalid metadata format'
    )
  }
}
