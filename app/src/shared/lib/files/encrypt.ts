/**
 * File encryption for .rme format
 */

import { encrypt } from '@/shared/lib/crypto'
import {
  RME_MAGIC,
  RME_VERSION,
  type EncryptFileOptions,
  type RmeFile,
  type RmeMetadata,
} from '@/shared/types/security'

import { serializeRme } from './format'
import { computeSha256 } from './hash'

/**
 * Result of file encryption
 */
export interface EncryptFileResult {
  /** Complete .rme file bytes */
  rmeBytes: Uint8Array
  /** Base64-encoded metadata nonce */
  metadataNonce: string
  /** Base64-encoded encrypted metadata */
  encryptedMetadata: string
  /** SHA-256 hash of encrypted file (hex) */
  encryptedHash: string
}

/**
 * Convert Uint8Array to Base64 string
 */
function toBase64(bytes: Uint8Array): string {
  const binary = String.fromCharCode(...bytes)
  return btoa(binary)
}

/**
 * Encrypt a file to .rme format
 *
 * @param content - File content to encrypt
 * @param dek - Document Encryption Key (32 bytes)
 * @param options - Encryption options
 * @returns Encrypted file result
 */
export async function encryptFile(
  content: Uint8Array,
  dek: Uint8Array,
  options: EncryptFileOptions
): Promise<EncryptFileResult> {
  // 1. Compute original file hash
  const originalHash = await computeSha256(content)

  // 2. Build metadata
  const metadata: RmeMetadata = {
    filename: options.filename,
    mimeType: options.mimeType ?? 'application/octet-stream',
    originalSize: content.length,
    originalHash,
    encryptedAt: new Date().toISOString(),
    logicalPath: options.logicalPath ?? `attachments/${options.filename}`,
    extra: options.extra,
  }

  // 3. Encrypt metadata
  const metadataJson = JSON.stringify(metadata)
  const metadataBytes = new TextEncoder().encode(metadataJson)
  const { ciphertext: encryptedMetadataBytes, nonce: metadataNonce } =
    await encrypt(dek, metadataBytes)

  // 4. Encrypt content
  const { ciphertext: encryptedContent, nonce: contentNonce } = await encrypt(
    dek,
    content
  )

  // 5. Build .rme file structure
  const rmeFile: RmeFile = {
    header: {
      magic: RME_MAGIC,
      version: RME_VERSION,
      headerLength: 11,
      metadataLength: encryptedMetadataBytes.length,
    },
    metadataNonce,
    encryptedMetadata: encryptedMetadataBytes,
    contentNonce,
    encryptedContent,
  }

  // 6. Serialize to binary
  const rmeBytes = serializeRme(rmeFile)

  // 7. Compute encrypted file hash
  const encryptedHash = await computeSha256(rmeBytes)

  return {
    rmeBytes,
    metadataNonce: toBase64(metadataNonce),
    encryptedMetadata: toBase64(encryptedMetadataBytes),
    encryptedHash,
  }
}
