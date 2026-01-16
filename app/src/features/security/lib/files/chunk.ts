/**
 * Chunked encryption for large files (>10MB)
 */

import { encrypt, decrypt } from '../crypto/xchacha20'
import { DEFAULT_CHUNK_SIZE } from '../types/file-format'

/** Large file threshold: 10MB */
export const LARGE_FILE_THRESHOLD = 10 * 1024 * 1024

/**
 * Check if a file is considered large
 */
export function isLargeFile(size: number): boolean {
  return size > LARGE_FILE_THRESHOLD
}

/**
 * Encrypted chunk with its nonce
 */
export interface EncryptedChunk {
  ciphertext: Uint8Array
  nonce: Uint8Array
}

/**
 * Split content into chunks
 */
export function* splitIntoChunks(
  content: Uint8Array,
  chunkSize: number = DEFAULT_CHUNK_SIZE
): Generator<{ chunk: Uint8Array; index: number; total: number }> {
  const total = Math.ceil(content.length / chunkSize)

  for (let i = 0; i < total; i++) {
    const start = i * chunkSize
    const end = Math.min(start + chunkSize, content.length)
    yield {
      chunk: content.slice(start, end),
      index: i,
      total,
    }
  }
}

/**
 * Encrypt content in chunks with progress callback
 *
 * @param content - Content to encrypt
 * @param dek - Document Encryption Key
 * @param chunkSize - Size of each chunk (default: 1MB)
 * @param onProgress - Progress callback (0-1)
 * @returns Array of encrypted chunks
 */
export async function encryptChunked(
  content: Uint8Array,
  dek: Uint8Array,
  chunkSize: number = DEFAULT_CHUNK_SIZE,
  onProgress?: (progress: number) => void
): Promise<{ chunks: EncryptedChunk[]; totalChunks: number }> {
  const chunks: EncryptedChunk[] = []
  let processed = 0

  for (const { chunk, index } of splitIntoChunks(content, chunkSize)) {
    const { ciphertext, nonce } = await encrypt(dek, chunk)
    chunks.push({ ciphertext, nonce })

    processed += chunk.length
    onProgress?.(processed / content.length)

    // Yield to UI thread periodically to prevent blocking
    if (index % 10 === 0) {
      await new Promise((resolve) => setTimeout(resolve, 0))
    }
  }

  return { chunks, totalChunks: chunks.length }
}

/**
 * Decrypt chunked content with progress callback
 *
 * @param chunks - Encrypted chunks
 * @param dek - Document Encryption Key
 * @param totalSize - Expected total size of decrypted content
 * @param onProgress - Progress callback (0-1)
 * @returns Decrypted content
 */
export async function decryptChunked(
  chunks: EncryptedChunk[],
  dek: Uint8Array,
  totalSize: number,
  onProgress?: (progress: number) => void
): Promise<Uint8Array> {
  const result = new Uint8Array(totalSize)
  let offset = 0

  for (let i = 0; i < chunks.length; i++) {
    const { ciphertext, nonce } = chunks[i]
    const plaintext = await decrypt(dek, ciphertext, nonce)
    result.set(plaintext, offset)
    offset += plaintext.length

    onProgress?.(offset / totalSize)

    // Yield to UI thread periodically
    if (i % 10 === 0) {
      await new Promise((resolve) => setTimeout(resolve, 0))
    }
  }

  return result
}
