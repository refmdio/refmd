/**
 * File Encryption Module
 *
 * Provides file encryption/decryption for .rme format attachments.
 * These are pure functions with no application state dependencies.
 */

// Hash computation
export { computeSha256 } from './hash'

// .rme format serialization
export { serializeRme, parseRme } from './format'

// File format utilities (re-exported from types)
export { isRmeFile } from '@/shared/types/security'

// File encryption
export { encryptFile, type EncryptFileResult } from './encrypt'

// File decryption
export { decryptFile, decryptMetadata } from './decrypt'

// Chunked encryption for large files
export {
  isLargeFile,
  splitIntoChunks,
  encryptChunked,
  decryptChunked,
  LARGE_FILE_THRESHOLD,
  type EncryptedChunk,
} from './chunk'
